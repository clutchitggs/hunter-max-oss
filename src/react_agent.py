"""
ReAct Agent v15 — Scout-Sniper Active Testing Orchestrator.

Architecture: Tiered Agentic Orchestration for Autonomous Vulnerability Research.

Phase 1 (Scout):
  - Fast Sonnet-tier ReAct agent identifies leads (BOLA, Mass Assignment, SSRF)
  - 7-step limit, kill switch for duplicate detection
  - Runs inline in pipeline, exits immediately after storing leads in react_leads table

Phase 2 (Snipers — fully decoupled via sniper_worker):
  - Object Specialist (Opus): Deep BOLA + Mass Assignment verification
  - Resource Specialist (Opus): Deep SSRF with OAST callbacks
  - Runs as background worker, never blocks the per-target pipeline

Rule: Never let a fast task (Scout) wait for a slow task (Sniper).

This file provides:
  - run_react_testing_v15(): Pipeline entry point — runs Scout only, stores leads
  - process_sniper_lead(): Called by sniper_worker — processes one lead with appropriate Sniper
  - run_react_testing(): v14 backward compat (still works for validation)
"""
import json
import logging
import re
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

TIMEOUT = 10
MAX_ITERATIONS = 5          # Max Think→Act→Observe cycles per endpoint
MAX_REQUESTS_PER_ENDPOINT = 10  # Hard cap per endpoint
MAX_BODY_SIZE = 50 * 1024   # 50KB request body limit
MAX_RESPONSE_SNIPPET = 2000  # Chars of response body shown to AI

_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
_session.verify = False
_adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


# =====================================================================
# HTTP TOOL LAYER — Hard safety constraints enforced here, not in prompts
# =====================================================================

class HttpTool:
    """Sandboxed HTTP tool for the ReAct agent. All safety at the tool level."""

    def __init__(self, scope_domains):
        """scope_domains: set of domains the agent is allowed to target."""
        self.scope_domains = {d.lower() for d in scope_domains}
        self.request_counts = {}  # endpoint → count
        self.total_requests = 0

    def _check_scope(self, url):
        """Verify URL is within scope. Returns (ok, reason)."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname.lower() if parsed.hostname else ""
        except Exception:
            return False, "Invalid URL"

        if not host:
            return False, "No hostname in URL"

        # Check if host matches any scope domain (exact or subdomain)
        in_scope = any(
            host == d or host.endswith(f".{d}")
            for d in self.scope_domains
        )
        if not in_scope:
            return False, f"Host '{host}' not in scope {self.scope_domains}"

        # Block internal targets — only check actual IPs, not hostnames
        # (0.gravatar.com is a valid public hostname, not an internal IP)
        if host in ("localhost", "0.0.0.0"):
            return False, "Localhost blocked"
        _is_ip = all(c in "0123456789." for c in host) and host.count(".") == 3
        if _is_ip and any(host.startswith(p) for p in ("127.", "10.", "192.168.", "172.16.", "0.")):
            return False, "Internal IP blocked"

        return True, "OK"

    def _check_rate(self, endpoint_key):
        """Check per-endpoint rate limit. Returns (ok, reason)."""
        count = self.request_counts.get(endpoint_key, 0)
        if count >= MAX_REQUESTS_PER_ENDPOINT:
            return False, f"Rate limit: {count}/{MAX_REQUESTS_PER_ENDPOINT} requests to this endpoint"
        return True, "OK"

    def execute(self, method, url, headers=None, body=None):
        """Execute an HTTP request with all safety checks.
        Returns dict with status, headers, body_snippet, or error."""

        method = method.upper()

        # HARD CONSTRAINT: No DELETE ever
        if method == "DELETE":
            return {"error": "DELETE method is forbidden — testing must be non-destructive"}

        # HARD CONSTRAINT: Only allowed methods
        if method not in ("GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"):
            return {"error": f"Method '{method}' not allowed. Use GET, POST, PUT, PATCH, HEAD, or OPTIONS"}

        # Scope check
        ok, reason = self._check_scope(url)
        if not ok:
            return {"error": f"Scope violation: {reason}"}

        # Rate check
        endpoint_key = f"{method}:{urlparse(url).path}"
        ok, reason = self._check_rate(endpoint_key)
        if not ok:
            return {"error": reason}

        # Body size check
        if body and len(str(body)) > MAX_BODY_SIZE:
            return {"error": f"Request body too large ({len(str(body))} bytes, max {MAX_BODY_SIZE})"}

        # Execute
        time.sleep(1)  # 1s delay between requests — mandatory
        self.request_counts[endpoint_key] = self.request_counts.get(endpoint_key, 0) + 1
        self.total_requests += 1

        try:
            kwargs = {"timeout": TIMEOUT, "allow_redirects": False}
            if headers:
                kwargs["headers"] = headers
            if body and method in ("POST", "PUT", "PATCH"):
                if isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    kwargs["data"] = str(body)[:MAX_BODY_SIZE]

            resp = _session.request(method, url, **kwargs)

            resp_headers = dict(list(resp.headers.items())[:20])
            body_snippet = resp.text[:MAX_RESPONSE_SNIPPET]

            return {
                "status_code": resp.status_code,
                "headers": resp_headers,
                "body_snippet": body_snippet,
                "body_length": len(resp.text),
                "redirect": resp.headers.get("Location", ""),
            }
        except Exception as e:
            return {"error": f"Request failed: {type(e).__name__}: {str(e)[:200]}"}


# =====================================================================
# REACT LOOP — Think → Act → Observe → Think
# =====================================================================

REACT_SYSTEM_PROMPT = """You are a security researcher testing a web application endpoint for vulnerabilities.
You have access to an HTTP tool that can make GET, POST, PUT, and PATCH requests.
DELETE is forbidden — you must verify vulnerabilities by READING state, not destroying it.

Your approach:
1. THINK: Analyze what you know about this endpoint and decide what to test
2. ACT: Make ONE HTTP request to test your hypothesis
3. OBSERVE: Analyze the response — what did you learn?
4. Repeat until you have enough evidence, then give your VERDICT

IMPORTANT RULES:
- You are testing for {vuln_class} specifically
- You have max {max_iterations} iterations — be efficient
- Prove vulnerabilities by READING unauthorized data, not by modifying/deleting
- If a test is inconclusive, try a different angle before giving up

{test_guidance}

For each iteration, reply ONLY JSON:
{{
  "thought": "what I'm thinking and why",
  "action": {{
    "method": "GET/POST/PUT/PATCH",
    "url": "full URL to request",
    "headers": {{}},
    "body": {{}}
  }},
  "done": false
}}

When you have enough evidence (or hit max iterations), reply:
{{
  "thought": "final analysis",
  "action": null,
  "done": true,
  "verdict": "vulnerable" or "not_vulnerable" or "needs_manual_check",
  "confidence": 1-10,
  "evidence_summary": "what you found, with specific HTTP evidence",
  "severity": "Critical/High/Medium/Low"
}}"""


def run_react_test(subdomain, endpoint_info, vuln_class, scope_domains, target_id=None):
    """Run a ReAct testing loop on one endpoint for one vuln class.

    Args:
        subdomain: the host being tested
        endpoint_info: dict with {endpoint, method, params, source} from api_schemas
        vuln_class: one of "mass_assignment", "ssrf", "auth_bypass", "open_redirect"
        scope_domains: set of allowed domains
        target_id: for DB storage

    Returns: dict with verdict, evidence, severity, or None if AI unavailable
    """
    from llm_client import call_tier

    tool = HttpTool(scope_domains)
    endpoint = endpoint_info.get("endpoint", "/")
    method = endpoint_info.get("method", "GET")
    params = endpoint_info.get("params", "")
    base_url = f"https://{subdomain}{endpoint}"

    test_guidance = _get_test_guidance(vuln_class, subdomain, endpoint, method, params)

    system_prompt = REACT_SYSTEM_PROMPT.format(
        vuln_class=vuln_class,
        max_iterations=MAX_ITERATIONS,
        test_guidance=test_guidance,
    )

    # Initial context for the AI
    conversation = f"""{system_prompt}

=== TARGET ===
Host: {subdomain}
Endpoint: {method} {endpoint}
Base URL: {base_url}
Parameters/context: {str(params)[:500]}
Source: {endpoint_info.get('source', 'unknown')}

Begin your first THINK → ACT cycle."""

    for iteration in range(MAX_ITERATIONS):
        # Call AI
        response = call_tier("tier2", conversation, max_tokens=600)
        if not response:
            log.warning(f"  [REACT] AI unavailable at iteration {iteration}")
            return None

        # Parse AI response
        data = _parse_react_response(response)
        if not data:
            log.warning(f"  [REACT] Could not parse AI response at iteration {iteration}")
            break

        thought = data.get("thought", "")
        action = data.get("action")
        done = data.get("done", False)

        log.info(f"  [REACT] {subdomain}{endpoint} iter={iteration} thought={thought[:80]}...")

        if done or not action:
            # AI is done — extract verdict
            return {
                "verdict": data.get("verdict", "not_vulnerable"),
                "confidence": data.get("confidence", 0),
                "evidence_summary": data.get("evidence_summary", ""),
                "severity": data.get("severity", "Low"),
                "iterations": iteration + 1,
                "total_requests": tool.total_requests,
                "vuln_class": vuln_class,
            }

        # Execute the action
        act_method = action.get("method", "GET")
        act_url = action.get("url", base_url)
        act_headers = action.get("headers")
        act_body = action.get("body")

        result = tool.execute(act_method, act_url, headers=act_headers, body=act_body)

        # Build observation for next iteration
        if result.get("error"):
            observation = f"ERROR: {result['error']}"
        else:
            observation = (
                f"HTTP {result['status_code']} | "
                f"Content-Length: {result.get('body_length', 0)} | "
                f"Redirect: {result.get('redirect', 'none')}\n"
                f"Headers: {json.dumps(dict(list(result.get('headers', {}).items())[:10]))}\n"
                f"Body: {result.get('body_snippet', '')[:800]}"
            )

        conversation += f"\n\n=== ITERATION {iteration + 1} ===\nYour response:\n{response}\n\nOBSERVATION:\n{observation}\n\nContinue your next THINK → ACT cycle (or set done=true if you have enough evidence)."

    # Hit max iterations without verdict
    return {
        "verdict": "not_vulnerable",
        "confidence": 3,
        "evidence_summary": "Max iterations reached without conclusive evidence",
        "severity": "Low",
        "iterations": MAX_ITERATIONS,
        "total_requests": tool.total_requests,
        "vuln_class": vuln_class,
    }


def _parse_react_response(text):
    """Parse the AI's JSON response, handling markdown fences and quirks."""
    if not text:
        return None
    # Strip markdown fences
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON object
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


# =====================================================================
# TEST GUIDANCE — per vuln class instructions for the AI
# =====================================================================

def _generate_react_report(subdomain, domain, endpoint, vuln_class, severity, result):
    """Generate a HackerOne-ready report from a confirmed ReAct finding.
    Uses Opus for report quality. Falls back to a template if AI unavailable."""
    from llm_client import call_tier

    evidence_summary = result.get("evidence_summary", "")
    iterations = result.get("iterations", 0)
    total_requests = result.get("total_requests", 0)
    confidence = result.get("confidence", 0)

    prompt = f"""Write a HackerOne bug bounty report for this confirmed vulnerability.
The vulnerability was discovered and verified by automated active testing (ReAct agent).
The evidence below is from REAL HTTP requests — this is not a guess.

Target: {subdomain} (parent domain: {domain})
Vulnerability: {vuln_class.replace('_', ' ').title()}
Severity: {severity}
Endpoint: https://{subdomain}{endpoint}
Confidence: {confidence}/10

Evidence from testing:
{evidence_summary}

Write the report in Markdown with these sections:
1. **Summary** (2-3 sentences — what the bug is, why it matters)
2. **Severity** ({severity} — justify with impact)
3. **Steps to Reproduce** (numbered, exact HTTP requests that prove the bug)
4. **Impact** (what an attacker can do — be specific to this application)
5. **Remediation** (how to fix it — be specific)

Be concise and factual. Only reference evidence from the testing above."""

    report = call_tier("tier3", prompt, max_tokens=3000)
    if not report:
        report = call_tier("tier2", prompt, max_tokens=2000)

    if not report:
        # Template fallback if AI unavailable
        report = f"""# {vuln_class.replace('_', ' ').title()} — {subdomain}

## Summary
Automated active testing discovered a {vuln_class.replace('_', ' ')} vulnerability on `{subdomain}{endpoint}`.

## Severity
**{severity}**

## Evidence
{evidence_summary}

## Steps to Reproduce
1. Send a request to `https://{subdomain}{endpoint}` as described in the evidence above.
2. Observe the response confirming the vulnerability.

## Impact
See evidence summary above.

## Remediation
Implement proper input validation and access controls on the affected endpoint.

---
*Discovered by automated ReAct agent ({iterations} iterations, {total_requests} requests)*"""

    return report


def _get_test_guidance(vuln_class, subdomain, endpoint, method, params):
    """Return specific testing guidance for each vuln class."""

    if vuln_class == "mass_assignment":
        return f"""MASS ASSIGNMENT TESTING:
You are testing whether the endpoint accepts hidden parameters that elevate privileges.

Strategy:
1. First, make a normal GET request to understand the response structure
2. Then, send a POST/PUT with extra fields that shouldn't be user-controllable:
   - role: "admin", isAdmin: true, account_type: "premium"
   - is_verified: true, email_verified: true, permissions: ["admin"]
   - plan: "enterprise", credits: 99999, discount: 100
3. Check if the response reflects the injected fields
4. PROOF = the response contains your injected values (state change verified by reading)

The endpoint is: {method} https://{subdomain}{endpoint}
Known params: {str(params)[:300]}"""

    elif vuln_class == "ssrf":
        return f"""SSRF (Server-Side Request Forgery) TESTING:
You are testing whether the endpoint fetches URLs and could be tricked into hitting internal services.

Strategy:
1. Look for parameters that accept URLs (url=, link=, redirect=, callback=, webhook=, fetch=, proxy=, img=, src=)
2. Try submitting a URL pointing to a known external canary (use https://httpbin.org/get as a test target)
3. Try URL schemes: http://169.254.169.254/latest/meta-data/ (AWS metadata)
4. Check if the response contains data from the target URL (proves server-side fetch)
5. PROOF = response body contains content from a URL YOU specified

IMPORTANT: Do NOT actually hit internal services. Use httpbin.org as your canary.
The endpoint is: {method} https://{subdomain}{endpoint}"""

    elif vuln_class == "auth_bypass":
        return f"""AUTH BYPASS TESTING:
You are testing whether authentication can be circumvented on this endpoint.

Strategy:
1. First, try accessing the endpoint without any auth headers — check if it's actually protected
2. Try common bypasses:
   - Add X-Forwarded-For: 127.0.0.1 header (IP whitelist bypass)
   - Add X-Original-URL or X-Rewrite-URL headers (path traversal bypass)
   - Try different HTTP methods (GET vs POST vs PUT — method override)
   - Try adding .json or /. or /..;/ to the path (path normalization bypass)
3. Check for rate limiting on password reset / login endpoints
4. PROOF = you can access protected data or functionality without valid credentials

The endpoint is: {method} https://{subdomain}{endpoint}"""

    elif vuln_class == "open_redirect":
        return f"""OPEN REDIRECT TESTING:
You are testing whether the endpoint redirects to attacker-controlled URLs.

Strategy:
1. Look for redirect parameters (redirect=, url=, next=, return=, returnTo=, goto=, destination=, continue=, redir=)
2. Try setting them to https://evil.com and check if the response is a 3xx redirect to that URL
3. Try bypass techniques:
   - //evil.com (protocol-relative)
   - /\\evil.com (backslash)
   - https://{subdomain}.evil.com (subdomain trick)
   - https://evil.com%40{subdomain} (@ bypass)
   - /redirect?url=//evil.com
4. PROOF = HTTP 3xx response with Location header pointing to your controlled URL

The endpoint is: {method} https://{subdomain}{endpoint}"""

    return "Test this endpoint for security vulnerabilities."


# =====================================================================
# TEST SELECTOR — picks which endpoints to test for which vulns
# =====================================================================

# Keywords that suggest an endpoint is relevant for each vuln class
VULN_ENDPOINT_SIGNALS = {
    "mass_assignment": {
        "keywords": ["register", "signup", "create", "update", "profile", "account", "user", "settings", "invite"],
        "methods": ["POST", "PUT", "PATCH"],
    },
    "ssrf": {
        "keywords": ["url", "fetch", "proxy", "webhook", "callback", "link", "import", "upload", "preview", "share"],
        "methods": ["GET", "POST"],
    },
    "auth_bypass": {
        "keywords": ["admin", "dashboard", "internal", "manage", "config", "settings", "panel", "api"],
        "methods": ["GET", "POST"],
    },
    "open_redirect": {
        "keywords": ["login", "logout", "redirect", "return", "callback", "oauth", "auth", "sso", "next", "goto"],
        "methods": ["GET"],
    },
}


def select_tests(api_schemas_rows):
    """Given a list of api_schema rows, select which endpoints to test for which vuln classes.
    Returns list of (endpoint_info, vuln_class) pairs."""
    tests = []

    for row in api_schemas_rows:
        endpoint = row.get("endpoint", "").lower()
        method = row.get("method", "GET").upper()

        for vuln_class, signals in VULN_ENDPOINT_SIGNALS.items():
            # Check if endpoint matches this vuln class
            keyword_match = any(kw in endpoint for kw in signals["keywords"])
            method_match = method in signals["methods"]

            if keyword_match and method_match:
                tests.append((row, vuln_class))

    # Deduplicate: max 3 tests per vuln class per target (cost control)
    seen = {}
    filtered = []
    for row, vuln_class in tests:
        count = seen.get(vuln_class, 0)
        if count < 3:
            filtered.append((row, vuln_class))
            seen[vuln_class] = count + 1

    return filtered


# =====================================================================
# MAIN ENTRY POINT — run_react_testing()
# =====================================================================

def run_react_testing(domain, target_id, live_hosts):
    """Full ReAct testing for a target. Reads api_schemas, selects endpoints,
    runs ReAct loops, stores confirmed vulns.

    Called by the pipeline's testing phase."""
    from db import get_conn, insert_vuln, log_activity

    # 1. Load discovered API schemas for this target
    with get_conn() as conn:
        schemas = [dict(r) for r in conn.execute(
            "SELECT subdomain, endpoint, method, params, source FROM api_schemas "
            "WHERE target_id = ? ORDER BY id", (target_id,)
        ).fetchall()]

    if not schemas:
        log.info(f"  [REACT] {domain}: no API schemas found — skipping active testing")
        return {"tests_run": 0, "findings": 0}

    # Build scope from target domain + live hosts
    scope_domains = {domain}
    scope_domains.update(h.split(":")[0] for h in live_hosts[:20])

    # 2. Select which endpoints to test for which vulns
    tests = select_tests(schemas)
    if not tests:
        log.info(f"  [REACT] {domain}: no testable endpoints matched — skipping")
        return {"tests_run": 0, "findings": 0}

    log.info(f"  [REACT] {domain}: {len(tests)} tests selected from {len(schemas)} endpoints")
    log_activity("scan", f"{domain}: ReAct agent starting {len(tests)} active tests")

    # 3. Run tests
    findings = 0
    tests_run = 0

    for endpoint_info, vuln_class in tests:
        subdomain = endpoint_info.get("subdomain", domain)
        endpoint = endpoint_info.get("endpoint", "/")

        log.info(f"  [REACT] Testing {vuln_class} on {subdomain}{endpoint}...")

        result = run_react_test(subdomain, endpoint_info, vuln_class, scope_domains, target_id)
        tests_run += 1

        if not result:
            continue

        verdict = result.get("verdict", "not_vulnerable")
        confidence = result.get("confidence", 0)

        if verdict == "vulnerable" and confidence >= 6:
            findings += 1
            severity = result.get("severity", "Medium")
            evidence = (
                f"ReAct Agent ({vuln_class}): {result.get('evidence_summary', '')}\n"
                f"Endpoint: {endpoint_info.get('method', 'GET')} {subdomain}{endpoint}\n"
                f"Confidence: {confidence}/10 | Iterations: {result.get('iterations', 0)} | "
                f"Requests: {result.get('total_requests', 0)}"
            )

            # Generate report directly — skip T1→T5, the agent already verified with real HTTP
            report = _generate_react_report(subdomain, domain, endpoint, vuln_class, severity, result)

            vuln_id = insert_vuln(target_id, subdomain, f"react:{vuln_class}", evidence, severity,
                                  f"https://{subdomain}{endpoint}")
            # Mark as 'reviewed' so T1→T5 pipeline never touches it
            if vuln_id:
                with get_conn() as c:
                    c.execute("UPDATE vulns SET status = 'reviewed', report_md = ? WHERE id = ?",
                              (report, vuln_id))
            log_activity("vuln", f"REACT {severity}: {vuln_class} on {subdomain}{endpoint} — REPORT READY")
            log.info(f"  *** [REACT] FOUND + REPORT: {vuln_class} on {subdomain}{endpoint} (confidence={confidence})")

        elif verdict == "needs_manual_check":
            evidence_summary = result.get('evidence_summary', '')
            vuln_id = insert_vuln(target_id, subdomain, f"react:{vuln_class}",
                                  f"NEEDS MANUAL CHECK: {evidence_summary}\nEndpoint: {subdomain}{endpoint}",
                                  "Medium", f"https://{subdomain}{endpoint}")
            if vuln_id:
                with get_conn() as c:
                    c.execute("UPDATE vulns SET status = 'needs_review' WHERE id = ?", (vuln_id,))
            log_activity("vuln", f"REACT MAYBE: {vuln_class} on {subdomain}{endpoint} — needs manual check")

        else:
            log.info(f"  [REACT] Clean: {vuln_class} on {subdomain}{endpoint} (confidence={confidence})")

    log.info(f"  [REACT] {domain}: DONE — {tests_run} tests, {findings} findings")
    log_activity("scan", f"{domain}: ReAct testing done — {tests_run} tests, {findings} findings")

    return {"tests_run": tests_run, "findings": findings}


# =====================================================================
# v15 ENTRY POINTS — Scout-Sniper Architecture
# =====================================================================

def run_react_testing_v15(domain, target_id, live_hosts):
    """v15 pipeline entry point: Run Scout ONLY, store leads, exit immediately.

    The Scout is fast (Sonnet, 7 steps). Leads are stored in react_leads table.
    Snipers are handled by a SEPARATE sniper_worker background task.
    This function NEVER blocks waiting for Snipers.

    Called by pipeline.py phase_testing().
    """
    from scout_agent import run_scout_sweep
    from db import log_activity

    log.info(f"  [v15] {domain}: Starting Scout sweep...")
    result = run_scout_sweep(domain, target_id, live_hosts)

    tests_run = result.get("tests_run", 0)
    leads = result.get("leads", [])

    if leads:
        log.info(f"  [v15] {domain}: Scout found {len(leads)} leads — queued for Sniper processing")
        log_activity("scan", f"{domain}: Scout produced {len(leads)} leads for Sniper verification")
    else:
        log.info(f"  [v15] {domain}: Scout found no high-confidence leads")

    # Return immediately — Snipers will process leads asynchronously via sniper_worker
    return {"tests_run": tests_run, "findings": 0, "leads_queued": len(leads)}


def process_sniper_lead(lead_row):
    """Process a single Scout lead with the appropriate Sniper agent.

    Called by sniper_worker in pipeline.py — runs as a background task,
    completely decoupled from the per-target pipeline.

    Args:
        lead_row: dict from react_leads table (includes domain from JOIN)

    Returns:
        dict with verdict, confidence, severity, report (if confirmed)
    """
    from db import get_conn, insert_vuln, update_lead, log_activity

    lead_id = lead_row["id"]
    vuln_class = lead_row["vuln_class"]
    subdomain = lead_row["subdomain"]
    endpoint = lead_row["endpoint"]
    target_id = lead_row["target_id"]
    domain = lead_row.get("domain", "")
    lead_data = json.loads(lead_row.get("lead_data", "{}"))

    log.info(f"  [SNIPER] Processing lead #{lead_id}: {vuln_class} on {subdomain}{endpoint}")

    # Mark lead as in_progress
    update_lead(lead_id, "in_progress")

    # Build scope from domain + subdomain
    scope_domains = {domain, subdomain}
    if "." in subdomain:
        # Add parent domain to scope
        parts = subdomain.split(".")
        if len(parts) >= 2:
            scope_domains.add(".".join(parts[-2:]))

    # Load credentials if available
    from scout_agent import _load_credentials
    program_handle = ""
    with get_conn() as conn:
        target_row = conn.execute("SELECT program_url FROM targets WHERE id = ?", (target_id,)).fetchone()
    if target_row and target_row["program_url"]:
        parts = target_row["program_url"].rstrip("/").split("/")
        program_handle = parts[-1] if parts else ""
    credentials = _load_credentials(program_handle) if program_handle else None

    try:
        result = None

        if vuln_class in ("bola", "mass_assignment"):
            from sniper_object import run_object_sniper
            result = run_object_sniper(lead_data, scope_domains, credentials)

        elif vuln_class == "ssrf":
            from sniper_resource import run_resource_sniper
            # Initialize OAST client if configured
            oast_client = None
            try:
                from oast_client import OASTClient
                oast_client = OASTClient()
                if oast_client.server_url:
                    oast_client.register()
                else:
                    oast_client = None
            except Exception:
                oast_client = None

            try:
                result = run_resource_sniper(lead_data, scope_domains, oast_client)
            finally:
                if oast_client:
                    oast_client.close()
        else:
            log.warning(f"  [SNIPER] Unknown vuln_class: {vuln_class}")
            update_lead(lead_id, "error", json.dumps({"error": f"Unknown vuln_class: {vuln_class}"}))
            return None

        if not result:
            update_lead(lead_id, "error", json.dumps({"error": "AI unavailable"}))
            return None

        verdict = result.get("verdict", "rejected")
        confidence = result.get("confidence", 0)
        severity = result.get("severity", "Low")
        report = result.get("report", "")

        # Store Sniper result
        update_lead(lead_id, verdict, json.dumps(result, default=str))

        if verdict == "confirmed" and confidence >= 7 and report:
            # Create vuln entry with report — skip T1-T5, Sniper already verified
            evidence = (
                f"Sniper ({vuln_class}): {result.get('evidence_summary', '')}\n"
                f"Endpoint: {lead_data.get('method', 'GET')} {subdomain}{endpoint}\n"
                f"Confidence: {confidence}/10 | Steps: {result.get('iterations', 0)} | "
                f"Requests: {result.get('total_requests', 0)}"
            )
            vuln_id = insert_vuln(
                target_id, subdomain, f"sniper:{vuln_class}", evidence,
                severity, f"https://{subdomain}{endpoint}",
            )
            if vuln_id:
                with get_conn() as c:
                    c.execute(
                        "UPDATE vulns SET status = 'reviewed', report_md = ? WHERE id = ?",
                        (report, vuln_id),
                    )
            log.info(f"  *** [SNIPER] CONFIRMED: {vuln_class} on {subdomain}{endpoint} "
                     f"(confidence={confidence}, severity={severity}) — REPORT READY")
            log_activity("vuln", f"SNIPER {severity}: {vuln_class} on {subdomain}{endpoint} — CONFIRMED")
            # Discord notification — Sniper confirmed, needs manual validation
            try:
                from notifier_discord import notify_finding_ready
                notify_finding_ready({
                    "id": vuln_id, "subdomain": subdomain, "vuln_type": f"sniper:{vuln_class}",
                    "severity": severity, "url": f"https://{subdomain}{endpoint}",
                    "target_domain": domain, "status": "reviewed",
                    "report_md": report, "source": f"Sniper ({vuln_class})",
                })
            except Exception:
                pass

        elif verdict == "needs_manual_check":
            vuln_id = insert_vuln(
                target_id, subdomain, f"sniper:{vuln_class}",
                f"NEEDS MANUAL CHECK: {result.get('evidence_summary', '')}",
                "Medium", f"https://{subdomain}{endpoint}",
            )
            if vuln_id:
                with get_conn() as c:
                    c.execute("UPDATE vulns SET status = 'needs_review' WHERE id = ?", (vuln_id,))
            log_activity("vuln", f"SNIPER MAYBE: {vuln_class} on {subdomain}{endpoint}")

        else:
            log.info(f"  [SNIPER] Rejected: {vuln_class} on {subdomain}{endpoint} (confidence={confidence})")

        return result

    except Exception as e:
        log.error(f"  [SNIPER] Error on lead #{lead_id}: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        update_lead(lead_id, "error", json.dumps({"error": str(e)}))
        return None
