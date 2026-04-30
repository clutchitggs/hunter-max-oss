"""
Scout Agent v15 — Fast lead identification via ReAct pattern.

The Scout is a high-speed, low-cost reasoning engine (Sonnet) that identifies
vulnerability leads across three classes: BOLA, Mass Assignment, SSRF.

Architecture (per ReAct paper, ICLR 2023):
  Thought → Action → Observation → Thought → ...
  Sparse thoughts at decision points. 7-step hard cap.
  Kill switch terminates on duplicate requests.

Leads with confidence >= 6 are dispatched to Snipers for deep verification.
The Scout NEVER writes reports — it only produces structured leads.
"""
import hashlib
import json
import logging
import re
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

# --- Constants ---
MAX_ITERATIONS = 7          # Per ReAct paper: 7 steps optimal
MAX_REQUESTS_PER_ENDPOINT = 12
MAX_BODY_SIZE = 50 * 1024
MAX_RESPONSE_SNIPPET = 2000
TIMEOUT = 10
LEAD_CONFIDENCE_THRESHOLD = 6  # Minimum confidence to dispatch to Sniper

_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
_session.verify = False
_adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


# =====================================================================
# KILL SWITCH — Duplicate request detection (ReAct paper failure mode #1)
# =====================================================================

class KillSwitch:
    """Detects when the model repeats the same request, preventing infinite loops.

    The ReAct paper (Table 2) identifies repetitive action generation as the #1
    failure mode. This switch terminates the loop immediately on duplicate detection.
    """

    def __init__(self):
        self.seen = set()
        self.triggered = False
        self.trigger_count = 0

    def check(self, method, url, body=None):
        """Returns True if this exact request was already made."""
        parsed = urlparse(url)
        if isinstance(body, dict):
            body_hash = hashlib.md5(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        elif body:
            body_hash = hashlib.md5(str(body).encode()).hexdigest()
        else:
            body_hash = "none"

        key = f"{method}:{parsed.netloc}{parsed.path}:{body_hash}"
        if key in self.seen:
            self.triggered = True
            self.trigger_count += 1
            return True
        self.seen.add(key)
        return False


# =====================================================================
# HTTP TOOL — Safety constraints enforced at tool layer, not prompts
# =====================================================================

class ScoutHttpTool:
    """Sandboxed HTTP tool with kill switch integration.

    All safety constraints are HARDCODED here. The AI model cannot bypass them
    regardless of what it generates — this is the tool-layer enforcement principle.
    """

    def __init__(self, scope_domains, credentials=None):
        """
        Args:
            scope_domains: set of allowed target domains
            credentials: optional dict {session_a: {token, user_id}, session_b: {token, user_id}}
        """
        self.scope_domains = {d.lower() for d in scope_domains}
        self.credentials = credentials or {}
        self.request_counts = {}
        self.total_requests = 0
        self.kill_switch = KillSwitch()

    def _check_scope(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.hostname.lower() if parsed.hostname else ""
        except Exception:
            return False, "Invalid URL"

        if not host:
            return False, "No hostname in URL"

        # Block internal targets — only check actual IPs, not hostnames
        # (0.gravatar.com is a valid public hostname, not an internal IP)
        if host in ("localhost", "0.0.0.0"):
            return False, "Localhost blocked"
        _is_ip = all(c in "0123456789." for c in host) and host.count(".") == 3
        if _is_ip and any(host.startswith(p) for p in ("127.", "10.", "192.168.", "172.16.", "0.")):
            return False, "Internal IP blocked"

        in_scope = any(host == d or host.endswith(f".{d}") for d in self.scope_domains)
        if not in_scope:
            return False, f"Host '{host}' not in scope"
        return True, "OK"

    def execute(self, method, url, headers=None, body=None):
        """Execute HTTP request with safety + kill switch enforcement."""
        method = method.upper()

        # HARD: No DELETE
        if method == "DELETE":
            return {"error": "DELETE method is forbidden — testing must be non-destructive"}

        if method not in ("GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"):
            return {"error": f"Method '{method}' not allowed"}

        # Scope check
        ok, reason = self._check_scope(url)
        if not ok:
            return {"error": f"Scope violation: {reason}"}

        # Kill switch check
        if self.kill_switch.check(method, url, body):
            return {"error": "KILL SWITCH: Duplicate request detected. You already sent this exact request. Try a DIFFERENT approach or end your investigation.",
                    "kill_switch": True}

        # Rate check
        endpoint_key = f"{method}:{urlparse(url).path}"
        count = self.request_counts.get(endpoint_key, 0)
        if count >= MAX_REQUESTS_PER_ENDPOINT:
            return {"error": f"Rate limit: {count}/{MAX_REQUESTS_PER_ENDPOINT} requests to this endpoint"}

        # Body size
        if body and len(str(body)) > MAX_BODY_SIZE:
            return {"error": f"Request body too large ({len(str(body))} bytes, max {MAX_BODY_SIZE})"}

        # Execute with mandatory delay
        time.sleep(1)
        self.request_counts[endpoint_key] = count + 1
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
            return {
                "status_code": resp.status_code,
                "headers": dict(list(resp.headers.items())[:20]),
                "body_snippet": resp.text[:MAX_RESPONSE_SNIPPET],
                "body_length": len(resp.text),
                "redirect": resp.headers.get("Location", ""),
            }
        except Exception as e:
            return {"error": f"Request failed: {type(e).__name__}: {str(e)[:200]}"}


# =====================================================================
# SCOUT SYSTEM PROMPT — Grounded reasoning with sparse thoughts
# =====================================================================

SCOUT_SYSTEM_PROMPT = """You are a security researcher performing FAST reconnaissance on a web API endpoint.
Your job is to IDENTIFY potential vulnerabilities, not to fully verify them. Think of yourself as a scout — find leads quickly and move on.

You have an HTTP tool that can make GET, POST, PUT, and PATCH requests.
DELETE is forbidden. You must verify findings by READING state, not destroying it.

APPROACH (ReAct pattern):
1. THINK: Analyze what you know. What's worth testing? What would a real attacker try first?
2. ACT: Make ONE HTTP request to test your hypothesis.
3. OBSERVE: What did the response tell you? Adjust your plan.
4. Repeat up to {max_iterations} iterations — be EFFICIENT. Don't waste steps.

CRITICAL RULES:
- You are testing for {vuln_class} specifically.
- You have max {max_iterations} iterations. Every step must have a PURPOSE.
- If the KILL SWITCH fires (duplicate request error), you MUST immediately set done=true.
- Prove things by READING unauthorized data, never by modifying/deleting.

{test_guidance}

{credentials_context}

For each step, reply ONLY with this JSON:
{{
  "thought": "what I'm reasoning about and why (1-2 sentences)",
  "action": {{
    "method": "GET/POST/PUT/PATCH",
    "url": "full URL to request",
    "headers": {{}},
    "body": {{}}
  }},
  "done": false
}}

When you have enough evidence OR hit an obstacle, reply:
{{
  "thought": "final analysis",
  "action": null,
  "done": true,
  "lead": {{
    "vuln_class": "{vuln_class}",
    "confidence": 1-10,
    "initial_evidence": "what you found with specific HTTP evidence",
    "payload_used": "the exact request that revealed the issue",
    "suggested_sniper_tests": ["what a deeper investigation should try next"]
  }}
}}

Set confidence >= 7 ONLY if you have concrete HTTP evidence (not just suspicion).
Set confidence 4-6 if the behavior is suspicious but unconfirmed.
Set confidence 1-3 if you found nothing interesting."""


# =====================================================================
# VULN CLASS GUIDANCE — What to test and how
# =====================================================================

def _get_scout_guidance(vuln_class, subdomain, endpoint, method, params, credentials=None):
    """Focused test guidance per vuln class."""

    if vuln_class == "bola":
        cred_hint = ""
        if credentials:
            cred_hint = f"""
CREDENTIALS AVAILABLE:
  Session A: Token={credentials['session_a']['token'][:30]}... User ID={credentials['session_a']['user_id']}
  Session B: Token={credentials['session_b']['token'][:30]}... User ID={credentials['session_b']['user_id']}
  Use Session A's token to try accessing Session B's resources."""

        return f"""BOLA (Broken Object Level Authorization) SCOUTING:
You are testing whether this endpoint lets you access OTHER users' data by changing ID parameters.

Strategy (3-4 steps max):
1. First, make a normal request to understand the response structure. Look for ID fields in the URL path or response.
2. If the endpoint has an ID parameter (in path like /users/123 or query like ?id=123):
   - Request with ID=1, note the response
   - Request with ID=2, note the response
   - If BOTH return real data → BOLA lead (no auth check on object access)
3. If no obvious ID param, try adding one: ?user_id=1, ?account_id=1, ?id=1
4. Check if the response changes based on ID → that means objects are being served without ownership verification
{cred_hint}
PROOF = different real data returned for different ID values (not just 404 vs 200)
Endpoint: {method} https://{subdomain}{endpoint}
Known params: {str(params)[:300]}"""

    elif vuln_class == "mass_assignment":
        return f"""MASS ASSIGNMENT SCOUTING:
You are testing whether this endpoint accepts hidden parameters that could elevate privileges.

Strategy (3-4 steps max):
1. GET the endpoint first to see what fields exist in the response
2. POST/PUT with the SAME fields PLUS privilege escalation fields:
   - role: "admin", isAdmin: true, is_staff: true
   - account_type: "premium", plan: "enterprise"
   - is_verified: true, email_verified: true
   - permissions: ["admin"], credits: 99999
3. Check if the response reflects your injected fields
4. If reflected → strong lead. If silently accepted (no error) → medium lead.

PROOF = response contains your injected privilege values
Endpoint: {method} https://{subdomain}{endpoint}
Known params: {str(params)[:300]}"""

    elif vuln_class == "ssrf":
        return f"""SSRF (Server-Side Request Forgery) SCOUTING:
You are testing whether this endpoint fetches URLs server-side and could be tricked into hitting internal services.

Strategy (3-4 steps max):
1. Identify URL-accepting parameters: url=, link=, redirect=, callback=, webhook=, fetch=, proxy=, img=, src=, href=
2. Submit a URL to https://httpbin.org/get as a canary — if the response contains httpbin content, the server fetched it
3. Try variations: http:// vs https://, with/without trailing slash, URL-encoded
4. If canary works → strong SSRF lead (Sniper will test with OAST for blind SSRF)

DO NOT test internal IPs yourself (169.254.x, localhost) — the Sniper will do that safely.
PROOF = response body contains content from YOUR specified URL
Endpoint: {method} https://{subdomain}{endpoint}
Known params: {str(params)[:300]}"""

    return "Test this endpoint for security vulnerabilities."


# =====================================================================
# SCOUT REACT LOOP
# =====================================================================

def _parse_scout_response(text):
    """Parse AI's JSON response, handling markdown fences."""
    if not text:
        return None
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def run_scout_test(subdomain, endpoint_info, vuln_class, scope_domains, credentials=None):
    """Run a Scout ReAct loop on one endpoint for one vuln class.

    Returns a VulnerabilityLead dict or None if AI unavailable.
    The Scout identifies leads — it does NOT produce final verdicts or reports.
    """
    from llm_client import call_tier

    endpoint = endpoint_info.get("endpoint", "/")
    method = endpoint_info.get("method", "GET")
    params = endpoint_info.get("params", "")
    base_url = f"https://{subdomain}{endpoint}"

    tool = ScoutHttpTool(scope_domains, credentials)
    guidance = _get_scout_guidance(vuln_class, subdomain, endpoint, method, params, credentials)

    cred_context = ""
    if credentials:
        cred_context = "CREDENTIALS: You have test credentials available. See the test guidance for details."

    system_prompt = SCOUT_SYSTEM_PROMPT.format(
        vuln_class=vuln_class,
        max_iterations=MAX_ITERATIONS,
        test_guidance=guidance,
        credentials_context=cred_context,
    )

    conversation = f"""{system_prompt}

=== TARGET ===
Host: {subdomain}
Endpoint: {method} {endpoint}
Base URL: {base_url}
Parameters/context: {str(params)[:500]}
Source: {endpoint_info.get('source', 'unknown')}

Begin your first THINK -> ACT cycle."""

    observations = []

    for iteration in range(MAX_ITERATIONS):
        response = call_tier("tier2", conversation, max_tokens=600)
        if not response:
            log.warning(f"  [SCOUT] AI unavailable at iteration {iteration}")
            return None

        data = _parse_scout_response(response)
        if not data:
            log.warning(f"  [SCOUT] Could not parse AI response at iteration {iteration}")
            break

        thought = data.get("thought", "")
        action = data.get("action")
        done = data.get("done", False)

        log.info(f"  [SCOUT] {subdomain}{endpoint} [{vuln_class}] step={iteration+1} — {thought[:80]}...")

        # Check if kill switch was triggered in previous iteration
        if tool.kill_switch.triggered:
            log.info(f"  [SCOUT] Kill switch active — forcing exit")
            done = True

        if done or not action:
            lead = data.get("lead", {})
            lead.setdefault("vuln_class", vuln_class)
            lead.setdefault("confidence", 0)
            lead.setdefault("initial_evidence", "No strong evidence found")
            lead["endpoint"] = endpoint
            lead["method"] = method
            lead["subdomain"] = subdomain
            lead["iterations"] = iteration + 1
            lead["total_requests"] = tool.total_requests
            lead["kill_switch_fired"] = tool.kill_switch.triggered
            lead["observations"] = observations
            return lead

        # Execute the action
        act_method = action.get("method", "GET")
        act_url = action.get("url", base_url)
        act_headers = action.get("headers")
        act_body = action.get("body")

        result = tool.execute(act_method, act_url, headers=act_headers, body=act_body)

        # Build observation
        if result.get("error"):
            observation = f"ERROR: {result['error']}"
            if result.get("kill_switch"):
                observation += "\n** KILL SWITCH TRIGGERED — You MUST set done=true in your next response. **"
        else:
            observation = (
                f"HTTP {result['status_code']} | "
                f"Content-Length: {result.get('body_length', 0)} | "
                f"Redirect: {result.get('redirect', 'none')}\n"
                f"Headers: {json.dumps(dict(list(result.get('headers', {}).items())[:10]))}\n"
                f"Body: {result.get('body_snippet', '')[:800]}"
            )

        observations.append({
            "step": iteration + 1,
            "action": f"{act_method} {act_url}",
            "status": result.get("status_code", "error"),
            "body_length": result.get("body_length", 0),
        })

        conversation += (
            f"\n\n=== STEP {iteration + 1} ===\n"
            f"Your response:\n{response}\n\n"
            f"OBSERVATION:\n{observation}\n\n"
            f"Continue your next THINK -> ACT cycle (or set done=true if you have enough evidence)."
        )

    # Hit max iterations
    return {
        "vuln_class": vuln_class,
        "confidence": 2,
        "initial_evidence": "Max iterations reached without conclusive evidence",
        "endpoint": endpoint,
        "method": method,
        "subdomain": subdomain,
        "iterations": MAX_ITERATIONS,
        "total_requests": tool.total_requests,
        "kill_switch_fired": tool.kill_switch.triggered,
        "observations": observations,
        "suggested_sniper_tests": [],
    }


# =====================================================================
# TEST SELECTION — Which endpoints to test for which vuln classes
# =====================================================================

SCOUT_ENDPOINT_SIGNALS = {
    "bola": {
        "keywords": ["users", "user", "account", "order", "orders", "profile",
                      "document", "file", "message", "messages", "comment",
                      "post", "item", "resource", "data", "record",
                      "invoice", "payment", "ticket", "project"],
        "methods": ["GET", "POST", "PUT", "PATCH"],
    },
    "mass_assignment": {
        "keywords": ["register", "signup", "create", "update", "profile",
                      "account", "user", "settings", "invite", "onboard"],
        "methods": ["POST", "PUT", "PATCH"],
    },
    "ssrf": {
        "keywords": ["url", "fetch", "proxy", "webhook", "callback", "link",
                      "import", "upload", "preview", "share", "image",
                      "screenshot", "pdf", "render", "load"],
        "methods": ["GET", "POST"],
    },
}

# Regex patterns that suggest ID-based endpoints (BOLA targets)
BOLA_ID_PATTERNS = [
    r"/\d+(?:/|$|\?)",      # /api/users/123
    r"/\{[^}]*id[^}]*\}",   # /api/users/{userId}
    r"\?.*id=",              # ?user_id=123
    r"/me(?:/|$|\?)",        # /api/users/me (test if /me can be replaced with another ID)
]


def select_scout_tests(api_schemas_rows):
    """Select which endpoints to test for which vuln classes.

    Returns list of (endpoint_info, vuln_class) pairs.
    Enhanced from v14 with BOLA ID-pattern detection.

    NOTE: auth_probe endpoints are stored as GET, but register/login are actually
    POST endpoints. For BOLA and mass_assignment, we ignore the stored method
    when the keyword match is strong — the Scout decides the right method to use.
    """
    tests = []

    for row in api_schemas_rows:
        endpoint = row.get("endpoint", "").lower()
        method = row.get("method", "GET").upper()
        source = row.get("source", "")

        for vuln_class, signals in SCOUT_ENDPOINT_SIGNALS.items():
            keyword_match = any(kw in endpoint for kw in signals["keywords"])
            method_match = method in signals["methods"]

            # BOLA gets extra detection: ID patterns in endpoint path
            if vuln_class == "bola" and not keyword_match:
                keyword_match = any(re.search(pat, endpoint) for pat in BOLA_ID_PATTERNS)

            # For BOLA and mass_assignment: auth_probe endpoints are stored as GET
            # but the Scout will try POST/PUT. Relax method check when keyword is strong.
            if vuln_class in ("bola", "mass_assignment") and keyword_match and not method_match:
                if source == "auth_probe" or "/api/" in endpoint:
                    method_match = True  # Scout decides the right method

            if keyword_match and method_match:
                tests.append((row, vuln_class))

    # Deduplicate: max 3 tests per vuln_class per target (cost control)
    seen = {}
    filtered = []
    for row, vuln_class in tests:
        count = seen.get(vuln_class, 0)
        if count < 3:
            filtered.append((row, vuln_class))
            seen[vuln_class] = count + 1

    return filtered


# =====================================================================
# CREDENTIALS LOADER
# =====================================================================

def _load_credentials(program_handle):
    """Load test credentials for a specific program from credentials.json."""
    from pathlib import Path
    cred_path = Path(__file__).resolve().parent.parent / "credentials.json"
    if not cred_path.exists():
        return None
    try:
        with open(cred_path) as f:
            data = json.load(f)
        programs = data.get("programs", {})
        creds = programs.get(program_handle)
        if creds and "session_a" in creds and "session_b" in creds:
            return creds
    except Exception:
        pass
    return None


# =====================================================================
# ENTRY POINT — run_scout_sweep()
# =====================================================================

def run_scout_sweep(domain, target_id, live_hosts):
    """Full Scout sweep for a target. Reads api_schemas, selects tests,
    runs Scout ReAct loops, returns list of leads.

    This is the Phase 3b entry point — called by the pipeline after api_mapper.
    """
    from db import get_conn, insert_lead, log_activity

    # 1. Load API schemas for this target
    with get_conn() as conn:
        schemas = [dict(r) for r in conn.execute(
            "SELECT subdomain, endpoint, method, params, source FROM api_schemas "
            "WHERE target_id = ? ORDER BY id", (target_id,)
        ).fetchall()]

        # Get program handle for credential lookup
        target_row = conn.execute(
            "SELECT program_url FROM targets WHERE id = ?", (target_id,)
        ).fetchone()

    if not schemas:
        log.info(f"  [SCOUT] {domain}: no API schemas found — skipping")
        return {"tests_run": 0, "leads": []}

    # Build scope
    scope_domains = {domain}
    scope_domains.update(h.split(":")[0] for h in live_hosts[:20])

    # Load credentials if available
    program_handle = ""
    if target_row and target_row["program_url"]:
        # Extract handle from URL like https://hackerone.com/<program>
        parts = target_row["program_url"].rstrip("/").split("/")
        program_handle = parts[-1] if parts else ""
    credentials = _load_credentials(program_handle) if program_handle else None

    # 2. Select tests
    tests = select_scout_tests(schemas)
    if not tests:
        log.info(f"  [SCOUT] {domain}: no testable endpoints matched")
        return {"tests_run": 0, "leads": []}

    log.info(f"  [SCOUT] {domain}: {len(tests)} tests selected from {len(schemas)} endpoints"
             f"{' (credentials loaded)' if credentials else ''}")
    log_activity("scan", f"{domain}: Scout starting {len(tests)} tests")

    # 3. Run tests
    leads = []
    tests_run = 0

    for endpoint_info, vuln_class in tests:
        subdomain = endpoint_info.get("subdomain", domain)
        endpoint = endpoint_info.get("endpoint", "/")

        log.info(f"  [SCOUT] Testing {vuln_class} on {subdomain}{endpoint}...")

        lead = run_scout_test(subdomain, endpoint_info, vuln_class, scope_domains, credentials)
        tests_run += 1

        if not lead:
            continue

        confidence = lead.get("confidence", 0)
        kill_fired = lead.get("kill_switch_fired", False)

        if kill_fired:
            log.info(f"  [SCOUT] Kill switch fired for {vuln_class} on {subdomain}{endpoint}")

        if confidence >= LEAD_CONFIDENCE_THRESHOLD:
            # Store lead in DB for Sniper dispatch
            lead_id = insert_lead(
                target_id, subdomain, endpoint, lead.get("method", "GET"),
                vuln_class, confidence, json.dumps(lead, default=str),
            )
            leads.append(lead)
            log.info(f"  *** [SCOUT] LEAD: {vuln_class} on {subdomain}{endpoint} "
                     f"(confidence={confidence}, lead_id={lead_id})")
            log_activity("vuln", f"Scout lead: {vuln_class} on {subdomain}{endpoint} (confidence={confidence})")
            # Discord notification — Scout found something, Sniper will verify
            try:
                from notifier_discord import notify_scout_lead
                notify_scout_lead({
                    "subdomain": subdomain, "vuln_class": vuln_class,
                    "confidence": confidence, "endpoint": endpoint,
                    "initial_evidence": lead.get("initial_evidence", ""),
                    "domain": domain,
                })
            except Exception:
                pass
        else:
            log.info(f"  [SCOUT] Low confidence ({confidence}): {vuln_class} on {subdomain}{endpoint}")

    log.info(f"  [SCOUT] {domain}: DONE — {tests_run} tests, {len(leads)} leads")
    log_activity("scan", f"{domain}: Scout done — {tests_run} tests, {len(leads)} leads")

    return {"tests_run": tests_run, "leads": leads}
