"""
Object Specialist Sniper — Deep BOLA + Mass Assignment verification.

Receives high-confidence leads from the Scout and performs exhaustive verification
using Opus-tier reasoning. Writes HackerOne-ready reports for confirmed vulnerabilities.

Vuln classes handled:
  - BOLA (Broken Object Level Authorization): ID manipulation, cross-user access
  - Mass Assignment: Hidden parameter injection for privilege escalation
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
# OBJECT SPECIALIST SYSTEM PROMPT
# =====================================================================

OBJECT_SNIPER_PROMPT = """You are a SENIOR security researcher performing DEEP VERIFICATION of a vulnerability lead.
A fast Scout agent identified this potential vulnerability. Your job is to CONFIRM or REJECT it with thorough testing, then write a professional bug bounty report if confirmed.

You have an HTTP tool for making requests. DELETE is forbidden.

THE LEAD FROM SCOUT:
{lead_summary}

YOUR MISSION ({vuln_class}):
{verification_guidance}

APPROACH:
1. REPRODUCE the Scout's finding first — confirm the basic behavior
2. GO DEEPER — try variations the Scout didn't test
3. PROVE IMPACT — show what an attacker could actually do
4. CONCLUDE — is this a real, reportable vulnerability?

You have {max_iterations} steps. Be thorough but efficient.
{credentials_context}

For each step, reply ONLY JSON:
{{
  "thought": "detailed reasoning about what to test next and why",
  "action": {{
    "method": "GET/POST/PUT/PATCH",
    "url": "full URL",
    "headers": {{}},
    "body": {{}}
  }},
  "done": false
}}

When done, reply:
{{
  "thought": "final verdict with full analysis",
  "action": null,
  "done": true,
  "verdict": "confirmed" or "rejected" or "needs_manual_check",
  "confidence": 1-10,
  "severity": "Critical/High/Medium/Low",
  "evidence_summary": "complete evidence chain with specific HTTP proof",
  "report": "Full HackerOne-ready Markdown report (if confirmed). Include: Summary, Severity, Steps to Reproduce (exact HTTP requests), Impact, Remediation."
}}"""


def _get_verification_guidance(vuln_class, lead_data, credentials=None):
    """Deep verification instructions per vuln class."""

    evidence = lead_data.get("initial_evidence", "")
    endpoint = lead_data.get("endpoint", "/")
    subdomain = lead_data.get("subdomain", "")

    if vuln_class == "bola":
        cred_section = ""
        if credentials:
            cred_section = f"""
CREDENTIALS AVAILABLE FOR CROSS-USER TESTING:
  Session A: Token={credentials['session_a']['token'][:40]}... (User ID: {credentials['session_a']['user_id']})
  Session B: Token={credentials['session_b']['token'][:40]}... (User ID: {credentials['session_b']['user_id']})

  TEST: Use Session A's token in Authorization header while accessing Session B's resources.
  PROOF: If Session A can read/modify Session B's data, BOLA is confirmed."""

        return f"""BOLA DEEP VERIFICATION:

Scout's initial finding: {evidence}

Your verification steps:
1. REPRODUCE: Repeat the Scout's request with different ID values. Confirm different data is returned.
2. ENUMERATE: Try 3-5 different ID values (1, 2, 100, 999, 0). Document which return data vs 404/403.
3. PRIVILEGE CHECK: If you find accessible objects, check if they contain SENSITIVE data (PII, financial, auth tokens).
4. WRITE TEST: Try PATCH/PUT on another user's object with a benign field change. Verify via subsequent GET.
   - IMPORTANT: Only modify non-destructive fields (like a display name). Never delete or corrupt data.
5. VERTICAL BOLA: Try accessing admin-level endpoints using the same ID manipulation technique.
{cred_section}

SEVERITY GUIDE:
- Critical: Can modify other users' data (write BOLA)
- High: Can read other users' sensitive data (read BOLA with PII)
- Medium: Can read other users' non-sensitive data
- Low: Can only enumerate user IDs without accessing data"""

    elif vuln_class == "mass_assignment":
        return f"""MASS ASSIGNMENT DEEP VERIFICATION:

Scout's initial finding: {evidence}

Your verification steps:
1. REPRODUCE: Repeat the Scout's request. Confirm injected fields are reflected/accepted.
2. PARAMETER POLLUTION: Try duplicate params: role=user&role=admin (some parsers take the last value)
3. NESTED OBJECTS: Try JSON nesting: {{"user": {{"role": "admin"}}}}, dot notation: user.role=admin
4. VERIFY PERSISTENCE: After injecting, GET the resource to check if the change persisted.
5. ESCALATION CHAIN: If role/permissions change works, what can the elevated role do?
   - Try accessing admin endpoints with the modified session
   - Check if elevated permissions unlock additional API features

COMMON FIELDS TO TRY:
- role, isAdmin, is_staff, is_superuser, admin, permissions
- account_type, plan, tier, subscription
- email_verified, is_verified, verified, active
- balance, credits, discount, price

SEVERITY GUIDE:
- Critical: Can escalate to admin role with full system access
- High: Can modify account type/permissions to gain premium features
- Medium: Can modify own verification status or bypass email verification
- Low: Can set non-security fields that shouldn't be user-controllable"""

    return "Verify this vulnerability lead thoroughly."


# =====================================================================
# SNIPER EXECUTION
# =====================================================================

def run_object_sniper(lead_data, scope_domains, credentials=None):
    """Run the Object Specialist Sniper on a Scout lead.

    Uses Opus (tier3) for deep reasoning and report generation.

    Args:
        lead_data: dict from Scout with vuln_class, initial_evidence, endpoint, etc.
        scope_domains: set of allowed domains
        credentials: optional {session_a: {token, user_id}, session_b: {token, user_id}}

    Returns:
        dict with verdict, confidence, severity, evidence_summary, report (if confirmed)
        or None if AI unavailable
    """
    from llm_client import call_tier

    vuln_class = lead_data.get("vuln_class", "bola")
    subdomain = lead_data.get("subdomain", "")
    endpoint = lead_data.get("endpoint", "/")
    base_url = f"https://{subdomain}{endpoint}"

    tool = ScoutHttpTool(scope_domains, credentials)
    guidance = _get_verification_guidance(vuln_class, lead_data, credentials)

    lead_summary = (
        f"Vulnerability: {vuln_class}\n"
        f"Target: {subdomain}{endpoint}\n"
        f"Scout confidence: {lead_data.get('confidence', 0)}/10\n"
        f"Initial evidence: {lead_data.get('initial_evidence', 'N/A')}\n"
        f"Payload used: {lead_data.get('payload_used', 'N/A')}\n"
        f"Scout observations: {json.dumps(lead_data.get('observations', []), default=str)[:500]}"
    )

    cred_context = ""
    if credentials:
        cred_context = "You have test credentials for cross-user testing. See verification guidance."

    prompt = OBJECT_SNIPER_PROMPT.format(
        lead_summary=lead_summary,
        vuln_class=vuln_class,
        verification_guidance=guidance,
        max_iterations=MAX_ITERATIONS,
        credentials_context=cred_context,
    )

    conversation = f"""{prompt}

=== TARGET ===
Host: {subdomain}
Endpoint: {lead_data.get('method', 'GET')} {endpoint}
Base URL: {base_url}

Begin your deep verification. Reproduce the Scout's finding first."""

    for iteration in range(MAX_ITERATIONS):
        # Use Opus (tier3) for deep reasoning
        response = call_tier("tier3", conversation, max_tokens=2000)
        if not response:
            # Fallback to Sonnet if Opus unavailable
            response = call_tier("tier2", conversation, max_tokens=1500)
        if not response:
            log.warning(f"  [SNIPER-OBJ] AI unavailable at step {iteration}")
            return None

        data = _parse_scout_response(response)
        if not data:
            log.warning(f"  [SNIPER-OBJ] Parse failed at step {iteration}")
            break

        thought = data.get("thought", "")
        action = data.get("action")
        done = data.get("done", False)

        log.info(f"  [SNIPER-OBJ] {subdomain}{endpoint} step={iteration+1} — {thought[:100]}...")

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
                "vuln_class": vuln_class,
            }
            return result

        # Execute action
        act_method = action.get("method", "GET")
        act_url = action.get("url", base_url)
        act_headers = action.get("headers")
        act_body = action.get("body")

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
        "vuln_class": vuln_class,
    }
