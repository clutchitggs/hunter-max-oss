"""
Tiered AI Security Reasoning Engine v15 — 5-Tier Pipeline

  T1 (GPT-4o-mini):  Quick triage — noise or worth investigating?
  T2 (Claude Sonnet): Investigate + Assess — verify evidence, profile tech
  T3 (Claude Sonnet): Devil's Advocate — challenges T2 low-confidence rejections
  T4 (Claude Opus):   Final verdict — submit or reject, writes report if approved
  T5 (Claude Opus):   Devil's Advocate — challenges T4 low-confidence rejections

Two layers of devil's advocates ensure nothing real slips through.
"""
import json
import logging
import re
import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

TIMEOUT = 5
_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
_session.verify = False
_adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


def _parse_json(text):
    """Parse JSON from LLM response, stripping markdown fences and fixing escapes."""
    if not text:
        return None
    # Strip markdown code fences
    text = re.sub(r"```json?\s*", "", text).replace("```", "").strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    # Fix common LLM JSON issues: escaped single quotes, trailing commas
    try:
        fixed = text.replace("\\'", "'").replace("'s", "s")
        fixed = re.sub(r",\s*}", "}", fixed)
        fixed = re.sub(r",\s*]", "]", fixed)
        return json.loads(fixed)
    except (json.JSONDecodeError, ValueError):
        pass
    # Last resort: extract JSON object from text
    try:
        match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (json.JSONDecodeError, ValueError):
        pass
    return None


# =====================================================================
# TIER 0: Free pattern matching — runs on EVERY HTTP response
# =====================================================================

def is_interesting(status_code, headers, body):
    """Fast pre-filter: should this response get AI analysis? Cost: $0."""
    body_lower = body[:3000].lower() if body else ""

    if status_code in (401, 403) and len(body) > 50:
        if any(kw in body_lower for kw in ["token", "header", "missing", "service", "unauthorized", "bearer"]):
            return True, "auth_info"

    if status_code in (500, 502, 503) and len(body) > 100:
        if any(kw in body_lower for kw in ["trace", "exception", "error", "stack", "debug", "line "]):
            return True, "error_leak"

    if status_code == 200 and len(body) > 50:
        if any(strong in body_lower for strong in ["x-service", "x-internal", "bearer", "api_key", "secret_key", "jdbc", "connection"]):
            return True, "sensitive_content"

    for h_name in headers:
        h_lower = h_name.lower()
        if any(kw in h_lower for kw in ["x-debug", "x-token", "x-service", "x-internal", "x-backend", "x-real-server"]):
            return True, "interesting_headers"

    if any(proto in body_lower for proto in ["postgres://", "mysql://", "mongodb://", "redis://", "amqp://", "jdbc:", "dsn="]):
        return True, "connection_string"

    return False, None


# =====================================================================
# TIER 1: GPT-4o-mini — TRIAGE
# Sees: raw evidence only
# =====================================================================

def tier1_triage(vuln_type, evidence, subdomain, url):
    """T1: Is this worth investigating or obvious noise? Returns (pass, reason)."""
    from llm_client import call_tier

    prompt = f"""You are a bug bounty triage bot. Quick assessment only.

Finding: {vuln_type}
Target: {subdomain}
URL: {url}
Evidence (may include automated verification results — trust [VERDICT] lines):
{evidence[:500]}

Should we INVESTIGATE this finding, or is it NOISE we should SKIP?

NOISE (skip these):
- Third-party CDN/analytics scripts (Optimizely, Google Analytics, Mutiny, OneTrust, Atlassian wrappers)
- Public client-side API keys MEANT to be in browser JS (Stripe publishable keys, Google Maps keys, reCAPTCHA keys)
- Standard public files (.well-known/assetlinks.json, robots.txt, security.txt)
- .DS_Store files on CDN/static hosting (low value, usually rejected by bounty programs)
- FingerprintJS / bot-detection subdomains (random alphanumeric prefixes like fp*, fpb*, fpjs* on any domain) — these CORS-reflect arbitrary origins BY DESIGN because the fingerprint script runs cross-origin. NOT a vulnerability.
- CORS reflections on analytics/tracking/pixel endpoints (crumbs.*, pixel.*, track.*, cdn.*) — these reflect origins by design and return no sensitive data

INVESTIGATE (keep these):
- Leaked SERVER secrets (AWS keys, database passwords, JWT signing keys, private API keys)
- Internal/staging URLs leaked in production JS
- CORS misconfigurations allowing credential theft
- Bearer tokens or session tokens in URLs
- Exposed admin panels, actuators, debug endpoints

Reply ONLY JSON: {{"investigate": true/false, "reason": "one sentence"}}"""

    data = _parse_json(call_tier("tier1", prompt, max_tokens=80))
    if not data:
        return False, "T1 unavailable"
    return data.get("investigate", False), data.get("reason", "")


# =====================================================================
# TIER 2: Claude Sonnet — INVESTIGATE + ASSESS
# Sees: raw evidence + T1 reasoning
# Sonnet is smart enough to investigate AND assess in one call
# =====================================================================

def tier2_investigate(vuln_type, evidence, subdomain, url, t1_result):
    """T2 (Sonnet): Investigate the finding AND assess bounty potential."""
    from llm_client import call_tier

    prompt = f"""You are a senior security researcher investigating a potential bug bounty finding.

TARGET: {subdomain}
FINDING TYPE: {vuln_type}
URL: {url}

EVIDENCE (verified by automated enrichment — [VERDICT] lines are machine-verified facts, trust them):
{evidence[:2000]}

PREVIOUS TRIAGE (T1 — GPT-4o-mini):
{t1_result}

KNOWN FALSE POSITIVE PATTERNS (reject with HIGH confidence 8+ if matched):
- FingerprintJS / bot-detection subdomains: random alphanumeric prefixes (fp*, fpb*, fpbi*, fpjs*) on any domain. These CORS-reflect arbitrary origins BY DESIGN. NOT a vulnerability. Example: fpbi8c1t.ubereats.com, fp.coinbase.com
- Analytics/tracking/pixel endpoints: crumbs.*, pixel.*, track.*, cdn.*, tag.* — CORS reflection is intentional, no sensitive data returned
- Expired Wayback Machine tokens: Bearer tokens found in web.archive.org/wayback URLs are historical snapshots, long expired and revoked
- Public client-side keys in JS: Stripe publishable keys (pk_live/pk_test), Google Maps API keys, reCAPTCHA site keys, Firebase config keys, Segment write keys — these are MEANT to be in browser JS
- Third-party SDK CORS: Optimizely, LaunchDarkly, Amplitude, Mixpanel, Datadog RUM endpoints all reflect origins by design

Do TWO things:

INVESTIGATE:
1. What technology/framework is this target running?
2. Is the evidence REAL (actual secret/vuln) or a false positive (placeholder, example, public key)?
3. Does this match any known false positive pattern above?
4. What would an attacker do with this?

ASSESS:
5. What is the real-world business impact?
6. What severity would HackerOne assign? (Critical/High/Medium/Low)
7. Would a bug bounty program actually PAY for this?

Reply ONLY JSON:
{{
  "verified": true/false,
  "tech_stack": "what tech this runs on",
  "analysis": "2-3 sentence investigation result",
  "risk": "what an attacker could do",
  "severity": "Critical/High/Medium/Low",
  "bounty_likely": true/false,
  "impact": "real business impact in 1 sentence",
  "confidence": 1-10
}}"""

    data = _parse_json(call_tier("tier2", prompt, max_tokens=800))
    if data:
        return data
    return {"verified": False, "analysis": "T2 could not parse response", "confidence": 0}


# =====================================================================
# TIER 3: Claude Sonnet — DEVIL'S ADVOCATE (challenges T2 rejections)
# Only runs when T2 rejects with confidence ≤ 4
# =====================================================================

def tier3_sonnet_challenge(vuln_type, evidence, subdomain, url, t1_result, t2_result):
    """T3 (Sonnet): Challenge a low-confidence T2 rejection."""
    from llm_client import call_tier

    t2_str = json.dumps(t2_result, indent=2) if isinstance(t2_result, dict) else str(t2_result)

    prompt = f"""You are a security researcher acting as DEVIL'S ADVOCATE.

A previous Sonnet reviewer REJECTED this finding but with LOW CONFIDENCE. Your job is to CHALLENGE that rejection and look for reasons it MIGHT be real.

TARGET: {subdomain}
FINDING: {vuln_type}
EVIDENCE (includes automated verification — [VERDICT] lines are facts):
{evidence[:800]}
URL: {url}

T1 TRIAGE: {t1_result}

T2 REJECTION (low confidence):
{t2_str}

CHALLENGE the rejection:
1. What did T2 miss or get wrong?
2. Is there a scenario where this IS exploitable?
3. What specific checks would confirm or deny this?

Reply ONLY JSON:
{{
  "verdict": "escalate" or "confirm_reject",
  "challenge": "what T2 missed or why they were right",
  "verification_steps": ["step 1", "step 2"],
  "confidence": 1-10,
  "potential_severity": "Critical/High/Medium/Low"
}}"""

    data = _parse_json(call_tier("tier2", prompt, max_tokens=800))
    if data:
        return data
    return {"verdict": "confirm_reject", "challenge": "T3 could not parse response", "confidence": 0}


# =====================================================================
# TIER 4: Claude Opus — SENIOR REVIEW (final gate)
# Sees: raw evidence + T1 + T2 (+ T3 if it ran)
# Makes the final call. Writes report ONLY if approved.
# =====================================================================

def tier4_senior_review(vuln_type, evidence, subdomain, url, domain, t1_result, t2_result, all_findings=None):
    """T4 (Opus): Final verdict. Decides submit or reject. Writes report if approved."""
    from llm_client import call_tier

    t2_str = json.dumps(t2_result, indent=2) if isinstance(t2_result, dict) else str(t2_result)

    other_findings = ""
    if all_findings and len(all_findings) > 1:
        other_findings = "\nOTHER FINDINGS ON SAME TARGET:\n" + "\n".join(
            f"- {f.get('vuln_type','?')}: {f.get('evidence','')[:100]}" for f in all_findings[:5] if f.get('vuln_type') != vuln_type
        )

    prompt = f"""You are a SENIOR security researcher and the final reviewer before a bug bounty submission.

=== FINDING (includes machine-verified enrichment — [VERDICT] lines are confirmed facts) ===
Target: {subdomain} (parent: {domain})
Type: {vuln_type}
Evidence:
{evidence[:1500]}
URL: {url}
{other_findings}

=== T1 TRIAGE (GPT-4o-mini) ===
{t1_result}

=== T2 INVESTIGATION (Claude Sonnet) ===
{t2_str}

=== KNOWN FALSE POSITIVES (reject with confidence 9+ if matched) ===
- FingerprintJS subdomains (fp*, fpb*, fpbi*, fpjs* + random chars): CORS reflection is BY DESIGN — these are bot-detection pixels, not APIs. No sensitive data. Always reject.
- Analytics/tracking CORS (crumbs.*, pixel.*, track.*, cdn.*, tag.*): reflect origins by design, no auth data returned.
- Expired Wayback tokens: Bearer tokens from web.archive.org snapshots are historical, expired, and revoked.
- Public client-side keys: Stripe pk_live, Google Maps, reCAPTCHA, Firebase config, Segment write keys — intended to be in browser JS.
- CORS on CDN/edge endpoints that return static content or empty responses — header reflection without sensitive data in response body is not exploitable.

=== YOUR TASK ===
Make your INDEPENDENT judgment:
1. Does this match any known false positive pattern above? If yes, reject with HIGH confidence.
2. Is this a REAL, VERIFIED vulnerability (not a false positive)?
3. Would a bug bounty program ACTUALLY PAY for this?
4. Is the evidence strong enough for a submission?

If YES — write a complete HackerOne report.
If NO — explain why you're rejecting it.

Reply ONLY JSON:
{{
  "verdict": "submit" or "reject",
  "reason": "1-2 sentences why",
  "severity": "Critical/High/Medium/Low",
  "confidence": 1-10,
  "report": "FULL HackerOne report in Markdown if verdict is submit, empty string if reject"
}}

If verdict is "submit", the report MUST include:
1. **Summary** (2-3 sentences)
2. **Severity** (with justification)
3. **Steps to Reproduce** (numbered, verifiable)
4. **Impact** (real business impact)
5. **Remediation** (actionable)"""

    data = _parse_json(call_tier("tier3", prompt, max_tokens=4000))
    if not data:
        # Fallback to tier2 if tier3 unavailable
        data = _parse_json(call_tier("tier2", prompt, max_tokens=4000))
    return data


# =====================================================================
# TIER 5: Claude Opus — DEVIL'S ADVOCATE
# Only runs on T4 rejections with LOW confidence (≤ 4/10)
# Challenges the rejection: "Are you sure? What if this IS real?"
# =====================================================================

def tier5_devils_advocate(vuln_type, evidence, subdomain, url, domain, t1_result, t2_result, t4_result):
    """T5: Challenge low-confidence T4 rejections. Second opinion from fresh Opus."""
    from llm_client import call_tier

    t2_str = json.dumps(t2_result, indent=2) if isinstance(t2_result, dict) else str(t2_result)
    t4_str = json.dumps(t4_result, indent=2) if isinstance(t4_result, dict) else str(t4_result)

    prompt = f"""You are a SENIOR bug bounty reviewer acting as a DEVIL'S ADVOCATE.

A previous Opus reviewer (T4) REJECTED this finding, but with LOW CONFIDENCE. Your job is to CHALLENGE that rejection. Look for reasons the finding MIGHT be real and worth submitting.

=== FINDING (includes machine-verified enrichment — [VERDICT] lines are confirmed facts) ===
Target: {subdomain} (parent: {domain})
Type: {vuln_type}
Evidence:
{evidence[:1000]}
URL: {url}

=== T1 TRIAGE (GPT-4o-mini) ===
{t1_result}

=== T2 INVESTIGATION (Sonnet) ===
{t2_str}

=== T4 REJECTION (Opus — low confidence) ===
{t4_str}

=== YOUR TASK ===
The previous reviewer wasn't confident in their rejection. Challenge it:

1. What did the previous reviewer MISS or get WRONG?
2. Is there a scenario where this IS a real, payable vulnerability?
3. Would it be worth manually verifying this before dismissing it?
4. Are there follow-up checks that could confirm or deny this?

If you believe this COULD be real and worth investigating:
  → verdict: "investigate" with specific steps to verify
If you agree with the rejection:
  → verdict: "confirm_reject" with why you're confident

Reply ONLY JSON:
{{
  "verdict": "investigate" or "confirm_reject",
  "challenge": "what the previous reviewer missed or why they were right",
  "verification_steps": ["step 1 to verify", "step 2"],
  "confidence": 1-10,
  "potential_severity": "Critical/High/Medium/Low if real"
}}"""

    data = _parse_json(call_tier("tier3", prompt, max_tokens=2000))
    if not data:
        # If Opus unavailable, try Sonnet
        data = _parse_json(call_tier("tier2", prompt, max_tokens=2000))
    return data


# =====================================================================
# Signal Collection (unchanged)
# =====================================================================

def collect_signals(subdomain):
    """Collect HTTP signals from a subdomain for AI analysis."""
    signals = []

    for scheme in ["https", "http"]:
        try:
            resp = _session.get(f"{scheme}://{subdomain}/", timeout=TIMEOUT, allow_redirects=True)
            interesting, reason = is_interesting(resp.status_code, dict(resp.headers), resp.text)
            signals.append({
                "url": f"{scheme}://{subdomain}/",
                "status": resp.status_code,
                "headers": {k: v for k, v in list(resp.headers.items())[:20]},
                "body_snippet": resp.text[:1500],
                "interesting": interesting,
                "reason": reason,
                "body_length": len(resp.text),
            })
            if resp.status_code < 500:
                break
        except Exception:
            continue

    probe_paths = ["/api", "/api/v1", "/graphql", "/health", "/status", "/robots.txt"]
    for path in probe_paths:
        try:
            resp = _session.get(f"https://{subdomain}{path}", timeout=TIMEOUT, allow_redirects=False)
            interesting, reason = is_interesting(resp.status_code, dict(resp.headers), resp.text)
            if interesting or (resp.status_code in (200, 401, 403) and len(resp.text) > 20):
                signals.append({
                    "url": f"https://{subdomain}{path}",
                    "status": resp.status_code,
                    "headers": {k: v for k, v in list(resp.headers.items())[:10]},
                    "body_snippet": resp.text[:800],
                    "interesting": interesting,
                    "reason": reason,
                })
        except Exception:
            continue

    return signals


# =====================================================================
# Phase G: Live host analysis (proactive — finds NEW vulns via AI)
# This is separate from Phase G2 which triages existing findings
# =====================================================================

def analyze_target(subdomain, target_id=None):
    """Proactive AI analysis on live hosts — looks for vulns in HTTP responses."""
    from db import log_activity, insert_vuln

    signals = collect_signals(subdomain)
    interesting_signals = [s for s in signals if s.get("interesting")]

    if not interesting_signals:
        return []

    log.info(f"  [AI] {subdomain}: {len(interesting_signals)} interesting signals")

    # T1 quick check on each signal
    for sig in interesting_signals:
        passed, reason = tier1_triage(
            sig.get("reason", "unknown"), sig.get("body_snippet", "")[:200],
            subdomain, sig["url"]
        )
        if passed:
            log.info(f"  [AI-T1] Interesting: {sig['url']} — {reason}")
            if target_id:
                insert_vuln(target_id, subdomain, f"ai:{sig.get('reason','signal')}", reason, "Medium", sig["url"])

    return []
