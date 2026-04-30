"""
Evidence Enrichment Layer v2 — Full verification suite.

Runs type-specific HTTP verification checks BEFORE any AI tier sees the finding.
Cost: $0 (just HTTP requests). Turns AI guesswork into fact-based decisions.

Supported types:
  Phase 1: cors, actuator, graphql, swagger/debug/phpinfo, js_secret (context)
  Phase 2: js_secret token validation (GitHub/Slack/Stripe/AWS), s3 buckets, wayback URLs
"""
import json
import logging
import re
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

TIMEOUT = 8
_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
_session.verify = False
_adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

EVIL_ORIGIN = "https://evil-cors-test.com"
EVIL_ORIGIN_2 = "https://attacker-check.evil.com"

# Verdict constants — keep in sync with infinite_hunter.py:612+ which reads these.
VERDICT_FP = "false_positive"
VERDICT_CONFIRMED = "confirmed"

# Paths and extensions that must NOT return text/html in a real application.
# If they do, it's a SPA catch-all serving the app shell — not the actual resource.
_NON_HTML_EXTENSIONS = (
    ".env", ".json", ".xml", ".yaml", ".yml", ".conf", ".config",
    ".key", ".pem", ".sql", ".bak", ".log", ".csv", ".txt",
    ".hprof", ".dump", ".tar", ".gz", ".zip", ".properties",
)
_NON_HTML_PATHS = (
    "/actuator/", "/actuator", "/heapdump", "/threaddump",
    "/jolokia/", "/metrics", "/.git/", "/.svn/",
    "/.DS_Store", "/.htpasswd", "/server-status",
    "/api-docs", "/swagger.json", "/openapi.json",
)

# Binary magic bytes required for certain vuln types.
# If the body doesn't start with these, the detector lied.
_MAGIC_BYTES = {
    "actuator_heapdump": b"JAVA PROFILE ",
    "ds_store": b"\x00\x00\x00\x01Bud1",
    "git_exposed": b"ref:",
}

_PARKED_SIGNALS = (
    "domain is for sale", "buy this domain", "parked by",
    "godaddy", "hugedomains", "sedoparking",
    "under construction", "this domain has expired",
    "coming soon", "page not found",
)


def enrich_finding(vuln_type, evidence, subdomain, url):
    """
    Main dispatcher. Returns enrichment dict with:
      enriched_evidence: str  — rich text for AI prompts
      verification_data: dict — structured results for DB storage
      auto_verdict: str|None  — "confirmed", "false_positive", or None
      confidence: int         — 1-10
    """
    try:
        if vuln_type == "cors_misconfiguration":
            return _enrich_cors(subdomain, url, evidence)
        elif vuln_type in ("actuator_exposed", "actuator_env"):
            return _enrich_actuator(subdomain, url, evidence)
        elif vuln_type == "graphql_introspection":
            return _enrich_graphql(subdomain, url, evidence)
        elif vuln_type in ("swagger_exposed", "debug_exposed", "server_status", "phpinfo"):
            return _enrich_endpoint(subdomain, url, evidence, vuln_type)
        elif vuln_type.startswith("js_secret:"):
            return _enrich_js_secret(subdomain, url, evidence, vuln_type)
        elif vuln_type == "s3_public_listing":
            return _enrich_s3(subdomain, url, evidence)
        elif vuln_type.startswith("wayback:"):
            return _enrich_wayback(subdomain, url, evidence, vuln_type)
        else:
            return _enrich_generic(subdomain, url, evidence, vuln_type)
    except Exception as e:
        log.warning(f"  [ENRICH] Failed for {vuln_type} on {subdomain}: {e}")
        return {
            "enriched_evidence": evidence,
            "verification_data": {"type": vuln_type, "error": str(e)},
            "auto_verdict": None,
            "confidence": 0,
        }


# =====================================================================
# CORS Enricher
# =====================================================================

def _enrich_cors(subdomain, url, evidence):
    """Verify CORS misconfiguration with actual HTTP requests."""
    target_url = url or f"https://{subdomain}/"
    data = {"type": "cors", "target": target_url, "checks": {}}

    # 1. Request with evil origin
    try:
        resp1 = _session.get(target_url, headers={"Origin": EVIL_ORIGIN}, timeout=TIMEOUT, allow_redirects=True)
        acao = resp1.headers.get("Access-Control-Allow-Origin", "")
        acac = resp1.headers.get("Access-Control-Allow-Credentials", "")
        data["checks"]["origin_test"] = {
            "origin_sent": EVIL_ORIGIN,
            "acao_returned": acao,
            "acac_returned": acac,
            "reflects": EVIL_ORIGIN in acao,
            "credentials": acac.lower() == "true",
            "status_code": resp1.status_code,
            "content_type": resp1.headers.get("Content-Type", ""),
            "body_length": len(resp1.text),
        }
    except Exception as e:
        data["checks"]["origin_test"] = {"error": str(e)}
        return _build_cors_result(data, evidence)

    reflects = EVIL_ORIGIN in acao
    has_creds = acac.lower() == "true"

    if not reflects:
        data["auto_verdict"] = "false_positive"
        data["reason"] = "CORS does not actually reflect arbitrary origins"
        return _build_cors_result(data, evidence)

    if not has_creds:
        data["auto_verdict"] = "false_positive"
        data["reason"] = "CORS reflects origin but Access-Control-Allow-Credentials is not true"
        return _build_cors_result(data, evidence)

    # 2. Check Set-Cookie for SameSite
    set_cookies = resp1.headers.get("Set-Cookie", "")
    # Get all Set-Cookie headers
    all_cookies = []
    for key, val in resp1.headers.items():
        if key.lower() == "set-cookie":
            all_cookies.append(val)

    samesite_values = []
    auth_cookies = []
    for cookie_str in all_cookies:
        ss_match = re.search(r"SameSite=(\w+)", cookie_str, re.IGNORECASE)
        samesite_values.append(ss_match.group(1) if ss_match else "Lax (default)")
        # Check if cookie looks like auth/session
        cookie_name = cookie_str.split("=")[0].strip().lower()
        if any(kw in cookie_name for kw in ["session", "sid", "auth", "token", "jwt", "csrf", "login"]):
            auth_cookies.append(cookie_name)

    data["checks"]["cookies"] = {
        "set_cookie_count": len(all_cookies),
        "samesite_values": samesite_values,
        "auth_cookies_found": auth_cookies,
        "all_samesite_strict_or_lax": all(
            v.lower() in ("strict", "lax", "lax (default)") for v in samesite_values
        ) if samesite_values else True,
    }

    # 3. Second origin to confirm reflection (not just allowlisted our test domain)
    time.sleep(0.5)
    try:
        resp2 = _session.get(target_url, headers={"Origin": EVIL_ORIGIN_2}, timeout=TIMEOUT, allow_redirects=True)
        acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")
        data["checks"]["second_origin"] = {
            "origin_sent": EVIL_ORIGIN_2,
            "acao_returned": acao2,
            "reflects": EVIL_ORIGIN_2 in acao2,
        }
    except Exception:
        data["checks"]["second_origin"] = {"error": "request failed"}

    # 4. Compare response with/without cookies (is response session-specific?)
    time.sleep(0.5)
    body_with_origin = resp1.text[:3000]
    try:
        resp_no_cookie = _session.get(target_url, timeout=TIMEOUT, allow_redirects=True,
                                       headers={"Origin": EVIL_ORIGIN, "Cookie": ""})
        body_no_cookie = resp_no_cookie.text[:3000]
        bodies_differ = body_with_origin != body_no_cookie
        data["checks"]["session_test"] = {
            "body_with_cookies_length": len(body_with_origin),
            "body_without_cookies_length": len(body_no_cookie),
            "bodies_differ": bodies_differ,
        }
    except Exception:
        bodies_differ = False
        data["checks"]["session_test"] = {"error": "request failed"}

    # 5. Capture response body snippet
    data["checks"]["response_body_snippet"] = body_with_origin[:2000]

    # Auto-verdict logic
    all_ss_safe = data["checks"]["cookies"].get("all_samesite_strict_or_lax", True)
    no_auth_cookies = len(auth_cookies) == 0

    if all_ss_safe and no_auth_cookies and not bodies_differ:
        data["auto_verdict"] = "false_positive"
        data["reason"] = "CORS reflects but: SameSite blocks cross-origin cookies, no auth cookies on subdomain, response is not session-specific"
    elif not all_ss_safe and bodies_differ:
        data["auto_verdict"] = "confirmed"
        data["reason"] = "CORS reflects arbitrary origins with credentials, SameSite=None allows cross-origin cookies, response contains session-specific data"
    else:
        data["auto_verdict"] = None
        data["reason"] = "CORS reflects with credentials but impact unclear — needs AI assessment"

    return _build_cors_result(data, evidence)


def _build_cors_result(data, evidence):
    checks = data.get("checks", {})
    ot = checks.get("origin_test", {})
    cookies = checks.get("cookies", {})
    session = checks.get("session_test", {})

    # Verdict-first line
    auto_verdict_val = data.get("auto_verdict")
    reason_val = data.get("reason", "")
    if auto_verdict_val:
        lines = [f"[VERDICT: {auto_verdict_val.upper()} — {reason_val}]"]
    else:
        lines = [f"[VERDICT: NEEDS AI REVIEW — {reason_val}]"]
    lines.append(f"== CORS Verification Results ==")
    lines.append(f"Target: {data.get('target', '?')}")

    if ot.get("error"):
        lines.append(f"Origin test: FAILED ({ot['error']})")
    else:
        lines.append(f"Origin sent: {ot.get('origin_sent', '?')}")
        lines.append(f"ACAO returned: {ot.get('acao_returned', 'none')}")
        lines.append(f"ACAC returned: {ot.get('acac_returned', 'none')}")
        lines.append(f"Reflects arbitrary origin: {'YES' if ot.get('reflects') else 'NO'}")
        lines.append(f"Credentials enabled: {'YES' if ot.get('credentials') else 'NO'}")
        lines.append(f"Response: {ot.get('status_code', '?')} {ot.get('content_type', '?')} ({ot.get('body_length', 0)} bytes)")

    if cookies:
        lines.append(f"Cookies set: {cookies.get('set_cookie_count', 0)}")
        lines.append(f"SameSite values: {', '.join(cookies.get('samesite_values', []))}")
        lines.append(f"Auth cookies found: {', '.join(cookies.get('auth_cookies_found', [])) or 'none'}")
        lines.append(f"All cookies SameSite=Strict/Lax: {'YES (blocks attack)' if cookies.get('all_samesite_strict_or_lax') else 'NO (vulnerable)'}")

    so = checks.get("second_origin", {})
    if so and not so.get("error"):
        lines.append(f"Second origin test: {'reflects' if so.get('reflects') else 'does NOT reflect'} {so.get('origin_sent', '')}")

    if session and not session.get("error"):
        lines.append(f"Response differs with/without cookies: {'YES (session-specific data)' if session.get('bodies_differ') else 'NO (same static content)'}")

    if data.get("reason"):
        lines.append(f"Enrichment verdict: {data['reason']}")

    enriched = "\n".join(lines)
    auto_verdict = data.get("auto_verdict")
    confidence = 8 if auto_verdict else 5

    return {
        "enriched_evidence": enriched,
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": confidence,
    }


# =====================================================================
# Endpoint Enrichers (actuator, graphql, swagger, debug)
# =====================================================================

def _enrich_actuator(subdomain, url, evidence):
    """Fetch actuator endpoints and record what they actually return."""
    base_url = url or f"https://{subdomain}/"
    if not base_url.endswith("/"):
        base_url = base_url.rsplit("/", 1)[0] + "/"

    data = {"type": "actuator", "target": base_url, "endpoints": {}}

    # Check multiple actuator paths
    paths = [
        ("root", "actuator"),
        ("health", "actuator/health"),
        ("env", "actuator/env"),
        ("info", "actuator/info"),
        ("mappings", "actuator/mappings"),
        ("prometheus", "actuator/prometheus"),
        ("beans", "actuator/beans"),
    ]

    sensitive_found = False
    for name, path in paths:
        try:
            full_url = base_url.rstrip("/").rsplit("/actuator", 1)[0] + "/" + path
            resp = _session.get(full_url, timeout=TIMEOUT, allow_redirects=True)
            body = resp.text[:3000]
            data["endpoints"][name] = {
                "url": full_url,
                "status": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
                "body_length": len(resp.text),
                "body_snippet": body[:1500],
            }
            ep_content_type = resp.headers.get("Content-Type", "")
            if resp.status_code == 200 and len(resp.text) > 100:
                if name in ("env", "mappings", "beans", "prometheus"):
                    # Only count as sensitive if response is JSON, not HTML (SPA catch-all)
                    if "text/html" not in ep_content_type:
                        sensitive_found = True
        except Exception as e:
            data["endpoints"][name] = {"error": str(e)}
        time.sleep(0.3)

    # Build enriched evidence (compute verdict first for header)
    lines_body = []
    for name, ep in data["endpoints"].items():
        if ep.get("error"):
            lines_body.append(f"/{name}: ERROR ({ep['error']})")
        else:
            status = ep["status"]
            size = ep["body_length"]
            snippet = ep.get("body_snippet", "")[:200]
            lines_body.append(f"/{name}: HTTP {status} ({size} bytes) — {snippet[:100]}...")

    # Check if root response is actually a real actuator (JSON with _links) or just a generic web page
    root_ep = data["endpoints"].get("root", {})
    root_is_html = "text/html" in root_ep.get("content_type", "")
    root_has_links = "_links" in root_ep.get("body_snippet", "") or '"self"' in root_ep.get("body_snippet", "")
    health_ep = data["endpoints"].get("health", {})
    health_is_json = health_ep.get("status") == 200 and "status" in health_ep.get("body_snippet", "")

    auto_verdict = None
    if sensitive_found:
        auto_verdict = "confirmed"
        reason = "Actuator endpoints return sensitive data (env/mappings/prometheus accessible)"
    elif root_is_html and not root_has_links and not health_is_json:
        auto_verdict = "false_positive"
        reason = "Not a real actuator — root returns HTML page, not JSON. Health endpoint missing or 404."
    elif all(ep.get("status", 0) in (403, 401, 404) for ep in data["endpoints"].values() if not ep.get("error")):
        auto_verdict = "false_positive"
        reason = "All actuator endpoints return 403/401/404 — authentication required"
    else:
        reason = "Some actuator endpoints accessible but sensitivity unclear"

    # Verdict-first header
    if auto_verdict:
        lines = [f"[VERDICT: {auto_verdict.upper()} — {reason}]"]
    else:
        lines = [f"[VERDICT: NEEDS AI REVIEW — {reason}]"]
    lines.append(f"== Actuator Verification Results ==")
    lines.append(f"Target: {base_url}")
    lines.extend(lines_body)

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": 8 if auto_verdict else 5,
    }


def _enrich_graphql(subdomain, url, evidence):
    """Test GraphQL introspection with a real query."""
    target_url = url or f"https://{subdomain}/graphql"
    data = {"type": "graphql", "target": target_url, "checks": {}}

    # Try introspection query
    query = '{"query":"{__schema{types{name}}}"}'
    try:
        resp = _session.post(target_url, data=query,
                             headers={"Content-Type": "application/json"},
                             timeout=TIMEOUT, allow_redirects=True)
        body = resp.text[:3000]
        has_schema = "__schema" in body or "__Schema" in body
        data["checks"]["introspection"] = {
            "status": resp.status_code,
            "has_schema": has_schema,
            "body_snippet": body[:2000],
            "type_count": body.count('"name"') if has_schema else 0,
        }
    except Exception as e:
        data["checks"]["introspection"] = {"error": str(e)}
        has_schema = False

    auto_verdict = "confirmed" if has_schema else "false_positive"
    reason = "GraphQL introspection returns full schema" if has_schema else "Introspection disabled or endpoint requires auth"

    lines = [f"[VERDICT: {auto_verdict.upper()} — {reason}]"]
    lines.append(f"== GraphQL Introspection Verification ==")
    lines.append(f"Target: {target_url}")
    intro = data["checks"].get("introspection", {})
    if intro.get("error"):
        lines.append(f"Introspection query: FAILED ({intro['error']})")
    else:
        lines.append(f"Status: HTTP {intro['status']}")
        lines.append(f"Schema exposed: {'YES' if has_schema else 'NO'}")
        if has_schema:
            lines.append(f"Types found: ~{intro.get('type_count', 0)}")
            lines.append(f"Response snippet: {intro.get('body_snippet', '')[:500]}")

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": 9 if auto_verdict else 5,
    }


def _enrich_endpoint(subdomain, url, evidence, vuln_type):
    """Generic endpoint enricher — fetch and record what it returns."""
    target_url = url or f"https://{subdomain}/"
    data = {"type": vuln_type, "target": target_url, "checks": {}}

    try:
        resp = _session.get(target_url, timeout=TIMEOUT, allow_redirects=True)
        body = resp.text[:3000]
        data["checks"]["fetch"] = {
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "body_length": len(resp.text),
            "body_snippet": body[:2000],
            "headers": {k: v for k, v in list(resp.headers.items())[:15]},
        }
    except Exception as e:
        data["checks"]["fetch"] = {"error": str(e)}

    fetch = data["checks"].get("fetch", {})

    auto_verdict = None
    reason = ""
    if fetch.get("status") in (403, 401):
        auto_verdict = "false_positive"
        reason = f"Endpoint requires auth (HTTP {fetch['status']})"
    elif fetch.get("status") == 200 and fetch.get("body_length", 0) > 200:
        auto_verdict = "confirmed"
        reason = "Endpoint accessible with real content"
    elif fetch.get("error"):
        reason = f"Could not verify: {fetch['error'][:60]}"
    else:
        reason = f"HTTP {fetch.get('status', '?')} — unclear"

    if auto_verdict:
        lines = [f"[VERDICT: {auto_verdict.upper()} — {reason}]"]
    else:
        lines = [f"[VERDICT: NEEDS AI REVIEW — {reason}]"]
    lines.append(f"== {vuln_type} Verification ==")
    lines.append(f"Target: {target_url}")
    if fetch.get("error"):
        lines.append(f"Fetch: FAILED ({fetch['error']})")
    else:
        lines.append(f"Status: HTTP {fetch['status']} ({fetch['content_type']})")
        lines.append(f"Body: {fetch['body_length']} bytes")
        lines.append(f"Content: {fetch.get('body_snippet', '')[:800]}")

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": 7 if auto_verdict else 4,
    }


# =====================================================================
# JS Secret Enricher (Phase 2 — context extraction + token validation)
# =====================================================================

def _extract_secret_value(evidence):
    """Extract secret value from JS secret evidence string."""
    if "Value:" in evidence:
        return evidence.split("Value:")[1].split("|")[0].strip().rstrip(".")
    return ""


def _validate_github_token(token):
    """Validate GitHub token by calling /user. Returns dict with result."""
    try:
        resp = _session.get("https://api.github.com/user",
                            headers={"Authorization": f"token {token}",
                                     "Accept": "application/vnd.github+json"},
                            timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            return {"valid": True, "user": data.get("login", "?"), "scopes": resp.headers.get("X-OAuth-Scopes", "?")}
        elif resp.status_code == 401:
            return {"valid": False, "reason": "401 Unauthorized — token expired or revoked"}
        else:
            return {"valid": False, "reason": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _validate_slack_token(token):
    """Validate Slack token by calling auth.test. Returns dict with result."""
    try:
        resp = _session.post("https://slack.com/api/auth.test",
                             data={"token": token}, timeout=TIMEOUT)
        data = resp.json()
        if data.get("ok"):
            return {"valid": True, "team": data.get("team", "?"), "user": data.get("user", "?")}
        else:
            return {"valid": False, "reason": data.get("error", "unknown")}
    except Exception as e:
        return {"error": str(e)}


def _validate_stripe_key(token):
    """Validate Stripe secret key by calling /v1/balance. Returns dict with result."""
    if token.startswith("pk_"):
        return {"valid": False, "reason": "Publishable key (pk_*) — intended to be public, not a vulnerability"}
    try:
        resp = _session.get("https://api.stripe.com/v1/balance",
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=TIMEOUT)
        if resp.status_code == 200:
            return {"valid": True, "type": "secret_key", "has_balance_access": True}
        elif resp.status_code == 401:
            return {"valid": False, "reason": "401 Unauthorized — key expired or revoked"}
        else:
            return {"valid": False, "reason": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _validate_aws_key(access_key, secret_key, region="us-east-1"):
    """Validate AWS keys using STS GetCallerIdentity via boto3. Returns dict with result."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        client = boto3.client("sts", aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key, region_name=region)
        identity = client.get_caller_identity()
        return {"valid": True, "account": identity.get("Account", "?"),
                "arn": identity.get("Arn", "?"), "user_id": identity.get("UserId", "?")}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
            return {"valid": False, "reason": f"AWS error: {code} — key invalid or expired"}
        return {"valid": False, "reason": str(e)}
    except ImportError:
        return {"skipped": True, "reason": "boto3 not installed — cannot validate AWS keys"}
    except Exception as e:
        return {"error": str(e)}


def _enrich_js_secret(subdomain, url, evidence, vuln_type):
    """Fetch JS file, extract context, and validate tokens if possible."""
    js_url = url
    if "Source:" in evidence:
        js_url = evidence.split("Source:")[-1].strip()

    data = {"type": vuln_type, "target": js_url, "checks": {}}
    secret_value = _extract_secret_value(evidence)

    # --- Fetch JS and extract context ---
    context = ""
    looks_placeholder = False
    is_third_party = False

    try:
        resp = _session.get(js_url, timeout=TIMEOUT, allow_redirects=True)
        if len(resp.text) > 2_000_000:
            data["checks"]["js_fetch"] = {"error": "File too large (>2MB)"}
        else:
            js_content = resp.text
            if secret_value and secret_value[:20] in js_content:
                idx = js_content.index(secret_value[:20])
                start = max(0, idx - 250)
                end = min(len(js_content), idx + len(secret_value) + 250)
                context = js_content[start:end]

            placeholder_signals = ["example", "sample", "placeholder", "xxx", "your_", "test",
                                   "dummy", "fake", "changeme", "todo", "replace", "CHANGE_ME"]
            looks_placeholder = any(sig in context.lower() for sig in placeholder_signals) if context else False

            third_party_cdns = ["cdnjs.cloudflare.com", "unpkg.com", "cdn.segment.com",
                                "cdn.optimizely.com", "js.stripe.com", "cdn.amplitude.com"]
            is_third_party = any(cdn in js_url for cdn in third_party_cdns)

            data["checks"]["js_fetch"] = {
                "status": resp.status_code,
                "file_size": len(js_content),
                "secret_found_in_file": bool(context),
                "surrounding_context": context[:500] if context else "secret not found in file",
                "looks_placeholder": looks_placeholder,
                "is_third_party_bundle": is_third_party,
            }
    except Exception as e:
        data["checks"]["js_fetch"] = {"error": str(e)}

    # --- Token validation (Phase 2) ---
    token_result = None
    if secret_value and not looks_placeholder and not is_third_party:
        time.sleep(0.5)
        if vuln_type in ("js_secret:github_token", "js_secret:github_pat"):
            token_result = _validate_github_token(secret_value)
            data["checks"]["token_validation"] = {"service": "github", **token_result}
        elif vuln_type == "js_secret:slack_token":
            token_result = _validate_slack_token(secret_value)
            data["checks"]["token_validation"] = {"service": "slack", **token_result}
        elif vuln_type == "js_secret:stripe_key":
            token_result = _validate_stripe_key(secret_value)
            data["checks"]["token_validation"] = {"service": "stripe", **token_result}
        elif vuln_type == "js_secret:aws_access_key":
            # AWS needs both access key and secret key — look for secret in context
            import re
            secret_match = re.search(r'[A-Za-z0-9/+=]{40}', context) if context else None
            if secret_match and len(secret_match.group()) == 40:
                token_result = _validate_aws_key(secret_value, secret_match.group())
                data["checks"]["token_validation"] = {"service": "aws", **token_result}
            else:
                data["checks"]["token_validation"] = {"service": "aws", "skipped": True,
                                                       "reason": "Secret key not found near access key"}

    # --- Build enriched evidence (verdict first for truncation resilience) ---
    auto_verdict = None
    reason = ""

    fetch = data["checks"].get("js_fetch", {})
    tv = data["checks"].get("token_validation", {})

    if fetch.get("looks_placeholder"):
        auto_verdict = "false_positive"
        reason = "Secret value is a placeholder/example"
    elif fetch.get("is_third_party_bundle"):
        auto_verdict = "false_positive"
        reason = "Secret is in a third-party CDN bundle, not the target's code"
    elif not fetch.get("secret_found_in_file") and not fetch.get("error"):
        auto_verdict = "false_positive"
        reason = "Secret no longer present in JS file"
    elif tv.get("valid") is True:
        auto_verdict = "confirmed"
        reason = f"TOKEN IS LIVE — validated against {tv.get('service', '?')} API"
    elif tv.get("valid") is False:
        if "Publishable key" in tv.get("reason", ""):
            auto_verdict = "false_positive"
            reason = tv["reason"]
        else:
            auto_verdict = "false_positive"
            reason = f"Token invalid/expired: {tv.get('reason', '?')}"

    # Verdict-first format
    lines = []
    if auto_verdict:
        lines.append(f"[VERDICT: {auto_verdict.upper()} — {reason}]")
    else:
        lines.append(f"[VERDICT: NEEDS AI REVIEW — token type not auto-validatable]")

    lines.append(f"== JS Secret Verification ({vuln_type}) ==")
    lines.append(f"JS file: {js_url}")
    lines.append(f"Secret: {secret_value[:40]}{'...' if len(secret_value) > 40 else ''}")

    if tv:
        svc = tv.get("service", "?")
        if tv.get("valid"):
            lines.append(f"TOKEN VALIDATION: LIVE on {svc} (user={tv.get('user', tv.get('arn', '?'))})")
        elif tv.get("valid") is False:
            lines.append(f"TOKEN VALIDATION: DEAD on {svc} ({tv.get('reason', '?')})")
        elif tv.get("skipped"):
            lines.append(f"TOKEN VALIDATION: SKIPPED ({tv.get('reason', '?')})")

    if not fetch.get("error"):
        lines.append(f"Found in file: {'YES' if fetch.get('secret_found_in_file') else 'NO'}")
        lines.append(f"Placeholder: {'YES' if looks_placeholder else 'NO'}")
        lines.append(f"Third-party: {'YES' if is_third_party else 'NO'}")
        if context:
            lines.append(f"Context:\n{context[:400]}")

    confidence = 9 if auto_verdict == "confirmed" else (7 if auto_verdict else 4)

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": confidence,
    }


# =====================================================================
# S3 Bucket Enricher (Phase 2 — verify listing, check sensitive files)
# =====================================================================

def _enrich_s3(subdomain, url, evidence):
    """Re-verify S3 bucket listing, check for sensitive files, verify ownership."""
    bucket_url = url or ""
    # Extract bucket name from evidence or URL
    bucket_name = ""
    if "'" in evidence:
        bucket_name = evidence.split("'")[1] if evidence.count("'") >= 2 else ""
    if not bucket_name and "s3.amazonaws.com" in bucket_url:
        bucket_name = bucket_url.split("//")[1].split(".s3")[0] if "//" in bucket_url else ""

    data = {"type": "s3", "bucket": bucket_name, "target": bucket_url, "checks": {}}

    # 1. Re-verify listing is accessible
    try:
        resp = _session.get(bucket_url, timeout=TIMEOUT)
        is_listable = resp.status_code == 200 and "<ListBucketResult" in resp.text
        data["checks"]["listing"] = {
            "status": resp.status_code,
            "listable": is_listable,
            "body_length": len(resp.text),
        }

        if is_listable:
            # 2. Parse file listing for sensitive patterns
            content = resp.text
            sensitive_patterns = [
                (".env", "Environment variables"),
                (".sql", "Database dump"),
                (".bak", "Backup file"),
                ("credentials", "Credentials file"),
                ("password", "Password file"),
                ("secret", "Secret file"),
                (".pem", "Private key"),
                (".key", "Private key"),
                (".csv", "Data export"),
                ("config", "Configuration file"),
                ("backup", "Backup file"),
                ("dump", "Database dump"),
                ("private", "Private file"),
            ]
            found_sensitive = []
            # Extract <Key> elements from XML
            import re
            keys = re.findall(r"<Key>([^<]+)</Key>", content)
            total_files = len(keys)

            for key in keys[:200]:
                key_lower = key.lower()
                for pattern, desc in sensitive_patterns:
                    if pattern in key_lower:
                        found_sensitive.append({"file": key, "reason": desc})
                        break

            data["checks"]["files"] = {
                "total_files": total_files,
                "sensitive_files": found_sensitive[:20],
                "sample_files": keys[:15],
            }

            # 3. Ownership check — does bucket name relate to target?
            domain_parts = subdomain.replace(".", "-").lower().split("-")
            bucket_lower = bucket_name.lower()
            ownership_match = any(part in bucket_lower for part in domain_parts if len(part) > 3)
            data["checks"]["ownership"] = {
                "bucket_name": bucket_name,
                "target_domain": subdomain,
                "likely_owned": ownership_match,
            }

    except Exception as e:
        data["checks"]["listing"] = {"error": str(e)}

    # Build enriched evidence (verdict first)
    listing = data["checks"].get("listing", {})
    files = data["checks"].get("files", {})
    ownership = data["checks"].get("ownership", {})

    auto_verdict = None
    reason = ""

    if listing.get("error"):
        reason = f"Could not verify: {listing['error']}"
    elif not listing.get("listable"):
        auto_verdict = "false_positive"
        reason = f"Bucket no longer publicly listable (HTTP {listing.get('status', '?')})"
    elif files.get("sensitive_files"):
        auto_verdict = "confirmed"
        reason = f"Bucket listable with {len(files['sensitive_files'])} sensitive files ({files['total_files']} total)"
    elif files.get("total_files", 0) > 0:
        auto_verdict = None  # Let AI decide — listable but no obvious sensitive files
        reason = f"Bucket listable with {files['total_files']} files but no obvious secrets detected"
    else:
        auto_verdict = "false_positive"
        reason = "Bucket listable but empty"

    lines = []
    if auto_verdict:
        lines.append(f"[VERDICT: {auto_verdict.upper()} — {reason}]")
    else:
        lines.append(f"[VERDICT: NEEDS AI REVIEW — {reason}]")

    lines.append(f"== S3 Bucket Verification ==")
    lines.append(f"Bucket: {bucket_name}")
    lines.append(f"URL: {bucket_url}")

    if listing.get("listable"):
        lines.append(f"Listing: ACCESSIBLE ({files.get('total_files', 0)} files)")
        if files.get("sensitive_files"):
            lines.append("SENSITIVE FILES FOUND:")
            for sf in files["sensitive_files"][:10]:
                lines.append(f"  - {sf['file']} ({sf['reason']})")
        if files.get("sample_files"):
            lines.append(f"Sample files: {', '.join(files['sample_files'][:8])}")
        lines.append(f"Ownership match: {'YES' if ownership.get('likely_owned') else 'UNCERTAIN'}")
    elif listing.get("error"):
        lines.append(f"Listing check: ERROR ({listing['error']})")
    else:
        lines.append(f"Listing: NOT ACCESSIBLE (HTTP {listing.get('status', '?')})")

    confidence = 9 if auto_verdict == "confirmed" else (7 if auto_verdict == "false_positive" else 5)

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": confidence,
    }


# =====================================================================
# Shared fetch + classifier used by wayback and generic enrichers.
# Returns the standard fetch dict plus the common FP verdict ladder
# (404/410, parked, redirected-away, SPA catch-all, magic-byte mismatch,
# 401/403 auth-gate). Callers layer type-specific checks on top.
# =====================================================================

def _fetch_and_classify(subdomain, target_url, vuln_type=None):
    """Fetch target_url once, return (fetch_dict, auto_verdict, reason)."""
    try:
        resp = _session.get(target_url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}, VERDICT_FP, f"URL unreachable: {str(e)[:80]}"

    body_text = resp.text[:1000]
    ctype = (resp.headers.get("Content-Type") or "").lower()
    final_url = str(resp.url)
    first_bytes = resp.content[:64]

    # Strict hostname comparison — substring-in-URL false-negatives when a
    # subdomain name appears inside an attacker-controlled final host.
    final_host = (urlparse(final_url).hostname or "").lower()
    redirected_away = final_host != subdomain.lower()

    url_path = target_url.split("?")[0].split("#")[0].lower()
    expects_non_html = (
        any(url_path.endswith(ext) for ext in _NON_HTML_EXTENSIONS)
        or any(p in url_path for p in _NON_HTML_PATHS)
    )
    is_spa_catchall = expects_non_html and "text/html" in ctype

    expected_magic = _MAGIC_BYTES.get(vuln_type) if vuln_type else None
    magic_ok = (expected_magic is None) or first_bytes.startswith(expected_magic)

    is_parked = any(sig in body_text.lower() for sig in _PARKED_SIGNALS)

    fetch = {
        "status": resp.status_code,
        "final_url": final_url,
        "content_type": ctype,
        "body_length": len(resp.content),
        "body_snippet": body_text[:500],
        "is_spa_catchall": is_spa_catchall,
        "redirected_away": redirected_away,
        "is_parked": is_parked,
        "expected_magic": expected_magic.decode("latin-1") if expected_magic else None,
        "magic_ok": magic_ok,
        "first_bytes_hex": first_bytes[:16].hex(),
    }

    status = resp.status_code
    if status in (404, 410):
        return fetch, VERDICT_FP, f"URL returns {status} — no longer exists"
    if is_parked:
        return fetch, VERDICT_FP, "Domain is parked/for sale"
    if redirected_away:
        return fetch, VERDICT_FP, f"Redirects away to: {final_url[:60]}"
    if is_spa_catchall:
        return fetch, VERDICT_FP, (
            "SPA catch-all: path implies non-HTML content but server returned text/html"
        )
    if expected_magic and not magic_ok:
        return fetch, VERDICT_FP, (
            f"Magic-byte mismatch: expected {fetch['expected_magic']!r} "
            f"for {vuln_type}, got {fetch['first_bytes_hex'][:20]}"
        )
    if status in (401, 403):
        return fetch, None, f"Endpoint exists but requires auth (HTTP {status})"

    return fetch, None, ""


# =====================================================================
# Wayback URL Enricher (Phase 2 — verify URL is still accessible)
# =====================================================================

def _enrich_wayback(subdomain, url, evidence, vuln_type):
    """Fetch the actual URL (not Wayback) and check if it returns real content."""
    target_url = url or f"https://{subdomain}/"
    fetch, auto_verdict, reason = _fetch_and_classify(subdomain, target_url, vuln_type)

    # Wayback-specific: once the standard ladder passes (200-ish, not parked,
    # on-origin, not SPA), require "meaningful content" before confirming.
    reachable = not fetch.get("error") and fetch.get("status") not in (401, 403)
    if auto_verdict is None and reachable:
        has_content = (
            fetch.get("status") == 200
            and fetch.get("body_length", 0) > 500
            and not fetch.get("is_parked")
        )
        fetch["has_meaningful_content"] = has_content
        if has_content:
            auto_verdict = VERDICT_CONFIRMED
            reason = "Endpoint still accessible with real content"
        else:
            auto_verdict = VERDICT_FP
            reason = (f"Endpoint returns minimal/empty content "
                      f"(HTTP {fetch.get('status', '?')}, {fetch.get('body_length', 0)} bytes)")

    data = {"type": vuln_type, "target": target_url, "checks": {"fetch": fetch}}

    lines = []
    if auto_verdict:
        lines.append(f"[VERDICT: {auto_verdict.upper()} — {reason}]")
    else:
        lines.append(f"[VERDICT: NEEDS AI REVIEW — {reason}]")

    lines.append(f"== Wayback URL Verification ({vuln_type}) ==")
    lines.append(f"URL: {target_url}")

    if not fetch.get("error"):
        lines.append(f"Status: HTTP {fetch['status']} ({fetch.get('content_type', '?')})")
        lines.append(f"Size: {fetch.get('body_length', 0)} bytes")
        if fetch.get("redirected_away"):
            lines.append(f"Redirected to: {fetch.get('final_url', '?')}")
        if fetch.get("body_snippet"):
            lines.append(f"Content:\n{fetch['body_snippet'][:500]}")
    else:
        lines.append(f"Error: {fetch['error']}")

    confidence = 8 if auto_verdict else 5

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": confidence,
    }


# =====================================================================
# Generic Fallback Enricher — runs for every vuln type without a
# specific enricher. Guards against detector evidence-string FPs by
# independently re-fetching the URL and recording ground truth
# (status, Content-Type, body head, magic bytes) before any LLM tier
# sees the finding.
#
# Root cause: vuln #109 partner.alibaba.com actuator_heapdump (Critical)
# was a FP because _match_actuator matched '"env"' substring in HTML
# <meta name="env"> and there was no enricher for actuator_heapdump —
# so T1→T2→T3→T4 all rubber-stamped a fake evidence string.
# =====================================================================

def _enrich_generic(subdomain, url, evidence, vuln_type):
    """Universal HTTP re-verification fallback for any vuln without a specific enricher."""
    target_url = url or f"https://{subdomain}/"
    fetch, auto_verdict, reason = _fetch_and_classify(subdomain, target_url, vuln_type)
    data = {"type": vuln_type, "target": target_url, "fetch": fetch}

    lines = []
    if auto_verdict:
        lines.append(f"[VERDICT: {auto_verdict.upper()} — {reason}]")
    else:
        lines.append(f"[VERDICT: NEEDS AI REVIEW — {reason or 'endpoint reachable, verify evidence'}]")

    lines.append(f"== Generic HTTP Verification ({vuln_type}) ==")
    lines.append(f"URL: {target_url}")
    lines.append(f"Original detector evidence: {evidence[:200]}")

    if not fetch.get("error"):
        lines.append(f"Status: HTTP {fetch['status']}")
        lines.append(f"Content-Type: {fetch.get('content_type', '?')}")
        lines.append(f"Body size: {fetch.get('body_length', 0)} bytes")
        lines.append(f"First 16 bytes (hex): {fetch.get('first_bytes_hex', '?')}")
        if fetch.get("redirected_away"):
            lines.append(f"Redirected to: {fetch.get('final_url', '?')}")
        if fetch.get("expected_magic"):
            lines.append(f"Expected magic bytes: {fetch['expected_magic']!r} — match: {fetch.get('magic_ok')}")
        if fetch.get("body_snippet"):
            lines.append(f"Body head:\n{fetch['body_snippet'][:400]}")
    else:
        lines.append(f"Error: {fetch['error']}")

    return {
        "enriched_evidence": "\n".join(lines),
        "verification_data": data,
        "auto_verdict": auto_verdict,
        "confidence": 8 if auto_verdict else 5,
    }
