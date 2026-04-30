"""
Multi-Vulnerability Passive Scanner
Checks subdomains for common misconfigurations via HTTP GET requests only.
No payloads, no fuzzing — purely passive detection.
"""
import requests
from requests.adapters import HTTPAdapter
from db import insert_vuln, log_activity

TIMEOUT = 5
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Connection-pooled session for 2-3x speed boost (reuses TCP connections)
_session = requests.Session()
_session.headers.update(HEADERS)
_session.verify = False
_adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

# Each check: (path, vuln_type, severity, match_function)
CHECKS = []


def _match_git(resp):
    """Exposed .git directory — leaks source code."""
    if resp.status_code == 200:
        body = resp.text[:200]
        if body.startswith("ref:") or "gitdir:" in body:
            return True, f"Git HEAD exposed: {body[:60]}"
    return False, None


def _match_env(resp):
    """Exposed .env file — leaks API keys, database credentials."""
    if resp.status_code == 200:
        body = resp.text[:500].lower()
        if any(k in body for k in ["db_password", "api_key", "secret", "database_url", "aws_", "token="]):
            return True, f"Env file with secrets (first 60 chars): {resp.text[:60]}"
    return False, None


def _match_config(resp):
    """Exposed config files — leaks internal configuration."""
    if resp.status_code == 200:
        body = resp.text[:500].lower()
        if any(k in body for k in ["password", "secret", "api_key", "database", "credentials"]):
            return True, f"Config file with secrets exposed"
    return False, None


def _match_directory_listing(resp):
    """Apache/Nginx directory listing — exposes file structure."""
    if resp.status_code == 200:
        body = resp.text[:500].lower()
        if "index of /" in body or "directory listing" in body:
            return True, "Directory listing enabled"
    return False, None


def _match_server_status(resp):
    """Apache server-status — leaks internal request info."""
    if resp.status_code == 200:
        body = resp.text[:500].lower()
        if "apache server status" in body or "server version" in body:
            return True, "Apache server-status exposed"
    return False, None


def _match_ds_store(resp):
    """.DS_Store file — leaks directory contents."""
    if resp.status_code == 200 and len(resp.content) > 8:
        if resp.content[:8] == b'\x00\x00\x00\x01Bud1':
            return True, ".DS_Store file exposed (leaks file/directory names)"
    return False, None


def _match_phpinfo(resp):
    """phpinfo() output — leaks server configuration."""
    if resp.status_code == 200:
        body = resp.text[:500].lower()
        if "php version" in body and "configuration" in body:
            return True, "phpinfo() exposed"
    return False, None


def _match_wp_config_bak(resp):
    """WordPress config backup — leaks database credentials."""
    if resp.status_code == 200:
        body = resp.text[:500]
        if "DB_NAME" in body or "DB_PASSWORD" in body:
            return True, "WordPress config backup exposed"
    return False, None


def _is_json_response(resp):
    """Guard against HTML SPA catch-all false positives.

    JSON-endpoint matchers (actuator, swagger, graphql) used to substring-match
    keywords like '"env"' or '"info"' — which also appear in HTML meta tags
    (e.g. <meta name="env" content="production">) on SPA catch-all pages,
    producing critical false positives (see vuln #109, partner.alibaba.com).

    Require Content-Type to declare JSON AND body to start with { or [.
    """
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "json" not in ctype and "javascript" not in ctype:
        return False
    stripped = resp.text.lstrip()[:1]
    return stripped in ("{", "[")


def _match_swagger(resp):
    """Exposed Swagger/OpenAPI spec — leaks internal API structure."""
    if resp.status_code == 200 and _is_json_response(resp):
        body = resp.text[:1000].lower()
        if any(k in body for k in ['"swagger"', '"openapi"', '"paths"']):
            return True, "Swagger/OpenAPI specification exposed — reveals internal API endpoints"
    return False, None


def _match_actuator(resp):
    """Spring Boot Actuator — leaks internal app info, env vars, health data."""
    if resp.status_code == 200 and _is_json_response(resp):
        body = resp.text[:1000].lower()
        # Require a strong signal (_links with actuator self-ref, or multiple endpoint keys)
        if '"_links"' in body and '"actuator"' in body:
            return True, "Spring Boot Actuator endpoint exposed (confirmed JSON response)"
    return False, None


def _match_actuator_env(resp):
    """Spring Boot Actuator /env — leaks environment variables and secrets."""
    if resp.status_code == 200 and _is_json_response(resp):
        body = resp.text[:2000].lower()
        if '"propertysources"' in body or '"activeprofiles"' in body or '"systemproperties"' in body:
            return True, "Spring Boot Actuator /env exposed — leaks environment variables"
    return False, None


def _match_heapdump(resp):
    """Spring Boot Actuator /heapdump — real heap dumps are BINARY (hprof format)."""
    if resp.status_code != 200:
        return False, None
    # Heap dumps are large binary files, NOT HTML. Reject HTML responses (SPA catch-all).
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "html" in ctype or "text/plain" in ctype:
        return False, None
    # Real .hprof file starts with ASCII magic: "JAVA PROFILE 1.0.1" or "JAVA PROFILE 1.0.2"
    if resp.content[:13] == b"JAVA PROFILE ":
        return True, "Spring Boot Actuator /heapdump exposed (valid hprof magic bytes)"
    # Also accept octet-stream with large binary body (some variants)
    if "octet-stream" in ctype and len(resp.content) > 10000 and b"<html" not in resp.content[:500].lower():
        return True, "Spring Boot Actuator /heapdump exposed (large binary octet-stream response)"
    return False, None


def _match_graphql(resp):
    """Exposed GraphQL endpoint with introspection enabled."""
    if resp.status_code == 200 and _is_json_response(resp):
        body = resp.text[:1000].lower()
        if '"data"' in body and ('"__schema"' in body or '"__type"' in body):
            return True, "GraphQL introspection enabled — exposes full API schema"
    return False, None


def _match_debug(resp):
    """Debug/error page leaking stack traces and framework info."""
    if resp.status_code in (200, 500):
        body = resp.text[:2000].lower()
        if "laravel" in body and ("exception" in body or "stack trace" in body):
            return True, "Laravel debug mode enabled — leaks source code paths and config"
        if "django" in body and "traceback" in body:
            return True, "Django debug mode enabled — leaks source code and settings"
        if "werkzeug" in body and "debugger" in body:
            return True, "Werkzeug debugger exposed — potential RCE"
    return False, None


# Define all checks: (url_path, vuln_type, severity, match_fn)
VULN_CHECKS = [
    ("/.git/HEAD", "git_exposed", "High", _match_git),
    ("/.env", "env_exposed", "Critical", _match_env),
    ("/.DS_Store", "ds_store", "Low", _match_ds_store),
    ("/server-status", "server_status", "Medium", _match_server_status),
    ("/phpinfo.php", "phpinfo", "Medium", _match_phpinfo),
    ("/wp-config.php.bak", "wp_config_backup", "Critical", _match_wp_config_bak),
    ("/config.json", "config_exposed", "High", _match_config),
    ("/.htpasswd", "htpasswd_exposed", "High", _match_env),
    ("/swagger.json", "swagger_exposed", "Medium", _match_swagger),
    ("/api-docs", "swagger_exposed", "Medium", _match_swagger),
    ("/openapi.json", "swagger_exposed", "Medium", _match_swagger),
    ("/v1/api-docs", "swagger_exposed", "Medium", _match_swagger),
    ("/v2/api-docs", "swagger_exposed", "Medium", _match_swagger),
    ("/actuator", "actuator_exposed", "High", _match_actuator),
    ("/actuator/env", "actuator_env", "Critical", _match_actuator_env),
    ("/actuator/heapdump", "actuator_heapdump", "Critical", _match_heapdump),
    ("/graphql?query={__schema{types{name}}}", "graphql_introspection", "Medium", _match_graphql),
    ("/_debug", "debug_exposed", "High", _match_debug),
]


def _triage_git(subdomain):
    """
    Auto-triage a .git finding. Returns (is_real, severity, detail).
    Checks: is it a private repo? Any local commits? Any secrets?
    """
    base = None
    for scheme in ["http", "https"]:
        try:
            r = _session.get(f"{scheme}://{subdomain}/.git/config", timeout=TIMEOUT,
                             allow_redirects=False, headers=HEADERS, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                base = scheme
                config_text = r.text
                break
        except Exception:
            continue

    if not base:
        return False, "Medium", "Could not access .git/config for triage"

    # Check 1: Is it a public repo?
    is_public = False
    if "github.com/" in config_text:
        # Extract the repo URL
        import re
        match = re.search(r'url\s*=\s*(https?://github\.com/\S+)', config_text)
        if match:
            repo_url = match.group(1).rstrip(".git")
            # Check if it's a public repo
            try:
                check = _session.get(repo_url, timeout=TIMEOUT, headers=HEADERS)
                if check.status_code == 200:
                    is_public = True
            except Exception:
                pass

    if is_public:
        # Check 2: Any LOCAL commits beyond the clone?
        try:
            r = _session.get(f"{base}://{subdomain}/.git/logs/HEAD", timeout=TIMEOUT,
                             allow_redirects=False, headers=HEADERS, verify=False)
            if r.status_code == 200:
                lines = [l.strip() for l in r.text.strip().split("\n") if l.strip()]
                # Only clone + checkout = no local changes
                if len(lines) <= 2 and all("clone:" in l or "checkout:" in l for l in lines):
                    return False, "Info", f"Public repo ({repo_url}), no local commits — false positive"
        except Exception:
            pass

        return True, "Low", f"Public repo ({repo_url}) but may have local modifications"

    # Private repo — this is the real deal
    # Check 3: Look for secrets in common paths
    secrets_found = []
    for path in ["/.env", "/.git/logs/HEAD"]:
        try:
            r = _session.get(f"{base}://{subdomain}{path}", timeout=TIMEOUT,
                             allow_redirects=False, headers=HEADERS, verify=False)
            if r.status_code == 200:
                body = r.text[:500].lower()
                if any(k in body for k in ["password", "secret", "api_key", "aws_", "token=", "db_"]):
                    secrets_found.append(path)
        except Exception:
            pass

    if secrets_found:
        return True, "Critical", f"Private repo with secrets found in {', '.join(secrets_found)}"

    return True, "High", f"Private repo exposed: {config_text[:80]}"


def _triage_env(subdomain, evidence):
    """Auto-triage .env finding. Check if it contains real secrets vs placeholder."""
    if any(k in evidence.lower() for k in ["password", "secret", "aws_", "api_key", "token="]):
        return True, "Critical", evidence
    return False, "Info", "Env file without real secrets — likely placeholder"


def scan_subdomain_vulns(subdomain, target_id=None):
    """Run all passive vuln checks with auto-triage on a single subdomain."""
    findings = []

    for path, vuln_type, severity, match_fn in VULN_CHECKS:
        url = f"https://{subdomain}{path}"
        try:
            resp = _session.get(url, timeout=TIMEOUT, allow_redirects=False,
                                headers=HEADERS, verify=False)
            is_vuln, evidence = match_fn(resp)

            if is_vuln:
                # AUTO-TRIAGE: verify before flagging
                if vuln_type == "git_exposed":
                    is_real, real_severity, triage_detail = _triage_git(subdomain)
                    if not is_real:
                        log_activity("triage", f"FILTERED: {subdomain}/.git — {triage_detail}")
                        continue  # Skip false positive
                    severity = real_severity
                    evidence = triage_detail

                elif vuln_type == "env_exposed":
                    is_real, real_severity, triage_detail = _triage_env(subdomain, evidence)
                    if not is_real:
                        log_activity("triage", f"FILTERED: {subdomain}/.env — {triage_detail}")
                        continue
                    severity = real_severity
                    evidence = triage_detail

                findings.append({
                    "subdomain": subdomain,
                    "vuln_type": vuln_type,
                    "evidence": evidence,
                    "severity": severity,
                    "url": url,
                })
                if target_id:
                    insert_vuln(target_id, subdomain, vuln_type, evidence, severity, url)
                log_activity("vuln", f"VERIFIED {severity}: {vuln_type} on {subdomain}")

        except Exception:
            if path in ("/.git/HEAD", "/.env"):
                try:
                    url_http = f"http://{subdomain}{path}"
                    resp = _session.get(url_http, timeout=TIMEOUT, allow_redirects=False,
                                        headers=HEADERS)
                    is_vuln, evidence = match_fn(resp)
                    if is_vuln:
                        # Triage HTTP findings too
                        if vuln_type == "git_exposed":
                            is_real, real_severity, triage_detail = _triage_git(subdomain)
                            if not is_real:
                                log_activity("triage", f"FILTERED: {subdomain}/.git — {triage_detail}")
                                continue
                            severity = real_severity
                            evidence = triage_detail
                        elif vuln_type == "env_exposed":
                            is_real, real_severity, triage_detail = _triage_env(subdomain, evidence)
                            if not is_real:
                                continue
                            severity = real_severity

                        findings.append({
                            "subdomain": subdomain,
                            "vuln_type": vuln_type,
                            "evidence": evidence,
                            "severity": severity,
                            "url": url_http,
                        })
                        if target_id:
                            insert_vuln(target_id, subdomain, vuln_type, evidence, severity, url_http)
                        log_activity("vuln", f"{vuln_type.upper()}: {subdomain}{path}")
                except Exception:
                    pass

    # CORS misconfiguration check (needs custom Origin header)
    # Known third-party services that intentionally reflect origins (not real vulns)
    CORS_FP_SERVICES = ["fingerprint", "fpjs", "fp.", "clarity.", "segment.", "analytics.", "cdn.", "tracking."]
    try:
        cors_headers = {**HEADERS, "Origin": "https://evil-cors-test.com"}
        resp = _session.get(f"https://{subdomain}/", timeout=TIMEOUT,
                            headers=cors_headers, verify=False, allow_redirects=True)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if "evil-cors-test.com" in acao and "true" in acac:
            # Triage: check if this is a known third-party fingerprinting/analytics service
            body = resp.text[:500]
            is_third_party = False

            # Check subdomain name patterns
            sub_lower = subdomain.lower()
            if any(fp in sub_lower for fp in CORS_FP_SERVICES):
                is_third_party = True

            # Check response for FingerprintJS/analytics signatures
            if '"products"' in body or '"requestId"' in body or '"v":"2"' in body:
                is_third_party = True

            if is_third_party:
                log_activity("triage", f"FILTERED CORS: {subdomain} — third-party service (intentional CORS)")
            else:
                # Check if endpoint serves actual sensitive data (not just empty/error responses)
                has_data = len(resp.text) > 50 and resp.status_code == 200
                severity = "High" if has_data else "Medium"
                evidence = f"CORS reflects arbitrary origin with credentials (ACAO: {acao}, ACAC: true)"
                if not has_data:
                    evidence += " — endpoint returns minimal data, verify impact manually"
                findings.append({
                    "subdomain": subdomain, "vuln_type": "cors_misconfiguration",
                    "evidence": evidence, "severity": severity,
                    "url": f"https://{subdomain}/",
                })
                if target_id:
                    insert_vuln(target_id, subdomain, "cors_misconfiguration", evidence, severity, f"https://{subdomain}/")
                log_activity("vuln", f"VERIFIED {severity}: cors_misconfiguration on {subdomain}")
    except Exception:
        pass

    return findings
