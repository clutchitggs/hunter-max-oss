"""
JavaScript Secret Scanner — Downloads JS files from web pages and scans for leaked secrets.
Major bug bounty revenue source: hardcoded API keys, tokens, internal URLs.
"""
import re
import logging
import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

TIMEOUT = 10
MAX_JS_SIZE = 2 * 1024 * 1024  # 2MB
MAX_JS_FILES = 20  # Per subdomain
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Connection-pooled session
_session = requests.Session()
_session.headers.update(HEADERS)
_session.verify = False
_adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

# Secret patterns — based on trufflehog/gitleaks patterns
JS_SECRET_PATTERNS = [
    ("aws_access_key",   r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_key",   r"""(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})"""),
    ("github_token",     r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    ("github_pat",       r"github_pat_[A-Za-z0-9_]{22,255}"),
    ("slack_token",      r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"),
    ("slack_webhook",    r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}"),
    ("google_api_key",   r"AIza[0-9A-Za-z\-_]{35}"),
    ("stripe_live_key",  r"sk_live_[0-9a-zA-Z]{24,99}"),
    ("stripe_pub_key",   r"pk_live_[0-9a-zA-Z]{24,99}"),
    ("private_key",      r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ("jwt_token",        r"eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_.+/=]{10,}"),
    ("generic_secret",   r"""(?i)(?:api_key|apikey|api_secret|access_token|auth_token|secret_key)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"]"""),
    ("firebase_url",     r"https://[a-z0-9-]+\.firebaseio\.com"),
    ("firebase_key",     r"https://[a-z0-9-]+\.firebaseapp\.com"),
    ("heroku_api",       r"""(?i)heroku.*[=:]\s*['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"""),
    ("mailgun_key",      r"key-[0-9a-zA-Z]{32}"),
    ("twilio_sid",       r"AC[0-9a-fA-F]{32}"),
    ("sendgrid_key",     r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    ("square_token",     r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}"),
    ("internal_url",     r"""(?:["'])https?://(?:internal|staging|stg|dev|admin|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"']*"""),
]

# False positive indicators
FP_INDICATORS = ["example", "sample", "placeholder", "xxx", "your_", "test", "dummy", "fake", "changeme", "todo"]


def _discover_js_urls(subdomain):
    """Fetch HTML page and extract JavaScript file URLs."""
    js_urls = set()
    for scheme in ["https", "http"]:
        try:
            resp = _session.get(f"{scheme}://{subdomain}/", timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code != 200:
                continue
            body = resp.text[:200000]  # First 200KB of HTML

            # Parse <script src="...">
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(body, "html.parser")
                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    if src.startswith("//"):
                        src = f"{scheme}:{src}"
                    elif src.startswith("/"):
                        src = f"{scheme}://{subdomain}{src}"
                    elif not src.startswith("http"):
                        src = f"{scheme}://{subdomain}/{src}"
                    if ".js" in src.split("?")[0]:
                        js_urls.add(src)
            except ImportError:
                # Fallback regex if bs4 not available
                for match in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body):
                    if match.startswith("//"):
                        match = f"{scheme}:{match}"
                    elif match.startswith("/"):
                        match = f"{scheme}://{subdomain}{match}"
                    elif not match.startswith("http"):
                        match = f"{scheme}://{subdomain}/{match}"
                    js_urls.add(match)

            break  # Got HTML successfully, don't try the other scheme
        except Exception:
            continue

    return list(js_urls)[:MAX_JS_FILES]


def _scan_js_content(content, js_url):
    """Scan JS content for secrets. Returns list of (pattern_name, matched_value)."""
    findings = []
    seen_values = set()

    for pattern_name, pattern in JS_SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            value = match.group(0)[:200]  # Cap length

            # Skip false positives
            context = content[max(0, match.start()-50):match.end()+50].lower()
            if any(fp in context for fp in FP_INDICATORS):
                continue
            if len(value) < 16 and pattern_name not in ("aws_access_key", "internal_url"):
                continue

            # Deduplicate
            if value in seen_values:
                continue
            seen_values.add(value)

            findings.append((pattern_name, value))

    return findings


def scan_js_secrets(subdomain, target_id=None):
    """Scan a subdomain's JavaScript files for leaked secrets. Returns list of vuln dicts."""
    from db import insert_vuln, log_activity

    js_urls = _discover_js_urls(subdomain)
    if not js_urls:
        return []

    all_vulns = []
    seen_secrets = set()

    for js_url in js_urls:
        try:
            resp = _session.get(js_url, timeout=TIMEOUT, allow_redirects=True, stream=True)

            # Check size before downloading
            content_length = int(resp.headers.get("Content-Length", 0))
            if content_length > MAX_JS_SIZE:
                continue

            content = resp.text[:MAX_JS_SIZE]
            if len(content) < 100:
                continue

            findings = _scan_js_content(content, js_url)

            for pattern_name, value in findings:
                dedup_key = f"{subdomain}:{pattern_name}:{value[:50]}"
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)

                severity = "High"
                if pattern_name in ("private_key", "aws_secret_key", "stripe_live_key"):
                    severity = "Critical"
                elif pattern_name in ("internal_url", "firebase_url"):
                    severity = "Medium"

                evidence = f"Secret type: {pattern_name} | Value: {value[:80]}... | Source: {js_url}"
                vuln = {
                    "subdomain": subdomain,
                    "vuln_type": f"js_secret:{pattern_name}",
                    "evidence": evidence,
                    "severity": severity,
                    "url": js_url,
                }
                all_vulns.append(vuln)

                if target_id:
                    insert_vuln(target_id, subdomain, f"js_secret:{pattern_name}", evidence, severity, js_url)

                log_activity("vuln", f"JS SECRET {severity}: {pattern_name} on {subdomain}")
                log.info(f"  *** JS SECRET: {pattern_name} in {js_url}")

        except Exception:
            continue

    return all_vulns
