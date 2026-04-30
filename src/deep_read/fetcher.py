"""Fetch homepage + same-origin JS bundles for a target subdomain.

Auth model:
  - Tal handles WAF / 2FA / SSO manually in his browser.
  - He pastes the resulting Cookie header (and optional auth headers) into the CLI.
  - Every HTTP request the fetcher makes (homepage + bundles) carries that
    session, so we see the post-login lazy-loaded admin/billing/tenant chunks
    that anonymous scrapes miss.

User-Agent: real Chrome string + sec-ch-ua hints to avoid being served the
'unsupported browser' shell that some SaaS apps return to python-requests.
"""
import logging
import re
from urllib.parse import urljoin, urlparse

import requests

from . import webpack_chunks

log = logging.getLogger("hunter.deep_read")

TIMEOUT = 15
MAX_BUNDLE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_BUNDLES = 30

# Real Chrome 124 on Win11 — matches what an operator's browser would send.
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

COMMON_BUNDLE_HINTS = (
    "/static/js/main.js", "/static/js/app.js", "/assets/app.js",
    "/_next/static/chunks/main.js", "/_next/static/chunks/webpack.js",
)


def _build_session(cookie=None, extra_headers=None):
    """
    cookie: raw 'name1=val1; name2=val2' string (Cookie header value)
    extra_headers: dict of additional headers (Authorization, X-CSRF-Token, etc.)

    NOTE: We deliberately strip 'Authorization' from this session because
    the fetcher only hits HTML + JS bundles, which are routinely served
    from S3/CloudFront. S3 rejects any non-AWS Authorization header
    with 400 InvalidArgument, breaking the SPA fetch. Bearer tokens
    belong on API calls (spec_finder/analyzer), not static assets.
    Cookies alone are sufficient to authenticate the SPA shell.
    """
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    if cookie:
        s.headers["Cookie"] = cookie
    if extra_headers:
        for k, v in extra_headers.items():
            if k.lower() == "authorization":
                log.info(f"[deep_read] dropping Authorization on static fetch "
                         f"(S3-safe); kept for API probes")
                continue
            s.headers[k] = v
    s.verify = False
    return s


def _bundle_headers():
    """When fetching a JS bundle, Sec-Fetch hints differ from a navigation."""
    return {
        "Accept": "*/*",
        "Sec-Fetch-Dest": "script",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Site": "same-origin",
    }


def fetch_target(subdomain, cookie=None, extra_headers=None):
    """
    Returns dict with:
      homepage_url, homepage_status, homepage_html (str, trimmed),
      final_url, bundles: [{url, status, size, content (str)}], notes: [str],
      authenticated: bool

    `subdomain` may be a bare host ("api.acme.io") or host+path
    ("console.acme.io/app/dashboard"). When auth-walled SaaS apps redirect
    "/" to a marketing site, pass the post-login path so we land in the app.
    """
    target = subdomain.lstrip("/")
    if "/" in target:
        host, _, path = target.partition("/")
        base = f"https://{host}/{path}"
    else:
        base = f"https://{target}/"
    s = _build_session(cookie=cookie, extra_headers=extra_headers)
    notes = []
    homepage_html = ""
    homepage_status = None
    final_url = base

    if cookie:
        notes.append(f"authenticated: cookie {len(cookie)} chars")
    if extra_headers:
        notes.append(f"extra headers: {sorted(extra_headers.keys())}")

    try:
        resp = s.get(base, timeout=TIMEOUT, allow_redirects=True)
        homepage_status = resp.status_code
        homepage_html = resp.text[:500_000]
        final_url = str(resp.url)
        # Detect login-wall: if we hit a /login or /sign-in redirect with no cookie,
        # warn loudly so Tal knows the deep surface is unreachable.
        if not cookie and re.search(r"/(login|signin|sign-in|auth|sso)(/|$|\?)",
                                    final_url, re.I):
            notes.append(
                f"WARN: homepage redirected to auth page ({final_url}). "
                "Pass --cookie to reach the post-login bundles."
            )
    except Exception as e:
        notes.append(f"homepage fetch failed: {e}")
        return {
            "homepage_url": base, "homepage_status": None,
            "homepage_html": "", "final_url": base,
            "bundles": [], "notes": notes,
            "authenticated": bool(cookie),
        }

    # Extract <script src=> + module preloads + Next.js chunks
    script_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', homepage_html, re.I):
        src = m.group(1).strip()
        if src:
            script_urls.add(urljoin(final_url, src))
    for m in re.finditer(
        r'<link[^>]+rel=["\'](?:modulepreload|preload)["\'][^>]+href=["\']([^"\']+\.js[^"\']*)["\']',
        homepage_html, re.I):
        script_urls.add(urljoin(final_url, m.group(1)))

    base_host = urlparse(final_url).hostname
    for hint in COMMON_BUNDLE_HINTS:
        script_urls.add(urljoin(final_url, hint))

    # Same-origin OR same-eTLD+1 (covers cdn.example.com when target is app.example.com)
    kept = []
    for u in script_urls:
        host = urlparse(u).hostname or ""
        if host == base_host or (
            base_host and host
            and host.split(".")[-2:] == base_host.split(".")[-2:]
        ):
            kept.append(u)

    bundles = []
    total_bytes = 0
    bundle_hdrs = _bundle_headers()
    for u in kept[:MAX_BUNDLES]:
        if total_bytes >= MAX_TOTAL_BYTES:
            notes.append(f"bundle byte budget exhausted at {total_bytes}")
            break
        try:
            r = s.get(u, timeout=TIMEOUT, allow_redirects=True, stream=True,
                      headers=bundle_hdrs)
            content = r.raw.read(MAX_BUNDLE_BYTES, decode_content=True)
            size = len(content)
            if r.status_code != 200 or size < 200:
                continue
            ctype = (r.headers.get("Content-Type") or "").lower()
            head = content[:200].decode("utf-8", errors="ignore").lstrip().lower()
            if "text/html" in ctype or head.startswith("<!doctype") or head.startswith("<html"):
                continue
            text = content.decode("utf-8", errors="ignore")
            bundles.append({
                "url": u,
                "status": r.status_code,
                "size": size,
                "content": text,
            })
            total_bytes += size
        except Exception as e:
            notes.append(f"bundle {u[:60]} failed: {e}")

    # Webpack / Module Federation chunk discovery —
    # if the entry bundles are tiny stubs, expand to the lazy-loaded chunks
    # before returning. Without this, SPAs ship 600 bytes of code and 0 endpoints.
    if bundles:
        target_host = urlparse(final_url).hostname or subdomain.split("/")[0]
        try:
            extras = webpack_chunks.discover(bundles, s, target_host,
                                             max_extra=200,
                                             byte_budget=max(0, MAX_TOTAL_BYTES - total_bytes))
            if extras:
                bundles.extend(extras)
                notes.append(f"webpack chunk discovery: +{len(extras)} bundles")
        except Exception as e:
            notes.append(f"webpack chunk discovery failed: {e}")

    return {
        "homepage_url": base,
        "homepage_status": homepage_status,
        "homepage_html": homepage_html,
        "final_url": final_url,
        "bundles": bundles,
        "notes": notes,
        "authenticated": bool(cookie),
    }
