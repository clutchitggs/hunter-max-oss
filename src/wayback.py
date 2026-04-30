"""
Wayback Machine URL Discovery — Finds forgotten/hidden endpoints from web archives.
Old admin panels, API endpoints, config files that may still be accessible.
"""
import logging
import re
import time
import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

TIMEOUT = 15
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
CDX_API = "https://web.archive.org/cdx/search/cdx"

# Session with connection pooling
_session = requests.Session()
_session.headers.update(HEADERS)
_session.verify = False
_adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

# Interesting URL patterns to check
INTERESTING_PATTERNS = [
    r"/admin", r"/api/", r"/config", r"/backup", r"/debug",
    r"/swagger", r"/graphql", r"/dashboard", r"/panel",
    r"/internal", r"/staging", r"/phpmyadmin", r"/adminer",
    r"\.sql$", r"\.bak$", r"\.env$", r"\.json$", r"\.xml$",
    r"\.yml$", r"\.yaml$", r"\.conf$", r"\.log$", r"\.csv$",
    r"/wp-admin", r"/wp-login", r"/actuator", r"/server-status",
    r"/\.git", r"/\.svn", r"/console", r"/manager",
]
INTERESTING_RE = re.compile("|".join(INTERESTING_PATTERNS), re.IGNORECASE)


def check_wayback_urls(domain, target_id=None):
    """Query Wayback Machine for historical URLs, check if interesting ones are still accessible."""
    from db import insert_vuln, log_activity

    # Query CDX API
    try:
        resp = _session.get(
            CDX_API,
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,statuscode,mimetype",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": "500",
            },
            timeout=30,
        )
        if resp.status_code != 200:
            log.info(f"  [WAYBACK] CDX API returned {resp.status_code}")
            return 0

        data = resp.json()
    except Exception as e:
        log.info(f"  [WAYBACK] CDX query failed: {e}")
        return 0

    if len(data) < 2:  # First row is header
        return 0

    # Filter for interesting URLs
    interesting = []
    seen_paths = set()
    for row in data[1:]:  # Skip header row
        url = row[0] if row else ""
        if not url:
            continue

        # Extract path
        path = re.sub(r"https?://[^/]+", "", url)
        if path in seen_paths:
            continue
        seen_paths.add(path)

        if INTERESTING_RE.search(url):
            interesting.append(url)

    if not interesting:
        return 0

    log.info(f"  [WAYBACK] Found {len(interesting)} interesting historical URLs, checking accessibility...")

    # Check top 50 URLs for current accessibility
    vulns_found = 0
    for url in interesting[:50]:
        try:
            time.sleep(0.5)  # Rate limit
            resp = _session.get(url, timeout=TIMEOUT, allow_redirects=True)

            if resp.status_code == 200 and len(resp.text) > 100:
                # Verify it's not a generic error/parking page
                body_lower = resp.text[:1000].lower()
                if any(fp in body_lower for fp in ["domain for sale", "buy this domain", "parked", "404"]):
                    continue

                # Extract subdomain
                subdomain = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
                path = "/" + "/".join(url.replace("https://", "").replace("http://", "").split("/")[1:])

                evidence = f"Historical URL still accessible: {path}"
                severity = "Medium"
                if any(kw in path.lower() for kw in [".sql", ".bak", "backup", ".env", "config", "actuator"]):
                    severity = "High"

                if target_id:
                    insert_vuln(target_id, subdomain, f"wayback:{path[:50]}", evidence, severity, url)

                log_activity("vuln", f"WAYBACK {severity}: {path} on {subdomain}")
                log.info(f"  *** WAYBACK: {url} (status {resp.status_code})")
                vulns_found += 1

        except Exception:
            continue

    return vulns_found
