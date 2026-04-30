"""
Scope Checker — verifies if a target domain has an active bug bounty program.
Checks HackerOne public directory and security.txt.
"""
import json
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

from db import get_conn, update_target_scope, log_activity

CACHE_FILE = Path(__file__).resolve().parent.parent / "data" / "programs_cache.json"
CACHE_MAX_AGE_DAYS = 7


def _load_cache():
    if CACHE_FILE.exists():
        with open(CACHE_FILE) as f:
            data = json.load(f)
        cached_at = data.get("cached_at", "")
        if cached_at:
            age = datetime.now(tz=timezone.utc) - datetime.fromisoformat(cached_at)
            if age < timedelta(days=CACHE_MAX_AGE_DAYS):
                return data.get("programs", {})
    return None


def _save_cache(programs):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump({
            "cached_at": datetime.now(tz=timezone.utc).isoformat(),
            "programs": programs,
        }, f, indent=2)


def fetch_hackerone_programs():
    """
    Fetch public bug bounty programs from HackerOne's directory.
    Returns dict mapping domain -> {platform, url, name}.
    """
    cached = _load_cache()
    if cached:
        return cached

    programs = {}
    page = 1
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}

    while page <= 20:  # Safety limit
        try:
            resp = requests.get(
                "https://hackerone.com/directory/programs",
                params={"page": page, "type": "hackerone", "order_direction": "DESC", "order_field": "started_accepting_at"},
                headers=headers,
                timeout=15,
            )
            if resp.status_code != 200:
                break

            data = resp.json()
            results = data.get("data", []) or data.get("results", [])
            if not results:
                break

            for prog in results:
                handle = prog.get("attributes", {}).get("handle", "") or prog.get("handle", "")
                name = prog.get("attributes", {}).get("name", "") or prog.get("name", "")
                # Try to extract domain from the handle or targets
                targets = prog.get("attributes", {}).get("targets", {}).get("in_scope", []) or []
                for target in targets:
                    asset = target.get("attributes", {}).get("asset_identifier", "") or target.get("asset_identifier", "")
                    if re.match(r"^[\w.-]+\.\w{2,}$", asset):  # Looks like a domain
                        programs[asset.lower()] = {
                            "platform": "hackerone",
                            "url": f"https://hackerone.com/{handle}",
                            "name": name,
                        }

                # Also map handle.com as a guess
                if handle:
                    programs[f"{handle}.com"] = {
                        "platform": "hackerone",
                        "url": f"https://hackerone.com/{handle}",
                        "name": name,
                    }

            page += 1
            time.sleep(1)  # Rate limiting
        except Exception as e:
            print(f"  [WARN] HackerOne fetch failed on page {page}: {e}")
            break

    _save_cache(programs)
    return programs


def check_security_txt(domain):
    """Check if the domain has a REAL security.txt with bug bounty info."""
    for path in [f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"]:
        try:
            resp = requests.get(path, timeout=10, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                continue
            text = resp.text

            # Must be plain text, not HTML (catches 404 pages that return 200)
            content_type = resp.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                continue
            if text.strip().startswith("<!") or text.strip().startswith("<html"):
                continue

            # Must contain Contact: field (required by RFC 9116)
            if "contact:" not in text.lower():
                continue

            # Must mention a bounty platform or program
            text_lower = text.lower()
            if any(kw in text_lower for kw in ["hackerone", "bugcrowd", "intigriti", "bug bounty", "bounty"]):
                return True, text
        except Exception:
            continue
    return False, None


def check_target_scope(target_id, domain):
    """
    Check if a domain has a bug bounty program.
    Updates target scope_status in DB.
    Returns True if in-scope.
    """
    programs = fetch_hackerone_programs()

    # Direct domain match
    domain_lower = domain.lower()
    if domain_lower in programs:
        prog = programs[domain_lower]
        update_target_scope(target_id, "in_scope", prog["platform"], prog["url"])
        log_activity("scope", f"IN SCOPE: {domain} ({prog['platform']}: {prog['name']})")
        return True

    # Check parent domain (e.g., sub.company.com -> company.com)
    parts = domain_lower.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in programs:
            prog = programs[parent]
            update_target_scope(target_id, "in_scope", prog["platform"], prog["url"])
            log_activity("scope", f"IN SCOPE (parent): {domain} -> {parent} ({prog['platform']})")
            return True

    # Check security.txt
    has_bounty, _txt = check_security_txt(domain)
    if has_bounty:
        update_target_scope(target_id, "in_scope", "security.txt", f"https://{domain}/.well-known/security.txt")
        log_activity("scope", f"IN SCOPE (security.txt): {domain}")
        return True

    # Not found
    update_target_scope(target_id, "out_of_scope")
    log_activity("scope", f"OUT OF SCOPE: {domain}")
    return False
