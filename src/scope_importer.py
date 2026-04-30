"""
Scope Importer — Import bug bounty programs from GitHub community lists.

Sources:
  1. projectdiscovery/public-bugbounty-programs — 798 programs with domains (JSON)
  2. Lissy93/bug-bounties — ~2,971 programs with URLs (YAML)

Imports paying bounty programs into the programs + targets tables.
Runs once on demand or as part of periodic sync.
"""
import json
import logging
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

from db import (
    get_conn, insert_program, insert_target, update_target_scope,
    insert_program_snapshot, log_activity,
)

log = logging.getLogger("hunter")

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "github_cache"

# Raw GitHub URLs
PD_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
LISSY_PLATFORM_URL = "https://raw.githubusercontent.com/Lissy93/bug-bounties/main/platform-programs.yml"

# Platforms to skip when extracting domains from Lissy93 URLs
PLATFORM_HOSTS = {
    "hackerone.com", "bugcrowd.com", "intigriti.com", "synack.com",
    "yeswehack.com", "hackenproof.com", "federacy.com", "cobalt.io",
    "openbugbounty.org", "immunefi.com", "huntr.dev", "huntr.com",
}

# TLDs that are too generic to be useful targets
SKIP_TLDS = {"gov", "edu", "mil"}


def _fetch_cached(url, name, max_age_hours=24):
    """Fetch URL with local file cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / name

    if cache_file.exists():
        import os
        age_hours = (time.time() - os.path.getmtime(cache_file)) / 3600
        if age_hours < max_age_hours:
            return cache_file.read_text(encoding="utf-8")

    log.info(f"Fetching {url}...")
    resp = requests.get(url, timeout=30, headers={"User-Agent": "Hunter-Scanner/2.0"})
    resp.raise_for_status()
    cache_file.write_text(resp.text, encoding="utf-8")
    return resp.text


def _is_valid_domain(domain):
    """Check if a string looks like a valid domain for scanning."""
    if not domain or len(domain) < 4:
        return False
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", domain):
        return False
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in SKIP_TLDS:
        return False
    # Skip IP addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        return False
    return True


def _extract_domain_from_url(url):
    """Extract the root domain from a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        host = host.lower().strip(".")
        if not host:
            return None
        # Skip platform URLs
        for ph in PLATFORM_HOSTS:
            if host == ph or host.endswith("." + ph):
                return None
        # Strip www.
        if host.startswith("www."):
            host = host[4:]
        if _is_valid_domain(host):
            return host
        return None
    except Exception:
        return None


def _get_existing_domains():
    """Get set of domains already in the targets table."""
    with get_conn() as conn:
        rows = conn.execute("SELECT domain FROM targets").fetchall()
        return {r["domain"].lower() for r in rows}


def _get_existing_handles():
    """Get set of program handles already in the programs table."""
    with get_conn() as conn:
        rows = conn.execute("SELECT handle FROM programs WHERE handle IS NOT NULL").fetchall()
        return {r["handle"].lower() for r in rows if r["handle"]}


def import_projectdiscovery():
    """
    Import from projectdiscovery/public-bugbounty-programs.
    JSON format: {"programs": [{"name", "url", "bounty", "domains": [...]}]}
    Only imports programs with bounty=true and non-empty domains.
    """
    log.info("Importing projectdiscovery/public-bugbounty-programs...")
    raw = _fetch_cached(PD_URL, "pd_programs.json", max_age_hours=72)
    data = json.loads(raw)
    programs = data.get("programs", [])

    existing_domains = _get_existing_domains()
    new_programs = 0
    new_targets = 0
    skipped_no_bounty = 0
    skipped_no_domains = 0

    for prog in programs:
        name = prog.get("name", "").strip()
        url = prog.get("url", "").strip()
        has_bounty = prog.get("bounty", False)
        domains = prog.get("domains", [])

        if not has_bounty:
            skipped_no_bounty += 1
            continue

        if not domains:
            skipped_no_domains += 1
            continue

        # Clean domains
        clean_domains = []
        for d in domains:
            d = d.strip().lower().lstrip("*.")
            if _is_valid_domain(d):
                clean_domains.append(d)

        if not clean_domains:
            continue

        # Determine platform from URL
        platform = "independent"
        program_url = url
        handle = None
        if "hackerone.com" in url:
            platform = "hackerone"
            m = re.search(r"hackerone\.com/([^/?#]+)", url)
            if m:
                handle = m.group(1)
        elif "bugcrowd.com" in url:
            platform = "bugcrowd"
        elif "intigriti.com" in url:
            platform = "intigriti"
        elif "yeswehack.com" in url:
            platform = "yeswehack"

        scope_str = ",".join(clean_domains)

        # Insert program
        pid = insert_program(
            name, handle or name.lower().replace(" ", "-"),
            platform, program_url, scope_str,
        )
        if pid:
            new_programs += 1

        # Store snapshot for scope change detection
        insert_program_snapshot(
            handle or name.lower().replace(" ", "-"),
            name, scope_str,
        )

        # Insert targets
        for domain in clean_domains:
            if domain.lower() not in existing_domains:
                tid = insert_target(domain)
                if tid:
                    update_target_scope(tid, "in_scope", platform, program_url)
                    new_targets += 1
                    existing_domains.add(domain.lower())

    log.info(
        f"projectdiscovery import: {new_programs} new programs, {new_targets} new targets "
        f"(skipped: {skipped_no_bounty} no-bounty, {skipped_no_domains} no-domains)"
    )
    log_activity("import", f"GitHub/projectdiscovery: +{new_programs} programs, +{new_targets} targets")
    return new_programs, new_targets


def import_lissy93():
    """
    Import from Lissy93/bug-bounties platform-programs.yml.
    YAML format: list of {company, url, handle?, contact?, rewards: [*bounty/*swag/*recognition]}
    Only imports programs with *bounty in rewards.
    Extracts domain from URL since this source doesn't list domains explicitly.
    """
    log.info("Importing Lissy93/bug-bounties...")
    raw = _fetch_cached(LISSY_PLATFORM_URL, "lissy93_programs.yml", max_age_hours=72)
    data = yaml.safe_load(raw)

    # The YAML has a top-level dict with 'companies' key
    if isinstance(data, dict):
        programs = data.get("companies", [])
    elif isinstance(data, list):
        programs = data
    else:
        log.warning("Lissy93 YAML parse failed — unexpected format")
        return 0, 0

    existing_domains = _get_existing_domains()
    existing_handles = _get_existing_handles()
    new_programs = 0
    new_targets = 0
    skipped_no_bounty = 0
    skipped_existing = 0

    for prog in programs:
        if not isinstance(prog, dict):
            continue

        name = prog.get("company", "").strip()
        url = prog.get("url", "").strip()
        handle = prog.get("handle", "")
        rewards = prog.get("rewards", [])

        # Only import bounty programs
        has_bounty = False
        for r in (rewards or []):
            if isinstance(r, str) and "bounty" in r.lower():
                has_bounty = True
                break
        if not has_bounty:
            skipped_no_bounty += 1
            continue

        # Skip if we already have this handle from HackerOne import
        if handle and handle.lower() in existing_handles:
            skipped_existing += 1
            continue

        # Extract domain from URL
        domain = _extract_domain_from_url(url)
        # Also try the contact URL
        if not domain:
            contact = prog.get("contact", "")
            if contact:
                domain = _extract_domain_from_url(contact)

        if not domain:
            continue

        if domain.lower() in existing_domains:
            skipped_existing += 1
            continue

        # Determine platform
        platform = "independent"
        program_url = url
        if handle:
            platform = "hackerone"
            program_url = f"https://hackerone.com/{handle}"

        # Insert program
        pid = insert_program(
            name, handle or name.lower().replace(" ", "-"),
            platform, program_url, domain,
        )
        if pid:
            new_programs += 1

        insert_program_snapshot(
            handle or name.lower().replace(" ", "-"),
            name, domain,
        )

        # Insert target
        if domain.lower() not in existing_domains:
            tid = insert_target(domain)
            if tid:
                update_target_scope(tid, "in_scope", platform, program_url)
                new_targets += 1
                existing_domains.add(domain.lower())

    log.info(
        f"Lissy93 import: {new_programs} new programs, {new_targets} new targets "
        f"(skipped: {skipped_no_bounty} no-bounty, {skipped_existing} existing)"
    )
    log_activity("import", f"GitHub/Lissy93: +{new_programs} programs, +{new_targets} targets")
    return new_programs, new_targets


def import_all():
    """Run all GitHub importers. Returns total (new_programs, new_targets)."""
    log_activity("import", "Starting GitHub scope import (projectdiscovery + Lissy93)...")
    total_progs = 0
    total_targets = 0

    # projectdiscovery first — it has actual domains
    try:
        p, t = import_projectdiscovery()
        total_progs += p
        total_targets += t
    except Exception as e:
        log.error(f"projectdiscovery import failed: {e}")
        log_activity("error", f"projectdiscovery import failed: {e}")

    # Lissy93 second — fills gaps with URL-extracted domains
    try:
        p, t = import_lissy93()
        total_progs += p
        total_targets += t
    except Exception as e:
        log.error(f"Lissy93 import failed: {e}")
        log_activity("error", f"Lissy93 import failed: {e}")

    log_activity(
        "import",
        f"GitHub scope import complete: +{total_progs} programs, +{total_targets} targets total"
    )
    log.info(f"=== GitHub import done: {total_progs} new programs, {total_targets} new targets ===")
    return total_progs, total_targets


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    from db import init_db
    init_db()
    progs, targets = import_all()
    print(f"\nDone! Imported {progs} programs, {targets} targets.")
