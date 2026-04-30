"""
Program Scanner v13 — Multi-signal program monitoring.

Features:
  1. HackerOne directory sync (weekly full refresh)
  2. New program detection (every 15 min, diff against snapshots)
  3. Scope change detection (every 6 hours, diff stored vs current)
  4. All signals feed into the priority queue
"""
import json
import re
import time
from pathlib import Path

import requests

from db import (
    insert_program, get_programs, insert_target, update_target_scope, log_activity,
    get_conn, get_known_handles, insert_program_snapshot, get_program_snapshot,
    update_snapshot_scope, enqueue_scan,
)

ROOT = Path(__file__).resolve().parent.parent
PROGRAMS_CACHE = ROOT / "data" / "h1_programs.json"


def fetch_h1_directory(max_pages=29):
    """
    Fetch bug bounty programs from HackerOne's public directory.
    Returns list of {company, handle, url, domains[], launched_at}.
    """
    # Check cache first (refresh weekly)
    if PROGRAMS_CACHE.exists():
        import os
        age_hours = (time.time() - os.path.getmtime(PROGRAMS_CACHE)) / 3600
        if age_hours < 168:  # 7 days
            with open(PROGRAMS_CACHE) as f:
                return json.load(f)

    log_activity("program", "Fetching HackerOne program directory...")
    programs = []
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }

    for page in range(1, max_pages + 1):
        try:
            resp = requests.get(
                "https://hackerone.com/directory/programs",
                params={
                    "page[number]": page,
                    "page[size]": 100,
                    "filter[type][]": "hackerone",
                    "sort": "-started_accepting_at",
                },
                headers=headers,
                timeout=15,
            )
            if resp.status_code != 200:
                break

            data = resp.json()
            items = data.get("data", [])
            if not items:
                break

            for item in items:
                attrs = item.get("attributes", {})
                handle = attrs.get("handle", "")
                name = attrs.get("name", "")

                domains = _extract_scope_domains(attrs)

                if handle:
                    programs.append({
                        "company": name,
                        "handle": handle,
                        "url": f"https://hackerone.com/{handle}",
                        "domains": list(set(domains)),
                        "launched_at": attrs.get("started_accepting_at", ""),
                    })

            time.sleep(1)  # Rate limit
        except Exception as e:
            log_activity("error", f"H1 directory fetch failed page {page}: {e}")
            break

    # Cache results
    PROGRAMS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(PROGRAMS_CACHE, "w") as f:
        json.dump(programs, f, indent=2)

    log_activity("program", f"Fetched {len(programs)} programs from HackerOne directory")
    return programs


def _extract_scope_domains(attrs):
    """Extract in-scope domains from program attributes."""
    domains = []
    targets = attrs.get("targets", {})
    if isinstance(targets, dict):
        in_scope = targets.get("in_scope", [])
        for t in in_scope:
            tattrs = t.get("attributes", {}) if isinstance(t, dict) else {}
            asset = tattrs.get("asset_identifier", "")
            asset_type = tattrs.get("asset_type", "")
            if asset_type in ("URL", "WILDCARD", "DOMAIN") and re.match(r"^[\w*.-]+\.\w{2,}$", asset):
                clean = asset.lstrip("*.")
                if clean:
                    domains.append(clean)
    return domains


def sync_programs_to_db():
    """Sync H1 programs into the programs table and create targets for their domains."""
    from datetime import datetime, timedelta, timezone
    programs = fetch_h1_directory()

    programs.sort(key=lambda p: p.get("launched_at") or "", reverse=True)

    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    new_count = sum(1 for p in programs if (p.get("launched_at") or "") >= cutoff)
    if new_count:
        log_activity("program", f"Found {new_count} programs launched in last 30 days — scanning first!")

    new_programs = 0
    new_targets = 0

    for prog in programs:
        if not prog["domains"]:
            continue

        scope_str = ",".join(prog["domains"])
        pid = insert_program(
            prog["company"], prog["handle"], "hackerone",
            prog["url"], scope_str,
        )
        if pid:
            new_programs += 1

        # Store snapshot for future diffing
        insert_program_snapshot(prog["handle"], prog["company"], scope_str)

        for domain in prog["domains"]:
            tid = insert_target(domain)
            if tid:
                update_target_scope(tid, "in_scope", "hackerone", prog["url"])
                new_targets += 1

    log_activity("program", f"Synced {new_programs} new programs, {new_targets} new in-scope targets")

    # Also import from GitHub community lists
    try:
        from scope_importer import import_all as github_import
        gh_progs, gh_targets = github_import()
        new_programs += gh_progs
        new_targets += gh_targets
    except Exception as e:
        log_activity("error", f"GitHub scope import failed during sync: {e}")

    return new_programs, new_targets


# =====================================================================
# NEW PROGRAM MONITOR — checks every 15 minutes (HIGHEST ROI)
# =====================================================================

def check_new_programs():
    """
    Fetch first 2 pages of H1 directory (newest first).
    Diff against stored snapshots.
    Returns list of new programs with their scope domains.
    """
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    known_handles = get_known_handles()
    new_programs = []

    for page in range(1, 3):  # Only 2 pages = 200 programs (newest first)
        try:
            resp = requests.get(
                "https://hackerone.com/directory/programs",
                params={
                    "page[number]": page,
                    "page[size]": 100,
                    "filter[type][]": "hackerone",
                    "sort": "-started_accepting_at",
                },
                headers=headers,
                timeout=15,
            )
            if resp.status_code != 200:
                break

            data = resp.json()
            items = data.get("data", [])
            if not items:
                break

            for item in items:
                attrs = item.get("attributes", {})
                handle = attrs.get("handle", "")
                name = attrs.get("name", "")

                if not handle or handle in known_handles:
                    continue

                domains = _extract_scope_domains(attrs)
                if not domains:
                    continue

                scope_str = ",".join(domains)

                # NEW PROGRAM FOUND!
                new_programs.append({
                    "company": name,
                    "handle": handle,
                    "url": f"https://hackerone.com/{handle}",
                    "domains": domains,
                    "launched_at": attrs.get("started_accepting_at", ""),
                })

                # Store in DB
                insert_program(name, handle, "hackerone", f"https://hackerone.com/{handle}", scope_str)
                insert_program_snapshot(handle, name, scope_str)

                log_activity("signal", f"NEW PROGRAM: {name} ({handle}) — {len(domains)} scope domains!")

            time.sleep(1)
        except Exception as e:
            log_activity("error", f"New program check failed: {e}")
            break

    if new_programs:
        total_domains = sum(len(p["domains"]) for p in new_programs)
        log_activity("signal", f"Detected {len(new_programs)} new programs with {total_domains} domains — enqueueing at P0!")

        # Enqueue all new program domains at HIGHEST PRIORITY
        for prog in new_programs:
            for domain in prog["domains"]:
                tid = insert_target(domain)
                if tid:
                    update_target_scope(tid, "in_scope", "hackerone", prog["url"])
                    enqueue_scan(tid, domain, priority=0, source="new_program", source_detail=prog["handle"])

    return new_programs


# =====================================================================
# SCOPE CHANGE DETECTOR — checks every 6 hours
# =====================================================================

def detect_scope_changes():
    """
    Compare current program scopes against stored snapshots.
    Returns list of (program_info, new_domains, removed_domains).
    """
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    changes = []

    # Only check programs we already track (from snapshots)
    known_handles = get_known_handles()
    if not known_handles:
        return changes

    # Fetch fresh directory data (use cache if recent, else fetch first 5 pages)
    programs = fetch_h1_directory(max_pages=5)

    for prog in programs:
        handle = prog.get("handle", "")
        if handle not in known_handles:
            continue

        snapshot = get_program_snapshot(handle)
        if not snapshot:
            continue

        current_domains = set(prog.get("domains", []))
        stored_domains = set(d.strip() for d in (snapshot.get("scope_domains") or "").split(",") if d.strip())

        new_domains = current_domains - stored_domains
        removed_domains = stored_domains - current_domains

        if new_domains:
            changes.append({
                "program": prog,
                "new_domains": list(new_domains),
                "removed_domains": list(removed_domains),
            })

            log_activity("signal", f"SCOPE CHANGE: {prog['company']} added {len(new_domains)} domains: {', '.join(list(new_domains)[:5])}")

            # Enqueue new scope domains at HIGH priority
            for domain in new_domains:
                tid = insert_target(domain)
                if tid:
                    update_target_scope(tid, "in_scope", "hackerone", prog["url"])
                    enqueue_scan(tid, domain, priority=1, source="scope_change", source_detail=handle)

            # Update snapshot with current scope
            update_snapshot_scope(handle, ",".join(current_domains))

    if changes:
        total_new = sum(len(c["new_domains"]) for c in changes)
        log_activity("signal", f"Scope changes detected: {len(changes)} programs, {total_new} new domains — enqueued at P1")

    return changes


def get_program_domains():
    """Get all in-scope domains from synced programs."""
    programs = get_programs()
    domains = []
    for p in programs:
        scope = p["scope_domains"] or ""
        for d in scope.split(","):
            d = d.strip()
            if d:
                domains.append({"domain": d, "program": p["company"], "url": p["url"]})
    return domains
