"""
Orchestrator — runs the full Hunter-Max pipeline.

Pipeline: crawl feeds → extract companies → check scope → scan → draft reports → alert

Usage:
    python src/orchestrator.py              # Run once
    python src/orchestrator.py --loop       # Run continuously on schedule
"""
import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"

# Ensure src/ is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import get_targets, get_findings, get_finding, log_activity, init_db
from ma_recon import load_config, fetch_and_store
from scope_checker import check_target_scope
from dns_checker import scan_all_in_scope
from report_drafter import draft_report
from notifier import alert_finding


def run_pipeline():
    """Execute one full pipeline cycle."""
    config = load_config()
    print(f"\n{'='*60}")
    print(f"[{datetime.now().isoformat()}] PIPELINE START")
    print(f"{'='*60}")

    # Phase 1: Crawl feeds
    print("\n[PHASE 1] Crawling M&A news feeds...")
    total, new = fetch_and_store(config)
    print(f"  Found {total} matches, {new} new acquisitions.")
    log_activity("pipeline", f"Phase 1 complete: {total} matches, {new} new")

    # Phase 2: Check scope for pending targets
    print("\n[PHASE 2] Checking scope for new targets...")
    pending_targets = get_targets(scope_status="pending")
    in_scope_count = 0
    for target in pending_targets:
        is_in = check_target_scope(target["id"], target["domain"])
        if is_in:
            in_scope_count += 1
        time.sleep(1)  # Rate limit scope checks
    print(f"  Checked {len(pending_targets)} targets. {in_scope_count} in-scope.")
    log_activity("pipeline", f"Phase 2 complete: {len(pending_targets)} checked, {in_scope_count} in-scope")

    # Phase 3: Scan in-scope targets
    print("\n[PHASE 3] Scanning in-scope targets for dangling CNAMEs...")
    finding_ids = scan_all_in_scope()
    print(f"  Found {len(finding_ids)} dangling CNAMEs.")
    log_activity("pipeline", f"Phase 3 complete: {len(finding_ids)} findings")

    # Phase 4: Draft reports for new findings
    print("\n[PHASE 4] Drafting reports for new findings...")
    new_findings = get_findings(status="new")
    for f in new_findings:
        draft_report(f["id"])
    print(f"  Drafted {len(new_findings)} reports.")

    # Phase 5: Alert on new findings
    print("\n[PHASE 5] Sending alerts...")
    alertable = get_findings(status="new")  # re-fetch (status unchanged by draft_report)
    for f in alertable:
        finding = get_finding(f["id"])
        if finding:
            alert_finding(dict(finding))
    print(f"  Alerted on {len(alertable)} findings.")

    print(f"\n{'='*60}")
    print(f"[{datetime.now().isoformat()}] PIPELINE COMPLETE")
    print(f"{'='*60}\n")
    log_activity("pipeline", "Full cycle complete")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Hunter-Max Orchestrator")
    parser.add_argument("--loop", action="store_true", help="Run continuously on schedule")
    args = parser.parse_args()

    init_db()

    if args.loop:
        config = load_config()
        interval = config.get("schedule", {}).get("crawl_interval_hours", 12)
        print(f"Running in loop mode. Interval: {interval} hours.")
        while True:
            try:
                run_pipeline()
            except Exception as e:
                print(f"[ERROR] Pipeline failed: {e}")
                log_activity("error", str(e))
            print(f"Sleeping {interval} hours until next cycle...")
            time.sleep(interval * 3600)
    else:
        run_pipeline()


if __name__ == "__main__":
    main()
