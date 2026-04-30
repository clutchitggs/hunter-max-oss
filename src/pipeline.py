"""
Hunter-Max v14 — Async Pipeline Orchestrator.

Parallel, priority-driven target processing with resource-aware semaphores.
Replaces the sequential run_cycle loop with concurrent workers.

Architecture:
  - Dispatcher: dequeues from scan_queue → sets targets to 'recon' phase
  - Target workers: process targets through phases (recon → scan → map → test)
  - Finding worker: processes vulns through AI pipeline (enrichment → T1-T5)
  - Signal tasks: background monitors that inject high-priority targets

Resource caps (2GB VPS safe):
  - Recon:   3 concurrent  (DNS/HTTP — moderate RAM)
  - Scan:    2 concurrent  (Nuclei — heavier CPU)
  - AI:      5 concurrent  (API-bound — low local resources)
  - Mapping: 1 concurrent  (Katana — high RAM, future)
  - ReAct:   3 concurrent  (API-bound, future)

Usage:
    python src/pipeline.py
    python src/pipeline.py --max-targets 10
"""
import asyncio
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import (
    init_db, get_conn,
    dequeue_scan, complete_scan, get_queue_depth, get_queue_stats,
    start_target_pipeline, claim_next_target, advance_target,
    release_target, complete_target, reset_stale_locks,
    get_pipeline_stats, get_unprocessed_vulns,
    log_activity, enqueue_scan,
)
from llm_client import get_budget_status, get_tier_budgets

# --- Logging ---
(ROOT / "logs").mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT / "logs" / "pipeline.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("pipeline")

# --- Config ---
def _load_config():
    try:
        with open(ROOT / "config.json") as f:
            return json.load(f)
    except Exception:
        return {}

# =====================================================================
# SEMAPHORES — Resource caps for 2GB VPS
# =====================================================================

RECON_SEM = asyncio.Semaphore(3)     # 3 concurrent recon jobs
SCAN_SEM = asyncio.Semaphore(2)      # 2 concurrent scan jobs (Nuclei is heavy)
AI_SEM = asyncio.Semaphore(5)        # 5 concurrent AI reasoning tasks
MAPPING_SEM = asyncio.Semaphore(1)   # 1 Katana at a time (Phase 3a)
REACT_SEM = asyncio.Semaphore(3)     # 3 concurrent Scout agents (Phase 3b — fast)
SNIPER_SEM = asyncio.Semaphore(2)    # 2 concurrent Sniper agents (Opus — expensive, slow)

# Max targets being processed simultaneously
MAX_CONCURRENT_TARGETS = 5

# Priority mapping: scan_queue priority (0=highest) → target priority (10=highest)
QUEUE_TO_TARGET_PRIORITY = {0: 10, 1: 8, 2: 6, 3: 3}

# Shutdown flag
_shutdown = False

# Worker health counters (visible in heartbeat)
_stats = {"targets_completed": 0, "targets_failed": 0, "vulns_processed": 0, "vulns_failed": 0}


# =====================================================================
# TARGET PROCESSING — Full pipeline per target with semaphore gating
# =====================================================================

async def process_target(target_id, domain, priority, source):
    """Process one target through the full pipeline.
    Each phase is gated by its semaphore — phases from different targets
    can overlap (Target A in AI while Target B in recon)."""
    from infinite_hunter import (
        phase_recon, phase_scan, phase_mapping, phase_testing, phase_ai_triage,
        _process_findings, SKIP_MEGA_DOMAINS,
    )

    if domain in SKIP_MEGA_DOMAINS:
        log.info(f"  [SKIP] {domain} — mega domain")
        complete_target(target_id)
        return

    priority_label = {10: "P0-NEW", 8: "P1-URGENT", 6: "P2-M&A", 3: "P3-ROTATION"}.get(priority, f"P{priority}")
    log.info(f"  [{priority_label}] Processing {domain} (source: {source})")
    log_activity("pipeline", f"{priority_label}: {domain} entering async pipeline ({source})")

    try:
        # --- Phase 1: RECON (subfinder + DNS + HTTP) ---
        advance_target(target_id, "recon")
        async with RECON_SEM:
            log.info(f"  [RECON] {domain} — starting (sem: {RECON_SEM._value} free)")
            live_hosts, all_findings, vuln_count = await asyncio.to_thread(
                phase_recon, domain, target_id, source
            )
            log.info(f"  [RECON] {domain} — done: {len(live_hosts)} live, {vuln_count} vulns")

        if not live_hosts:
            log.info(f"  [DONE] {domain} — no live hosts, skipping scan phase")
            complete_target(target_id)
            # Still process findings from dangling CNAME checks
            _process_findings(all_findings, domain, source, "")
            return

        # Store live host count in metadata for dashboard
        advance_target(target_id, "scanning", metadata_update={
            "live_hosts": len(live_hosts),
            "recon_vulns": vuln_count,
        })

        # --- Phase 2: SCANNING (Nuclei + JS + Wayback + S3 + AI reasoning) ---
        async with SCAN_SEM:
            log.info(f"  [SCAN] {domain} — starting ({len(live_hosts)} live hosts)")
            vuln_count2, js_count, ai_count = await asyncio.to_thread(
                phase_scan, domain, target_id, live_hosts
            )
            total_vulns = vuln_count + vuln_count2 + js_count + ai_count
            log.info(f"  [SCAN] {domain} — done: {total_vulns} total vulns")

        # --- SCORING GATE (decides whether to deep-scan or skip to done) ---
        # Passive findings from scanning are already being picked up by
        # the finding_worker background task — no delay for urgent vulns.
        from target_scorer import should_deep_scan, MAPPING_THRESHOLD
        try:
            proceed, score, breakdown = await asyncio.to_thread(should_deep_scan, target_id)
        except Exception as e:
            proceed, score, breakdown = True, 50, {"error": str(e)}  # Default to proceed on error

        advance_target(target_id, "scored", metadata_update={
            "scan_vulns": vuln_count2 + js_count + ai_count,
            "score": score,
        })

        if not proceed:
            log.info(f"  [SCORE] {domain}: {score}/100 — below threshold ({MAPPING_THRESHOLD}), skipping deep scan")
            log_activity("pipeline", f"{domain}: score {score} — passive only (static/dead)")
            # AI triage for any passive findings still happens via finding_worker
            complete_target(target_id)
            _process_findings(all_findings, domain, source, "")
            return

        log.info(f"  [SCORE] {domain}: {score}/100 — proceeding to deep scan "
                 f"(surface={breakdown.get('surface_area',0)}, prog={breakdown.get('program_value',0)}, "
                 f"vulns={breakdown.get('vuln_signals',0)})")

        # --- Phase 3: MAPPING (Katana + JS parsing + Swagger + auth flows) ---
        advance_target(target_id, "mapping")
        async with MAPPING_SEM:
            log.info(f"  [MAP] {domain} — starting API discovery")
            mapping_summary = await asyncio.to_thread(
                phase_mapping, domain, target_id, live_hosts
            )
            # total_stored counts ALL inserted api_schemas rows (katana + js + swagger + auth).
            # The katana-discovered "interesting" endpoints would otherwise be invisible to
            # the schema gate, since the prior count summed only js_routes + api_docs.
            endpoints = mapping_summary.get("total_stored", 0)
            log.info(f"  [MAP] {domain} — done: {endpoints} endpoints discovered")

        # --- SCHEMA GATE (v15 Kill List Filter #4) ---
        # If mapping found zero API routes, zero Swagger/GraphQL, AND zero auth flows,
        # the Scout has nothing to test. Skip active testing to save tokens.
        auth_flows = len(mapping_summary.get("auth_flows", []))
        api_docs = len(mapping_summary.get("api_docs", []))
        js_routes = mapping_summary.get("js_routes", 0)
        # endpoints is total_stored — already includes katana/js/swagger/graphql/auth inserts.
        total_schema = endpoints

        if total_schema == 0:
            log.info(f"  [SCHEMA-GATE] {domain}: NO API surface (js={js_routes}, docs={api_docs}, auth={auth_flows}) — skipping Scout")
            log_activity("pipeline", f"{domain}: Schema Gate — no API surface, Scout skipped")
            complete_target(target_id)
            _process_findings(all_findings, domain, source, "")
            _stats["targets_completed"] += 1
            return

        log.info(f"  [SCHEMA-GATE] {domain}: {total_schema} endpoints (js={js_routes}, docs={api_docs}, auth={auth_flows}) — Scout cleared")

        # --- Phase 4: SCOUT TESTING (fast lead identification) ---
        advance_target(target_id, "testing", metadata_update={
            "mapping_endpoints": endpoints,
            "auth_flows": auth_flows,
        })
        async with REACT_SEM:
            log.info(f"  [SCOUT] {domain} — starting active testing")
            react_result = await asyncio.to_thread(
                phase_testing, domain, target_id, live_hosts
            )
            leads_queued = react_result.get("leads_queued", 0)
            total_vulns += react_result.get("findings", 0)
            log.info(f"  [SCOUT] {domain} — done: {react_result.get('tests_run', 0)} tests, {leads_queued} leads queued for Sniper")

        # --- Final AI TRIAGE sweep (catches anything finding_worker hasn't processed yet) ---
        if total_vulns > 0:
            advance_target(target_id, "ai_triage", metadata_update={
                "react_leads": leads_queued,
            })
            async with AI_SEM:
                log.info(f"  [AI] {domain} — final AI triage sweep")
                await asyncio.to_thread(phase_ai_triage, target_id, domain)
                log.info(f"  [AI] {domain} — AI triage complete")

        # --- Done ---
        complete_target(target_id)
        _process_findings(all_findings, domain, source, "")
        _stats["targets_completed"] += 1
        log_activity("pipeline", f"{domain}: pipeline complete — {total_vulns} vulns processed")

    except Exception as e:
        _stats["targets_failed"] += 1
        log.error(f"  [ERROR] {domain} (target_id={target_id}): pipeline failed — {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        release_target(target_id)
        log_activity("error", f"{domain} (id={target_id}): {type(e).__name__}: {e}")


# =====================================================================
# FINDING WORKER — processes orphan vulns through AI pipeline
# =====================================================================

async def finding_worker():
    """Continuously process unprocessed vulns through the AI pipeline.
    Runs as a background task, independent of target processing."""
    from infinite_hunter import _process_single_vuln

    log.info("[FINDING-WORKER] Started — processing orphan vulns")

    while not _shutdown:
        try:
            vulns = get_unprocessed_vulns(limit=10)
            if vulns:
                log.info(f"  [FINDING-WORKER] Processing {len(vulns)} vulns...")
                for vrow in vulns:
                    if _shutdown:
                        break
                    domain = vrow.get("domain", "")
                    if not domain and "." in vrow["subdomain"]:
                        domain = vrow["subdomain"].split(".", 1)[-1]
                    async with AI_SEM:
                        try:
                            await asyncio.to_thread(_process_single_vuln, vrow, domain)
                            _stats["vulns_processed"] += 1
                        except Exception as e:
                            _stats["vulns_failed"] += 1
                            log.warning(f"  [FINDING-WORKER] Vuln {vrow['id']} ({vrow['vuln_type']} on {vrow['subdomain']}): {type(e).__name__}: {e}")
            else:
                await asyncio.sleep(30)  # No vulns to process, check again in 30s
        except Exception as e:
            log.warning(f"  [FINDING-WORKER] Error: {e}")
            await asyncio.sleep(10)

        await asyncio.sleep(2)  # Small delay between batches


# =====================================================================
# SNIPER WORKER — processes Scout leads through Opus verification
# Fully decoupled from per-target pipeline. Never blocks the Scout.
# =====================================================================

async def sniper_worker():
    """Continuously process Scout leads through Sniper agents.
    Runs as a background task, independent of target processing.

    Pattern: identical to finding_worker but for react_leads table.
    Rule: Never let a fast task (Scout) wait for a slow task (Sniper).
    """
    from react_agent import process_sniper_lead
    from db import get_pending_leads

    log.info("[SNIPER-WORKER] Started — processing Scout leads")

    while not _shutdown:
        try:
            leads = get_pending_leads(limit=5)
            if leads:
                log.info(f"  [SNIPER-WORKER] Processing {len(leads)} leads...")
                for lead in leads:
                    if _shutdown:
                        break
                    async with SNIPER_SEM:
                        try:
                            result = await asyncio.to_thread(process_sniper_lead, lead)
                            if result and result.get("verdict") == "confirmed":
                                _stats["vulns_processed"] += 1
                                log.info(f"  [SNIPER-WORKER] Lead #{lead['id']} CONFIRMED!")
                        except Exception as e:
                            _stats["vulns_failed"] += 1
                            log.warning(f"  [SNIPER-WORKER] Lead #{lead['id']} "
                                        f"({lead['vuln_class']} on {lead['subdomain']}): "
                                        f"{type(e).__name__}: {e}")
            else:
                await asyncio.sleep(30)  # No leads, check again in 30s
        except Exception as e:
            log.warning(f"  [SNIPER-WORKER] Error: {e}")
            await asyncio.sleep(10)

        await asyncio.sleep(2)


# =====================================================================
# DISPATCHER — dequeues from scan_queue, launches target workers
# =====================================================================

async def dispatcher(active_tasks):
    """Pull from scan_queue and launch target processing tasks."""
    log.info("[DISPATCHER] Started — pulling from scan queue")

    while not _shutdown:
        # Only dispatch if we have capacity
        if len(active_tasks) < MAX_CONCURRENT_TARGETS:
            item = await asyncio.to_thread(dequeue_scan)
            if item:
                target_id = item["target_id"]
                domain = item["domain"]
                queue_priority = item["priority"]
                source = item["source"]
                queue_id = item["id"]

                # Map queue priority (0=highest) to target priority (10=highest)
                target_priority = QUEUE_TO_TARGET_PRIORITY.get(queue_priority, 5)

                # Set target into pipeline
                await asyncio.to_thread(
                    start_target_pipeline, target_id, target_priority, source
                )

                # Launch processing task
                task = asyncio.create_task(
                    process_target(target_id, domain, target_priority, source),
                    name=f"target:{domain}",
                )
                active_tasks.add(task)
                task.add_done_callback(lambda t: active_tasks.discard(t))

                # Mark queue item as completed (target pipeline tracks progress now)
                await asyncio.to_thread(complete_scan, queue_id)

                log.info(f"  [DISPATCH] {domain} → priority {target_priority} ({source})")
            else:
                await asyncio.sleep(5)  # Empty queue, check again in 5s
        else:
            await asyncio.sleep(3)  # At capacity, wait for slot

        await asyncio.sleep(1)  # Prevent tight loop


# =====================================================================
# SIGNAL SOURCES — background tasks that feed the priority queue
# =====================================================================

async def signal_runner():
    """Run all signal sources on their configured intervals."""
    config = _load_config()
    sig_conf = config.get("signals", {})

    intervals = {
        "new_programs": sig_conf.get("new_program_interval_min", 15) * 60,
        "scope_changes": sig_conf.get("scope_change_interval_hours", 6) * 3600,
        "cves": sig_conf.get("cve_check_interval_hours", 6) * 3600,
        "m_and_a": sig_conf.get("m_and_a_interval_hours", 6) * 3600,
        "program_sync": 604800,  # 7 days
    }

    last_check = {}

    log.info("[SIGNALS] Started — monitoring all signal sources")

    while not _shutdown:
        now = time.time()

        # Signal 1: New programs (highest ROI — priority 10)
        if now - last_check.get("new_programs", 0) > intervals["new_programs"]:
            try:
                from program_scanner import check_new_programs
                new = await asyncio.to_thread(check_new_programs)
                if new:
                    log.info(f"  [SIGNAL] NEW PROGRAMS: {len(new)} detected!")
                    for p in new:
                        log.info(f"    -> {p['company']} ({p['handle']}) — {len(p['domains'])} domains")
            except Exception as e:
                log.warning(f"  [SIGNAL] New program check failed: {e}")
            last_check["new_programs"] = now

        # Signal 2: Scope changes
        if now - last_check.get("scope_changes", 0) > intervals["scope_changes"]:
            try:
                from program_scanner import detect_scope_changes
                changes = await asyncio.to_thread(detect_scope_changes)
                if changes:
                    total_new = sum(len(c["new_domains"]) for c in changes)
                    log.info(f"  [SIGNAL] SCOPE CHANGES: {len(changes)} programs, {total_new} new domains")
            except Exception as e:
                log.warning(f"  [SIGNAL] Scope change check failed: {e}")
            last_check["scope_changes"] = now

        # Signal 3: CVE racing
        if now - last_check.get("cves", 0) > intervals["cves"]:
            try:
                from cve_monitor import fetch_recent_cves, match_cves_to_targets
                cves = await asyncio.to_thread(fetch_recent_cves, hours=24)
                if cves:
                    matches = await asyncio.to_thread(match_cves_to_targets, cves)
                    log.info(f"  [SIGNAL] CVE: {len(cves)} new CVEs, {len(matches)} target matches")
            except Exception as e:
                log.warning(f"  [SIGNAL] CVE check failed: {e}")
            last_check["cves"] = now

        # Signal 4: M&A feed
        if now - last_check.get("m_and_a", 0) > intervals["m_and_a"]:
            try:
                from ma_recon import load_config as ma_load, fetch_and_store
                from infinite_hunter import _enqueue_m_and_a_targets
                ma_config = ma_load()
                total, new = await asyncio.to_thread(
                    fetch_and_store, ma_config, None, lambda: _shutdown
                )
                log.info(f"  [SIGNAL] M&A: {total} matches, {new} new")
                if not _shutdown:
                    await asyncio.to_thread(_enqueue_m_and_a_targets)
            except Exception as e:
                log.warning(f"  [SIGNAL] M&A crawl failed: {e}")
            last_check["m_and_a"] = now

        # Signal 5: Full directory sync (weekly)
        if now - last_check.get("program_sync", 0) > intervals["program_sync"]:
            try:
                from program_scanner import sync_programs_to_db
                new_progs, new_tgts = await asyncio.to_thread(sync_programs_to_db)
                log.info(f"  [SIGNAL] Program sync: {new_progs} new programs, {new_tgts} new targets")
            except Exception as e:
                log.warning(f"  [SIGNAL] Program sync failed: {e}")
            last_check["program_sync"] = now

        # Bulk rescore targets (every 12 hours)
        if now - last_check.get("scoring", 0) > 43200:
            try:
                from target_scorer import score_all_targets
                count, top = await asyncio.to_thread(score_all_targets)
                log.info(f"  [SIGNAL] Scoring: {count} targets rescored")
            except Exception as e:
                log.warning(f"  [SIGNAL] Scoring failed: {e}")
            last_check["scoring"] = now

        # Rotation: fill queue if empty
        queue_depth = await asyncio.to_thread(get_queue_depth)
        if queue_depth == 0:
            try:
                from infinite_hunter import _enqueue_rotation_targets
                await asyncio.to_thread(_enqueue_rotation_targets)
            except Exception as e:
                log.warning(f"  [SIGNAL] Rotation enqueue failed: {e}")

        await asyncio.sleep(30)  # Check signals every 30s


# =====================================================================
# HEARTBEAT — periodic status logging
# =====================================================================

async def heartbeat_task(active_tasks):
    """Log pipeline health every 60 seconds."""
    cycle = 0
    while not _shutdown:
        cycle += 1
        now = datetime.now().strftime("%I:%M %p")
        budget = get_budget_status()
        queue = get_queue_stats()
        pipeline = get_pipeline_stats()

        active_domains = [t.get_name().replace("target:", "") for t in active_tasks if not t.done()]

        phase_summary = " | ".join(f"{p}:{s['total']}({s['active']})" for p, s in pipeline.items() if s["total"] > 0)

        fail_rate = ""
        if _stats["targets_completed"] + _stats["targets_failed"] > 0:
            total = _stats["targets_completed"] + _stats["targets_failed"]
            fail_pct = (_stats["targets_failed"] / total) * 100
            fail_rate = f" | Health: {_stats['targets_completed']}/{total} ok ({fail_pct:.0f}% fail)"

        log.info(
            f"[HEARTBEAT] {now} | Cycle: {cycle} | "
            f"Active: {len(active_tasks)} [{', '.join(active_domains[:3])}] | "
            f"Queue: {queue.get('total_pending', 0)} | "
            f"Pipeline: {phase_summary} | "
            f"Budget: ${budget.get('spent', 0):.3f}/${budget.get('limit', 0)}"
            f"{fail_rate}"
        )

        await asyncio.sleep(60)


# =====================================================================
# MAIN — starts all workers and runs forever
# =====================================================================

async def main(max_targets=None):
    global _shutdown, MAX_CONCURRENT_TARGETS

    if max_targets:
        MAX_CONCURRENT_TARGETS = max_targets

    init_db()

    # Crash recovery: release any targets stuck in_progress
    stale = reset_stale_locks(timeout_minutes=30)
    if stale:
        log.info(f"  [STARTUP] Released {stale} stale target locks (crash recovery)")

    tier_budgets = get_tier_budgets()
    queue_depth = get_queue_depth()

    log.info("=" * 70)
    log.info("HUNTER-MAX v14 — ASYNC PIPELINE ORCHESTRATOR")
    log.info(f"Max concurrent targets: {MAX_CONCURRENT_TARGETS}")
    log.info(f"Semaphores: recon={RECON_SEM._value} scan={SCAN_SEM._value} ai={AI_SEM._value}")
    log.info(f"Queue depth: {queue_depth}")
    for t, info in tier_budgets.items():
        log.info(f"  {t}: {info['model']} — ${info['daily_limit']}/day (enabled: {info['enabled']})")
    log.info("=" * 70)

    active_tasks = set()

    # Start all background workers
    signal_task = asyncio.create_task(signal_runner(), name="signals")
    dispatch_task = asyncio.create_task(dispatcher(active_tasks), name="dispatcher")
    finding_task = asyncio.create_task(finding_worker(), name="finding-worker")
    sniper_task = asyncio.create_task(sniper_worker(), name="sniper-worker")
    heartbeat = asyncio.create_task(heartbeat_task(active_tasks), name="heartbeat")

    log.info("[PIPELINE] All workers started (v15: Scout-Sniper). Entering main loop...")
    log_activity("pipeline", "Async pipeline v15 started (Scout-Sniper architecture)")

    # Wait for shutdown signal
    try:
        await asyncio.gather(signal_task, dispatch_task, finding_task, heartbeat)
    except asyncio.CancelledError:
        log.info("[PIPELINE] Shutting down...")
    finally:
        _shutdown = True
        # Wait for active target tasks to finish (with timeout)
        if active_tasks:
            log.info(f"[PIPELINE] Waiting for {len(active_tasks)} active targets to finish...")
            done, pending = await asyncio.wait(active_tasks, timeout=60)
            if pending:
                log.warning(f"[PIPELINE] {len(pending)} targets didn't finish in time, releasing locks")
                for task in pending:
                    task.cancel()
        log_activity("pipeline", "Async pipeline v14 stopped")


def run():
    import argparse
    parser = argparse.ArgumentParser(description="Hunter-Max v14 — Async Pipeline")
    parser.add_argument("--max-targets", type=int, default=5, help="Max concurrent targets (default: 5)")
    parser.add_argument("--import-scope", action="store_true", help="Import programs from GitHub lists, then exit")
    args = parser.parse_args()

    if args.import_scope:
        init_db()
        from scope_importer import import_all
        progs, targets = import_all()
        log.info(f"Import complete: {progs} programs, {targets} targets")
        return

    # Handle SIGTERM/SIGINT gracefully
    loop = asyncio.new_event_loop()

    def shutdown_handler():
        global _shutdown
        _shutdown = True
        log.info("[PIPELINE] Shutdown signal received")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        loop.run_until_complete(main(max_targets=args.max_targets))
    except KeyboardInterrupt:
        log.info("[PIPELINE] Interrupted by user")
    finally:
        loop.close()


if __name__ == "__main__":
    run()
