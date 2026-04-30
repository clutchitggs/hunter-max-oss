"""
Infinite Hunter v14 — Async Pipeline Architecture.

Async, priority-driven pipeline with phase-based target processing.

Pipeline Phases (per target):
  1. RECON:    Subfinder + wordlist + DNS/HTTP checks → live_hosts + basic vulns
  2. SCANNING: Nuclei + JS secrets + Wayback + S3 → vuln findings
  3. MAPPING:  (Phase 3a) Katana + API schema discovery → api_schemas
  4. TESTING:  (Phase 3b) ReAct agent → logic bug testing
  AI TRIAGE:  Enrichment → T1 → T2 → T3 → T4 → T5 (runs on findings, parallel)

Signal Sources (feed targets with priority):
  - New Program Monitor   (15 min)  → priority 10
  - Scope Change Detector (6 hours) → priority 8
  - CVE Racing Monitor    (6 hours) → priority 8
  - M&A Feed Crawl        (12 hrs)  → priority 6
  - Continuous Rotation    (idle)    → priority 3

Entry points:
  - pipeline.py (PREFERRED) — async orchestrator, parallel processing
  - infinite_hunter.py --loop — legacy sequential mode (backward compat)
"""
import json
import subprocess
import sys
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dns.resolver
import requests

from db import (
    init_db, get_conn, get_acquisitions, get_targets,
    insert_target, update_target_scope, insert_scan, insert_finding,
    update_finding_report, count_acquisitions, count_targets, count_findings,
    log_activity, get_finding,
    enqueue_scan, dequeue_scan, complete_scan, get_queue_depth, get_queue_stats,
)
from ma_recon import load_config, fetch_and_store
from scope_checker import check_security_txt
from report_drafter import draft_report
from llm_client import extract_companies as llm_extract, get_budget_status, call_tier

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT / "logs" / "hunter.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("hunter")

# --- Config loading ---

def _load_scanner_config():
    try:
        with open(ROOT / "config.json") as f:
            return json.load(f)
    except Exception:
        return {}

# --- Wordlist ---
_BUILTIN_PREFIXES = [
    "dev", "staging", "stage", "stg", "test", "testing", "qa",
    "api", "api2", "api-v1", "api-v2", "app", "app2", "www",
    "mail", "email", "smtp", "pop", "imap",
    "blog", "docs", "doc", "documentation", "wiki",
    "status", "cdn", "assets", "static", "media", "images", "img",
    "beta", "alpha", "demo", "preview", "sandbox",
    "old", "legacy", "v1", "v2", "v3", "archive",
    "admin", "panel", "dashboard", "console",
    "portal", "gateway", "proxy",
    "support", "help", "helpdesk", "kb",
    "internal", "intranet", "corp", "office",
    "jenkins", "ci", "cd", "build", "deploy",
    "git", "gitlab", "github", "bitbucket", "repo",
    "jira", "confluence", "slack", "teams",
    "grafana", "prometheus", "kibana", "elastic", "monitor",
    "auth", "login", "sso", "id", "identity", "accounts", "oauth",
    "signup", "register", "onboarding",
    "shop", "store", "ecommerce", "pay", "payment", "billing", "checkout",
    "upload", "files", "download", "share",
    "vpn", "remote", "rdp", "ssh",
    "ns1", "ns2", "dns", "mx", "ftp", "sftp",
    "staging-api", "dev-api", "test-api", "beta-api",
    "dev-app", "staging-app", "test-app",
    "m", "mobile", "wap",
    "cms", "wp", "wordpress", "drupal",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "s3", "bucket", "storage", "backup",
]


def _load_wordlist():
    wordlist_path = ROOT / "data" / "wordlist.txt"
    if wordlist_path.exists():
        with open(wordlist_path) as f:
            prefixes = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if len(prefixes) > 100:
            return prefixes
    return _BUILTIN_PREFIXES


SUBDOMAIN_PREFIXES = _load_wordlist()

DANGLING_FINGERPRINTS = {
    "aws_s3": {
        "cname_patterns": [".s3.amazonaws.com", ".s3-website", ".s3."],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    "github_pages": {
        "cname_patterns": [".github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here"],
    },
    "heroku": {
        "cname_patterns": [".herokuapp.com", ".herokussl.com"],
        "fingerprints": ["no-such-app", "There is no app configured at that hostname"],
    },
    "azure": {
        "cname_patterns": [".azurewebsites.net", ".azureedge.net", ".azurefd.net",
                           ".cloudapp.azure.com", ".trafficmanager.net"],
        "fingerprints": ["404 Web Site not found", "This web app is stopped"],
    },
    "vercel": {
        "cname_patterns": [".vercel.app", ".now.sh", "vercel-dns.com"],
        "fingerprints": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
    },
    "shopify": {
        "cname_patterns": [".myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
    },
    "cloudfront": {
        "cname_patterns": [".cloudfront.net"],
        "fingerprints": ["The request could not be satisfied", "Bad Request"],
    },
}

KNOWN_BOUNTY_PROGRAMS = {
    "google": "https://bughunters.google.com",
    "microsoft": "https://msrc.microsoft.com/",
    "at&t": "https://hackerone.com/att",
    "qualcomm": "https://hackerone.com/qualcomm",
    "uber": "https://hackerone.com/uber",
    "airbnb": "https://hackerone.com/airbnb",
    "github": "https://bounty.github.com/",
    "gitlab": "https://hackerone.com/gitlab",
    "shopify": "https://hackerone.com/shopify",
    "paypal": "https://hackerone.com/paypal",
    "twitter": "https://hackerone.com/x",
    "salesforce": "https://bugcrowd.com/salesforce",
    "oracle": "https://hackerone.com/oracle",
    "cisco": "https://hackerone.com/cisco",
    "adobe": "https://hackerone.com/adobe",
    "ibm": "https://hackerone.com/ibm",
    "intel": "https://hackerone.com/intel",
    "vmware": "https://hackerone.com/vmware",
    "dell": "https://hackerone.com/dell",
    "hp": "https://hackerone.com/hp",
    "sony": "https://hackerone.com/sony",
    "samsung": "https://security.samsungmobile.com/",
    "snap": "https://hackerone.com/snapchat",
    "tiktok": "https://hackerone.com/tiktok",
    "dropbox": "https://hackerone.com/dropbox",
    "slack": "https://hackerone.com/slack",
    "zoom": "https://hackerone.com/zoom",
    "cloudflare": "https://hackerone.com/cloudflare",
    "stripe": "https://hackerone.com/stripe",
    "square": "https://hackerone.com/square",
    "robinhood": "https://hackerone.com/robinhood",
    "coinbase": "https://hackerone.com/coinbase",
    "meta": "https://www.facebook.com/whitehat",
    "facebook": "https://www.facebook.com/whitehat",
    "apple": "https://security.apple.com/bounty/",
    "yahoo": "https://hackerone.com/yahoo",
    "verizon": "https://hackerone.com/verizon",
    "t-mobile": "https://hackerone.com/t-mobile",
    "grammarly": "https://hackerone.com/grammarly",
    "indeed": "https://hackerone.com/indeed",
    "automattic": "https://hackerone.com/automattic",
    "brave": "https://hackerone.com/brave",
    "nextcloud": "https://hackerone.com/nextcloud",
}

SKIP_MEGA_DOMAINS = {
    "google.com", "youtube.com", "microsoft.com", "azure.com",
    "office.com", "apple.com", "icloud.com", "linkedin.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
}


# =====================================================================
# DNS + HTTP helpers (unchanged)
# =====================================================================

def resolve_cname(fqdn):
    try:
        answers = dns.resolver.resolve(fqdn, "CNAME")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


def resolve_exists(fqdn):
    for rtype in ["CNAME", "A"]:
        try:
            dns.resolver.resolve(fqdn, rtype)
            return True
        except Exception:
            continue
    return False


def check_http_dangling(subdomain, cname):
    for provider, info in DANGLING_FINGERPRINTS.items():
        if any(p in cname.lower() for p in info["cname_patterns"]):
            for scheme in ["https", "http"]:
                try:
                    resp = requests.get(
                        f"{scheme}://{subdomain}", timeout=10,
                        allow_redirects=True, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    body = resp.text[:3000]
                    for fp in info["fingerprints"]:
                        if fp.lower() in body.lower():
                            return provider, fp, resp.status_code
                except Exception:
                    continue
    return None, None, None


def get_acquirer_bounty(acquirer):
    if not acquirer:
        return None
    acq_lower = acquirer.lower()
    for company, url in KNOWN_BOUNTY_PROGRAMS.items():
        if company in acq_lower:
            return url
    return None


def _run_subfinder(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "20"],
            capture_output=True, text=True, timeout=40,
        )
        if result.returncode == 0:
            subs = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
            return subs
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


# =====================================================================
# Live Status Ticker (for dashboard)
# =====================================================================

_live_status = {
    "domain": "", "checked": 0, "total": 0, "live_count": 0,
    "phase": "idle", "cnames": 0, "vulns": 0, "dangling": 0,
    "recent": [],
    "source": "",       # v13: what signal triggered this scan
    "queue_depth": 0,   # v13: how many items in queue
}
_STATUS_FILE = ROOT / "data" / "live_status.json"


def _flush_status():
    try:
        import time as _t
        _live_status["ts"] = _t.time()
        with open(_STATUS_FILE, "w") as f:
            json.dump(_live_status, f)
    except Exception:
        pass


def _set_status(phase, domain="", detail="", source=""):
    _live_status.update({
        "phase": phase, "domain": domain, "checked": 0, "total": 0,
        "live_count": 0, "cnames": 0, "vulns": 0, "dangling": 0, "recent": [],
        "source": source, "queue_depth": get_queue_depth(),
    })
    _flush_status()


# =====================================================================
# Subdomain Scanner Worker (runs Tier 0 + Tier 1 inline)
# =====================================================================

def _check_single_sub(args):
    """Worker: checks one subdomain for CNAME + vulns + Tier 0/1 triage."""
    fqdn, target_id = args
    results = {"cnames": [], "dangling": [], "vulns": [], "fqdn": fqdn, "live": False, "ai_flagged": False}

    # CNAME check
    cnames = resolve_cname(fqdn)
    if cnames:
        for cname in cnames:
            if "hugedomains" in cname.lower() or "sedoparking" in cname.lower():
                continue
            results["cnames"].append((fqdn, cname))
            provider, fingerprint, status_code = check_http_dangling(fqdn, cname)
            if provider:
                results["dangling"].append({
                    "subdomain": fqdn, "cname_target": cname,
                    "provider": provider, "fingerprint": fingerprint,
                    "http_status": status_code,
                })

    # Check if alive
    is_alive = bool(cnames) or resolve_exists(fqdn)
    if is_alive:
        results["live"] = True

    # Update live ticker
    status = "live" if is_alive else "nxdomain"
    if cnames:
        status = f"cname:{cnames[0][:30]}"
    _live_status["recent"].append({"s": fqdn, "r": status})
    if len(_live_status["recent"]) > 15:
        _live_status["recent"] = _live_status["recent"][-15:]

    # Vuln checks on live hosts
    if is_alive:
        try:
            from vuln_scanner import scan_subdomain_vulns
            vulns = scan_subdomain_vulns(fqdn, target_id=target_id)
            results["vulns"] = vulns
        except Exception:
            pass

    return results


# =====================================================================
# PIPELINE PHASE FUNCTIONS — callable independently by async orchestrator
# =====================================================================

def phase_recon(domain, target_id=None, source=""):
    """Phase 1: Subdomain enumeration + DNS/HTTP checks.
    Returns (live_hosts, all_findings, vuln_count)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    config = _load_scanner_config()
    http_workers = config.get("scanner", {}).get("http_workers", 30)

    # Phase A: Subfinder + Wordlist
    subs_found = _run_subfinder(domain)
    dict_subs = [f"{p}.{domain}" for p in SUBDOMAIN_PREFIXES]
    all_subs = list(set(subs_found + dict_subs))

    log_activity("scan", f"{domain}: scanning {len(all_subs)} subdomains ({len(subs_found)} real + {len(SUBDOMAIN_PREFIXES)} dict)")

    _live_status.update({
        "domain": domain, "checked": 0, "total": len(all_subs),
        "live_count": 0, "phase": "recon", "cnames": 0,
        "vulns": 0, "dangling": 0, "recent": [], "source": source,
    })
    _flush_status()

    all_findings = []
    live_hosts = []
    cname_count = 0
    vuln_count = 0
    checked = 0
    total = len(all_subs)

    # Phase B: Parallel DNS + HTTP checks
    work = [(fqdn, target_id) for fqdn in all_subs]
    with ThreadPoolExecutor(max_workers=http_workers) as pool:
        futures = {pool.submit(_check_single_sub, w): w for w in work}
        for future in as_completed(futures):
            try:
                res = future.result()
            except Exception:
                checked += 1
                continue

            checked += 1

            if res.get("live"):
                live_hosts.append(res["fqdn"])

            if checked % 5 == 0 or checked == total:
                _live_status["checked"] = checked
                _live_status["live_count"] = len(live_hosts)
                _live_status["cnames"] = cname_count
                _live_status["dangling"] = len(all_findings)
                _live_status["vulns"] = vuln_count
                _flush_status()

            if checked % 500 == 0:
                log_activity("scan", f"{domain}: {checked}/{total} | {cname_count} CNAMEs | {len(all_findings)} dangling | {vuln_count} vulns")

            for fqdn, cname in res["cnames"]:
                cname_count += 1
                if target_id:
                    insert_scan(target_id, fqdn, cname, "unknown", False)

            for f in res["dangling"]:
                log.info(f"  *** DANGLING: {f['subdomain']} -> {f['cname_target']} ({f['provider']})")
                log_activity("finding", f"DANGLING: {f['subdomain']} -> {f['cname_target']} ({f['provider']})")
                all_findings.append(f)
                if target_id:
                    scan_id = insert_scan(target_id, f["subdomain"], f["cname_target"], f["provider"], True)
                    insert_finding(scan_id, target_id, f["subdomain"], f["cname_target"], f["provider"], f["fingerprint"])

            for v in res["vulns"]:
                vuln_count += 1
                log.info(f"  *** VULN: {v['vuln_type']} on {v['subdomain']}")

    log_activity("scan", f"{domain}: Recon done — {total} subs, {cname_count} CNAMEs, {len(all_findings)} dangling, {vuln_count} vulns, {len(live_hosts)} live")
    return live_hosts, all_findings, vuln_count


def phase_scan(domain, target_id, live_hosts):
    """Phase 2: Nuclei + JS secrets + Wayback + S3 + AI reasoning.
    Returns (vuln_count, js_count, ai_count)."""
    from concurrent.futures import ThreadPoolExecutor

    config = _load_scanner_config()
    sc = config.get("scanner", {})
    js_workers = sc.get("js_workers", 10)
    ai_max_hosts = sc.get("ai_max_hosts", 10)
    vuln_count = 0
    js_count = 0
    ai_count = 0

    # Phase C: Nuclei
    _live_status["phase"] = "nuclei"
    _flush_status()
    if live_hosts:
        try:
            from nuclei_runner import run_nuclei_batch
            nuclei_count = run_nuclei_batch(live_hosts, target_id)
            vuln_count += nuclei_count
            if nuclei_count:
                log_activity("scan", f"{domain}: Nuclei found {nuclei_count} vulns on {len(live_hosts)} live hosts")
        except Exception as e:
            log.warning(f"  [NUCLEI] Failed: {e}")

    # Phase D: JS secrets
    _live_status["phase"] = "js_scan"
    _flush_status()
    if live_hosts:
        try:
            from js_analyzer import scan_js_secrets
            def _js_scan(host):
                try:
                    return len(scan_js_secrets(host, target_id))
                except Exception:
                    return 0
            with ThreadPoolExecutor(max_workers=js_workers) as js_pool:
                js_count = sum(js_pool.map(_js_scan, live_hosts[:30]))
            if js_count:
                log_activity("scan", f"{domain}: JS scanning found {js_count} secrets")
        except Exception:
            pass

    # Phase E: Wayback
    _live_status["phase"] = "wayback"
    _flush_status()
    try:
        from wayback import check_wayback_urls
        wb_count = check_wayback_urls(domain, target_id)
        vuln_count += wb_count
        if wb_count:
            log_activity("scan", f"{domain}: Wayback found {wb_count} accessible historical URLs")
    except Exception as e:
        log.warning(f"  [WAYBACK] Failed: {e}")

    # Phase F: S3 buckets
    _live_status["phase"] = "s3"
    _flush_status()
    try:
        from s3_enum import check_s3_buckets
        s3_count = check_s3_buckets(domain, target_id=target_id)
        vuln_count += s3_count
        if s3_count:
            log_activity("scan", f"{domain}: S3 found {s3_count} public buckets!")
    except Exception as e:
        log.warning(f"  [S3] Failed: {e}")

    # Phase G: Proactive AI reasoning on live hosts
    _live_status["phase"] = "ai_reasoning"
    _flush_status()
    if live_hosts:
        try:
            from ai_analyzer import analyze_target
            for host in live_hosts[:ai_max_hosts]:
                ai_findings = analyze_target(host, target_id)
                ai_count += len(ai_findings)
            if ai_count:
                log_activity("scan", f"{domain}: AI reasoning found {ai_count} vulns on {len(live_hosts[:ai_max_hosts])} hosts")
        except Exception as e:
            log.warning(f"  [AI] Reasoning failed: {e}")

    log_activity("scan", f"{domain}: Scanning done — {vuln_count} vulns, {js_count} JS secrets, {ai_count} AI findings")
    return vuln_count, js_count, ai_count


def phase_testing(domain, target_id, live_hosts):
    """Phase 4: Scout agent — fast lead identification for logic bugs.
    v15: Runs Scout only (fast Sonnet). Leads are stored in react_leads table
    and processed by sniper_worker asynchronously. Never blocks the pipeline."""
    try:
        from react_agent import run_react_testing_v15
        result = run_react_testing_v15(domain, target_id, live_hosts)
        return result
    except Exception as e:
        log.warning(f"  [SCOUT] Failed for {domain}: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e), "tests_run": 0, "findings": 0}


def phase_mapping(domain, target_id, live_hosts):
    """Phase 3: API schema discovery — Katana + JS parsing + Swagger + auth flows.
    Produces the attack surface map for the ReAct agent (Phase 4)."""
    try:
        from api_mapper import run_api_mapping
        summary = run_api_mapping(domain, target_id, live_hosts)
        return summary
    except Exception as e:
        log.warning(f"  [MAPPING] Failed for {domain}: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


def phase_ai_triage(target_id, domain):
    """Phase 4: Run enrichment + T1→T2→T3→T4→T5 on all new vulns for a target.
    This is the AI production line — each tier sees all previous tiers' work."""
    try:
        from ai_analyzer import tier1_triage, tier2_investigate, tier3_sonnet_challenge, tier4_senior_review, tier5_devils_advocate
        from db import get_conn as _gc

        with _gc() as _c:
            new_vulns = [dict(r) for r in _c.execute(
                "SELECT id, subdomain, vuln_type, evidence, severity, url FROM vulns "
                "WHERE target_id = ? AND status = 'new'", (target_id,)
            ).fetchall()]

        if not new_vulns:
            return

        log.info(f"  [PIPELINE] {len(new_vulns)} findings entering AI production line...")
        log_activity("scan", f"{domain}: {len(new_vulns)} findings entering T1→T2→T3→T4→T5 pipeline")

        all_finding_dicts = [{"vuln_type": v["vuln_type"], "evidence": (v["evidence"] or "")[:150], "severity": v["severity"]} for v in new_vulns]

        for vrow in new_vulns[:20]:
            _process_single_vuln(vrow, domain, all_finding_dicts)

    except Exception as e:
        log.warning(f"  [PIPELINE] AI production line failed: {e}")
        import traceback
        traceback.print_exc()


def _process_single_vuln(vrow, domain, all_finding_dicts=None):
    """Process one vuln through the full enrichment + T1→T5 pipeline.
    Callable standalone by the async finding worker."""
    from ai_analyzer import tier1_triage, tier2_investigate, tier3_sonnet_challenge, tier4_senior_review, tier5_devils_advocate
    from db import get_conn as _gc

    vid = vrow["id"]
    vtype = vrow["vuln_type"]
    vsub = vrow["subdomain"]
    vevidence = vrow["evidence"] or ""
    vurl = vrow["url"] or f"https://{vsub}/"

    # Dedup
    with _gc() as _c2:
        dup = _c2.execute(
            "SELECT status, t1_result, t2_result, t3_result, t3_challenge, t5_challenge, report_md "
            "FROM vulns WHERE vuln_type = ? AND evidence = ? AND id != ? AND status NOT IN ('new','t1_pass') LIMIT 1",
            (vtype, vevidence, vid)
        ).fetchone()
    if dup:
        log.info(f"  [DEDUP] {vtype} on {vsub} — copying from already-processed duplicate")
        with _gc() as _c2:
            _c2.execute(
                "UPDATE vulns SET status=?, t1_result=?, t2_result=?, t3_result=?, t3_challenge=?, t5_challenge=?, report_md=? WHERE id=?",
                (dup[0], dup[1], dup[2], dup[3], dup[4], dup[5], dup[6], vid)
            )
        return

    # === ENRICHMENT ===
    try:
        from evidence_enricher import enrich_finding as _enrich
        _live_status["phase"] = "enriching"
        _flush_status()
        enrichment = _enrich(vtype, vevidence, vsub, vurl)
        enriched_ev = enrichment.get("enriched_evidence", vevidence)
        with _gc() as _c2:
            _c2.execute("UPDATE vulns SET enriched_evidence=?, enrichment_data=?, enrichment_status='enriched' WHERE id=?",
                       (enriched_ev, json.dumps(enrichment.get("verification_data", {})), vid))
        if enrichment.get("auto_verdict") == "false_positive":
            log.info(f"  [ENRICH] AUTO-KILLED: {vtype} on {vsub}")
            log_activity("triage", f"Enrichment auto-filtered: {vtype} on {vsub}")
            with _gc() as _c2:
                _c2.execute("UPDATE vulns SET status='filtered', t1_result=? WHERE id=?",
                           (f"FAIL: Auto-filtered by enrichment", vid))
            return
        elif enrichment.get("auto_verdict") == "confirmed":
            log.info(f"  [ENRICH] CONFIRMED: {vtype} on {vsub}")
            log_activity("scan", f"Enrichment confirmed: {vtype} on {vsub}")
            # Discord notification for High/Critical enricher-confirmed findings
            if vrow.get("severity", "").lower() in ("high", "critical"):
                try:
                    from notifier_discord import notify_enricher_confirmed
                    notify_enricher_confirmed({
                        "subdomain": vsub, "vuln_type": vtype,
                        "severity": vrow.get("severity", "High"),
                        "url": vurl, "target_domain": domain,
                        "enriched_evidence": enriched_ev,
                    })
                except Exception:
                    pass
        vevidence = enriched_ev
    except Exception as e:
        log.warning(f"  [ENRICH] Failed: {e}")

    # === T1: TRIAGE ===
    _live_status["phase"] = "t1_triage"
    _flush_status()
    t1_pass, t1_reason = tier1_triage(vtype, vevidence, vsub, vurl)
    t1_text = f"{'PASS' if t1_pass else 'FAIL'}: {t1_reason}"

    with _gc() as _c2:
        _c2.execute("UPDATE vulns SET t1_result = ? WHERE id = ?", (t1_text, vid))

    if not t1_pass:
        log.info(f"  [T1] FILTERED: {vtype} on {vsub} — {t1_reason}")
        log_activity("triage", f"T1 filtered: {vtype} on {vsub} ({t1_reason})")
        with _gc() as _c2:
            _c2.execute("UPDATE vulns SET status = 'filtered' WHERE id = ?", (vid,))
        return

    log.info(f"  [T1] PASS: {vtype} on {vsub} — {t1_reason}")
    log_activity("scan", f"T1 passed: {vtype} on {vsub}")
    with _gc() as _c2:
        _c2.execute("UPDATE vulns SET status = 't1_pass' WHERE id = ?", (vid,))

    # === T2: INVESTIGATE ===
    _live_status["phase"] = "t2_investigate"
    _flush_status()
    t2_data = tier2_investigate(vtype, vevidence, vsub, vurl, t1_text)
    t2_text = json.dumps(t2_data) if t2_data else "T2 unavailable"

    with _gc() as _c2:
        _c2.execute("UPDATE vulns SET t2_result = ? WHERE id = ?", (t2_text, vid))

    t2_confidence = t2_data.get("confidence", 0) if t2_data else 0
    t2_verified = t2_data.get("verified", False) if t2_data else False
    t2_parse_failed = t2_data and "could not parse" in t2_data.get("analysis", "")

    if not t2_verified and not t2_parse_failed and t2_confidence > 0:
        if t2_confidence <= 6:
            # T3: Sonnet DA challenges low-confidence rejection
            log.info(f"  [T3] T2 low confidence ({t2_confidence}/10) — Sonnet DA challenging...")
            _live_status["phase"] = "t3_challenge"
            _flush_status()
            t3_challenge = tier3_sonnet_challenge(vtype, vevidence, vsub, vurl, t1_text, t2_data)
            t3_text = json.dumps(t3_challenge) if t3_challenge else "T3 unavailable"
            with _gc() as _c2:
                _c2.execute("UPDATE vulns SET t3_challenge = ? WHERE id = ?", (t3_text, vid))
            t3_conf = t3_challenge.get("confidence", 5) if t3_challenge else 5
            t3_escalate = (t3_challenge and t3_challenge.get("verdict") == "escalate") or t3_conf <= 4
            if t3_escalate:
                log.info(f"  [T3] ESCALATED ({t3_conf}/10)")
                log_activity("scan", f"T3 Sonnet DA escalated: {vtype} on {vsub}")
            else:
                log.info(f"  [T3] Confirmed T2 rejection ({t3_conf}/10): {vtype} on {vsub}")
                log_activity("triage", f"T3 confirmed T2 rejection: {vtype} on {vsub}")
                with _gc() as _c2:
                    _c2.execute("UPDATE vulns SET status = 'filtered' WHERE id = ?", (vid,))
                return
        else:
            log.info(f"  [T2] REJECTED (confidence {t2_confidence}): {vtype} on {vsub}")
            log_activity("triage", f"T2 rejected: {vtype} on {vsub}")
            with _gc() as _c2:
                _c2.execute("UPDATE vulns SET status = 'filtered' WHERE id = ?", (vid,))
            return
    elif t2_parse_failed or not t2_data:
        log.info(f"  [T2] PARSE FAILED — escalating (T1 passed)")
        log_activity("triage", f"T2 inconclusive on {vsub}, escalating")
    else:
        log.info(f"  [T2] VERIFIED: {vtype} on {vsub}")
        log_activity("scan", f"T2 verified: {vtype} on {vsub}")

    with _gc() as _c2:
        _c2.execute("UPDATE vulns SET status = 't2_pass' WHERE id = ?", (vid,))

    # === T4: OPUS SENIOR REVIEW ===
    _live_status["phase"] = "t4_review"
    _flush_status()
    log.info(f"  [T4] OPUS reviewing: {vtype} on {vsub}...")
    log_activity("scan", f"T4 Opus reviewing: {vtype} on {vsub}")

    t4_data = tier4_senior_review(vtype, vevidence, vsub, vurl, domain, t1_text, t2_data, all_finding_dicts)
    t4_text = json.dumps(t4_data) if t4_data else "T4 unavailable"
    with _gc() as _c2:
        _c2.execute("UPDATE vulns SET t3_result = ? WHERE id = ?", (t4_text, vid))

    if not t4_data:
        log.info(f"  [T4] Unavailable for {vsub}")
        return

    verdict = t4_data.get("verdict", "reject")
    reason = t4_data.get("reason", "")
    confidence = t4_data.get("confidence", 0)

    if verdict == "submit" and t4_data.get("report"):
        log.info(f"  *** [T4] APPROVED: {vtype} on {vsub} — {reason}")
        log_activity("vuln", f"OPUS APPROVED: {vtype} on {vsub} — REPORT READY")
        with _gc() as _c2:
            _c2.execute("UPDATE vulns SET status = 'reviewed', report_md = ?, severity = ? WHERE id = ?",
                        (t4_data["report"], t4_data.get("severity", vrow["severity"]), vid))
        # Discord notification with full context file for manual validation
        try:
            from notifier_discord import notify_finding_ready
            notify_finding_ready({
                "id": vid, "subdomain": vsub, "vuln_type": vtype,
                "severity": t4_data.get("severity", vrow["severity"]),
                "url": vurl, "target_domain": domain, "status": "reviewed",
                "report_md": t4_data["report"], "source": "T4 Opus",
                "evidence": vevidence, "enriched_evidence": vrow.get("enriched_evidence", ""),
                "t1_result": t1_text, "t2_result": t2_text,
            })
        except Exception:
            pass
    else:
        # === T5: OPUS DEVIL'S ADVOCATE ===
        if confidence <= 4:
            log.info(f"  [T5] T4 low confidence ({confidence}/10) — Opus DA challenging...")
            _live_status["phase"] = "t5_challenge"
            _flush_status()
            t5_data = tier5_devils_advocate(vtype, vevidence, vsub, vurl, domain, t1_text, t2_data, t4_data)
            t5_text = json.dumps(t5_data) if t5_data else "T5 unavailable"
            with _gc() as _c2:
                _c2.execute("UPDATE vulns SET t5_challenge = ? WHERE id = ?", (t5_text, vid))
            t5_conf = t5_data.get("confidence", 5) if t5_data else 5
            t5_escalate = (t5_data and t5_data.get("verdict") == "investigate") or t5_conf <= 4
            if t5_escalate:
                log.info(f"  *** [T5] CHALLENGED ({t5_conf}/10) — may be real!")
                log_activity("vuln", f"T5 CHALLENGE: {vtype} on {vsub} — NEEDS MANUAL CHECK")
                steps = t5_data.get("verification_steps", [])
                steps_str = "\n".join(f"- {s}" for s in steps[:5])
                report_text = f"T5 DEVIL'S ADVOCATE — NEEDS MANUAL CHECK\n\nChallenge: {t5_data.get('challenge','')}\nSeverity if real: {t5_data.get('potential_severity','?')}\n\nVerification steps:\n{steps_str}"
                with _gc() as _c2:
                    _c2.execute("UPDATE vulns SET status = 'needs_review', report_md = ? WHERE id = ?",
                                (report_text, vid))
                # Discord notification with full context file for manual validation
                try:
                    from notifier_discord import notify_finding_ready
                    notify_finding_ready({
                        "id": vid, "subdomain": vsub, "vuln_type": vtype,
                        "severity": t5_data.get("potential_severity", "Medium"),
                        "url": vurl, "target_domain": domain, "status": "needs_review",
                        "report_md": report_text, "source": "T5 Challenge",
                        "evidence": vevidence, "enriched_evidence": vrow.get("enriched_evidence", ""),
                        "t1_result": t1_text, "t2_result": t2_text,
                    })
                except Exception:
                    pass
            else:
                log.info(f"  [T5] Confirmed rejection: {vtype} on {vsub}")
                log_activity("triage", f"T5 confirmed: {vtype} on {vsub}")
                with _gc() as _c2:
                    _c2.execute("UPDATE vulns SET status = 'rejected', report_md = ? WHERE id = ?",
                                (f"REJECTED: {reason}\nT5 confirmed: {t5_data.get('challenge','') if t5_data else ''}", vid))
        else:
            log.info(f"  [T4] REJECTED ({confidence}/10): {vtype} on {vsub} — {reason}")
            log_activity("triage", f"Opus rejected: {vtype} on {vsub}")
            with _gc() as _c2:
                _c2.execute("UPDATE vulns SET status = 'rejected', report_md = ? WHERE id = ?",
                            (f"REJECTED by Opus: {reason}", vid))


# =====================================================================
# SCAN DOMAIN — Legacy wrapper (backward compat, calls phase functions)
# =====================================================================

def scan_domain(domain, target_id=None, prefetched_subs=None, source=""):
    """Full scan pipeline for a single domain. Legacy sequential wrapper."""
    live_hosts, all_findings, vuln_count = phase_recon(domain, target_id, source)

    _live_status["checked"] = _live_status.get("total", 0)
    _live_status["live_count"] = len(live_hosts)
    _live_status["phase"] = "nuclei"
    _flush_status()

    vuln_count2, js_count, ai_count = phase_scan(domain, target_id, live_hosts)
    total_vulns = vuln_count + vuln_count2 + js_count + ai_count

    if total_vulns > 0:
        phase_ai_triage(target_id, domain)

    log_activity("scan", f"{domain}: DONE — {len(live_hosts)} live, {len(all_findings)} dangling, {total_vulns} vulns")
    return all_findings


# =====================================================================
# Finding Report Generator (unchanged)
# =====================================================================

def generate_finding_report(subdomain, cname, provider, fingerprint, domain, acquirer):
    bounty_url = get_acquirer_bounty(acquirer) or "N/A"
    report = f"""# Subdomain Takeover Vulnerability

## Target
- **Subdomain:** `{subdomain}`
- **Parent Domain:** `{domain}`
- **Acquirer:** {acquirer or 'Unknown'}
- **Bug Bounty Program:** {bounty_url}

## Summary
A dangling CNAME record on `{subdomain}` points to `{cname}` ({provider}).
The underlying cloud resource is unclaimed, enabling subdomain takeover.

## Evidence
| Field | Value |
|-------|-------|
| Subdomain | `{subdomain}` |
| CNAME Target | `{cname}` |
| Provider | {provider} |
| Fingerprint | `{fingerprint}` |

## Steps to Reproduce
1. Query the CNAME record: `dig CNAME {subdomain}`
2. Confirm it points to `{cname}`
3. Visit `https://{subdomain}` in a browser
4. Observe the error page indicating the {provider} resource is unclaimed

## Impact
An attacker could register the unclaimed {provider} resource and serve
arbitrary content on `{subdomain}`, enabling phishing, cookie theft,
and session hijacking.

## Severity
**Medium** (CVSS ~6.1)

## Remediation
1. Remove the stale CNAME record for `{subdomain}` from DNS
2. Alternatively, re-provision the {provider} resource
"""
    findings_dir = ROOT / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    slug = subdomain.replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    path = findings_dir / f"REPORT_{slug}_{ts}.md"
    with open(path, "w") as f:
        f.write(report)
    log.info(f"  Report saved: {path}")
    return path


# =====================================================================
# SIGNAL SOURCES — feed the priority queue
# =====================================================================

# Timestamps for signal source intervals (in-memory, persists across cycles)
_last_check = {}


def _run_signal_sources():
    """Check all signal sources and enqueue discovered targets."""
    now = time.time()
    config = _load_scanner_config()
    sig_conf = config.get("signals", {})

    # Signal 1: New program detection (every 15 min — HIGHEST ROI)
    interval = sig_conf.get("new_program_interval_min", 15) * 60
    if now - _last_check.get("new_programs", 0) > interval:
        _set_status("checking_programs", "Checking for new programs...")
        try:
            from program_scanner import check_new_programs
            new = check_new_programs()
            if new:
                log.info(f"  [SIGNAL] NEW PROGRAMS: {len(new)} detected!")
                for p in new:
                    log.info(f"    -> {p['company']} ({p['handle']}) — {len(p['domains'])} domains")
        except Exception as e:
            log.warning(f"  [SIGNAL] New program check failed: {e}")
        _last_check["new_programs"] = now

    # Signal 2: Scope change detection (every 6 hours)
    interval = sig_conf.get("scope_change_interval_hours", 6) * 3600
    if now - _last_check.get("scope_changes", 0) > interval:
        _set_status("checking_scope", "Checking for scope changes...")
        try:
            from program_scanner import detect_scope_changes
            changes = detect_scope_changes()
            if changes:
                total_new = sum(len(c["new_domains"]) for c in changes)
                log.info(f"  [SIGNAL] SCOPE CHANGES: {len(changes)} programs, {total_new} new domains")
        except Exception as e:
            log.warning(f"  [SIGNAL] Scope change check failed: {e}")
        _last_check["scope_changes"] = now

    # Signal 3: CVE racing (every 6 hours)
    interval = sig_conf.get("cve_check_interval_hours", 6) * 3600
    if now - _last_check.get("cves", 0) > interval:
        _set_status("checking_cves", "Checking for new CVEs...")
        try:
            from cve_monitor import fetch_recent_cves, match_cves_to_targets
            cves = fetch_recent_cves(hours=24)
            if cves:
                matches = match_cves_to_targets(cves)
                log.info(f"  [SIGNAL] CVE: {len(cves)} new CVEs, {len(matches)} target matches")
        except Exception as e:
            log.warning(f"  [SIGNAL] CVE check failed: {e}")
        _last_check["cves"] = now

    # Signal 4: M&A feed crawl (every 12 hours)
    interval = sig_conf.get("m_and_a_interval_hours", 12) * 3600
    if now - _last_check.get("m_and_a", 0) > interval:
        _set_status("crawling", "Crawling M&A RSS feeds...")
        try:
            ma_config = load_config()
            total, new = fetch_and_store(ma_config)
            log.info(f"  [SIGNAL] M&A: {total} matches, {new} new")
            # Process M&A targets into queue
            _enqueue_m_and_a_targets()
        except Exception as e:
            log.warning(f"  [SIGNAL] M&A crawl failed: {e}")
        _last_check["m_and_a"] = now

    # Signal 5: Program directory sync (every 7 days)
    if now - _last_check.get("program_sync", 0) > 604800:
        _set_status("syncing", "Syncing HackerOne program directory...")
        try:
            from program_scanner import sync_programs_to_db
            new_progs, new_tgts = sync_programs_to_db()
            log.info(f"  [SIGNAL] Program sync: {new_progs} new programs, {new_tgts} new targets")
        except Exception as e:
            log.warning(f"  [SIGNAL] Program sync failed: {e}")
        _last_check["program_sync"] = now


def _enqueue_m_and_a_targets():
    """Process M&A acquisitions into the scan queue."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT a.acquirer, a.target_company, a.target_domain, a.id as acq_id
            FROM acquisitions a
            WHERE a.target_domain IS NOT NULL
            AND a.target_domain != ''
            AND a.id NOT IN (SELECT COALESCE(acquisition_id, 0) FROM targets WHERE scope_status != 'pending')
            LIMIT 20
        """).fetchall()

    for row in rows:
        domain = row["target_domain"]
        acquirer = row["acquirer"]
        acq_id = row["acq_id"]

        if len(domain) > 60 or " " in domain:
            continue

        target_id = insert_target(domain, acquisition_id=acq_id)

        bounty_url = get_acquirer_bounty(acquirer)
        if bounty_url:
            update_target_scope(target_id, "in_scope", "known_program", bounty_url)
            log_activity("scope", f"IN SCOPE: {domain} ({acquirer} has bounty)")
            enqueue_scan(target_id, domain, priority=1, source="m_and_a", source_detail=acquirer)
        else:
            has_bounty, _ = check_security_txt(domain)
            if has_bounty:
                update_target_scope(target_id, "in_scope", "security.txt", f"https://{domain}/.well-known/security.txt")
                enqueue_scan(target_id, domain, priority=1, source="m_and_a", source_detail=acquirer)
            else:
                update_target_scope(target_id, "out_of_scope")


def _enqueue_rotation_targets():
    """Smart rotation feeder. Two paths into the queue:

    1. First-pass: never-scanned in-scope targets. Without this, freshly imported
       targets are stranded — the v15 "high-value rotation" criteria require
       api_schemas data, which only exists after a first scan. Chicken-and-egg.
    2. Re-scan: high-value targets (score >= 25 AND api_schemas present) due
       for rotation per rotation_rescan_days.
    """
    with get_conn() as conn:
        config = _load_scanner_config()
        rescan_days = config.get("signals", {}).get("rotation_rescan_days", 7)

        # julianday() compare: last_scanned_at stores ISO-8601 from _now() while
        # datetime('now', ...) returns a different format — lex compare mis-fires
        # near day boundaries. See db.enqueue_scan cooldown for the same fix.
        rows = conn.execute("""
            SELECT t.id, t.domain
            FROM targets t
            WHERE t.scope_status = 'in_scope'
            AND t.domain NOT IN (SELECT domain FROM scan_queue WHERE status IN ('pending', 'running'))
            AND (
                t.last_scanned_at IS NULL
                OR (
                    CAST(json_extract(t.scan_metadata, '$.score') AS INTEGER) >= 25
                    AND t.id IN (SELECT DISTINCT target_id FROM api_schemas)
                    AND julianday(t.last_scanned_at) < julianday('now', ? || ' days')
                )
            )
            ORDER BY (t.last_scanned_at IS NULL) DESC, t.last_scanned_at ASC
            LIMIT 20
        """, (f"-{rescan_days}",)).fetchall()

    enqueued = 0
    for row in rows:
        if row["domain"] not in SKIP_MEGA_DOMAINS:
            enqueue_scan(row["id"], row["domain"], priority=3, source="smart_rotation")
            enqueued += 1

    if enqueued:
        log_activity("pipeline", f"Smart rotation: enqueued {enqueued} high-value targets (score>=25, has API)")


# =====================================================================
# ORPHAN FINDER — processes findings left at 'new' from previous scans
# =====================================================================

def _process_orphan_findings():
    """Process findings at 'new' or 't1_pass' through the AI pipeline.
    Now delegates to _process_single_vuln (shared with phase_ai_triage)."""
    try:
        from db import get_unprocessed_vulns

        orphans = get_unprocessed_vulns(limit=200)
        if not orphans:
            return

        new_count = sum(1 for o in orphans if o["status"] == "new")
        t1p_count = sum(1 for o in orphans if o["status"] == "t1_pass")
        log.info(f"  [PIPELINE] Processing {len(orphans)} orphan findings ({new_count} new, {t1p_count} t1_pass)...")
        log_activity("scan", f"Processing {len(orphans)} orphan findings through AI pipeline")

        for vrow in orphans:
            domain = vrow.get("domain", vrow["subdomain"].split(".", 1)[-1] if "." in vrow["subdomain"] else vrow["subdomain"])
            try:
                _process_single_vuln(vrow, domain)
            except Exception as e:
                log.warning(f"  [PIPELINE] Failed on vuln {vrow['id']}: {e}")

    except Exception as e:
        log.warning(f"  [PIPELINE] Orphan processing failed: {e}")
        import traceback
        traceback.print_exc()


# =====================================================================
# MAIN RUN CYCLE — Queue-driven loop
# =====================================================================

def run_cycle(batch_size=5):
    """
    v13 Queue-driven scan cycle:
    1. Run all signal sources (each enqueues work into priority queue)
    2. If queue empty, enqueue rotation targets
    3. Dequeue highest-priority item and scan it
    4. Repeat for batch_size items
    """
    # Step 0: Process any orphan findings (from previous scans) through AI pipeline
    _process_orphan_findings()

    # Step 1: Check all signal sources
    _run_signal_sources()

    # Step 2: If queue is empty, fill with rotation targets
    if get_queue_depth() == 0:
        _enqueue_rotation_targets()

    # Step 3: Dequeue and scan
    total_scanned = 0
    total_findings = 0

    for _ in range(batch_size):
        item = dequeue_scan()
        if not item:
            break

        domain = item["domain"]
        target_id = item["target_id"]
        source = item["source"]
        priority = item["priority"]
        queue_id = item["id"]

        if domain in SKIP_MEGA_DOMAINS:
            log.info(f"  [SKIP] {domain} — mega domain")
            if target_id:
                insert_scan(target_id, domain, "", "skipped", False)
            complete_scan(queue_id)
            continue

        priority_label = {0: "P0-NEW_PROGRAM", 1: "P1-URGENT", 2: "P2-M&A", 3: "P3-ROTATION"}.get(priority, f"P{priority}")
        log.info(f"  [{priority_label}] Scanning {domain} (source: {source})")
        log_activity("scan", f"{priority_label}: {domain} ({source}: {item.get('source_detail', '')})")

        _set_status("scanning", domain, source=source)

        # Prefetch subfinder
        prefetched = _run_subfinder(domain)

        # Run full scan
        try:
            findings = scan_domain(domain, target_id=target_id, prefetched_subs=prefetched, source=source)
            total_scanned += 1
            total_findings += _process_findings(findings, domain, source, "")
            complete_scan(queue_id, status='completed')
        except Exception as e:
            log.error(f"  Scan failed for {domain}: {e}")
            complete_scan(queue_id, status='failed')

    return total_scanned, total_findings


def _process_findings(findings, domain, acquirer, bounty_url):
    count = 0
    if not findings:
        log.info(f"  Clean: {domain}")
        return 0

    for f in findings:
        count += 1
        generate_finding_report(
            f["subdomain"], f["cname_target"], f["provider"],
            f["fingerprint"], domain, acquirer,
        )

    return count


# =====================================================================
# Heartbeat + Main
# =====================================================================

def heartbeat(cycle, total_scanned, total_findings):
    now = datetime.now().strftime("%I:%M %p")
    queue = get_queue_stats()
    budget = get_budget_status()
    log.info(
        f"[HEARTBEAT] {now} | Cycle: {cycle} | "
        f"Scanned: {total_scanned} | Hits: {total_findings} | "
        f"Queue: {queue.get('total_pending', 0)} pending | "
        f"Budget: ${budget.get('spent', 0):.3f}/${budget.get('limit', 0)} | "
        f"Status: Active"
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Infinite Hunter v13 — AI-First Revenue Machine")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=1, help="Minutes between cycles (default: 1)")
    parser.add_argument("--batch", type=int, default=5, help="Targets per cycle (default: 5)")
    parser.add_argument("--import-scope", action="store_true", help="Import programs from GitHub lists, then exit")
    args = parser.parse_args()

    init_db()

    if args.import_scope:
        from scope_importer import import_all
        progs, targets = import_all()
        log.info(f"Import complete: {progs} programs, {targets} targets")
        return

    from llm_client import get_tier_budgets

    log.info("=" * 60)
    log.info("INFINITE HUNTER v13 — AI-FIRST REVENUE MACHINE")
    log.info(f"Mode: {'LOOP' if args.loop else 'SINGLE RUN'}")
    log.info(f"Batch: {args.batch} | Interval: {args.interval}min")
    log.info(f"Subdomain prefixes: {len(SUBDOMAIN_PREFIXES)}")
    log.info(f"Signal sources: new_programs(15m), scope_changes(6h), cves(6h), m_and_a(12h)")

    tier_budgets = get_tier_budgets()
    for t, info in tier_budgets.items():
        log.info(f"  {t}: {info['model']} — ${info['daily_limit']}/day (enabled: {info['enabled']})")
    log.info("=" * 60)

    cycle = 0
    total_scanned = 0
    total_findings = 0

    while True:
        cycle += 1
        try:
            scanned, findings = run_cycle(batch_size=args.batch)
            total_scanned += scanned
            total_findings += findings
        except Exception as e:
            log.error(f"Cycle {cycle} failed: {e}")

        heartbeat(cycle, total_scanned, total_findings)

        if not args.loop:
            break

        log.info(f"Sleeping {args.interval} minutes...\n")
        time.sleep(args.interval * 60)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
