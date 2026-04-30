"""
Target Scoring Engine — Session 5 (revised).

Scores in-scope targets from 1-100 to prioritize pipeline decisions.
Called at TWO points:
  1. After scanning (pre-mapping): decides whether to run Katana + deep mapping
  2. Periodically (every 12h): rescores with full data including api_schemas

Scoring factors:
  1. Surface Area     (0-25): Live hosts, subdomains, JS files — is there anything here?
  2. Program Value    (0-25): Known high-payer? Platform? SaaS/fintech?
  3. Vuln Signals     (0-20): Passive scan found vulns? Nuclei hits? Interesting tech?
  4. Freshness        (0-15): New program = gold rush. Old = competition.
  5. API Richness     (0-15): Endpoints discovered (post-mapping bonus, 0 before mapping)

MAPPING THRESHOLD = 25
  Score >= 25 → run Katana, JS parsing, Swagger probing, auth detection, ReAct testing
  Score < 25  → static site or dead target, skip to done (passive vulns still get AI triage)
"""
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("hunter")

MAPPING_THRESHOLD = 25  # Minimum score to run deep mapping + testing


def score_target(target_id):
    """Score a single target. Returns (score 1-100, breakdown dict)."""
    from db import get_conn

    with get_conn() as conn:
        target = conn.execute(
            "SELECT t.*, p.company, p.handle, p.launched_at, p.scope_domains "
            "FROM targets t LEFT JOIN programs p ON t.program_url LIKE '%' || p.handle || '%' "
            "WHERE t.id = ?", (target_id,)
        ).fetchone()

        if not target:
            return 0, {"error": "target not found"}

        target = dict(target)
        domain = target["domain"]

        # --- Data from recon + scanning (available pre-mapping) ---

        live_subs = conn.execute(
            "SELECT COUNT(DISTINCT subdomain) FROM scans WHERE target_id = ?", (target_id,)
        ).fetchone()[0]

        vuln_count = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE target_id = ?", (target_id,)
        ).fetchone()[0]

        # Nuclei findings by severity (tech fingerprinting signal)
        nuclei_high = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE target_id = ? AND vuln_type LIKE 'nuclei:%' "
            "AND severity IN ('High', 'Critical')", (target_id,)
        ).fetchone()[0]

        nuclei_any = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE target_id = ? AND vuln_type LIKE 'nuclei:%'",
            (target_id,)
        ).fetchone()[0]

        # JS secrets found (signal of complex web app with bundles)
        js_secrets = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE target_id = ? AND vuln_type LIKE 'js_secret:%'",
            (target_id,)
        ).fetchone()[0]

        react_vulns = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE target_id = ? AND vuln_type LIKE 'react:%'",
            (target_id,)
        ).fetchone()[0]

        # --- Data from mapping (only available post-mapping, 0 before) ---

        api_count = conn.execute(
            "SELECT COUNT(*) FROM api_schemas WHERE target_id = ?", (target_id,)
        ).fetchone()[0]

        has_swagger = conn.execute(
            "SELECT COUNT(*) FROM api_schemas WHERE target_id = ? AND source = 'swagger'",
            (target_id,)
        ).fetchone()[0] > 0

        has_graphql = conn.execute(
            "SELECT COUNT(*) FROM api_schemas WHERE target_id = ? AND source = 'graphql'",
            (target_id,)
        ).fetchone()[0] > 0

        has_auth = conn.execute(
            "SELECT COUNT(*) FROM api_schemas WHERE target_id = ? AND source = 'auth_probe'",
            (target_id,)
        ).fetchone()[0] > 0

        mutation_count = conn.execute(
            "SELECT COUNT(*) FROM api_schemas WHERE target_id = ? AND method IN ('POST', 'PUT', 'PATCH')",
            (target_id,)
        ).fetchone()[0]

    # =====================================================================
    # CALCULATE SCORES
    # =====================================================================
    breakdown = {}

    # 1. Surface Area (0-25) — is there anything worth scanning here?
    surface_score = 0
    if live_subs >= 20:
        surface_score += 12     # Large attack surface
    elif live_subs >= 5:
        surface_score += 8      # Medium surface
    elif live_subs >= 1:
        surface_score += 4      # At least something is alive
    # else: 0 — nothing alive, likely dead domain

    if js_secrets > 0:
        surface_score += 6      # JS bundles found = real web app, not static
    if nuclei_any > 0:
        surface_score += 4      # Nuclei found something = active service
    if vuln_count > 3:
        surface_score += 3      # Multiple findings = interesting target

    surface_score = min(25, surface_score)
    breakdown["surface_area"] = round(surface_score, 1)

    # 2. Program Value (0-25) — is the bounty program worth the effort?
    program_score = 5  # Base for being in scope

    handle = target.get("handle", "")
    company = target.get("company", "")

    high_payers = {"stripe", "coinbase", "shopify", "uber", "airbnb", "github", "gitlab",
                   "dropbox", "slack", "zoom", "cloudflare", "robinhood", "paypal",
                   "twitter", "snap", "tiktok", "meta", "yahoo", "brave"}
    if handle and handle.lower() in high_payers:
        program_score += 15
    elif company:
        saas_signals = ["api", "cloud", "platform", "saas", "fintech", "payment", "bank", "crypto"]
        if any(sig in company.lower() for sig in saas_signals):
            program_score += 8

    if target.get("program_platform") == "hackerone":
        program_score += 3
    elif target.get("program_platform") == "bugcrowd":
        program_score += 2

    program_score = min(25, program_score)
    breakdown["program_value"] = round(program_score, 1)

    # 3. Vuln Signals (0-20) — did passive scanning already find interesting stuff?
    vuln_signal_score = 0
    if nuclei_high > 0:
        vuln_signal_score += 10    # High/critical Nuclei finding = juicy target
    elif nuclei_any > 0:
        vuln_signal_score += 4     # Any Nuclei finding = worth looking deeper
    if js_secrets > 0:
        vuln_signal_score += 5     # JS secrets = developer mistakes, likely more bugs
    if react_vulns > 0:
        vuln_signal_score += 5     # ReAct already found something = keep hitting it

    vuln_signal_score = min(20, vuln_signal_score)
    breakdown["vuln_signals"] = round(vuln_signal_score, 1)

    # 4. Freshness (0-15) — new programs have less competition
    freshness_score = 0
    launched = target.get("launched_at", "")
    if launched:
        try:
            launch_date = datetime.fromisoformat(launched.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - launch_date).days
            if age_days <= 2:
                freshness_score = 15
            elif age_days <= 7:
                freshness_score = 12
            elif age_days <= 30:
                freshness_score = 8
            elif age_days <= 90:
                freshness_score = 4
            else:
                freshness_score = 1
        except (ValueError, TypeError):
            freshness_score = 2

    scan_meta = target.get("scan_metadata", "")
    if scan_meta:
        try:
            meta = json.loads(scan_meta)
            source = meta.get("source", "")
            if source in ("new_program", "m_and_a"):
                freshness_score = min(15, freshness_score + 5)
        except (json.JSONDecodeError, TypeError):
            pass

    breakdown["freshness"] = round(freshness_score, 1)

    # 5. API Richness (0-15) — post-mapping bonus (0 before mapping, that's fine)
    api_score = 0
    if api_count > 0:
        api_score += min(7, api_count * 0.5)
        if has_swagger:
            api_score += 3
        if has_graphql:
            api_score += 3
        if has_auth:
            api_score += 2

    api_score = min(15, api_score)
    breakdown["api_richness"] = round(api_score, 1)

    total = round(surface_score + program_score + vuln_signal_score + freshness_score + api_score)
    total = max(1, min(100, total))
    breakdown["total"] = total

    return total, breakdown


def should_deep_scan(target_id):
    """Quick check: should this target get Katana + ReAct testing?
    Call after scanning phase to decide whether to proceed to mapping."""
    score, breakdown = score_target(target_id)
    proceed = score >= MAPPING_THRESHOLD
    return proceed, score, breakdown


def score_all_targets():
    """Score all in-scope targets and update priorities.
    Returns (scored_count, top_targets)."""
    from db import get_conn

    with get_conn() as conn:
        targets = conn.execute(
            "SELECT id, domain FROM targets WHERE scope_status = 'in_scope'"
        ).fetchall()

    scored = []
    for target in targets:
        tid = target["id"]
        domain = target["domain"]
        score, breakdown = score_target(tid)
        scored.append((tid, domain, score, breakdown))

    with get_conn() as conn:
        for tid, domain, score, _ in scored:
            if score >= 80:
                priority = 10
            elif score >= 60:
                priority = 8
            elif score >= 40:
                priority = 6
            elif score >= 20:
                priority = 4
            else:
                priority = 2
            conn.execute(
                "UPDATE targets SET priority = MAX(COALESCE(priority, 0), ?) WHERE id = ?",
                (priority, tid)
            )

    scored.sort(key=lambda x: x[2], reverse=True)
    top = scored[:20]

    log.info(f"  [SCORER] Scored {len(scored)} targets. Top 5:")
    for tid, domain, score, bd in top[:5]:
        log.info(f"    {score:3d} — {domain} (surface={bd.get('surface_area',0)}, prog={bd.get('program_value',0)}, "
                 f"vulns={bd.get('vuln_signals',0)}, fresh={bd.get('freshness',0)}, api={bd.get('api_richness',0)})")

    return len(scored), [(d, s, b) for _, d, s, b in top]


def get_target_score(target_id):
    """Get score for a single target (for dashboard display)."""
    score, breakdown = score_target(target_id)
    return {"score": score, **breakdown}
