"""
Hunter-Max Dashboard v15 — Password-protected live dashboard.
"""
import json
import os
import sys
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

from db import (
    init_db, get_live_data, get_finding, get_findings, get_acquisitions,
    get_targets, update_finding_status, log_activity, count_findings,
    get_queue_stats, get_pipeline_stats,
)

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

DASHBOARD_PW = os.environ.get("DASHBOARD_PASSWORD")
if not DASHBOARD_PW:
    raise RuntimeError("DASHBOARD_PASSWORD env var must be set; refusing to "
                       "start with a default password.")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authed"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def _load_config():
    with open(ROOT / "config.json") as f:
        return json.load(f)


def _get_budget():
    bf = ROOT / "data" / "budget.json"
    if bf.exists():
        with open(bf) as f:
            return json.load(f)
    return {"total_spent": 0, "calls": 0}


# --- Auth ---

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw == DASHBOARD_PW:
            session["authed"] = True
            session.permanent = True
            return redirect(url_for("index"))
        error = "Wrong password"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hunter-Max — Login</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh}}
.login-box{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:340px;text-align:center}}
.login-box h1{{font-size:20px;font-weight:800;margin-bottom:6px;letter-spacing:1px}}
.login-box .sub{{font-size:11px;color:#484f58;margin-bottom:24px}}
.login-box input{{width:100%;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;margin-bottom:12px;outline:none}}
.login-box input:focus{{border-color:#58a6ff}}
.login-box button{{width:100%;padding:10px;background:#238636;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:700;cursor:pointer}}
.login-box button:hover{{background:#2ea043}}
.error{{color:#f85149;font-size:12px;margin-bottom:10px}}
</style></head><body>
<div class="login-box">
<h1>HUNTER-MAX</h1>
<div class="sub">Enter password to access dashboard</div>
{"<div class='error'>"+error+"</div>" if error else ""}
<form method="POST">
<input type="password" name="password" placeholder="Password" autofocus>
<button type="submit">Enter</button>
</form>
</div></body></html>"""


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Headers ---

@app.after_request
def add_no_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# --- Pages ---

@app.route("/")
@login_required
def index():
    tpl = ROOT / "templates" / "index.html"
    mtime = int(os.path.getmtime(tpl)) if tpl.exists() else 0
    return render_template("index.html", cache_bust=mtime)


# --- API ---

@app.route("/api/live")
@login_required
def api_live():
    data = get_live_data()
    budget = _get_budget()
    config = _load_config()
    data["budget"] = {
        "spent": round(budget.get("total_spent", 0), 4),
        "limit": config.get("llm", {}).get("budget_usd", 15.0),
        "calls": budget.get("calls", 0),
    }
    data["queue"] = get_queue_stats()
    try:
        from llm_client import get_tier_budgets
        data["tier_budgets"] = get_tier_budgets()
    except Exception:
        data["tier_budgets"] = {}
    data["pipeline"] = get_pipeline_stats()
    data["timestamp"] = datetime.utcnow().isoformat()
    return jsonify(data)


@app.route("/api/scan-status")
@login_required
def api_scan_status():
    status_file = ROOT / "data" / "live_status.json"
    try:
        if status_file.exists():
            with open(status_file) as f:
                return jsonify(json.load(f))
    except Exception:
        pass
    return jsonify({"phase": "idle", "domain": "", "checked": 0, "total": 0, "recent": []})


@app.route("/api/finding/<int:fid>")
@login_required
def api_finding(fid):
    f = get_finding(fid)
    if not f:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(f))


@app.route("/api/finding/<int:fid>/approve", methods=["POST"])
@login_required
def api_approve(fid):
    update_finding_status(fid, "approved")
    f = get_finding(fid)
    name = f["subdomain"] if f else f"#{fid}"
    log_activity("approve", f"Approved: {name}")
    return jsonify({"ok": True, "status": "approved"})


@app.route("/api/finding/<int:fid>/skip", methods=["POST"])
@login_required
def api_skip(fid):
    update_finding_status(fid, "skipped")
    f = get_finding(fid)
    name = f["subdomain"] if f else f"#{fid}"
    log_activity("skip", f"Skipped: {name}")
    return jsonify({"ok": True, "status": "skipped"})


@app.route("/api/vuln/<int:vid>")
@login_required
def api_vuln(vid):
    from db import get_vuln
    v = get_vuln(vid)
    if not v:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(v))


@app.route("/api/vuln/<int:vid>/approve", methods=["POST"])
@login_required
def api_vuln_approve(vid):
    from db import update_vuln_status, get_vuln
    update_vuln_status(vid, "approved")
    v = get_vuln(vid)
    name = v["subdomain"] if v else f"#{vid}"
    log_activity("approve", f"Vuln approved: {v['vuln_type']} on {name}")
    return jsonify({"ok": True})


@app.route("/api/vuln/<int:vid>/skip", methods=["POST"])
@login_required
def api_vuln_skip(vid):
    from db import update_vuln_status, get_vuln
    update_vuln_status(vid, "skipped")
    v = get_vuln(vid)
    name = v["subdomain"] if v else f"#{vid}"
    log_activity("skip", f"Vuln skipped: {v['vuln_type']} on {name}")
    return jsonify({"ok": True})


@app.route("/api/reports")
@login_required
def api_reports():
    """List all report-ready findings (reviewed by T4 or ReAct agent)."""
    from db import get_conn
    with get_conn() as conn:
        vulns = [dict(r) for r in conn.execute(
            "SELECT v.id, v.subdomain, v.vuln_type, v.severity, v.status, v.report_md, v.created_at, "
            "v.url, t.domain as target_domain, t.program_url "
            "FROM vulns v LEFT JOIN targets t ON v.target_id = t.id "
            "WHERE v.status IN ('reviewed', 'needs_review', 'approved') AND v.report_md IS NOT NULL "
            "ORDER BY CASE v.status WHEN 'reviewed' THEN 0 WHEN 'needs_review' THEN 1 ELSE 2 END, v.id DESC"
        ).fetchall()]
    return jsonify({"reports": vulns, "count": len(vulns)})


@app.route("/api/scores")
@login_required
def api_scores():
    """Get top scored targets."""
    try:
        from target_scorer import score_all_targets
        count, top = score_all_targets()
        return jsonify({
            "scored": count,
            "top": [{"domain": d, "score": s, "breakdown": b} for d, s, b in top],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/score/<int:tid>")
@login_required
def api_score_target(tid):
    """Get score for a single target."""
    try:
        from target_scorer import get_target_score
        return jsonify(get_target_score(tid))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Threat Matrix + Chain Analyzer (v15) ---

@app.route("/api/threat_matrix/<int:tid>")
@login_required
def api_threat_matrix(tid):
    """Return all findings for a target grouped by endpoint path.

    Groups: active leads (Scout/Sniper), passive vulns (AI pipeline),
    and dropped findings (XSS/CSRF, info/low) — all by endpoint.
    """
    from db import get_conn
    from urllib.parse import urlparse

    with get_conn() as conn:
        target = conn.execute("SELECT domain, program_url FROM targets WHERE id = ?", (tid,)).fetchone()
        if not target:
            return jsonify({"error": "target not found"}), 404

        # All vulns for this target, excluding filtered CORS (pure noise)
        vulns = [dict(r) for r in conn.execute(
            "SELECT id, subdomain, vuln_type, evidence, severity, url, status, "
            "report_md, t1_result, t2_result, enrichment_status, created_at "
            "FROM vulns WHERE target_id = ? "
            "AND NOT (status = 'filtered' AND vuln_type LIKE 'cors%') "
            "ORDER BY id DESC", (tid,)
        ).fetchall()]

        # Scout leads
        leads = [dict(r) for r in conn.execute(
            "SELECT id, subdomain, endpoint, method, vuln_class, confidence, "
            "sniper_status, lead_data, created_at "
            "FROM react_leads WHERE target_id = ? ORDER BY confidence DESC", (tid,)
        ).fetchall()]

        # API schemas (discovered endpoints)
        schemas = [dict(r) for r in conn.execute(
            "SELECT subdomain, endpoint, method, params, source "
            "FROM api_schemas WHERE target_id = ? ORDER BY id", (tid,)
        ).fetchall()]

        # Cached chain analyses
        cached = {}
        for r in conn.execute(
            "SELECT subdomain, endpoint, analysis, created_at "
            "FROM chain_analyses WHERE target_id = ?", (tid,)
        ).fetchall():
            key = f"{r['subdomain']}:{r['endpoint']}"
            cached[key] = {"analysis": r["analysis"], "cached_at": r["created_at"]}

    # Group everything by (subdomain, endpoint_path)
    endpoints = {}

    def _get_key(subdomain, url_or_endpoint):
        """Extract (subdomain, path) grouping key."""
        path = url_or_endpoint or "/"
        if path.startswith("http"):
            try:
                parsed = urlparse(path)
                path = parsed.path or "/"
                subdomain = parsed.hostname or subdomain
            except Exception:
                pass
        # Normalize: strip query params, trailing slash
        path = path.split("?")[0].rstrip("/") or "/"
        return subdomain, path

    def _ensure_ep(sub, path):
        key = f"{sub}:{path}"
        if key not in endpoints:
            endpoints[key] = {
                "subdomain": sub, "endpoint": path,
                "active_leads": [], "passive_vulns": [], "dropped": [],
                "schemas": [], "chain_analysis": cached.get(key),
            }
        return key

    # Group vulns
    client_side = {"xss", "csrf", "clickjacking", "x-frame-options", "frame-injection"}
    for v in vulns:
        sub, path = _get_key(v["subdomain"], v.get("url", ""))
        key = _ensure_ep(sub, path)
        vtype_lower = v["vuln_type"].lower()
        is_client = any(cs in vtype_lower for cs in client_side)
        is_info_low = v["severity"].lower() in ("info", "low")

        if is_client or is_info_low:
            endpoints[key]["dropped"].append(v)
        elif v["status"] in ("reviewed", "needs_review", "approved"):
            endpoints[key]["active_leads"].append(v)
        else:
            endpoints[key]["passive_vulns"].append(v)

    # Group leads
    for l in leads:
        key = _ensure_ep(l["subdomain"], l["endpoint"])
        endpoints[key]["active_leads"].append({
            "id": l["id"], "type": f"scout:{l['vuln_class']}",
            "confidence": l["confidence"], "sniper_status": l["sniper_status"],
            "source": "scout_lead",
        })

    # Group schemas
    for s in schemas:
        key = _ensure_ep(s["subdomain"], s["endpoint"])
        endpoints[key]["schemas"].append(s)

    # Sort endpoints: those with most findings first
    sorted_eps = sorted(endpoints.values(),
                        key=lambda e: len(e["active_leads"]) * 10 + len(e["dropped"]) + len(e["passive_vulns"]),
                        reverse=True)

    return jsonify({
        "target_id": tid,
        "domain": target["domain"],
        "program_url": target["program_url"],
        "endpoints": sorted_eps,
        "total_endpoints": len(sorted_eps),
    })


@app.route("/api/analyze_chain", methods=["POST"])
@login_required
def api_analyze_chain():
    """On-demand AI chain analysis for a specific endpoint.

    Takes the active leads + dropped findings for one endpoint,
    sends to Sonnet for chain potential analysis. Results are cached.
    """
    from db import get_conn
    from llm_client import call_tier

    data = request.json or {}
    target_id = data.get("target_id")
    subdomain = data.get("subdomain", "")
    endpoint = data.get("endpoint", "/")
    force = data.get("force", False)  # Force re-analysis even if cached

    if not target_id or not subdomain:
        return jsonify({"error": "target_id and subdomain required"}), 400

    cache_key = f"{subdomain}:{endpoint}"

    # Check cache first (unless force re-analyze)
    if not force:
        with get_conn() as conn:
            cached = conn.execute(
                "SELECT analysis, created_at FROM chain_analyses "
                "WHERE target_id = ? AND subdomain = ? AND endpoint = ?",
                (target_id, subdomain, endpoint),
            ).fetchone()
        if cached:
            return jsonify({
                "analysis": cached["analysis"],
                "cached": True,
                "cached_at": cached["created_at"],
            })

    # Gather all findings for this endpoint
    with get_conn() as conn:
        target = conn.execute("SELECT domain, program_url FROM targets WHERE id = ?", (target_id,)).fetchone()
        domain = target["domain"] if target else subdomain

        vulns = [dict(r) for r in conn.execute(
            "SELECT vuln_type, severity, status, evidence, url FROM vulns "
            "WHERE target_id = ? AND subdomain = ?", (target_id, subdomain),
        ).fetchall()]

        leads = [dict(r) for r in conn.execute(
            "SELECT vuln_class, confidence, sniper_status, lead_data FROM react_leads "
            "WHERE target_id = ? AND subdomain = ? AND endpoint = ?",
            (target_id, subdomain, endpoint),
        ).fetchall()]

    if not vulns and not leads:
        return jsonify({"analysis": "No findings on this endpoint to analyze.", "cached": False})

    # Build the context for Sonnet
    active_section = ""
    dropped_section = ""
    client_side = {"xss", "csrf", "clickjacking", "x-frame-options"}

    for v in vulns:
        vtype = v["vuln_type"].lower()
        is_client = any(cs in vtype for cs in client_side)
        is_low = v["severity"].lower() in ("info", "low")
        entry = f"  - {v['vuln_type']} (Severity: {v['severity']}, Status: {v['status']}): {(v['evidence'] or '')[:200]}"

        if is_client or is_low:
            dropped_section += entry + "\n"
        elif v["status"] in ("reviewed", "needs_review", "approved", "new", "t1_pass"):
            active_section += entry + "\n"
        else:
            dropped_section += entry + "\n"

    for l in leads:
        active_section += f"  - Scout Lead: {l['vuln_class']} (Confidence: {l['confidence']}/10, Sniper: {l['sniper_status']})\n"

    prompt = f"""You are an elite bug bounty hunter. Review the following vulnerabilities found on a single API endpoint. Your ONLY job is to tell me if these low-level/passive bugs can be chained with the active leads to escalate the impact.

TARGET: {subdomain} (program: {domain})
ENDPOINT: {endpoint}

ACTIVE LEADS (confirmed or high-confidence):
{active_section or '  None'}

PASSIVE / DROPPED FINDINGS (low-severity, client-side, or filtered):
{dropped_section or '  None'}

INSTRUCTIONS:
1. If you see a chain that escalates severity, describe it as a numbered 3-step attack chain.
2. Estimate the COMBINED severity (e.g., "XSS + BOLA = Account Takeover → Critical") and approximate HackerOne bounty range.
3. If no obvious chain exists, just say "No chain potential — findings are isolated."

Be concise. Max 200 words."""

    analysis = call_tier("tier2", prompt, max_tokens=500)
    if not analysis:
        return jsonify({"error": "AI unavailable — check budget"}), 503

    # Cache the result
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO chain_analyses (target_id, subdomain, endpoint, analysis, created_at) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            (target_id, subdomain, endpoint, analysis),
        )

    log_activity("chain", f"Chain analysis on {subdomain}{endpoint}")

    # Discord notification if a real chain was found (not "no chain")
    no_chain_signals = ["no chain", "no meaningful chain", "no obvious chain", "no escalation"]
    has_chain = not any(sig in analysis.lower() for sig in no_chain_signals)
    if has_chain:
        try:
            from notifier_discord import notify_chain_found
            target_row = conn.execute("SELECT domain FROM targets WHERE id = ?", (target_id,)).fetchone() if target_id else None
            notify_chain_found(subdomain, endpoint, analysis, domain=target_row["domain"] if target_row else "")
        except Exception:
            pass

    return jsonify({
        "analysis": analysis,
        "cached": False,
        "cost_note": "~$0.01-0.03 (Sonnet)",
    })


@app.route("/api/threat_matrix_targets")
@login_required
def api_threat_matrix_targets():
    """List targets that have findings, for the Threat Matrix tab selector."""
    from db import get_conn
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT t.id, t.domain, t.program_url,
                   COUNT(DISTINCT v.id) as vuln_count,
                   COUNT(DISTINCT l.id) as lead_count,
                   COUNT(DISTINCT a.id) as schema_count
            FROM targets t
            LEFT JOIN vulns v ON v.target_id = t.id
                AND v.status NOT IN ('filtered')
                AND v.vuln_type NOT LIKE 'cors%'
            LEFT JOIN react_leads l ON l.target_id = t.id
            LEFT JOIN api_schemas a ON a.target_id = t.id
            WHERE t.scope_status = 'in_scope'
            GROUP BY t.id
            HAVING vuln_count > 0 OR lead_count > 0
            ORDER BY lead_count DESC, vuln_count DESC
        """).fetchall()]
    return jsonify({"targets": rows})


def main():
    init_db()
    config = _load_config()
    dash = config.get("dashboard", {})
    app.run(host=dash.get("host", "0.0.0.0"), port=dash.get("port", 5000), debug=False)


if __name__ == "__main__":
    main()
