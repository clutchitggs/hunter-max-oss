"""
Discord Webhook Notifier v2 — Complete notification system.

The system filters. We verify. Then submit.

NOTIFICATION TRIGGERS (ordered by priority):

1. REPORT READY (red/orange embed + .txt file)
   - T4 Opus approves a finding
   - T5 devil's advocate escalates
   - Sniper confirms a vulnerability

2. ENRICHER CONFIRMED (green embed)
   - Enrichment HTTP checks confirm a High/Critical finding
   - Real HTTP proof, not AI guess — worth immediate attention

3. SCOUT LEAD (blue embed)
   - Scout found a lead with confidence >= 6
   - Sniper will verify, but you know it's coming

4. CHAIN POTENTIAL (purple text)
   - Mixed vuln classes on same subdomain
   - Deduplicated: one notification per subdomain

5. SYSTEM STATUS (plain text)
   - Budget alerts, pipeline start/stop
"""
import io
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

log = logging.getLogger("hunter")

ROOT = Path(__file__).resolve().parent.parent


def _load_webhook_url():
    """Load Discord webhook URL from .env or config.json."""
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=True)
    url = os.environ.get("DISCORD_WEBHOOK_URL", "")
    if url:
        return url
    try:
        with open(ROOT / "config.json") as f:
            return json.load(f).get("discord", {}).get("webhook_url", "")
    except Exception:
        return ""


def _send(payload, webhook_url=None):
    """Send a webhook payload. Returns True on success."""
    url = webhook_url or _load_webhook_url()
    if not url:
        return False
    try:
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def _send_with_file(embed, file_content, filename, webhook_url=None):
    """Send an embed card + a downloadable .txt file as two messages."""
    url = webhook_url or _load_webhook_url()
    if not url:
        return False
    try:
        # First: embed card with @everyone
        requests.post(url, json={
            "username": "Hunter-Max",
            "content": "@everyone",
            "embeds": [embed],
            "allowed_mentions": {"parse": ["everyone"]},
        }, timeout=10)

        # Second: file below the card
        resp = requests.post(url,
            data={"payload_json": json.dumps({
                "username": "Hunter-Max",
                "content": "Download and paste to Claude for manual validation:",
            })},
            files={"file": (filename, io.BytesIO(file_content.encode("utf-8")), "text/plain")},
            timeout=15,
        )
        return resp.status_code in (200, 204)
    except Exception as e:
        log.warning(f"[DISCORD] Error: {e}")
        return False


# =====================================================================
# 1. REPORT READY — T4 approved / T5 escalated / Sniper confirmed
# =====================================================================

def notify_finding_ready(vuln_data):
    """Report-ready finding with downloadable validation file."""
    vid = vuln_data.get("id", "?")
    subdomain = vuln_data.get("subdomain", "unknown")
    vuln_type = vuln_data.get("vuln_type", "unknown").replace("_", " ")
    severity = vuln_data.get("severity", "Medium")
    url = vuln_data.get("url", "")
    domain = vuln_data.get("target_domain", subdomain)
    program_url = vuln_data.get("program_url", "")
    source = vuln_data.get("source", "pipeline")
    status = vuln_data.get("status", "reviewed")

    colors = {"Critical": 0xFF0000, "High": 0xFF6600, "Medium": 0xFFCC00, "Low": 0x888888}

    if status == "needs_review":
        title = f"NEEDS REVIEW: {vuln_type} on {subdomain}"
        desc = "T5 challenged this finding. Might be real — needs manual verification."
    else:
        title = f"REPORT READY: {vuln_type} on {subdomain}"
        desc = "Pipeline approved. Ready for manual validation before submission."

    embed = {
        "title": title, "description": desc,
        "color": colors.get(severity, 0x5865F2),
        "fields": [
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "Type", "value": vuln_type, "inline": True},
            {"name": "Source", "value": source, "inline": True},
            {"name": "Target", "value": f"`{subdomain}`", "inline": False},
            {"name": "URL", "value": url[:200] if url else "N/A", "inline": False},
        ],
        "footer": {"text": f"Finding #{vid} | {domain}"},
    }
    if program_url:
        embed["fields"].append({"name": "Program", "value": program_url, "inline": False})

    file_content = f"""HUNTER-MAX FINDING — MANUAL VALIDATION REQUIRED
{'='*60}

Finding ID: #{vid}
Status: {status}
Source: {source}
Timestamp: {datetime.utcnow().isoformat()}Z

TARGET
  Subdomain: {subdomain}
  Domain: {domain}
  URL: {url}
  Program: {program_url or 'N/A'}

CLASSIFICATION
  Type: {vuln_type}
  Severity: {severity}

EVIDENCE
{vuln_data.get('evidence', 'N/A')}

ENRICHED EVIDENCE
{vuln_data.get('enriched_evidence', 'N/A')}

AI PIPELINE RESULTS
  T1: {vuln_data.get('t1_result', 'N/A')}
  T2: {vuln_data.get('t2_result', 'N/A')}

REPORT (AI-generated — needs manual verification)
{'='*60}
{vuln_data.get('report_md', 'No report generated')}
{'='*60}

NEXT STEPS:
1. Paste this file to Claude
2. Claude will make live HTTP requests to verify
3. If confirmed, submit to HackerOne
4. If false positive, skip
"""

    ok = _send_with_file(embed, file_content, f"finding_{vid}_{subdomain.replace('.', '_')}.txt")
    if ok:
        log.info(f"[DISCORD] REPORT READY: {vuln_type} on {subdomain} (#{vid})")
    return ok


# =====================================================================
# 2. ENRICHER CONFIRMED — High/Critical finding verified by HTTP
# =====================================================================

def notify_enricher_confirmed(vuln_data):
    """Enrichment HTTP checks confirmed a High/Critical finding.
    Real HTTP proof — not AI guess. Worth immediate attention."""
    subdomain = vuln_data.get("subdomain", "unknown")
    vuln_type = vuln_data.get("vuln_type", "unknown").replace("_", " ")
    severity = vuln_data.get("severity", "Medium")
    url = vuln_data.get("url", "")
    enriched = vuln_data.get("enriched_evidence", "")
    domain = vuln_data.get("target_domain", subdomain)

    embed = {
        "title": f"ENRICHER CONFIRMED: {vuln_type} on {subdomain}",
        "description": "HTTP verification confirmed this finding. Real proof, not AI guess. Check before AI triage runs.",
        "color": 0x238636,  # Green
        "fields": [
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "Type", "value": vuln_type, "inline": True},
            {"name": "Target", "value": f"`{subdomain}`", "inline": False},
            {"name": "URL", "value": url[:200] if url else "N/A", "inline": False},
            {"name": "Enrichment Verdict", "value": enriched[:300] if enriched else "N/A", "inline": False},
        ],
        "footer": {"text": domain},
    }

    ok = _send({"username": "Hunter-Max", "content": "@everyone", "embeds": [embed],
                "allowed_mentions": {"parse": ["everyone"]}})
    if ok:
        log.info(f"[DISCORD] ENRICHER CONFIRMED: {vuln_type} on {subdomain}")
    return ok


# =====================================================================
# 3. SCOUT LEAD — High-confidence lead queued for Sniper
# =====================================================================

def notify_scout_lead(lead_data):
    """Scout found a lead. Sniper will verify, but heads up."""
    subdomain = lead_data.get("subdomain", "unknown")
    vuln_class = lead_data.get("vuln_class", "unknown")
    confidence = lead_data.get("confidence", 0)
    endpoint = lead_data.get("endpoint", "/")
    evidence = lead_data.get("initial_evidence", "")
    domain = lead_data.get("domain", subdomain)

    embed = {
        "title": f"SCOUT LEAD: {vuln_class} on {subdomain}{endpoint}",
        "description": f"Scout identified a lead (confidence {confidence}/10). Sniper is verifying.",
        "color": 0x1F6FEB,  # Blue
        "fields": [
            {"name": "Vuln Class", "value": vuln_class, "inline": True},
            {"name": "Confidence", "value": f"{confidence}/10", "inline": True},
            {"name": "Endpoint", "value": f"`{subdomain}{endpoint}`", "inline": False},
            {"name": "Initial Evidence", "value": evidence[:300] if evidence else "N/A", "inline": False},
        ],
        "footer": {"text": domain},
    }

    ok = _send({"username": "Hunter-Max", "content": "@everyone", "embeds": [embed],
                "allowed_mentions": {"parse": ["everyone"]}})
    if ok:
        log.info(f"[DISCORD] SCOUT LEAD: {vuln_class} on {subdomain}{endpoint} (confidence={confidence})")
    return ok


# =====================================================================
# 4. CHAIN POTENTIAL — Mixed vuln classes on same subdomain
# =====================================================================

def notify_chain_found(subdomain, endpoint, analysis, domain=""):
    """Chain analyzer identified a viable attack chain."""
    embed = {
        "title": f"CHAIN DETECTED: {subdomain}{endpoint}",
        "description": "Chain analyzer found a potential attack chain. Needs manual validation.",
        "color": 0xA855F7,  # Purple
        "fields": [
            {"name": "Target", "value": f"`{subdomain}{endpoint}`", "inline": False},
            {"name": "Analysis", "value": analysis[:500], "inline": False},
        ],
        "footer": {"text": domain or subdomain},
    }

    ok = _send({"username": "Hunter-Max", "content": "@everyone", "embeds": [embed],
                "allowed_mentions": {"parse": ["everyone"]}})
    if ok:
        log.info(f"[DISCORD] CHAIN DETECTED: {subdomain}{endpoint}")
    return ok


def notify_chain_potential(subdomain, endpoint, active_types, passive_types, domain=""):
    """Mixed vuln classes detected on same subdomain."""
    ok = _send({
        "username": "Hunter-Max",
        "content": (
            f"@everyone\n"
            f"**[Chain Potential]** `{subdomain}` has mixed findings:\n"
            f"Active: {', '.join(active_types[:5])}\n"
            f"Passive/Dropped: {', '.join(passive_types[:5])}\n"
            f"Consider running chain analysis on the dashboard."
        ),
        "allowed_mentions": {"parse": ["everyone"]},
    })
    if ok:
        log.info(f"[DISCORD] CHAIN POTENTIAL: {subdomain}")
    return ok


# =====================================================================
# 5. SYSTEM STATUS — Budget alerts, pipeline events
# =====================================================================

def notify_pipeline_status(message):
    """Simple status message (budget alerts, start/stop)."""
    return _send({"username": "Hunter-Max", "content": f"**[Pipeline]** {message}"})
