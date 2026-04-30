"""
Notifier — sends Telegram alerts when findings are discovered.
"""
import json
from pathlib import Path

import requests

from db import update_finding_status, log_activity

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"


def _load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def send_telegram(message):
    """Send a message via Telegram bot."""
    config = _load_config()
    notif = config.get("notification", {})

    if not notif.get("enabled"):
        return False

    token = notif.get("telegram_token", "")
    chat_id = notif.get("telegram_chat_id", "")
    if not token or not chat_id:
        return False

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown",
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"  [WARN] Telegram send failed: {e}")
        return False


def alert_finding(finding):
    """Send a Telegram alert for a new finding and update its status."""
    sub = finding["subdomain"]
    provider = finding["provider"]
    severity = finding.get("severity", "Medium")
    cname = finding["cname_target"]

    message = (
        f"*FINDING ALERT*\n\n"
        f"Subdomain: `{sub}`\n"
        f"CNAME: `{cname}`\n"
        f"Provider: {provider}\n"
        f"Severity: {severity}\n\n"
        f"Check dashboard to approve/skip."
    )

    sent = send_telegram(message)
    update_finding_status(finding["id"], "alerted")
    log_activity("alert", f"{'Telegram sent' if sent else 'Alert logged (Telegram disabled)'}: {sub}")
    return sent
