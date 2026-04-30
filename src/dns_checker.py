"""
Dangling CNAME Checker (v10 — Hunter-Max)
Scans in-scope targets from the database for dangling CNAME records.
Only processes targets that have been verified as in-scope by scope_checker.

Usage:
    python src/dns_checker.py                       # Scan all in-scope targets
    python src/dns_checker.py --target-id 5         # Scan a specific target
"""
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import dns.resolver
except ImportError:
    print("Missing dependency: pip install dnspython")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests")
    sys.exit(1)

from db import (
    get_targets, insert_scan, insert_finding, log_activity,
    get_conn,
)

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"

CLOUD_PROVIDERS = {
    "aws_s3": {
        "cname_patterns": [".s3.amazonaws.com", ".s3-website"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    "heroku": {
        "cname_patterns": [".herokuapp.com", ".herokussl.com"],
        "fingerprints": ["no-such-app", "There is no app configured at that hostname"],
    },
    "github_pages": {
        "cname_patterns": [".github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here"],
    },
    "azure": {
        "cname_patterns": [".azurewebsites.net", ".cloudapp.azure.com", ".trafficmanager.net"],
        "fingerprints": ["404 Web Site not found", "This web app is stopped"],
    },
    "vercel": {
        "cname_patterns": [".vercel.app", ".now.sh"],
        "fingerprints": ["The deployment could not be found"],
    },
    "shopify": {
        "cname_patterns": [".myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable"],
    },
}


def _load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def resolve_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        return [str(rdata.target).rstrip(".") for rdata in answers]
    except Exception:
        return []


def check_http_fingerprint(domain, fingerprints):
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{domain}", timeout=10,
                allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"},
            )
            body = resp.text[:5000]
            for fp in fingerprints:
                if fp.lower() in body.lower():
                    return True, fp, resp.status_code
        except Exception:
            continue
    return False, None, None


def enumerate_subdomains(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "60"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
    except FileNotFoundError:
        print(f"  [!] subfinder not installed — skipping subdomain enumeration for {domain}")
    except subprocess.TimeoutExpired:
        print(f"  [!] subfinder timed out for {domain}")
    return []


def scan_target(target_id, domain, delay=2):
    """Scan a single in-scope target. Returns list of finding IDs."""
    config = _load_config()
    scan_delay = config.get("schedule", {}).get("scan_delay_seconds", delay)

    print(f"  Enumerating subdomains for {domain}...")
    subdomains = enumerate_subdomains(domain)

    if not subdomains:
        log_activity("scan", f"No subdomains found for {domain}")
        return []

    print(f"  Found {len(subdomains)} subdomains. Checking CNAME records...")
    log_activity("scan", f"Scanning {len(subdomains)} subdomains for {domain}")

    finding_ids = []
    for i, sub in enumerate(subdomains):
        cnames = resolve_cname(sub)
        if not cnames:
            continue

        for cname in cnames:
            for provider, info in CLOUD_PROVIDERS.items():
                if any(p in cname.lower() for p in info["cname_patterns"]):
                    is_dangling, fingerprint, status = check_http_fingerprint(sub, info["fingerprints"])

                    scan_id = insert_scan(target_id, sub, cname, provider, is_dangling)

                    if is_dangling:
                        finding_id = insert_finding(
                            scan_id=scan_id, target_id=target_id,
                            subdomain=sub, cname_target=cname,
                            provider=provider, fingerprint=fingerprint,
                        )
                        finding_ids.append(finding_id)
                        print(f"  [FINDING] {sub} -> {cname} ({provider})")
                        log_activity("finding", f"Dangling CNAME: {sub} -> {cname} ({provider})")

        if (i + 1) % 25 == 0:
            print(f"  ... checked {i + 1}/{len(subdomains)}")

        time.sleep(scan_delay)

    return finding_ids


def scan_all_in_scope():
    """Scan all in-scope targets that haven't been scanned recently."""
    targets = get_targets(scope_status="in_scope")
    if not targets:
        print("  No in-scope targets to scan.")
        return []

    all_findings = []
    for target in targets:
        findings = scan_target(target["id"], target["domain"])
        all_findings.extend(findings)

    return all_findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Dangling CNAME Scanner")
    parser.add_argument("--target-id", type=int, help="Scan a specific target by ID")
    args = parser.parse_args()

    if args.target_id:
        with get_conn() as conn:
            target = conn.execute("SELECT * FROM targets WHERE id = ?", (args.target_id,)).fetchone()
        if not target:
            print(f"Target {args.target_id} not found.")
            sys.exit(1)
        findings = scan_target(target["id"], target["domain"])
        print(f"Scan complete. {len(findings)} findings.")
    else:
        findings = scan_all_in_scope()
        print(f"Scan complete. {len(findings)} total findings across all in-scope targets.")


if __name__ == "__main__":
    main()
