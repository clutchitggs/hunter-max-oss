"""
Nuclei Integration — Runs ProjectDiscovery's nuclei scanner in batch mode.
6000+ vulnerability templates vs our 17 custom checks. This is the biggest upgrade.
Concurrency settings read from config.json (scanner section).
"""
import json
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger("hunter")

ROOT = Path(__file__).resolve().parent.parent

# Nuclei binary paths (try multiple locations)
NUCLEI_PATHS = [
    "/home/ubuntu/go/bin/nuclei",
    "/usr/local/bin/nuclei",
    "nuclei",
]

# Lean tag set — focused on high-value, fast checks only
NUCLEI_TAGS = "exposure,takeover,misconfig"
NUCLEI_SEVERITY = "medium,high,critical"


def _load_scanner_config():
    """Load scanner settings from config.json."""
    try:
        with open(ROOT / "config.json") as f:
            return json.load(f).get("scanner", {})
    except Exception:
        return {}


def _find_nuclei():
    """Find the nuclei binary."""
    for path in NUCLEI_PATHS:
        try:
            result = subprocess.run([path, "-version"], capture_output=True, timeout=10)
            if result.returncode == 0:
                return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def run_nuclei_batch(live_hosts, target_id=None):
    """
    Run nuclei on a list of live hostnames. Returns count of vulns found.
    Uses batch mode for efficiency — one nuclei invocation for all hosts.
    """
    if not live_hosts:
        return 0

    nuclei_bin = _find_nuclei()
    if not nuclei_bin:
        log.warning("  Nuclei not installed — skipping. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return 0

    # Write hosts to per-target temp files (async-safe — multiple scans can run concurrently)
    suffix = f"_{target_id}" if target_id else f"_{id(live_hosts)}"
    hosts_file = ROOT / "data" / f"nuclei_targets{suffix}.txt"
    output_file = ROOT / "data" / f"nuclei_output{suffix}.jsonl"

    try:
        with open(hosts_file, "w") as f:
            for host in live_hosts:
                f.write(f"https://{host}\n")
                f.write(f"http://{host}\n")

        # Clean previous output for this target
        if output_file.exists():
            output_file.unlink()

        sc = _load_scanner_config()
        rate_limit = str(sc.get("nuclei_rate_limit", 30))
        concurrency = str(sc.get("nuclei_concurrency", 3))
        timeout_sec = sc.get("nuclei_timeout_sec", 300)

        log.info(f"  [NUCLEI] Scanning {len(live_hosts)} live hosts with {NUCLEI_TAGS} templates (c={concurrency}, rl={rate_limit})...")

        cmd = [
            nuclei_bin,
            "-l", str(hosts_file),
            "-tags", NUCLEI_TAGS,
            "-severity", NUCLEI_SEVERITY,
            "-rate-limit", rate_limit,
            "-concurrency", concurrency,
            "-bulk-size", "5",
            "-timeout", "5",
            "-jsonl",
            "-o", str(output_file),
            "-silent",
            "-duc",  # disable update check
            "-page-timeout", "10",
            "-max-host-error", "5",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env={"PATH": "/home/ubuntu/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/home/ubuntu"},
        )

        if result.returncode != 0 and result.stderr:
            log.warning(f"  [NUCLEI] stderr: {result.stderr[:200]}")

        # Parse results
        vulns_found = 0
        if output_file.exists():
            vulns_found = _parse_nuclei_output(output_file, target_id)

        log.info(f"  [NUCLEI] Done — {vulns_found} vulns found")
        return vulns_found

    except subprocess.TimeoutExpired:
        log.warning(f"  [NUCLEI] Timed out after {timeout_sec}s — killing")
        # Kill any lingering nuclei process
        try:
            import os, signal
            os.system("pkill -f nuclei 2>/dev/null")
        except Exception:
            pass
        return 0
    except Exception as e:
        log.warning(f"  [NUCLEI] Failed: {e}")
        return 0
    finally:
        # Clean up both temp files
        for f in (hosts_file, output_file):
            try:
                if f.exists():
                    f.unlink()
            except Exception:
                pass


def _parse_nuclei_output(output_path, target_id):
    """Parse nuclei JSONL output and insert vulns into DB."""
    from db import insert_vuln, log_activity

    count = 0
    seen = set()

    with open(output_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = result.get("template-id", "unknown")
            info = result.get("info", {})
            name = info.get("name", template_id)
            severity = info.get("severity", "medium").capitalize()
            matched_url = result.get("matched-at", "")
            host = result.get("host", "")

            # Extract subdomain from host URL
            subdomain = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

            # Deduplicate within this scan
            dedup_key = f"{subdomain}:{template_id}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # v15 Kill List Filter #2: Hard-drop info/low nuclei findings.
            # These generate hundreds of "Missing Security Header" and "Verbose Error"
            # alerts that cost real money to triage through T1-T5 and always get filtered.
            if severity.lower() in ("info", "low"):
                continue

            vuln_type = f"nuclei:{template_id}"
            evidence = f"{name}"
            matcher = result.get("matcher-name", "")
            extracted = result.get("extracted-results", [])
            if matcher:
                evidence += f" (matcher: {matcher})"
            if extracted:
                evidence += f" | extracted: {', '.join(str(e)[:100] for e in extracted[:3])}"

            if target_id:
                insert_vuln(target_id, subdomain, vuln_type, evidence, severity, matched_url)

            log_activity("vuln", f"NUCLEI {severity}: {name} on {subdomain}")
            count += 1

    return count
