"""
CVE Racing Monitor v13 — Watch for critical CVEs and scan bounty targets.

When a critical CVE drops, the first hunter to check bounty program domains
for that specific vuln gets the bounty. This module:
  1. Fetches recent CVEs from NVD RSS + GitHub Advisory API
  2. Filters for critical/high severity
  3. Cross-references against known program tech stacks
  4. Enqueues matched targets at priority 1 for immediate scanning
"""
import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

try:
    import feedparser
except ImportError:
    feedparser = None

from db import (
    insert_cve_alert, get_recent_cve_ids, get_conn,
    enqueue_scan, log_activity,
)

log = logging.getLogger("hunter")

ROOT = Path(__file__).resolve().parent.parent

# NVD RSS feed for analyzed CVEs
NVD_RSS = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"

# GitHub Advisory API (public, no auth needed for read)
GITHUB_ADVISORY_API = "https://api.github.com/advisories"

# Tech keywords to match CVEs against bounty program targets
# Maps CVE product/vendor keywords to nuclei template tags
TECH_KEYWORDS = {
    "spring": ["spring", "java"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "wordpress": ["wordpress", "wp"],
    "drupal": ["drupal"],
    "jenkins": ["jenkins"],
    "docker": ["docker", "container"],
    "kubernetes": ["kubernetes", "k8s"],
    "nodejs": ["node", "express", "npm"],
    "react": ["react", "next.js", "nextjs"],
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "laravel": ["laravel", "php"],
    "rails": ["rails", "ruby"],
    "grafana": ["grafana"],
    "confluence": ["confluence", "atlassian"],
    "jira": ["jira", "atlassian"],
    "gitlab": ["gitlab"],
    "elasticsearch": ["elastic", "kibana"],
    "redis": ["redis"],
    "mongodb": ["mongodb", "mongo"],
    "postgres": ["postgres", "postgresql"],
    "mysql": ["mysql", "mariadb"],
    "openssl": ["openssl", "tls", "ssl"],
    "log4j": ["log4j", "log4shell"],
    "struts": ["struts"],
    "tomcat": ["tomcat"],
    "iis": ["iis", "microsoft"],
    "exchange": ["exchange", "microsoft"],
    "sharepoint": ["sharepoint", "microsoft"],
    "fortinet": ["fortinet", "fortigate"],
    "paloalto": ["paloalto", "pan-os"],
    "citrix": ["citrix"],
    "vmware": ["vmware", "vcenter"],
    "ivanti": ["ivanti", "pulse"],
    "sonicwall": ["sonicwall"],
}


def fetch_recent_cves(hours=24):
    """
    Fetch critical/high CVEs from NVD RSS + GitHub Advisory API.
    Returns list of {cve_id, description, severity, affected_products, published}.
    """
    cves = []
    known_ids = get_recent_cve_ids()

    # Source 1: NVD RSS
    cves.extend(_fetch_nvd_rss(hours, known_ids))

    # Source 2: GitHub Advisory API
    cves.extend(_fetch_github_advisories(hours, known_ids))

    if cves:
        log_activity("signal", f"CVE monitor found {len(cves)} new critical/high CVEs")

    return cves


def _fetch_nvd_rss(hours, known_ids):
    """Fetch from NVD RSS feed."""
    if not feedparser:
        return []

    cves = []
    try:
        feed = feedparser.parse(NVD_RSS)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        for entry in feed.entries[:50]:  # Last 50 entries
            cve_id = ""
            title = entry.get("title", "")
            # Extract CVE ID from title (format: "CVE-2026-XXXXX")
            match = re.search(r"(CVE-\d{4}-\d+)", title)
            if match:
                cve_id = match.group(1)

            if not cve_id or cve_id in known_ids:
                continue

            description = entry.get("summary", "")[:500]
            published = entry.get("published", "")

            # Filter for severity keywords in description
            desc_lower = description.lower()
            is_critical = any(kw in desc_lower for kw in [
                "critical", "remote code execution", "rce", "authentication bypass",
                "sql injection", "command injection", "arbitrary code",
                "unauthenticated", "pre-auth", "privilege escalation",
            ])
            is_high = any(kw in desc_lower for kw in [
                "high", "information disclosure", "ssrf", "path traversal",
                "directory traversal", "xml injection", "deserialization",
            ])

            if not (is_critical or is_high):
                continue

            severity = "Critical" if is_critical else "High"

            # Extract affected products from description
            products = _extract_products(description)

            cves.append({
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "affected_products": products,
                "published": published,
                "source": "nvd",
            })

    except Exception as e:
        log.warning(f"  [CVE] NVD RSS fetch failed: {e}")

    return cves


def _fetch_github_advisories(hours, known_ids):
    """Fetch from GitHub Advisory API."""
    cves = []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        resp = requests.get(
            GITHUB_ADVISORY_API,
            params={
                "type": "reviewed",
                "severity": "critical,high",
                "per_page": 30,
            },
            headers={"Accept": "application/vnd.github+json", "User-Agent": "Hunter-Max/1.0"},
            timeout=15,
        )

        if resp.status_code != 200:
            return cves

        for advisory in resp.json():
            cve_id = advisory.get("cve_id", "")
            if not cve_id or cve_id in known_ids:
                continue

            published = advisory.get("published_at", "")
            if published and published < cutoff:
                continue

            description = advisory.get("summary", "")[:500]
            severity = advisory.get("severity", "high").capitalize()

            # Extract product from vulnerable packages
            products = []
            for vuln in advisory.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                pkg_name = pkg.get("name", "")
                if pkg_name:
                    products.append(pkg_name)

            products_str = ", ".join(products[:5]) if products else _extract_products(description)

            cves.append({
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "affected_products": products_str,
                "published": published,
                "source": "github",
            })

    except Exception as e:
        log.warning(f"  [CVE] GitHub Advisory fetch failed: {e}")

    return cves


def _extract_products(description):
    """Extract product/tech names from CVE description."""
    desc_lower = description.lower()
    found = []
    for product, keywords in TECH_KEYWORDS.items():
        if any(kw in desc_lower for kw in keywords):
            found.append(product)
    return ", ".join(found[:5]) if found else "unknown"


def match_cves_to_targets(cves):
    """
    Cross-reference CVEs against known program targets.
    Checks vulns table for matching tech stacks (from AI profiling).
    Returns list of (cve, domain, target_id) matches.
    """
    if not cves:
        return []

    matches = []

    with get_conn() as conn:
        # Get all in-scope targets
        targets = conn.execute(
            "SELECT id, domain FROM targets WHERE scope_status = 'in_scope'"
        ).fetchall()

        # Get known tech stacks from AI profiling (stored in vulns/activity_log)
        tech_data = conn.execute(
            "SELECT DISTINCT message FROM activity_log "
            "WHERE event_type = 'scan' AND message LIKE 'AI profiled%' "
            "ORDER BY id DESC LIMIT 500"
        ).fetchall()

    # Build domain -> tech stack mapping
    domain_tech = {}
    for row in tech_data:
        msg = row["message"]
        # Parse "AI profiled subdomain.example.com: Spring Boot, Java"
        match = re.search(r"AI profiled (\S+): (.+)", msg)
        if match:
            sub = match.group(1)
            tech = match.group(2).lower()
            # Map subdomain to parent domain
            parts = sub.split(".")
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                domain_tech[parent] = domain_tech.get(parent, "") + " " + tech

    for cve in cves:
        products = cve.get("affected_products", "").lower()
        desc = cve.get("description", "").lower()
        combined = products + " " + desc

        # Store the CVE alert
        insert_cve_alert(
            cve["cve_id"], cve["description"], cve["severity"],
            cve["affected_products"], cve.get("published", ""),
        )

        # Match against targets
        for target in targets:
            domain = target["domain"]
            target_id = target["id"]

            # Check if any tech keyword from the CVE matches the target's known tech
            target_tech = domain_tech.get(domain, "").lower()

            matched = False
            for product, keywords in TECH_KEYWORDS.items():
                if any(kw in combined for kw in keywords):
                    if any(kw in target_tech for kw in keywords):
                        matched = True
                        break

            if matched:
                matches.append({
                    "cve": cve,
                    "domain": domain,
                    "target_id": target_id,
                })

                log_activity("signal", f"CVE MATCH: {cve['cve_id']} may affect {domain} (tech: {target_tech[:50]})")

                # Enqueue at high priority
                enqueue_scan(
                    target_id, domain, priority=1,
                    source="cve", source_detail=cve["cve_id"]
                )

    if matches:
        log_activity("signal", f"CVE racing: {len(matches)} target matches across {len(cves)} CVEs — enqueued at P1")

    return matches
