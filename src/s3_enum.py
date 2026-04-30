"""
S3 Bucket Enumeration — Checks common bucket naming patterns for public access.
Publicly listable S3 buckets are a high-severity finding for bug bounty.
"""
import logging
import re
import time
import requests

log = logging.getLogger("hunter")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0"}

# Suffixes to append to company/domain name
BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-bak", "-dev", "-development",
    "-staging", "-stg", "-prod", "-production", "-test", "-testing",
    "-assets", "-static", "-media", "-uploads", "-files", "-data",
    "-logs", "-public", "-private", "-internal", "-archive",
    "-docs", "-documents", "-images", "-cdn", "-content",
    "-db", "-database", "-dump", "-export", "-import",
    "-s3", "-aws", "-cloud", "-storage", "-web", "-api",
]


def _check_bucket(bucket_name):
    """Check if an S3 bucket is publicly accessible. Returns (exists, listable, status)."""
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if resp.status_code == 200:
            if "<ListBucketResult" in resp.text[:500]:
                return True, True, resp.status_code  # Publicly listable
            return True, False, resp.status_code  # Exists but content unclear
        if resp.status_code == 403:
            return True, False, resp.status_code  # Exists, access denied
        return False, False, resp.status_code  # Doesn't exist
    except Exception:
        return False, False, 0


def check_s3_buckets(domain, company_name=None, target_id=None):
    """Enumerate common S3 bucket names based on domain and company name."""
    from db import insert_vuln, log_activity

    # Generate candidate names
    candidates = set()

    # From domain: example.com → example
    domain_base = domain.split(".")[0].lower()
    candidates.add(domain_base)

    # From company name if provided
    if company_name:
        clean = re.sub(r"[^a-z0-9]", "-", company_name.lower()).strip("-")
        candidates.add(clean)
        # Also try without dashes
        candidates.add(clean.replace("-", ""))

    # From full domain: example.com → example-com, example.com
    domain_dashed = domain.replace(".", "-").lower()
    candidates.add(domain_dashed)
    candidates.add(domain.lower())

    # Generate all combinations with suffixes
    all_buckets = set()
    for base in candidates:
        for suffix in BUCKET_SUFFIXES:
            bucket = f"{base}{suffix}"
            if 3 <= len(bucket) <= 63:  # S3 bucket name constraints
                all_buckets.add(bucket)

    log.info(f"  [S3] Checking {len(all_buckets)} bucket name candidates...")

    vulns_found = 0
    for bucket in sorted(all_buckets):
        time.sleep(0.5)  # Rate limit
        exists, listable, status = _check_bucket(bucket)

        if listable:
            evidence = f"S3 bucket publicly listable: {bucket}.s3.amazonaws.com (directory listing enabled)"
            url = f"https://{bucket}.s3.amazonaws.com/"

            if target_id:
                insert_vuln(target_id, domain, "s3_public_listing", evidence, "High", url)

            log_activity("vuln", f"S3 BUCKET High: {bucket} is publicly listable!")
            log.info(f"  *** S3 PUBLIC: {bucket}.s3.amazonaws.com")
            vulns_found += 1

    return vulns_found
