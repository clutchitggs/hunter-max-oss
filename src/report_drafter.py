"""
Report Drafter — generates professional HackerOne-format vulnerability reports.
Uses LLM if configured, falls back to template-based generation.
"""
import json
from datetime import datetime
from pathlib import Path

from db import get_finding, update_finding_report, log_activity

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
REPORTS_DIR = ROOT / "reports"


def _load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _llm_draft(finding, config):
    """Use LLM API to draft a polished report."""
    llm_conf = config.get("llm", {})
    provider = llm_conf.get("provider", "none")
    api_key = llm_conf.get("api_key", "")

    if provider == "none" or not api_key:
        return None

    prompt = f"""You are a professional security researcher writing a bug bounty report for HackerOne.

A subdomain takeover vulnerability was found:
- Subdomain: {finding['subdomain']}
- CNAME target: {finding['cname_target']}
- Cloud provider: {finding['provider']}
- HTTP fingerprint: {finding['fingerprint']}
- Target domain: {finding.get('target_domain', 'unknown')}

Write a professional vulnerability report in Markdown with these sections:
1. **Summary** (2-3 sentences)
2. **Severity** (Medium, with justification)
3. **Steps to Reproduce** (numbered, verifiable by the security team)
4. **Impact** (what an attacker could do: phishing, cookie theft, session hijacking)
5. **Remediation** (specific actionable steps)

Be concise, factual, and professional. No speculation."""

    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
            )
            return resp.choices[0].message.content

        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text

    except Exception as e:
        print(f"  [WARN] LLM draft failed: {e}")
        return None


def _template_draft(finding):
    """Fallback template-based report generation."""
    sub = finding["subdomain"]
    cname = finding["cname_target"]
    provider = finding["provider"]
    fingerprint = finding["fingerprint"]
    target_domain = finding.get("target_domain", "unknown")

    return f"""# Subdomain Takeover Vulnerability — {sub}

## Summary
A dangling CNAME record on `{sub}` points to `{cname}` ({provider}).
The underlying cloud resource is unclaimed, allowing an attacker to register it and
serve arbitrary content on `{sub}`.

## Severity
**Medium** — upgradeable to High if the subdomain handles authentication, API traffic,
or is referenced by the main application for loading scripts/assets.

## Steps to Reproduce
1. Run `dig CNAME {sub}` to confirm the CNAME record points to `{cname}`.
2. Visit `https://{sub}` in a browser.
3. Observe the error page with fingerprint: `{fingerprint}`.
4. This confirms the {provider} resource is unclaimed and available for registration.

## Impact
An attacker who claims the orphaned {provider} resource could:
- **Phishing**: Serve a convincing login page on `{sub}` (trusted subdomain of `{target_domain}`).
- **Cookie theft**: If `{target_domain}` sets cookies on `*.{target_domain}`, the attacker can read them.
- **Session hijacking**: Stolen cookies could grant access to authenticated sessions.
- **Reputation damage**: Serve malware or defacement content under the trusted domain.

## Remediation
1. **Remove** the stale CNAME record for `{sub}` from your DNS configuration.
2. Alternatively, **re-provision** the {provider} resource to reclaim the endpoint.
3. Audit other subdomains for similar dangling records.
"""


def draft_report(finding_id):
    """Generate a report for a finding. Returns the Markdown text."""
    finding = get_finding(finding_id)
    if not finding:
        return None

    config = _load_config()

    # Try LLM first, fall back to template
    report = _llm_draft(dict(finding), config)
    if not report:
        report = _template_draft(dict(finding))

    # Save to DB
    update_finding_report(finding_id, report)

    # Save to file
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = finding["subdomain"].replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    path = REPORTS_DIR / f"{slug}_{ts}.md"
    with open(path, "w") as f:
        f.write(report)

    log_activity("report", f"Report drafted for {finding['subdomain']}")
    return report
