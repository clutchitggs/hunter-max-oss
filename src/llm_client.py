"""
Tiered LLM Client v15 — 5-tier pipeline.

Tier 1: GPT-4o-mini    — cheap triage
Tier 2: Claude Sonnet   — investigate + assess
Tier 3: Claude Sonnet   — devil's advocate on T2 low-confidence rejections
Tier 4: Claude Opus     — final verdict + report
Tier 5: Claude Opus     — devil's advocate on T4 low-confidence rejections

Budget tracking per-tier with daily resets.
"""
import json
import os
import re
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env", override=True)

CONFIG_PATH = ROOT / "config.json"
BUDGET_FILE = ROOT / "data" / "budget.json"

# Model definitions with pricing (per 1M tokens, April 2026)
# 3-tier: mini (triage) → Sonnet (investigate) → Opus (verdict)
TIERS = {
    "tier1": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "input_price": 0.15,
        "output_price": 0.60,
        "max_tokens_default": 200,
        "api_key_env": "OPENAI_API_KEY",
    },
    "tier2": {
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
        "input_price": 3.00,
        "output_price": 15.00,
        "max_tokens_default": 600,
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "tier3": {
        "provider": "anthropic",
        "model": "claude-opus-4-6",
        "input_price": 15.00,
        "output_price": 75.00,
        "max_tokens_default": 1000,
        "api_key_env": "ANTHROPIC_API_KEY",
    },
}


def _load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _load_budget():
    if BUDGET_FILE.exists():
        with open(BUDGET_FILE) as f:
            return json.load(f)
    return {"total_spent": 0.0, "calls": 0, "per_tier": {}}


def _save_budget(data):
    BUDGET_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(BUDGET_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _get_tier_data(budget, tier):
    """Get or initialize per-tier tracking data with daily reset."""
    today = date.today().isoformat()
    per_tier = budget.setdefault("per_tier", {})
    td = per_tier.setdefault(tier, {
        "spent_today": 0.0, "spent_total": 0.0,
        "calls_today": 0, "calls_total": 0,
        "last_reset": today,
    })
    # Daily budget reset
    if td.get("last_reset") != today:
        td["spent_today"] = 0.0
        td["calls_today"] = 0
        td["last_reset"] = today
    return td


def _estimate_cost(input_tokens, output_tokens, tier_info):
    return (input_tokens * tier_info["input_price"] + output_tokens * tier_info["output_price"]) / 1_000_000


def _get_anthropic_spent(budget):
    """Sum up Anthropic-only spending (tier2 + tier3)."""
    per_tier = budget.get("per_tier", {})
    t2 = per_tier.get("tier2", {}).get("spent_total", 0)
    t3 = per_tier.get("tier3", {}).get("spent_total", 0)
    return t2 + t3


def get_budget_status():
    """Overall budget status based on actual Anthropic balance."""
    config = _load_config()
    llm_cfg = config.get("llm", {})
    anthropic_balance = llm_cfg.get("anthropic_balance_usd", 10.0)
    stop_threshold = llm_cfg.get("stop_at_remaining_usd", 1.0)
    budget = _load_budget()
    anthropic_spent = _get_anthropic_spent(budget)
    remaining = anthropic_balance - anthropic_spent
    return {
        "spent": round(budget.get("total_spent", 0), 4),
        "anthropic_spent": round(anthropic_spent, 4),
        "limit": anthropic_balance,
        "remaining": round(remaining, 4),
        "calls": budget.get("calls", 0),
        "ok": remaining > stop_threshold,
    }


def get_tier_budgets():
    """Per-tier budget breakdown for dashboard."""
    config = _load_config()
    tier_config = config.get("tiers", {})
    budget = _load_budget()
    result = {}
    for tier_name in TIERS:
        td = _get_tier_data(budget, tier_name)
        tc = tier_config.get(tier_name, {})
        daily_limit = tc.get("daily_budget_usd", 0.10)
        result[tier_name] = {
            "spent_today": round(td["spent_today"], 6),
            "spent_total": round(td["spent_total"], 4),
            "daily_limit": daily_limit,
            "daily_remaining": round(daily_limit - td["spent_today"], 6),
            "calls_today": td["calls_today"],
            "calls_total": td["calls_total"],
            "enabled": tc.get("enabled", True),
            "model": TIERS[tier_name]["model"],
        }
    return result


def call_tier(tier, prompt, max_tokens=None):
    """
    Call a specific tier model with budget tracking.
    Returns response text, or None if budget exceeded / unavailable.
    """
    if tier not in TIERS:
        return None

    tier_info = TIERS[tier]
    config = _load_config()

    # Check if tier is enabled
    tier_config = config.get("tiers", {}).get(tier, {})
    if not tier_config.get("enabled", True):
        return None

    # Check Anthropic balance for Anthropic tiers (tier2/tier3)
    llm_cfg = config.get("llm", {})
    budget = _load_budget()

    if tier_info["provider"] == "anthropic":
        anthropic_balance = llm_cfg.get("anthropic_balance_usd", 10.0)
        stop_threshold = llm_cfg.get("stop_at_remaining_usd", 1.0)
        anthropic_spent = _get_anthropic_spent(budget)
        remaining = anthropic_balance - anthropic_spent
        if remaining <= stop_threshold:
            return None

    # Check per-tier daily budget
    td = _get_tier_data(budget, tier)
    daily_limit = tier_config.get("daily_budget_usd", 0.10)
    if td["spent_today"] >= daily_limit:
        return None

    # Get API key
    api_key = os.environ.get(tier_info["api_key_env"], "")
    if not api_key:
        import logging
        logging.getLogger("hunter").warning(f"  [LLM-{tier}] No API key for {tier_info['api_key_env']}")
        return None

    if max_tokens is None:
        max_tokens = tier_info["max_tokens_default"]

    try:
        provider = tier_info["provider"]
        model = tier_info["model"]

        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0,
            )
            text = resp.choices[0].message.content.strip()
            cost = _estimate_cost(resp.usage.prompt_tokens, resp.usage.completion_tokens, tier_info)

        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            resp = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text.strip()
            cost = _estimate_cost(resp.usage.input_tokens, resp.usage.output_tokens, tier_info)

        else:
            return None

        # Track spending
        budget["total_spent"] = budget.get("total_spent", 0) + cost
        budget["calls"] = budget.get("calls", 0) + 1
        td["spent_today"] += cost
        td["spent_total"] += cost
        td["calls_today"] += 1
        td["calls_total"] += 1
        _save_budget(budget)

        # Low balance alert — fires once when Anthropic balance hits stop threshold
        if tier_info["provider"] == "anthropic":
            anthropic_balance = llm_cfg.get("anthropic_balance_usd", 10.0)
            stop_threshold = llm_cfg.get("stop_at_remaining_usd", 1.0)
            anthropic_spent = _get_anthropic_spent(budget)
            remaining = anthropic_balance - anthropic_spent
            if remaining <= stop_threshold and not budget.get("_low_balance_alerted"):
                budget["_low_balance_alerted"] = True
                _save_budget(budget)
                try:
                    from notifier_discord import notify_pipeline_status
                    notify_pipeline_status(
                        f"SYSTEM STOPPED — Anthropic balance hit ${remaining:.2f} remaining. "
                        f"Spent: ${anthropic_spent:.2f} of ${anthropic_balance:.2f}. "
                        f"All AI calls paused. Top up Anthropic, update anthropic_balance_usd in config.json, "
                        f"and restart the scanner."
                    )
                except Exception:
                    pass
                import logging
                logging.getLogger("hunter").warning(f"  [BUDGET] STOPPED: Anthropic ${remaining:.2f} remaining")

        return text

    except Exception as e:
        import logging
        logging.getLogger("hunter").warning(f"  [LLM-{tier}] API Error: {e}")
        return None


def call_llm(prompt, max_tokens=200):
    """Backward-compatible wrapper — calls Tier 1 (GPT-4o-mini)."""
    return call_tier("tier1", prompt, max_tokens)


def extract_companies(title):
    """Use LLM to extract acquirer and target from a headline."""
    prompt = (
        f'Extract the acquiring company and acquired company from this M&A headline.\n'
        f'Headline: "{title}"\n'
        f'Return ONLY valid JSON: {{"acquirer": "...", "target": "...", "target_domain": "..."}}\n'
        f'For target_domain, use the actual company domain (e.g., "wiz.io" not "wizinc.com").\n'
        f'If unsure of the domain, guess: lowercase company name + ".com".\n'
        f'If this headline is NOT about a corporate acquisition, return {{"acquirer": null, "target": null, "target_domain": null}}'
    )

    text = call_tier("tier1", prompt, max_tokens=150)
    if not text:
        return None

    try:
        text = re.sub(r"```json?\s*", "", text).replace("```", "").strip()
        data = json.loads(text)
        if data.get("acquirer") and data.get("target"):
            return data
    except (json.JSONDecodeError, ValueError):
        pass

    return None


def draft_report_llm(subdomain, cname, provider, fingerprint, domain, acquirer):
    """Use Tier 4 (Opus) to draft a professional vulnerability report."""
    prompt = f"""Write a professional HackerOne subdomain takeover vulnerability report in Markdown.

Facts:
- Subdomain: {subdomain}
- CNAME points to: {cname}
- Cloud provider: {provider}
- HTTP fingerprint: {fingerprint}
- Parent domain: {domain}
- Acquirer: {acquirer}

Include these sections:
1. **Summary** (2-3 sentences)
2. **Severity** (Medium, with justification)
3. **Steps to Reproduce** (numbered, verifiable)
4. **Impact** (phishing, cookie theft, session hijacking)
5. **Remediation** (actionable steps)

Be concise, factual, professional."""

    # Try Tier 4 first, fall back to Tier 3, then Tier 2
    for tier in ["tier4", "tier3", "tier2"]:
        result = call_tier(tier, prompt, max_tokens=800)
        if result:
            return result
    return None
