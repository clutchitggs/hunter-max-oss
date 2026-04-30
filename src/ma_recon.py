"""
M&A Reconnaissance News Crawler (v10 — Hunter-Max)
Monitors RSS feeds, extracts companies via LLM or regex, writes to SQLite.

Usage:
    python src/ma_recon.py              # Scan configured RSS feeds
    python src/ma_recon.py --recent 3   # Only entries from last 3 days
"""
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from time import mktime

try:
    import feedparser
except ImportError:
    print("Missing dependency: pip install feedparser")
    sys.exit(1)

try:
    import requests as _requests
except ImportError:
    _requests = None

from db import insert_acquisition, insert_target, log_activity, count_acquisitions, get_conn

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


# --- LLM Extraction ---

def _llm_extract(title, config):
    """Use LLM to extract acquirer and target from a headline."""
    try:
        from llm_client import extract_companies
        return extract_companies(title)
    except ImportError:
        pass

    # Inline fallback if llm_client not available
    llm_conf = config.get("llm", {})
    provider = llm_conf.get("provider", "none")
    api_key = llm_conf.get("api_key", "")

    if provider == "none" or not api_key:
        return None

    prompt = (
        f'Extract the acquiring company and acquired company from this headline.\n'
        f'Headline: "{title}"\n'
        f'Return ONLY valid JSON: {{"acquirer": "...", "target": "...", "target_domain": "..."}}\n'
        f'If you cannot determine the domain, guess it as the company name lowercased with no spaces + ".com".\n'
        f'If this is not about a corporate acquisition, return {{"acquirer": null, "target": null, "target_domain": null}}'
    )

    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150,
                temperature=0,
            )
            text = resp.choices[0].message.content.strip()
        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=150,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text.strip()
        else:
            return None

        # Parse JSON from response (handle markdown code blocks)
        text = re.sub(r"```json?\s*", "", text).replace("```", "").strip()
        data = json.loads(text)
        if data.get("acquirer") and data.get("target"):
            return data
    except Exception as e:
        print(f"  [WARN] LLM extraction failed: {e}")

    return None


# --- Regex Fallback ---

def strip_html(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&\w+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def regex_extract(title):
    """Regex-based extraction as LLM fallback."""
    patterns = [
        r"(.{2,40}?)\s+(?:acquires|to acquire|to buy|has acquired|buys)\s+(.{2,40}?)(?:\s+for|\s+in|\.|,|$)",
        r"(.{2,40}?)\s+(?:completes? acquisition of|completed? its? purchase of)\s+(.{2,40}?)(?:\s+for|\.|,|$)",
    ]

    # Strip source attribution from Google News titles
    if " - " in title:
        title = title.rsplit(" - ", 1)[0]

    text = strip_html(title)
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            acquirer = matches[0][0].strip().strip('"\'')
            target = matches[0][1].strip().strip('"\'')
            if len(acquirer) > 2 and len(target) > 2:
                domain = re.sub(r"[^a-z0-9]", "", target.lower()) + ".com"
                return {"acquirer": acquirer, "target": target, "target_domain": domain}

    return None


# --- Feed Fetching ---

def fetch_and_store(config, max_age_days=None, stop_check=None):
    """Fetch RSS feeds, extract companies, store in database.

    stop_check: optional callable returning True to abort between feeds.
    Used by the pipeline to short-circuit on shutdown so SIGTERM doesn't
    block until all 7 feeds finish (each up to 8s) and trigger a SIGKILL.
    """
    keywords = config.get("acquisition_keywords", [])
    new_count = 0
    total_count = 0

    for feed_url in config.get("feeds", []):
        if stop_check and stop_check():
            return total_count, new_count
        print(f"  Fetching {feed_url[:60]}...")
        try:
            if _requests:
                resp = _requests.get(feed_url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                feed = feedparser.parse(resp.content)
            else:
                feed = feedparser.parse(feed_url)
        except Exception as e:
            print(f"  [WARN] Failed to fetch: {e}")
            continue

        for entry in feed.entries:
            title = entry.get("title", "")
            link = entry.get("link", "")
            published = entry.get("published", "")

            # Strip source from Google News
            title_clean = title.rsplit(" - ", 1)[0] if " - " in title else title
            text = f"{title_clean} {entry.get('summary', '')}".lower()

            # Age filter
            if max_age_days and hasattr(entry, "published_parsed") and entry.published_parsed:
                pub_time = datetime.fromtimestamp(mktime(entry.published_parsed), tz=timezone.utc)
                cutoff = datetime.now(tz=timezone.utc) - timedelta(days=max_age_days)
                if pub_time < cutoff:
                    continue

            if not any(kw in text for kw in keywords):
                continue

            total_count += 1

            # Skip LLM call if this link is already in DB
            with get_conn() as conn:
                exists = conn.execute("SELECT id FROM acquisitions WHERE link = ?", (link,)).fetchone()
            if exists:
                continue

            # Extract companies: LLM first, regex fallback
            extracted = _llm_extract(title_clean, config)
            if not extracted:
                extracted = regex_extract(title_clean)

            acquirer = extracted["acquirer"] if extracted else None
            target_co = extracted["target"] if extracted else None
            target_domain = extracted["target_domain"] if extracted else None

            # Store acquisition
            acq_id = insert_acquisition(
                title=title, link=link, published=published,
                source=feed_url, acquirer=acquirer,
                target_company=target_co, target_domain=target_domain,
            )

            if acq_id:  # New entry (not duplicate)
                new_count += 1
                # Create target if domain was extracted
                if target_domain:
                    insert_target(target_domain, acquisition_id=acq_id)

    return total_count, new_count


def main():
    import argparse
    parser = argparse.ArgumentParser(description="M&A News Crawler")
    parser.add_argument("--recent", type=int, default=None, help="Only entries from last N days")
    args = parser.parse_args()

    config = load_config()
    feeds = config.get("feeds", [])
    print(f"[{datetime.now().isoformat()}] Scanning {len(feeds)} RSS feeds...")

    total, new = fetch_and_store(config, max_age_days=args.recent)
    log_activity("crawl", f"Scanned {len(feeds)} feeds: {total} matches, {new} new")
    print(f"Results: {total} matches, {new} new. Total in DB: {count_acquisitions()}")


if __name__ == "__main__":
    main()
