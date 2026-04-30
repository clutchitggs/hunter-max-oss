"""
CLI entry: python -m src.deep_read <subdomain> [options]

Auth model — the operator does the authentication in a normal browser
session and the tool simply rides that session:

  1. Log into the target in Chrome (handle WAF / 2FA / SSO manually).
  2. DevTools → Network → copy the Cookie header from any XHR.
  3. Pass it via --cookie "name=val; name=val".
  4. (Optional) --header "Authorization: Bearer xxx" for token-auth APIs,
     or --header "X-CSRF-Token: xxx" when endpoints require it.
     --header is repeatable.

Examples:
  python -m src.deep_read app.example.com
  python -m src.deep_read app.example.com --cookie "session=abc; csrf=def"
  python -m src.deep_read api.example.com --header "Authorization: Bearer eyJ..."
"""
import argparse
import logging
import sys
from pathlib import Path

from . import fetcher, js_parser, spec_finder, analyzer, report

log = logging.getLogger("hunter.deep_read")

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "reports" / "deep_read"


def _parse_headers(header_args):
    """Turn ['Authorization: Bearer x', 'X-Foo: bar'] into {'Authorization':'Bearer x', ...}."""
    out = {}
    for raw in header_args or []:
        if ":" not in raw:
            log.warning(f"--header skipped (no colon): {raw}")
            continue
        name, _, value = raw.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        out[name] = value
    return out


def run_deep_read(target, use_ai=True, out_path=None, cookie=None, headers=None):
    """
    Full pipeline for a target subdomain.
    Returns (markdown, out_path, stats).
    """
    log.info(f"[deep_read] fetching {target} (auth={'yes' if cookie else 'no'})")
    fetch_data = fetcher.fetch_target(target, cookie=cookie, extra_headers=headers)
    for n in fetch_data.get("notes") or []:
        log.info(f"[deep_read] {n}")

    log.info(f"[deep_read] parsed {len(fetch_data.get('bundles') or [])} bundles")
    endpoints = js_parser.extract_all(fetch_data.get("bundles") or [])

    log.info(f"[deep_read] probing specs")
    specs = spec_finder.find_specs(target, cookie=cookie, extra_headers=headers)

    # Categorize for logging
    by_kind = {}
    for ep in endpoints:
        by_kind[ep["kind"]] = by_kind.get(ep["kind"], 0) + 1
    high_signal = sum(1 for ep in endpoints if ep["high_signal"])
    log.info(f"[deep_read] endpoints={len(endpoints)} by_kind={by_kind} "
             f"high_signal={high_signal} "
             f"openapi={bool(specs.get('openapi'))} graphql={bool(specs.get('graphql'))}")

    analysis = None
    if use_ai:
        log.info("[deep_read] running Claude reasoning pass")
        analysis = analyzer.analyze(target, fetch_data, endpoints, specs)
    else:
        log.info("[deep_read] --no-ai: skipping reasoning pass")

    md = report.render(target, fetch_data, endpoints, specs, analysis or {})

    if out_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        safe = target.replace(":", "_").replace("/", "_")
        ts = __import__("datetime").datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"{safe}_{ts}.md"
    Path(out_path).write_text(md, encoding="utf-8")
    log.info(f"[deep_read] report written to {out_path}")

    return md, out_path, {
        "endpoints": len(endpoints),
        "by_kind": by_kind,
        "high_signal": high_signal,
        "openapi": bool(specs.get("openapi")),
        "graphql": bool(specs.get("graphql")),
        "hypotheses": len((analysis or {}).get("hypotheses") or []),
        "killed": len((analysis or {}).get("killed") or []),
        "authenticated": bool(cookie),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Deep Read — JS-bundle reasoning for bug bounty triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("target", help="subdomain e.g. app.example.com")
    ap.add_argument("--no-ai", action="store_true",
                    help="skip Claude reasoning pass (cheap dry-run)")
    ap.add_argument("--out", default=None, help="output markdown path")
    ap.add_argument("--cookie", default=None,
                    help='full Cookie header value, e.g. "session=abc; csrf=def"')
    ap.add_argument("--header", action="append", default=[],
                    help='extra header "Name: value" (repeatable)')
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = _parse_headers(args.header)

    md, path, stats = run_deep_read(
        args.target,
        use_ai=not args.no_ai,
        out_path=args.out,
        cookie=args.cookie,
        headers=headers,
    )
    print(f"\n=== Deep Read: {args.target} ===")
    print(f"authenticated={stats['authenticated']}  endpoints={stats['endpoints']}  "
          f"high_signal={stats['high_signal']}  by_kind={stats['by_kind']}")
    print(f"openapi={stats['openapi']}  graphql={stats['graphql']}  "
          f"hypotheses={stats['hypotheses']}  killed={stats['killed']}")
    print(f"report: {path}")


if __name__ == "__main__":
    main()
