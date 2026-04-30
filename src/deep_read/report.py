"""Render a Deep Read result as markdown."""
from datetime import datetime, timezone


def render(target, fetch_data, endpoints, specs, analysis):
    lines = []
    lines.append(f"# Deep Read — `{target}`")
    lines.append(f"_{datetime.now(timezone.utc).isoformat(timespec='seconds')}_")
    lines.append("")

    # Summary
    summary = (analysis or {}).get("summary", "(no analysis)")
    lines.append("## Summary")
    lines.append(summary)
    lines.append("")

    # Hypotheses (the thing Tal actually tests)
    hs = (analysis or {}).get("hypotheses") or []
    lines.append(f"## Hypotheses to test ({len(hs)})")
    if not hs:
        lines.append("_No surviving hypotheses — nothing worth testing from this pass._")
    for i, h in enumerate(hs, 1):
        conf = h.get("confidence", "?")
        bc = h.get("bug_class", "?")
        lines.append(f"### {i}. {h.get('title','(untitled)')}  — confidence {conf}/10, class `{bc}`")
        lines.append(f"- **Endpoint**: `{h.get('endpoint','?')}`")
        lines.append(f"- **Security claim**: {h.get('security_claim','?')}")
        lines.append(f"- **Why**: {h.get('why','?')}")
        lines.append("")
        lines.append("```bash")
        lines.append(h.get("curl_test", "# (no curl provided)"))
        lines.append("```")
        lines.append("")

    # Killed (transparency — Tal can audit what got dropped)
    killed = (analysis or {}).get("killed") or []
    if killed:
        lines.append(f"<details><summary>Dropped by kill-list ({len(killed)})</summary>")
        lines.append("")
        for h in killed:
            lines.append(f"- **{h.get('title','?')}** → `{h.get('killed_rule')}`: {h.get('killed_reason')}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Artifacts (collapsed)
    lines.append("<details><summary>Artifacts</summary>")
    lines.append("")
    lines.append("### Fetch")
    lines.append(f"- homepage_url: `{fetch_data.get('homepage_url')}`")
    lines.append(f"- final_url: `{fetch_data.get('final_url')}`")
    lines.append(f"- homepage_status: `{fetch_data.get('homepage_status')}`")
    lines.append(f"- bundles: {len(fetch_data.get('bundles') or [])}")
    for b in (fetch_data.get("bundles") or [])[:15]:
        lines.append(f"  - {b['size']:>8} bytes — {b['url']}")
    lines.append("")
    oa = specs.get("openapi")
    if oa:
        lines.append(f"### OpenAPI: `{oa['url']}` ({oa['path_count']} paths, {oa['format']})")
    gq = specs.get("graphql")
    if gq:
        lines.append(f"### GraphQL introspection: `{gq['url']}` ({gq['type_count']} types)")
        if gq.get("interesting_types"):
            lines.append("Interesting type names: " + ", ".join(gq["interesting_types"]))
    lines.append("")
    # Group endpoints by kind so server-leaks and high-signal items pop visually
    by_kind = {}
    for ep in endpoints:
        by_kind.setdefault(ep.get("kind", "api"), []).append(ep)
    high_signal_count = sum(1 for ep in endpoints if ep.get("high_signal"))
    lines.append(f"### JS endpoints extracted: {len(endpoints)} "
                 f"(high_signal={high_signal_count}, "
                 f"by_kind={ {k: len(v) for k, v in by_kind.items()} })")
    for kind in ("server-leak", "graphql", "api", "route"):
        items = by_kind.get(kind, [])
        if not items:
            continue
        lines.append(f"#### {kind} ({len(items)})")
        for ep in items[:40]:
            star = " ⭐" if ep.get("high_signal") else ""
            terms = (",".join(ep.get("signal_terms") or [])) if ep.get("signal_terms") else ""
            terms_str = f" [{terms}]" if terms else ""
            lines.append(f"- `[{ep['confidence']}]` `{ep['method']:6} {ep['path']}`{star}{terms_str}")
        if len(items) > 40:
            lines.append(f"- ... and {len(items)-40} more")
    lines.append("")
    lines.append("</details>")

    return "\n".join(lines)
