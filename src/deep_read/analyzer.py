"""
Claude Opus reasoning pass — turn raw artifacts into a ranked hypothesis list.

Input contract (slim, structured):
  - We send Claude a JSON payload, NOT a flat prose endpoint table.
  - The payload is data-reduced via js_parser.reduce_for_llm() before serialization:
      * server-leak + graphql records always included (P1 signals)
      * high_signal API records always included with 5-line snippet
      * high-confidence non-signal records included WITHOUT snippet (saves tokens)
      * routes only if high_signal
      * cap at 80 items
  - This keeps prompts tight and on-topic, so Claude reasons on attack surface
    that actually carries lift instead of generic /api/users hallucinations.

Output contract:
  Strict JSON with `summary` + `hypotheses[]` — same as before, kill-list still applied.
"""
import json
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from src.llm_client import call_tier  # noqa: E402
from src.deep_read.js_parser import reduce_for_llm  # noqa: E402

log = logging.getLogger("hunter.deep_read")

# =====================================================================
# Kill-list — applied after the LLM responds. Each rule encodes a
# pattern that has historically produced false positives in real
# engagements. Add to this list as you learn new "looks like a bug,
# isn't" shapes.
# =====================================================================
KILL_RULES = [
    ("401_403_differential",
     re.compile(r"401\s*(->|→|to)\s*403|differential.*auth|403.*differential", re.I),
     "401→403 differential usually means a shared identity provider, not an auth bypass"),
    ("cloudfront_takeover",
     re.compile(r"cloudfront.*(takeover|not\s*configured|could\s*not\s*be\s*satisfied)", re.I),
     "CloudFront CNAMEs are not takeoverable"),
    ("s3_403_exists",
     re.compile(r"s3.*403.*(exists|confirmed)|listbucket.*denied.*exists", re.I),
     "S3 403 does not prove file existence when ListBucket is denied"),
    ("twilio_sid",
     re.compile(r"twilio\s*(sid|account\s*id)", re.I),
     "Twilio SIDs are public identifiers, not secrets"),
    ("stripe_publishable",
     re.compile(r"stripe.*(publishable|pk_live|pk_test)", re.I),
     "Stripe publishable keys are public by design"),
    ("internal_url_only",
     re.compile(r"^\s*internal\s*url\s*(leak|disclosed)?\s*$", re.I),
     "Internal URL disclosure alone is not payable on mainstream programs"),
    ("github_pages_not_configured",
     re.compile(r"github\s*pages.*not\s*configured|there\s*isn.?t\s*a\s*github\s*pages", re.I),
     "GitHub Pages 'not configured' is not takeoverable without org membership"),
]


def apply_kill_list(hypotheses):
    surviving, killed = [], []
    for h in hypotheses:
        blob = " ".join([
            str(h.get("title", "")),
            str(h.get("security_claim", "")),
            str(h.get("why", "")),
            str(h.get("bug_class", "")),
        ])
        matched = None
        for rule_id, pattern, reason in KILL_RULES:
            if pattern.search(blob):
                matched = (rule_id, reason)
                break
        if matched:
            h = dict(h, killed_rule=matched[0], killed_reason=matched[1])
            killed.append(h)
        else:
            if not h.get("security_claim") or not h.get("curl_test"):
                h = dict(h, killed_rule="no_claim_or_test",
                         killed_reason="hypothesis missing specific claim or curl test")
                killed.append(h)
            else:
                surviving.append(h)
    return surviving, killed


# =====================================================================
# Prompt
# =====================================================================
SYSTEM_RULES = """You are a senior bug bounty hunter reviewing attack surface.
You will receive a JSON object describing a target and the API surface we
extracted from its JS bundles. Your job: produce a ranked list of CONCRETE,
TESTABLE hypotheses that a human hunter should manually verify in ~30 minutes.

INPUT JSON FIELDS:
- target, authenticated_scrape, openapi, graphql_types
- endpoints[] — each item:
    kind: "api" | "server-leak" | "graphql" | "route"
       * "server-leak" means an Express/Spring/Flask handler was found in a
         JS bundle = sourcemap or SSR leak. Always worth a P1 hypothesis on
         its own (full source disclosure) PLUS reasoning over the routes.
       * "graphql" means a named operation we found in gql`` templates.
       * "route" means a client-side page route — useful as a hint of what
         authenticated pages exist, NOT an API endpoint to curl.
    method, path, confidence (high/medium/low), reason, signal_terms[],
    snippet (5-line code context — only present for high-signal items)

STRICT RULES — violating any voids the hypothesis:
1. Each hypothesis MUST name a specific endpoint (path + method) — NEVER from "route" kind.
2. Each hypothesis MUST state in ONE sentence what security property is claimed
   to be broken (e.g. "tenant A can read tenant B's invoices via /api/v2/billing?org_id=").
3. Each hypothesis MUST include an exact curl one-liner using <TOKEN>/<USER_ID>
   placeholders that would produce evidence of the issue or clearly falsify it.
4. Confidence is 1-10. Below 6, drop the hypothesis.
5. Prefer (high lift): BOLA/IDOR via id parameters, broken access control on
   undocumented admin/billing endpoints, GraphQL type-level escalation,
   undocumented impersonation/internal/debug endpoints, mass-assignment on
   PUT/PATCH endpoints, SSRF on webhook/callback/integration endpoints.
6. Prefer: endpoints present in JS bundles but MISSING from the OpenAPI spec
   (or no OpenAPI at all). The gap IS the attack surface.
7. ALWAYS produce a separate hypothesis for any "server-leak" record claiming
   "Source map / SSR bundle leak — full backend route table disclosed".
8. Do NOT propose: 401→403 differentials, CloudFront takeovers, S3 403 existence
   inference, Twilio SID disclosure, Stripe publishable key disclosure, generic
   "internal URL disclosed" findings.
9. Do NOT invent endpoints. Reason ONLY over what appears in the JSON.
10. If the scrape was unauthenticated, weight your confidence accordingly —
    you only saw the public bundle, the high-value surface lives behind auth.

OUTPUT — STRICT JSON, no markdown fence, no commentary:
{
  "summary": "1-3 sentence overview of the target's attack surface and how to attack it",
  "hypotheses": [
    {
      "title": "short name",
      "endpoint": "METHOD /path",
      "bug_class": "BOLA|IDOR|broken-auth|priv-esc|GraphQL-escalation|undoc-admin|SSRF|mass-assignment|sourcemap-leak|other",
      "security_claim": "one sentence",
      "why": "2-4 sentences of reasoning grounded in the artifacts",
      "curl_test": "exact curl one-liner",
      "confidence": 1-10
    }
  ]
}

If you find nothing worth testing, return {"summary": "...", "hypotheses": []}.
"""


def _build_payload(target, fetch_data, endpoints, specs):
    """Build the structured JSON payload sent to Claude."""
    reduced = reduce_for_llm(endpoints, max_items=80, snippet_only_for_signal=True)

    # Strip noisy / large fields from each endpoint record
    slim_endpoints = []
    for e in reduced:
        item = {
            "kind": e["kind"],
            "method": e["method"],
            "path": e["path"],
            "confidence": e["confidence"],
            "reason": e["reason"],
        }
        if e.get("signal_terms"):
            item["signal_terms"] = e["signal_terms"]
        if "snippet" in e and e["snippet"]:
            item["snippet"] = e["snippet"]
        slim_endpoints.append(item)

    payload = {
        "target": target,
        "final_url": fetch_data.get("final_url"),
        "homepage_status": fetch_data.get("homepage_status"),
        "authenticated_scrape": bool(fetch_data.get("authenticated")),
        "bundles_fetched": len(fetch_data.get("bundles") or []),
        "openapi": None,
        "graphql_types": [],
        "endpoints": slim_endpoints,
    }

    oa = specs.get("openapi")
    if oa:
        payload["openapi"] = {
            "url": oa["url"],
            "format": oa["format"],
            "path_count": oa["path_count"],
            "summary": oa["summary"][:6000],
        }

    gq = specs.get("graphql")
    if gq:
        payload["graphql_types"] = gq.get("interesting_types") or []

    return payload


def _build_prompt(target, fetch_data, endpoints, specs):
    payload = _build_payload(target, fetch_data, endpoints, specs)
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)
    return SYSTEM_RULES + "\n\nINPUT:\n" + payload_json + \
           "\n\nProduce the JSON output now. No commentary before or after."


def _extract_json(text):
    if not text:
        return None
    t = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.I)
    t = re.sub(r"\s*```$", "", t)
    start = t.find("{")
    if start == -1:
        return None
    depth = 0
    end = None
    in_str = False
    esc = False
    for i in range(start, len(t)):
        ch = t[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
    if end is None:
        return None
    candidate = t[start:end]
    try:
        return json.loads(candidate)
    except Exception as e:
        log.warning(f"JSON parse failed: {e}; head={candidate[:200]}")
        return None


def analyze(target, fetch_data, endpoints, specs, max_tokens=8000):
    prompt = _build_prompt(target, fetch_data, endpoints, specs)
    log.info(f"[deep_read] prompt size: {len(prompt)} chars")

    text = call_tier("tier3", prompt, max_tokens=max_tokens)
    if not text:
        log.error("[deep_read] Opus call returned None (budget exhausted or API error)")
        return None

    parsed = _extract_json(text)
    if not parsed:
        return {
            "summary": "(parse failed)", "hypotheses": [], "killed": [],
            "prompt_chars": len(prompt), "raw": text[:2000],
        }

    hypotheses = parsed.get("hypotheses") or []
    surviving, killed = apply_kill_list(hypotheses)

    return {
        "summary": parsed.get("summary", ""),
        "hypotheses": surviving,
        "killed": killed,
        "prompt_chars": len(prompt),
    }
