"""Extract API call sites + routes + server-route leaks + GraphQL ops from JS bundles.

Regex-based by design (NOT AST):
  - Modern minified Webpack/Vite/Next chunks defeat AST parsers in practice.
  - We optimize for recall — precision is the LLM's job downstream.

Endpoint kinds (separated so the LLM reasons differently over each):
  - "api"         : real HTTP call sites (fetch / axios / XHR / wrapped api(METHOD,URL))
  - "route"       : client-side page routes (router.push / <Route path=>) — pages worth
                    visiting authenticated, NOT endpoints to attack directly
  - "server-leak" : Express / Spring / Flask handlers found in JS — only present when a
                    sourcemap was leaked or an SSR bundle was shipped. Standalone P1 signal.
  - "graphql"     : named mutation / query operations from gql template literals

Each record:
  { kind, method, path, context, snippet, bundle_url, confidence,
    reason, high_signal, signal_terms }
"""
import re

# ====================================================================
# HIGH-SIGNAL KEYWORDS
# Source of truth: paths/contexts containing any of these survive the
# data-reducer cut and get a code snippet sent to the LLM.
#
# A short keyword list (admin / role / tenant / impersonate / permission)
# misses a lot of high-value vertical surfaces. This expanded list covers
# the categories that historically convert into real findings: financial
# state-mutation, identity, integrations.
# ====================================================================
HIGH_SIGNAL_KEYWORDS = (
    # auth / identity
    "admin", "superuser", "sudo", "root", "internal", "private", "debug",
    "actuator", "impersonate", "switch_user", "assume", "act_as",
    "role", "roles", "permission", "permissions", "scope", "acl",
    "tenant", "tenants", "org", "org_id", "organization", "workspace",
    "team", "account", "account_id", "user_id", "userid", "uid",
    "oauth", "saml", "sso", "session", "apikey", "api_key", "secret",
    # financial / billing — high-conversion category
    "billing", "invoice", "invoices", "payment", "payments", "charge",
    "subscription", "subscriptions", "refund", "discount", "coupon",
    "credit", "debit", "payout", "wallet", "ledger", "transaction",
    "dunning", "netsuite", "tax", "vat",
    # state-mutation verbs on protected resources
    "promote", "demote", "grant", "revoke", "approve", "reject",
    "export", "import", "backup", "restore", "migrate", "purge",
    "set-state", "set_state", "setstate", "activate", "deactivate",
    "suspend", "unsuspend", "ban", "unban",
    # cross-tenant / invitation surface
    "invite", "invitation", "invitee", "share", "transfer",
    "members", "membership",
    # webhooks / integrations (often unauthenticated)
    "webhook", "callback", "integration", "connector",
    # GraphQL classics
    "mutation", "introspection",
)

_HIGH_SIGNAL_RE = re.compile(
    r"(?:^|[/_\-?&=.{}])(" + "|".join(map(re.escape, HIGH_SIGNAL_KEYWORDS)) + r")(?:[/_\-?&=.}]|$)",
    re.I,
)

# ====================================================================
# Path drop list — pure token waste
# ====================================================================
_DROP_PREFIXES = (
    "/static/", "/assets/", "/fonts/", "/images/", "/img/", "/icons/",
    "/css/", "/_next/static/", "/_nuxt/", "/build/", "/dist/", "/public/",
)
_DROP_EXT = re.compile(
    r"\.(css|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|ico|map|mp4|mp3|webp|avif|otf|pdf|zip)(\?|#|$)",
    re.I,
)


def _looks_like_path(s):
    if not s or not s.startswith("/"):
        return False
    if len(s) < 2 or len(s) > 200:
        return False
    for pre in _DROP_PREFIXES:
        if s.startswith(pre):
            return False
    if _DROP_EXT.search(s):
        return False
    # drop fragments / query-only / pure data urls
    if s.startswith("//") or s.startswith("/#"):
        return False
    return True


# ====================================================================
# 5-line snippet (±2 lines around the match)
# ====================================================================
def _snippet_lines(text, start, end, before=2, after=2):
    line_start = text.rfind("\n", 0, start) + 1
    cur = line_start
    for _ in range(before):
        prev_nl = text.rfind("\n", 0, cur - 1)
        if prev_nl < 0:
            cur = 0
            break
        cur = prev_nl + 1
    snip_start = cur

    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    cur = line_end
    for _ in range(after):
        nxt_nl = text.find("\n", cur + 1)
        if nxt_nl < 0:
            cur = len(text)
            break
        cur = nxt_nl
    snip_end = cur

    raw = text[snip_start:snip_end]
    lines = []
    for ln in raw.split("\n"):
        ln = re.sub(r"[ \t]+", " ", ln).strip()
        if len(ln) > 400:
            ln = ln[:400] + "…"
        if ln:
            lines.append(ln)
    return "\n".join(lines)


def _high_signal(path, snippet):
    blob = f"{path}\n{snippet}"
    matches = _HIGH_SIGNAL_RE.findall(blob)
    if not matches:
        return False, []
    seen = []
    for m in matches:
        m_low = m.lower()
        if m_low not in seen:
            seen.append(m_low)
    return True, seen


def _verb_near(snippet):
    m = re.search(
        r"""(?:method|type|httpMethod|verb)\s*[:=]\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]""",
        snippet, re.I)
    return m.group(1).upper() if m else None


def _record(text, m_start, m_end, *, kind, method, path, confidence,
            reason, bundle_url):
    snippet = _snippet_lines(text, m_start, m_end)
    hs, terms = _high_signal(path, snippet)
    return {
        "kind": kind,
        "method": method,
        "path": path,
        "context": re.sub(r"\s+", " ", snippet)[:500],
        "snippet": snippet,
        "bundle_url": bundle_url,
        "confidence": confidence,
        "reason": reason,
        "high_signal": hs,
        "signal_terms": terms,
    }


# ====================================================================
# Patterns — split into typed extractors so each can tag `kind` correctly
# ====================================================================
def _extract_api(text, bundle_url):
    out = []

    # 1. fetch("/...")
    for m in re.finditer(r"""\bfetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", text, re.I):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        snippet = _snippet_lines(text, m.start(), m.end())
        method = _verb_near(snippet) or ("POST" if re.search(r"\bbody\s*:", snippet) else "GET")
        out.append(_record(text, m.start(), m.end(), kind="api", method=method,
                           path=path, confidence="high", reason="fetch()",
                           bundle_url=bundle_url))

    # 2. axios.METHOD("/...")
    for m in re.finditer(
        r"""\baxios\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
        text, re.I):
        path = m.group(2)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="api",
                           method=m.group(1).upper(), path=path,
                           confidence="high",
                           reason=f"axios.{m.group(1).lower()}()",
                           bundle_url=bundle_url))

    # 3. plain axios("/...")
    for m in re.finditer(r"""\baxios\s*\(\s*['"`]([^'"`\s]+)['"`]""", text, re.I):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        snippet = _snippet_lines(text, m.start(), m.end())
        method = _verb_near(snippet) or "?"
        out.append(_record(text, m.start(), m.end(), kind="api", method=method,
                           path=path, confidence="high", reason="axios()",
                           bundle_url=bundle_url))

    # 4. XHR .open("METHOD","URL")
    for m in re.finditer(
        r"""\.open\s*\(\s*['"`]([A-Z]+)['"`]\s*,\s*['"`]([^'"`\s]+)['"`]""", text):
        path = m.group(2)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="api",
                           method=m.group(1).upper(), path=path,
                           confidence="high", reason="XHR .open()",
                           bundle_url=bundle_url))

    # 5. WRAPPER STYLE — minified bundles wrap into helper(METHOD,PATH,...) or
    #    helper(PATH,{method:...}). This pattern often hides high-value surfaces.
    #    Match: anyfunc("METHOD","/path")
    for m in re.finditer(
        r"""\(\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]\s*,\s*['"`](/[^'"`\s]+)['"`]""",
        text, re.I):
        path = m.group(2)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="api",
                           method=m.group(1).upper(), path=path,
                           confidence="high",
                           reason="wrapper(METHOD,PATH)",
                           bundle_url=bundle_url))

    # 6. WRAPPER reverse — anyfunc("/path","METHOD") or anyfunc("/path",{method:})
    for m in re.finditer(
        r"""\(\s*['"`](/[^'"`\s]+)['"`]\s*,\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]""",
        text, re.I):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="api",
                           method=m.group(2).upper(), path=path,
                           confidence="high",
                           reason="wrapper(PATH,METHOD)",
                           bundle_url=bundle_url))

    # 7. url:"/..." config-object assignments (medium confidence)
    for m in re.finditer(r"""\burl\s*[:=]\s*['"`]([^'"`\s]+)['"`]""", text):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        snippet = _snippet_lines(text, m.start(), m.end())
        method = _verb_near(snippet) or "?"
        out.append(_record(text, m.start(), m.end(), kind="api", method=method,
                           path=path, confidence="medium",
                           reason="url: assignment", bundle_url=bundle_url))

    # 8. Bare interesting path literal (low confidence — last resort)
    for m in re.finditer(r"""['"`](/[A-Za-z0-9_\-/.{}:]+)['"`]""", text):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        if not _HIGH_SIGNAL_RE.search(path):
            continue  # only keep bare literals if path itself is high-signal
        out.append(_record(text, m.start(), m.end(), kind="api", method="?",
                           path=path, confidence="low",
                           reason="bare interesting path",
                           bundle_url=bundle_url))

    return out


def _extract_routes(text, bundle_url):
    """Client-side page routes — pages worth visiting authenticated."""
    out = []
    # router.push("/path") / router.replace("/path") / navigate("/path") / history.push
    for m in re.finditer(
        r"""\b(?:router|history|navigate|navigation)\s*(?:\.\s*(?:push|replace|navigate))?\s*\(\s*['"`]([^'"`\s]+)['"`]""",
        text, re.I):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="route",
                           method="GET", path=path, confidence="medium",
                           reason="router.push/replace",
                           bundle_url=bundle_url))

    # <Route path="/admin"> / <Route path={'/admin'}>  — JSX (sourcemap or dev bundle)
    for m in re.finditer(
        r"""<\s*Route\b[^>]*\bpath\s*=\s*\{?\s*['"`]([^'"`\s]+)['"`]""", text, re.I):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="route",
                           method="GET", path=path, confidence="high",
                           reason="<Route path=>", bundle_url=bundle_url))

    return out


def _extract_server_leaks(text, bundle_url):
    """
    Server-side route handlers found in JS = sourcemap leak or SSR bundle.
    Standalone P1 signal regardless of the route content.
    """
    out = []
    # Express: app.METHOD("/...") / router.METHOD("/...") — distinguish from client router by verb
    for m in re.finditer(
        r"""\b(?:app|router|server|api)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
        text):
        path = m.group(2)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="server-leak",
                           method=m.group(1).upper(), path=path,
                           confidence="high",
                           reason="Express handler in JS = sourcemap/SSR leak",
                           bundle_url=bundle_url))

    # Spring: @GetMapping("/...") @PostMapping("/...") @RequestMapping("/...")
    for m in re.finditer(
        r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?['"`]([^'"`\s]+)['"`]""",
        text):
        decorator = m.group(1)
        method_map = {"GetMapping": "GET", "PostMapping": "POST",
                      "PutMapping": "PUT", "DeleteMapping": "DELETE",
                      "PatchMapping": "PATCH", "RequestMapping": "?"}
        out.append(_record(text, m.start(), m.end(), kind="server-leak",
                           method=method_map.get(decorator, "?"),
                           path=m.group(2), confidence="high",
                           reason=f"Spring @{decorator} = sourcemap/SSR leak",
                           bundle_url=bundle_url))

    # Flask / FastAPI: @app.route("/...", methods=["POST"]) or @router.get("/...")
    for m in re.finditer(
        r"""@\w+\.(?:route|get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
        text):
        path = m.group(1)
        if not _looks_like_path(path):
            continue
        out.append(_record(text, m.start(), m.end(), kind="server-leak",
                           method="?", path=path, confidence="high",
                           reason="Flask/FastAPI decorator = sourcemap leak",
                           bundle_url=bundle_url))

    return out


def _extract_graphql(text, bundle_url):
    """Named GraphQL operations inside template literals or strings."""
    out = []
    # mutation Foo(...) / query Foo(...) inside any string-ish container
    for m in re.finditer(
        r"""(mutation|query)\s+([A-Z][A-Za-z0-9_]*)\s*[\(\{]""", text):
        op_kind = m.group(1).lower()
        op_name = m.group(2)
        out.append(_record(text, m.start(), m.end(), kind="graphql",
                           method=op_kind.upper(),
                           path=f"#graphql:{op_kind}:{op_name}",
                           confidence="high",
                           reason=f"named GraphQL {op_kind}",
                           bundle_url=bundle_url))

    # gql`...` / graphql`...` — tagged templates, capture the first op name
    for m in re.finditer(
        r"""\b(?:gql|graphql)\s*`([^`]{0,2000})`""", text):
        body = m.group(1)
        op_match = re.search(r"\b(mutation|query|subscription)\s+([A-Za-z0-9_]+)", body)
        if op_match:
            op_kind = op_match.group(1).lower()
            op_name = op_match.group(2)
            out.append(_record(text, m.start(), m.end(), kind="graphql",
                               method=op_kind.upper(),
                               path=f"#graphql:{op_kind}:{op_name}",
                               confidence="high",
                               reason="gql`` template", bundle_url=bundle_url))

    return out


def extract_endpoints(bundle):
    """Returns list of all endpoint records from one bundle."""
    text = bundle["content"]
    bundle_url = bundle["url"]
    return (
        _extract_api(text, bundle_url)
        + _extract_routes(text, bundle_url)
        + _extract_server_leaks(text, bundle_url)
        + _extract_graphql(text, bundle_url)
    )


def extract_all(bundles):
    """Extract endpoints from all bundles + dedupe."""
    seen = {}
    rank = {"high": 3, "medium": 2, "low": 1}
    for b in bundles:
        for ep in extract_endpoints(b):
            key = (ep["kind"], ep["method"], ep["path"])
            existing = seen.get(key)
            if existing is None:
                seen[key] = ep
                continue
            new_score = (rank[ep["confidence"]], int(ep["high_signal"]))
            old_score = (rank[existing["confidence"]], int(existing["high_signal"]))
            if new_score > old_score:
                seen[key] = ep

    # Second pass: if (kind, path) has any record with a known method,
    # drop the method="?" duplicate — it's just noise.
    by_kp = {}
    for ep in seen.values():
        by_kp.setdefault((ep["kind"], ep["path"]), []).append(ep)
    cleaned = []
    for (_kind, _path), records in by_kp.items():
        has_known = any(r["method"] != "?" for r in records)
        for r in records:
            if has_known and r["method"] == "?":
                continue
            cleaned.append(r)

    kind_rank = {"server-leak": 0, "graphql": 1, "api": 2, "route": 3}
    return sorted(cleaned, key=lambda e: (
        kind_rank.get(e["kind"], 9),
        0 if e["high_signal"] else 1,
        {"high": 0, "medium": 1, "low": 2}[e["confidence"]],
        e["path"],
    ))


def reduce_for_llm(endpoints, max_items=80, snippet_only_for_signal=True):
    """
    Lethal data reducer for the LLM payload.

    Rules:
      1. ALWAYS keep all server-leak and graphql records (P1 signals).
      2. Then all high_signal API records.
      3. Then high-confidence non-signal API records.
      4. Routes only if high_signal (otherwise just noise for an attacker).
      5. Cap at `max_items`.
      6. Strip `snippet` field from non-high-signal items unless
         snippet_only_for_signal=False — saves massive tokens.
    """
    server_leaks = [e for e in endpoints if e["kind"] == "server-leak"]
    graphql_ops = [e for e in endpoints if e["kind"] == "graphql"]
    apis = [e for e in endpoints if e["kind"] == "api"]
    routes = [e for e in endpoints if e["kind"] == "route"]

    high_apis = [e for e in apis if e["high_signal"]]
    other_high_conf = [e for e in apis if not e["high_signal"] and e["confidence"] == "high"]
    signal_routes = [e for e in routes if e["high_signal"]]

    out = []
    out.extend(server_leaks)
    out.extend(graphql_ops)
    out.extend(high_apis)
    out.extend(signal_routes)
    out.extend(other_high_conf)

    out = out[:max_items]

    if snippet_only_for_signal:
        slim = []
        for e in out:
            slim_e = dict(e)
            if not e["high_signal"] and e["kind"] not in ("server-leak", "graphql"):
                slim_e.pop("snippet", None)
                slim_e.pop("context", None)
            slim.append(slim_e)
        return slim

    return out
