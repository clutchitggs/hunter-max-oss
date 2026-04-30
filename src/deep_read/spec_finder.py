"""Probe common spec locations: OpenAPI, Swagger, GraphQL.

Auth-aware: reuses the operator's session cookie / headers so authenticated
Swagger UIs and authenticated GraphQL introspection (e.g. /admin/graphql)
are reachable.
"""
import json
import logging
import re

import requests

log = logging.getLogger("hunter.deep_read")

TIMEOUT = 10

OPENAPI_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/api-docs.json", "/api/docs", "/api/openapi.json",
    "/api/swagger.json", "/docs/openapi.json", "/docs/swagger.json",
    "/swagger-resources", "/swagger-ui/", "/swagger-ui.html",
    # Authenticated endpoints common in B2B SaaS
    "/admin/openapi.json", "/internal/openapi.json", "/api/v1/openapi.json",
    "/api/v2/openapi.json",
)
GRAPHQL_PATHS = (
    "/graphql", "/api/graphql", "/query", "/graphiql", "/v1/graphql",
    "/admin/graphql", "/internal/graphql",
)

GRAPHQL_INTROSPECT = {
    "query": "{__schema{types{name kind fields{name type{name kind}}}}}"
}

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _session(cookie=None, extra_headers=None):
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "*/*"})
    if cookie:
        s.headers["Cookie"] = cookie
    if extra_headers:
        for k, v in extra_headers.items():
            s.headers[k] = v
    s.verify = False
    return s


def _is_openapi_json(text):
    try:
        data = json.loads(text)
        return isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data)
    except Exception:
        return False


def _is_openapi_yaml(text):
    head = text[:4096].lower()
    return ("openapi:" in head or "swagger:" in head) and "paths:" in head


def find_specs(subdomain, cookie=None, extra_headers=None):
    """
    Returns dict:
      openapi: {url, format, path_count, summary} or None
      graphql: {url, type_count, interesting_types} or None
      notes: [str]
    """
    base = f"https://{subdomain}"
    s = _session(cookie=cookie, extra_headers=extra_headers)
    notes = []
    if cookie:
        notes.append("authenticated probe")
    result = {"openapi": None, "graphql": None, "notes": notes}

    for p in OPENAPI_PATHS:
        url = base + p
        try:
            r = s.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        text = r.text[:300_000]
        fmt = None
        if _is_openapi_json(text):
            fmt = "json"
        elif _is_openapi_yaml(text):
            fmt = "yaml"
        if not fmt:
            continue
        path_count = 0
        summary = text[:8000]
        if fmt == "json":
            try:
                data = json.loads(text)
                paths = data.get("paths") or {}
                path_count = len(paths)
                lines = []
                for ep_path, ep_def in list(paths.items())[:120]:
                    if isinstance(ep_def, dict):
                        methods = [m.upper() for m in ep_def.keys()
                                   if m.lower() in {"get", "post", "put", "patch",
                                                    "delete", "options", "head"}]
                        lines.append(f"{','.join(methods) or '?'} {ep_path}")
                summary = "\n".join(lines)[:8000]
            except Exception:
                pass
        result["openapi"] = {"url": url, "format": fmt,
                             "path_count": path_count, "summary": summary}
        notes.append(f"openapi found at {url} ({path_count} paths)")
        break

    for p in GRAPHQL_PATHS:
        url = base + p
        try:
            r = s.post(url, json=GRAPHQL_INTROSPECT, timeout=TIMEOUT,
                       headers={"Content-Type": "application/json"})
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        schema = (data.get("data") or {}).get("__schema")
        if not schema or not isinstance(schema.get("types"), list):
            continue
        types = schema["types"]
        interesting_keywords = re.compile(
            r"admin|internal|impersonate|super|tenant|org|billing|invoice|"
            r"invite|role|permission|debug|payment|subscription|refund|"
            r"export|import|webhook|account|member",
            re.I)
        interesting = [t.get("name") for t in types
                       if t.get("name") and interesting_keywords.search(t.get("name", ""))][:30]
        result["graphql"] = {
            "url": url, "type_count": len(types), "interesting_types": interesting,
        }
        notes.append(f"graphql introspection at {url} ({len(types)} types)")
        break

    return result
