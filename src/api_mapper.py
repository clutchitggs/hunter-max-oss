"""
API Schema Discovery — Phase 3a.

Deep-maps application attack surface by discovering API endpoints, parameters, and auth flows.
This is what gives the ReAct agent (Phase 3b) its targets.

Discovery methods:
  1. Katana deep crawler (ProjectDiscovery) — follows links, forms, JS redirects
  2. JS bundle parser — extracts API routes from webpack chunks, fetch() calls, axios configs
  3. Swagger/OpenAPI/GraphQL probing — checks common documentation endpoints
  4. Auth flow detection — login, register, password reset, OAuth endpoints

All discovered endpoints are stored in the api_schemas DB table.
"""
import json
import logging
import re
import subprocess
import time
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("hunter")

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 10
MAX_JS_SIZE = 2 * 1024 * 1024

_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
_session.verify = False
_adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

# Katana binary paths
KATANA_PATHS = [
    "/home/ubuntu/go/bin/katana",
    "/root/go/bin/katana",
    "/usr/local/bin/katana",
    "katana",
]


# =====================================================================
# 1. KATANA DEEP CRAWLER
# =====================================================================

def _find_katana():
    """Find the katana binary."""
    for path in KATANA_PATHS:
        try:
            result = subprocess.run([path, "-version"], capture_output=True, timeout=10)
            if result.returncode == 0:
                return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def run_katana(domain, target_id=None, max_depth=3, timeout_sec=180):
    """Run Katana crawler on a domain. Returns list of discovered URLs.
    Respects 2GB VPS memory constraints with conservative settings."""
    katana_bin = _find_katana()
    if not katana_bin:
        log.warning("  [KATANA] Not installed — skipping deep crawl. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []

    # Per-target output file (async-safe)
    suffix = f"_{target_id}" if target_id else f"_{hash(domain) % 100000}"
    output_file = ROOT / "data" / f"katana_output{suffix}.txt"

    try:
        if output_file.exists():
            output_file.unlink()

        cmd = [
            katana_bin,
            "-u", f"https://{domain}",
            "-d", str(max_depth),         # Crawl depth
            "-jc",                         # Parse JS for links
            "-kf", "all",                  # Known file discovery
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf",  # Skip media
            "-c", "5",                     # 5 concurrent requests (VPS-safe)
            "-rl", "20",                   # 20 requests/sec rate limit
            "-timeout", "10",              # Per-request timeout
            "-retry", "1",
            "-o", str(output_file),
            "-silent",
            "-nc",                         # No color
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec,
            env={"PATH": "/home/ubuntu/go/bin:/root/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
                 "HOME": "/root"},
        )

        if result.returncode != 0 and result.stderr:
            log.warning(f"  [KATANA] stderr: {result.stderr[:200]}")

        urls = []
        if output_file.exists():
            with open(output_file) as f:
                urls = [line.strip() for line in f if line.strip()]

        log.info(f"  [KATANA] {domain}: discovered {len(urls)} URLs (depth={max_depth})")
        return urls

    except subprocess.TimeoutExpired:
        log.warning(f"  [KATANA] Timed out after {timeout_sec}s on {domain}")
        try:
            import os
            os.system("pkill -f katana 2>/dev/null")
        except Exception:
            pass
        return []
    except Exception as e:
        log.warning(f"  [KATANA] Failed on {domain}: {e}")
        return []
    finally:
        try:
            if output_file.exists():
                output_file.unlink()
        except Exception:
            pass


# =====================================================================
# 2. JS BUNDLE API ROUTE PARSER
# =====================================================================

# Patterns that indicate API endpoints in JS code
API_ROUTE_PATTERNS = [
    # fetch("/api/v1/users") or fetch('/api/users')
    (r"""fetch\s*\(\s*['"`]([/][a-zA-Z0-9_/\-\.]+)['"`]""", "fetch"),
    # axios.get("/api/users") / axios.post / axios.put / axios.delete — captures method + url
    (r"""axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([/][a-zA-Z0-9_/\-\.]+)['"`]""", "axios"),
    # $.ajax({url: "/api/users"}) or jQuery patterns
    (r"""(?:url|endpoint)\s*[:=]\s*['"`]([/][a-zA-Z0-9_/\-\.]+)['"`]""", "config"),
    # "/api/v1/users" or "/api/v2/accounts" standalone strings
    (r"""['"`](/api/[a-zA-Z0-9_/\-\.]+)['"`]""", "api_string"),
    # "/graphql" endpoint references
    (r"""['"`](/graphql[a-zA-Z0-9_/\-\.]*)['"`]""", "graphql"),
    # "/v1/", "/v2/", "/v3/" versioned paths
    (r"""['"`](/v[1-3]/[a-zA-Z0-9_/\-\.]+)['"`]""", "versioned"),
    # Route definitions: path: "/users/:id" or route("/users")
    (r"""(?:path|route)\s*[:=(]\s*['"`]([/][a-zA-Z0-9_/:.\-]+)['"`]""", "route_def"),
    # HTTP method + path patterns: method: "POST", url: "/api/create"
    (r"""['"`]((?:GET|POST|PUT|PATCH|DELETE)\s+/[a-zA-Z0-9_/\-\.]+)['"`]""", "method_path"),
]

# Patterns for hidden parameters in JS
PARAM_PATTERNS = [
    # name="hidden_field" or name: "role"
    (r"""name\s*[:=]\s*['"`]([a-zA-Z_][a-zA-Z0-9_]{2,30})['"`]""", "form_field"),
    # params: {isAdmin: true} or data: {role: "admin"}
    (r"""(?:params|data|body|payload)\s*[:=]\s*\{([^}]{5,300})\}""", "request_body"),
]

# Endpoints that are interesting for testing
INTERESTING_ENDPOINT_KEYWORDS = [
    "admin", "user", "account", "auth", "login", "register", "signup",
    "password", "reset", "token", "session", "role", "permission",
    "upload", "file", "delete", "create", "update", "invite",
    "webhook", "callback", "payment", "billing", "checkout",
    "settings", "config", "profile", "export", "import", "download",
]


def extract_api_routes_from_js(js_content, js_url=""):
    """Extract API routes and parameters from JavaScript content.
    Returns list of {endpoint, method, params, source}."""
    routes = []
    seen = set()

    for pattern, source_type in API_ROUTE_PATTERNS:
        for match in re.finditer(pattern, js_content):
            # Axios pattern has 2 groups (method, url), others have 1 (url)
            if source_type == "axios" and match.lastindex and match.lastindex >= 2:
                method = match.group(1).upper()
                endpoint = match.group(2).strip()
            else:
                endpoint = match.group(1).strip()
                method = "GET"

            # Filter noise
            if len(endpoint) < 3 or len(endpoint) > 200:
                continue
            if endpoint.count("/") < 1:
                continue
            if any(endpoint.endswith(ext) for ext in (".js", ".css", ".html", ".png", ".jpg", ".svg", ".ico")):
                continue

            if endpoint in seen:
                continue
            seen.add(endpoint)

            # Extract method from method_path pattern ("POST /api/create")
            if source_type == "method_path" and " " in endpoint:
                method, endpoint = endpoint.split(" ", 1)

            routes.append({
                "endpoint": endpoint,
                "method": method,
                "source": source_type,
                "js_url": js_url,
            })

    # Extract parameters from request bodies
    params_found = []
    for pattern, source_type in PARAM_PATTERNS:
        for match in re.finditer(pattern, js_content):
            raw = match.group(1)
            # Extract field names from object literals
            field_names = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]{2,30})\s*:', raw)
            params_found.extend(field_names)

    return routes, list(set(params_found))


def parse_js_bundles(subdomain, target_id=None):
    """Discover JS files from a subdomain and extract API routes.
    Returns (routes_list, params_list)."""
    all_routes = []
    all_params = []

    # Discover JS URLs (reuse js_analyzer pattern)
    js_urls = []
    for scheme in ["https", "http"]:
        try:
            resp = _session.get(f"{scheme}://{subdomain}/", timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code != 200:
                continue
            body = resp.text[:200000]
            for match in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body):
                if match.startswith("//"):
                    match = f"{scheme}:{match}"
                elif match.startswith("/"):
                    match = f"{scheme}://{subdomain}{match}"
                elif not match.startswith("http"):
                    match = f"{scheme}://{subdomain}/{match}"
                js_urls.append(match)
            break
        except Exception:
            continue

    for js_url in js_urls[:15]:  # Cap at 15 JS files
        try:
            resp = _session.get(js_url, timeout=TIMEOUT, allow_redirects=True)
            if len(resp.text) > MAX_JS_SIZE or len(resp.text) < 100:
                continue
            routes, params = extract_api_routes_from_js(resp.text, js_url)
            all_routes.extend(routes)
            all_params.extend(params)
        except Exception:
            continue

    # Deduplicate routes by endpoint
    seen = set()
    unique_routes = []
    for r in all_routes:
        key = f"{r['method']}:{r['endpoint']}"
        if key not in seen:
            seen.add(key)
            unique_routes.append(r)

    log.info(f"  [JS-PARSE] {subdomain}: {len(unique_routes)} API routes, {len(set(all_params))} params from {len(js_urls)} JS files")
    return unique_routes, list(set(all_params))


# =====================================================================
# 3. SWAGGER / OPENAPI / GRAPHQL PROBE
# =====================================================================

SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/redoc",
    "/.well-known/openapi.json",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/gql",
]


def probe_api_docs(subdomain, target_id=None):
    """Check common Swagger/OpenAPI/GraphQL paths. Returns list of discovered doc endpoints."""
    found = []
    base_url = f"https://{subdomain}"

    # Swagger/OpenAPI probing
    for path in SWAGGER_PATHS:
        try:
            resp = _session.get(f"{base_url}{path}", timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 100:
                # Check if it's actually API docs (not a generic 200 page)
                body = resp.text[:2000].lower()
                is_swagger = any(kw in body for kw in ["swagger", "openapi", "paths", "api-docs", '"info"', "basepath"])
                if is_swagger:
                    # Try to extract endpoint paths from the spec
                    endpoints = _extract_swagger_endpoints(resp.text)
                    found.append({
                        "path": path,
                        "type": "swagger/openapi",
                        "url": f"{base_url}{path}",
                        "endpoints_count": len(endpoints),
                        "endpoints": endpoints[:50],  # Cap stored endpoints
                    })
                    log.info(f"  [API-DOCS] {subdomain}{path}: Swagger/OpenAPI found — {len(endpoints)} endpoints")
                    break  # Found docs, no need to check more paths
        except Exception:
            continue
        time.sleep(0.3)

    # GraphQL probing
    for path in GRAPHQL_PATHS:
        try:
            # Introspection query
            resp = _session.post(
                f"{base_url}{path}",
                json={"query": "{__schema{queryType{name}mutationType{name}types{name kind}}}"},
                headers={"Content-Type": "application/json"},
                timeout=TIMEOUT,
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                types = _extract_graphql_types(resp.text)
                found.append({
                    "path": path,
                    "type": "graphql",
                    "url": f"{base_url}{path}",
                    "types_count": len(types),
                    "types": types[:50],
                })
                log.info(f"  [API-DOCS] {subdomain}{path}: GraphQL found — {len(types)} types")
                break
        except Exception:
            continue
        time.sleep(0.3)

    return found


def _extract_swagger_endpoints(spec_text):
    """Extract API endpoint paths from a Swagger/OpenAPI spec."""
    endpoints = []
    try:
        spec = json.loads(spec_text)
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if isinstance(methods, dict):
                for method in methods:
                    if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                        op = methods[method]
                        params = []
                        if isinstance(op, dict):
                            for p in op.get("parameters", []):
                                if isinstance(p, dict):
                                    params.append(p.get("name", ""))
                        endpoints.append({
                            "path": path,
                            "method": method.upper(),
                            "params": [p for p in params if p],
                            "summary": op.get("summary", "")[:100] if isinstance(op, dict) else "",
                        })
    except (json.JSONDecodeError, AttributeError):
        # Try YAML
        try:
            import yaml
            spec = yaml.safe_load(spec_text)
            if isinstance(spec, dict) and "paths" in spec:
                for path, methods in spec["paths"].items():
                    if isinstance(methods, dict):
                        for method in methods:
                            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                                endpoints.append({"path": path, "method": method.upper(), "params": [], "summary": ""})
        except Exception:
            pass
    return endpoints


def _extract_graphql_types(response_text):
    """Extract GraphQL type names from introspection response."""
    types = []
    try:
        data = json.loads(response_text)
        schema_types = data.get("data", {}).get("__schema", {}).get("types", [])
        for t in schema_types:
            name = t.get("name", "")
            kind = t.get("kind", "")
            # Skip internal types
            if not name.startswith("__"):
                types.append({"name": name, "kind": kind})
    except Exception:
        pass
    return types


# =====================================================================
# 4. AUTH FLOW DETECTION
# =====================================================================

AUTH_PATHS = [
    ("/login", "login"),
    ("/signin", "login"),
    ("/auth/login", "login"),
    ("/api/auth/login", "login"),
    ("/api/login", "login"),
    ("/register", "register"),
    ("/signup", "register"),
    ("/auth/register", "register"),
    ("/api/auth/register", "register"),
    ("/api/register", "register"),
    ("/api/signup", "register"),
    ("/forgot-password", "password_reset"),
    ("/password/reset", "password_reset"),
    ("/api/auth/forgot-password", "password_reset"),
    ("/api/password/reset", "password_reset"),
    ("/oauth/authorize", "oauth"),
    ("/auth/oauth", "oauth"),
    ("/api/oauth/token", "oauth"),
    ("/.well-known/openid-configuration", "oidc"),
]


def detect_auth_flows(subdomain, target_id=None):
    """Probe for authentication-related endpoints. Returns list of found auth endpoints."""
    found = []
    base_url = f"https://{subdomain}"

    for path, flow_type in AUTH_PATHS:
        try:
            resp = _session.get(f"{base_url}{path}", timeout=TIMEOUT, allow_redirects=False)
            # Auth endpoints typically return 200, 302 (redirect to form), 405 (method not allowed but exists), or 401
            if resp.status_code in (200, 302, 303, 307, 401, 405):
                found.append({
                    "path": path,
                    "flow_type": flow_type,
                    "status": resp.status_code,
                    "url": f"{base_url}{path}",
                    "redirect": resp.headers.get("Location", "") if resp.status_code in (302, 303, 307) else "",
                })
        except Exception:
            continue
        time.sleep(0.2)

    if found:
        log.info(f"  [AUTH] {subdomain}: {len(found)} auth endpoints ({', '.join(set(f['flow_type'] for f in found))})")
    return found


# =====================================================================
# 5. MAIN ENTRY POINT — run_api_mapping()
# =====================================================================

def run_api_mapping(domain, target_id, live_hosts):
    """Full API mapping for a target. Runs all discovery methods and stores results.
    Called by the pipeline's mapping phase.

    Returns dict with discovery summary."""
    from db import insert_api_schema, log_activity

    total_stored = 0
    summary = {
        "katana_urls": 0,
        "js_routes": 0,
        "js_params": [],
        "api_docs": [],
        "auth_flows": [],
    }

    # 1. Katana crawl on main domain
    log.info(f"  [MAPPING] {domain}: starting API discovery...")
    katana_urls = run_katana(domain, target_id)
    summary["katana_urls"] = len(katana_urls)

    # Extract API-looking URLs from Katana output
    for url in katana_urls:
        # Filter to API-relevant URLs
        path = url.split("://", 1)[-1].split("/", 1)[-1] if "/" in url else ""
        if not path:
            continue
        is_interesting = any(kw in path.lower() for kw in INTERESTING_ENDPOINT_KEYWORDS) or "/api/" in path.lower()
        if is_interesting:
            method = "GET"
            subdomain = url.split("://")[-1].split("/")[0].split(":")[0]
            endpoint = "/" + path.split("?")[0]
            row_id = insert_api_schema(target_id, subdomain, endpoint, method, source="katana")
            if row_id:
                total_stored += 1

    # 2. JS bundle parsing on top live hosts
    for host in live_hosts[:5]:
        routes, params = parse_js_bundles(host, target_id)
        summary["js_routes"] += len(routes)
        summary["js_params"].extend(params)

        for r in routes:
            row_id = insert_api_schema(
                target_id, host, r["endpoint"], r["method"],
                params=json.dumps({"source_type": r["source"], "js_url": r.get("js_url", "")}),
                source="js_parse",
            )
            if row_id:
                total_stored += 1

    summary["js_params"] = list(set(summary["js_params"]))[:50]

    # 3. Swagger/OpenAPI/GraphQL probing on top hosts
    for host in live_hosts[:5]:
        docs = probe_api_docs(host, target_id)
        summary["api_docs"].extend(docs)

        for doc in docs:
            if doc["type"] == "swagger/openapi":
                for ep in doc.get("endpoints", []):
                    params_str = json.dumps(ep.get("params", [])) if ep.get("params") else None
                    row_id = insert_api_schema(
                        target_id, host, ep["path"], ep["method"],
                        params=params_str, source="swagger",
                    )
                    if row_id:
                        total_stored += 1
            elif doc["type"] == "graphql":
                row_id = insert_api_schema(
                    target_id, host, doc["path"], "POST",
                    params=json.dumps({"types": [t["name"] for t in doc.get("types", [])[:20]]}),
                    source="graphql",
                )
                if row_id:
                    total_stored += 1

    # 4. Auth flow detection
    for host in live_hosts[:5]:
        auth = detect_auth_flows(host, target_id)
        summary["auth_flows"].extend(auth)

        for a in auth:
            row_id = insert_api_schema(
                target_id, host, a["path"], "GET",
                params=json.dumps({"flow_type": a["flow_type"], "status": a["status"]}),
                source="auth_probe",
            )
            if row_id:
                total_stored += 1

    summary["total_stored"] = total_stored

    log.info(
        f"  [MAPPING] {domain}: DONE — {total_stored} endpoints stored | "
        f"katana={summary['katana_urls']} urls, js={summary['js_routes']} routes, "
        f"docs={len(summary['api_docs'])}, auth={len(summary['auth_flows'])}"
    )
    log_activity("scan", f"{domain}: API mapping — {total_stored} endpoints discovered")

    return summary
