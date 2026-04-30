"""Discover lazy-loaded webpack chunks (incl. Module Federation remotes).

Modern SaaS apps ship a tiny entry bundle (`main.js` + `runtime.js`) that
loads everything else dynamically. Without expanding those, Deep Read sees
~600 bytes of stub code and zero endpoints.

This module:
  1. Scans an initial bundle for the webpack chunk-URL function
     (`__webpack_require__.u = e => name(e) + "." + hash(e) + ".js"`)
     and reconstructs every chunk URL.
  2. Detects Module Federation remotes from runtime metadata
     (`remoteName: "@scope/name"`) and probes the federated host for
     each `<host>/<name>/remoteEntry.js`.
  3. Recursively expands any remoteEntry it finds (each remote has its
     own chunk graph).

Returns a list of fully-qualified URLs the caller should fetch.
"""
import logging
import re
from urllib.parse import urljoin, urlparse

log = logging.getLogger("hunter.deep_read")

# Common federated hosts to try when runtime references a remote by name only.
# Falls back to same-eTLD+1 'federated.<root>' if nothing else hits.
FEDERATED_HOST_HINTS = ("federated", "remotes", "mfe", "microfrontend")


def _extract_chunk_map(js):
    """
    Find: __webpack_require__.u = e => "" + (({nameMap})[e] || e) + "." + ({hashMap})[e] + ".js"
    Returns (name_map: dict[int,str], hash_map: dict[int,str]) or (None, None).
    """
    i = js.find("__webpack_require__.u=")
    if i < 0:
        return None, None
    block = js[i:i + 4000]

    # Two object literals separated by + "." +
    # Be lenient: both maps are { id:"str", id:"str", ... }
    objs = re.findall(r"\{([0-9]+\s*:\s*\"[^\"]+\"(?:\s*,\s*[0-9]+\s*:\s*\"[^\"]+\")*)\}", block)
    if len(objs) < 1:
        return None, None

    def _parse(obj_body):
        out = {}
        for m in re.finditer(r"([0-9]+)\s*:\s*\"([^\"]+)\"", obj_body):
            out[int(m.group(1))] = m.group(2)
        return out

    if len(objs) >= 2:
        return _parse(objs[0]), _parse(objs[1])
    # Only a hash map (no friendly names) — chunk filename is just "{id}.{hash}.js"
    return {}, _parse(objs[0])


def _build_chunk_urls(base_dir_url, name_map, hash_map):
    """
    base_dir_url: e.g. 'https://federated.acme.com/billing-common/'  (must end with /)
    """
    urls = []
    if not hash_map:
        return urls
    for chunk_id, h in hash_map.items():
        name = name_map.get(chunk_id, str(chunk_id)) if name_map else str(chunk_id)
        urls.append(f"{base_dir_url}{name}.{h}.js")
    return urls


def _extract_federation_remotes(js):
    """
    Returns a set of remote module names like '@cld-remote/billing-common'.
    Module Federation runtime serializes remotes as: remoteName:"@scope/name".
    """
    return set(re.findall(r'remoteName\s*:\s*"([^"]+)"', js))


def _candidate_federated_hosts(target_host):
    """
    Given 'console.acme.com' return likely federated hosts to probe.
    """
    parts = target_host.split(".")
    out = []
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
        for hint in FEDERATED_HOST_HINTS:
            out.append(f"{hint}.{root}")
    out.append(target_host)  # same host fallback
    return out


def discover(initial_bundles, session, target_host, max_extra=200, byte_budget=15 * 1024 * 1024):
    """
    initial_bundles: list of {url, content} dicts already fetched
    session: requests.Session with auth headers set
    target_host: hostname of the original target (e.g. 'console.acme.com')

    Returns list of extra bundle dicts ({url, status, size, content}).
    """
    discovered_urls = []
    federation_remote_names = set()

    # Pass 1: scan each initial bundle for own-chunks + federation remotes
    for b in initial_bundles:
        url = b["url"]
        js = b["content"]
        # The chunk loader's base dir = directory containing this bundle
        base_dir = url.rsplit("/", 1)[0] + "/"
        name_map, hash_map = _extract_chunk_map(js)
        if hash_map:
            chunks = _build_chunk_urls(base_dir, name_map, hash_map)
            log.info(f"[webpack] {url.rsplit('/',1)[1]}: discovered {len(chunks)} chunks")
            discovered_urls.extend(chunks)
        federation_remote_names.update(_extract_federation_remotes(js))

    # Pass 2: probe federated hosts for each remote's remoteEntry
    federated_entries = []
    if federation_remote_names:
        host_candidates = _candidate_federated_hosts(target_host)
        log.info(f"[webpack] federation remotes: {sorted(federation_remote_names)}")
        for full in federation_remote_names:
            # '@cld-remote/billing-common' -> 'billing-common'
            name = full.split("/", 1)[-1] if "/" in full else full
            for host in host_candidates:
                url = f"https://{host}/{name}/remoteEntry.js"
                try:
                    r = session.head(url, timeout=8, allow_redirects=True)
                    if r.status_code == 200:
                        federated_entries.append(url)
                        break  # found this remote, stop probing hosts
                except Exception:
                    pass
        log.info(f"[webpack] federated remoteEntries reachable: {len(federated_entries)}")

    # Pass 3: fetch each remoteEntry and harvest its chunks
    bundles_out = []
    total = 0
    for url in federated_entries:
        if total >= byte_budget or len(bundles_out) >= max_extra:
            break
        try:
            r = session.get(url, timeout=15, allow_redirects=True)
            if r.status_code != 200:
                continue
            js = r.text
            bundles_out.append({"url": url, "status": 200, "size": len(js), "content": js})
            total += len(js)
            base_dir = url.rsplit("/", 1)[0] + "/"
            name_map, hash_map = _extract_chunk_map(js)
            if hash_map:
                chunks = _build_chunk_urls(base_dir, name_map, hash_map)
                log.info(f"[webpack] {url.rsplit('/',2)[1]}: {len(chunks)} federated chunks")
                discovered_urls.extend(chunks)
        except Exception as e:
            log.info(f"[webpack] remoteEntry fetch failed {url}: {e}")

    # Pass 4: fetch all discovered chunk URLs (deduped)
    seen = {b["url"] for b in initial_bundles} | {b["url"] for b in bundles_out}
    for url in discovered_urls:
        if url in seen:
            continue
        seen.add(url)
        if total >= byte_budget or len(bundles_out) >= max_extra:
            break
        try:
            r = session.get(url, timeout=10, allow_redirects=True)
            if r.status_code != 200 or len(r.content) < 200:
                continue
            text = r.text
            bundles_out.append({"url": url, "status": 200, "size": len(text), "content": text})
            total += len(text)
        except Exception:
            pass

    log.info(f"[webpack] expanded to {len(bundles_out)} extra bundles "
             f"({total/1024:.0f} KB)")
    return bundles_out
