import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from exposureintel.ingest import Component

from .cache import Cache, query_key
from .models import Vulnerability, parse_record

log = logging.getLogger(__name__)

OSV_BASE = "https://api.osv.dev"
BATCH_SIZE = 1000  # OSV's documented maximum queries per batch
QUERY_TTL = 24 * 3600  # re-ask OSV about a package after a day
TIMEOUT = 30.0
MAX_ATTEMPTS = 4
MAX_PAGE_ROUNDS = 100  # safety stop for pagination
FETCH_WORKERS = 8


class OsvError(RuntimeError):
    """Raised when OSV cannot be reached or returns something unusable."""


@dataclass
class OsvResult:
    vulns: dict[str, list[Vulnerability]] = field(default_factory=dict)  # keyed by purl
    unchecked: list[Component] = field(default_factory=list)  # offline and not cached


def make_client() -> httpx.Client:
    return httpx.Client(
        base_url=OSV_BASE,
        timeout=TIMEOUT,
        headers={"User-Agent": "exposureintel/0.1.0"},
    )


def _send(client: httpx.Client, method: str, path: str, **kwargs) -> dict:
    """Send a request, retrying transient failures with exponential backoff."""
    delay = 1.0
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = client.request(method, path, **kwargs)
        except httpx.TransportError as exc:
            problem = str(exc) or type(exc).__name__
        else:
            if resp.status_code == 429 or resp.status_code >= 500:
                problem = f"HTTP {resp.status_code}"
            elif resp.status_code >= 400:
                raise OsvError(f"OSV rejected the request (HTTP {resp.status_code})")
            else:
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise OsvError("OSV returned invalid JSON") from exc
                if not isinstance(data, dict):
                    raise OsvError("OSV returned an unexpected response")
                return data
        if attempt == MAX_ATTEMPTS - 1:
            raise OsvError(f"OSV request failed after {MAX_ATTEMPTS} attempts: {problem}")
        time.sleep(delay)
        delay *= 2
    raise OsvError("unreachable")  # pragma: no cover


def _query_ids(client: httpx.Client, comps: list[Component]) -> dict[str, dict[str, str]]:
    """Ask OSV which vulns affect each component. Returns {purl: {vuln_id: modified}}."""
    out: dict[str, dict[str, str]] = {c.purl: {} for c in comps}
    pending: list[tuple[Component, str | None]] = [(c, None) for c in comps]

    for _ in range(MAX_PAGE_ROUNDS):
        if not pending:
            break
        following: list[tuple[Component, str | None]] = []
        for start in range(0, len(pending), BATCH_SIZE):
            chunk = pending[start : start + BATCH_SIZE]
            queries = []
            for comp, token in chunk:
                query: dict = {
                    "package": {"name": comp.name, "ecosystem": comp.ecosystem},
                    "version": comp.version,
                }
                if token:
                    query["page_token"] = token
                queries.append(query)

            data = _send(client, "POST", "/v1/querybatch", json={"queries": queries})
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                raise OsvError("Unexpected response shape from OSV querybatch")

            for (comp, _token), res in zip(chunk, results):
                res = res if isinstance(res, dict) else {}
                for vuln in res.get("vulns") or []:
                    if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                        modified = vuln.get("modified")
                        out[comp.purl][vuln["id"]] = modified if isinstance(modified, str) else ""
                next_token = res.get("next_page_token")
                if isinstance(next_token, str) and next_token:
                    following.append((comp, next_token))
        pending = following
    else:
        raise OsvError("OSV pagination did not finish")
    return out


def _fetch_record(client: httpx.Client, vuln_id: str) -> dict:
    return _send(client, "GET", f"/v1/vulns/{quote(vuln_id, safe='')}")


def find_vulnerabilities(
    components: list[Component],
    cache: Cache,
    *,
    client: httpx.Client | None = None,
    offline: bool = False,
    refresh: bool = False,
    ttl: float = QUERY_TTL,
) -> OsvResult:
    """Find known vulnerabilities for each component, using the cache where possible."""
    comps = list(components)
    ids_by_purl: dict[str, dict[str, str]] = {}
    to_query: list[Component] = []
    for comp in comps:
        use_cache = offline or not refresh
        cached = cache.get_query(query_key(comp), None if offline else ttl) if use_cache else None
        if cached is not None:
            ids_by_purl[comp.purl] = cached
        else:
            to_query.append(comp)

    result = OsvResult()
    owns_client = client is None and not offline
    if owns_client:
        client = make_client()
    try:
        if offline:
            result.unchecked = to_query
        elif to_query:
            assert client is not None
            fetched = _query_ids(client, to_query)
            for comp in to_query:
                ids_by_purl[comp.purl] = fetched[comp.purl]
                cache.put_query(query_key(comp), fetched[comp.purl])

        # Gather the full record for every distinct vulnerability ID.
        wanted: dict[str, str] = {}
        for ids in ids_by_purl.values():
            wanted.update(ids)

        records: dict[str, dict] = {}
        missing: dict[str, str] = {}
        for vuln_id, modified in wanted.items():
            cached_record = cache.get_record(vuln_id)
            if cached_record and (offline or not modified or cached_record[0] == modified):
                records[vuln_id] = cached_record[1]
            elif offline:
                log.warning("No cached record for %s (offline), skipping", vuln_id)
            else:
                missing[vuln_id] = modified

        if missing:
            assert client is not None
            with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
                bodies = list(pool.map(lambda v: _fetch_record(client, v), missing))
            for (vuln_id, modified), body in zip(missing.items(), bodies):
                records[vuln_id] = body
                cache.put_record(vuln_id, str(body.get("modified") or modified), body)
    finally:
        if owns_client and client is not None:
            client.close()

    for comp in comps:
        if comp.purl not in ids_by_purl:
            continue  # unchecked (offline, nothing cached)
        found = []
        for vuln_id in ids_by_purl[comp.purl]:
            body = records.get(vuln_id)
            vuln = parse_record(body, comp) if body else None
            if vuln:
                found.append(vuln)
        found.sort(key=lambda v: v.id)
        result.vulns[comp.purl] = found
    return result
