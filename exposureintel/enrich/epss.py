import httpx

from .cache import Cache, EpssRow
from .http import SourceError, fetch_json

SOURCE = "FIRST EPSS"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_TTL = 24 * 3600  # scores are republished daily
CHUNK = 100  # 100 CVE ids stay well under the API's 2000-character limit


def _number(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _fetch_chunk(client: httpx.Client, chunk: list[str]) -> dict[str, EpssRow]:
    data = fetch_json(
        client,
        EPSS_URL,
        source=SOURCE,
        params={"cve": ",".join(chunk), "limit": len(chunk)},
    )
    rows = data.get("data")
    if not isinstance(rows, list):
        raise SourceError(SOURCE, "response is missing data")
    found: dict[str, EpssRow] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("cve"), str):
            date = row.get("date")
            found[row["cve"].upper()] = (
                _number(row.get("epss")),
                _number(row.get("percentile")),
                date if isinstance(date, str) else None,
            )
    return found


def lookup_epss(
    client: httpx.Client | None,
    cache: Cache,
    cves: list[str],
    *,
    offline: bool,
    refresh: bool,
) -> tuple[dict[str, EpssRow], list[str]]:
    """Return ({cve: EPSS row}, error messages). CVEs missing from the dict are unknown."""
    wanted = sorted(set(cves))
    skip_cache = refresh and not offline
    known = {} if skip_cache else cache.get_epss(wanted, None if offline else EPSS_TTL)
    if offline or client is None:
        return known, []

    errors: list[str] = []
    todo = [cve for cve in wanted if cve not in known]
    for start in range(0, len(todo), CHUNK):
        chunk = todo[start : start + CHUNK]
        try:
            scores = _fetch_chunk(client, chunk)
        except SourceError as exc:
            errors.append(str(exc))
            known.update(cache.get_epss(chunk, None))  # fall back to older cached scores
            continue
        # A CVE that FIRST has no score for is remembered as "no score" so we don't re-ask.
        rows = {cve: scores.get(cve, (None, None, None)) for cve in chunk}
        cache.put_epss(rows)
        known.update(rows)
    return known, list(dict.fromkeys(errors))
