import os
import time

import httpx

from .cache import Cache
from .http import SourceError, fetch_json

SOURCE = "CISA KEV"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TTL = 12 * 3600  # refresh the catalog twice a day


def kev_url() -> str:
    """The feed URL; EXPOSUREINTEL_KEV_URL overrides it (handy for mirrors or testing)."""
    return os.environ.get("EXPOSUREINTEL_KEV_URL") or KEV_URL


def _download(client: httpx.Client, cache: Cache) -> None:
    data = fetch_json(client, kev_url(), source=SOURCE)
    rows = []
    for entry in data.get("vulnerabilities") or []:
        if isinstance(entry, dict) and isinstance(entry.get("cveID"), str):
            ransomware = entry.get("knownRansomwareCampaignUse") == "Known"
            rows.append(
                (
                    entry["cveID"].upper(),
                    str(entry.get("dateAdded") or ""),
                    str(entry.get("dueDate") or ""),
                    int(ransomware),
                )
            )
    if not rows:
        # Never replace a good cache with an empty or broken download.
        raise SourceError(SOURCE, "feed contained no entries")
    cache.replace_kev(rows, str(data.get("catalogVersion") or ""))


def ensure_kev(
    client: httpx.Client | None, cache: Cache, *, offline: bool, refresh: bool
) -> str | None:
    """Make sure the cache holds a usable KEV catalog.

    Returns a warning message if older cached data had to be used, None if all is well.
    Raises SourceError when no usable data exists at all.
    """
    fetched = cache.kev_fetched_at()
    if offline or client is None:
        if fetched is None:
            raise SourceError(SOURCE, "no cached data available while offline")
        return None

    fresh = fetched is not None and time.time() - fetched <= KEV_TTL
    if fresh and not refresh:
        return None
    try:
        _download(client, cache)
    except SourceError as exc:
        if fetched is None:
            raise
        return f"{exc}; using older cached KEV data"
    return None
