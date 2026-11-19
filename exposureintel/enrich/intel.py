from collections.abc import Iterable
from dataclasses import dataclass, field

import httpx

from .cache import Cache, EpssRow, KevRow
from .epss import lookup_epss
from .http import SourceError
from .kev import ensure_kev
from .models import Vulnerability
from .osv import make_client


@dataclass(frozen=True)
class Intel:
    """Threat intel for one vulnerability. None means unknown; False means checked, no."""

    cves: tuple[str, ...] = ()
    in_kev: bool | None = None
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_ransomware: bool | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None


@dataclass
class IntelResult:
    intel: dict[str, Intel] = field(default_factory=dict)  # keyed by vulnerability id
    warnings: list[str] = field(default_factory=list)


def _build(
    cves: tuple[str, ...], kev: dict[str, KevRow] | None, epss: dict[str, EpssRow]
) -> Intel:
    """Combine intel across every CVE alias of one vulnerability (worst case wins)."""
    if not cves:
        return Intel()  # KEV and EPSS are keyed by CVE, so there is nothing to look up
    fields: dict = {"cves": cves}

    if kev is not None:
        hits = [kev[cve] for cve in cves if cve in kev]
        fields["in_kev"] = bool(hits)
        if hits:
            earliest = min(hits, key=lambda hit: hit[0])
            fields["kev_date_added"] = earliest[0]
            fields["kev_due_date"] = earliest[1]
            fields["kev_ransomware"] = any(hit[2] for hit in hits)

    scored = [epss[cve] for cve in cves if cve in epss and epss[cve][0] is not None]
    if scored:
        best = max(scored, key=lambda row: row[0] or 0.0)
        fields["epss"] = best[0]
        fields["epss_percentile"] = best[1]
        fields["epss_date"] = best[2]
    return Intel(**fields)


def enrich_vulnerabilities(
    vulns: Iterable[Vulnerability],
    cache: Cache,
    *,
    client: httpx.Client | None = None,
    offline: bool = False,
    refresh: bool = False,
) -> IntelResult:
    """Attach KEV and EPSS intel to each vulnerability. Source outages become warnings."""
    unique = list({v.id: v for v in vulns}.values())
    cves = sorted({cve.upper() for v in unique for cve in v.cve_ids})
    result = IntelResult()

    owns_client = client is None and not offline
    if owns_client:
        client = make_client()
    try:
        kev: dict[str, KevRow] | None = None
        if cves:
            try:
                note = ensure_kev(client, cache, offline=offline, refresh=refresh)
                kev = cache.get_kev(cves)
                if note:
                    result.warnings.append(note)
            except SourceError as exc:
                result.warnings.append(f"{exc}; KEV status unknown")

        epss_rows, errors = lookup_epss(client, cache, cves, offline=offline, refresh=refresh)
        result.warnings.extend(errors)
        missing = [cve for cve in cves if cve not in epss_rows]
        if missing:
            result.warnings.append(f"EPSS score unavailable for {len(missing)} CVE(s)")
    finally:
        if owns_client and client is not None:
            client.close()

    for vuln in unique:
        vuln_cves = tuple(cve.upper() for cve in vuln.cve_ids)
        result.intel[vuln.id] = _build(vuln_cves, kev, epss_rows)
    return result
