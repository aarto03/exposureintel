import argparse
import logging
import sys

from exposureintel.enrich import (
    Cache,
    Intel,
    OsvError,
    default_cache_path,
    enrich_vulnerabilities,
    find_vulnerabilities,
)
from exposureintel.ingest import IngestError, load_components


def describe(intel: Intel) -> str:
    parts = []
    if intel.in_kev:
        parts.append("KEV, ransomware use" if intel.kev_ransomware else "KEV")
    if intel.epss is not None:
        text = f"EPSS {intel.epss:.3f}"
        if intel.epss_percentile is not None:
            text += f" (p{intel.epss_percentile * 100:.0f})"
        parts.append(text)
    return f"  [{'; '.join(parts)}]" if parts else ""


def main() -> None:
    parser = argparse.ArgumentParser(prog="exposureintel")
    parser.add_argument("sbom", help="Path to SBOM or lockfile")
    parser.add_argument("--offline", action="store_true", help="Use only cached data")
    parser.add_argument("--refresh", action="store_true", help="Ignore cached query results")
    parser.add_argument("--cache-path", help="Location of the SQLite cache file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="warning: %(message)s")
    try:
        components = load_components(args.sbom)
        with Cache(args.cache_path or default_cache_path()) as cache:
            result = find_vulnerabilities(
                components, cache, offline=args.offline, refresh=args.refresh
            )
            all_vulns = [v for vulns in result.vulns.values() for v in vulns]
            intel = enrich_vulnerabilities(
                all_vulns, cache, offline=args.offline, refresh=args.refresh
            )
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    except OsvError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(3)

    print(f"Parsed {len(components)} components")
    for comp in components:
        vulns = result.vulns.get(comp.purl)
        if vulns is None:
            print(f"  {comp.name} {comp.version}: not checked (no cached data)")
            continue
        print(f"  {comp.name} {comp.version}: {len(vulns)} known vulnerabilities")
        for v in vulns:
            fixed = ", ".join(v.fixed_versions) or "no fix listed"
            cves = f" ({', '.join(v.cve_ids)})" if v.cve_ids else ""
            tags = describe(intel.intel.get(v.id, Intel()))
            print(f"      {v.id}{cves}  fixed in: {fixed}{tags}")
    if result.unchecked:
        print(f"\n{len(result.unchecked)} component(s) could not be checked offline.")
    for warning in intel.warnings:
        print(f"warning: {warning}", file=sys.stderr)


if __name__ == "__main__":
    main()
