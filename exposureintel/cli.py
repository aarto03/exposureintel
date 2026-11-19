import argparse
import logging
import sys

from exposureintel.ingest import IngestError, load_components


def main() -> None:
    parser = argparse.ArgumentParser(prog="exposureintel")
    parser.add_argument("sbom", help="Path to SBOM or lockfile")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="warning: %(message)s")
    try:
        components = load_components(args.sbom)
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    print(f"Parsed {len(components)} components")
    for c in components:
        flag = {True: " (direct)", False: " (transitive)", None: ""}[c.direct]
        print(f"  {c.ecosystem}: {c.name} {c.version}{flag}")


if __name__ == "__main__":
    main()
