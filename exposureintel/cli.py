import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="exposureintel")
    parser.add_argument("sbom", help="Path to SBOM or lockfile")
    parser.parse_args()
    print("ExposureIntel v0.1.0: not implemented yet")


if __name__ == "__main__":
    main()
