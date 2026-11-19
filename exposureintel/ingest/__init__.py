import json
from pathlib import Path

from . import cyclonedx, npm_lock, requirements, spdx
from .models import Component, IngestError

__all__ = ["Component", "IngestError", "load_components"]

MAX_BYTES = 50 * 1024 * 1024  # refuse absurdly large inputs


def load_components(path: str | Path) -> list[Component]:
    """Read an SBOM or lockfile and return its packages, sorted."""
    p = Path(path)
    if not p.is_file():
        raise IngestError(f"File not found: {p}")
    if p.stat().st_size > MAX_BYTES:
        raise IngestError(f"{p.name} is larger than {MAX_BYTES // (1024 * 1024)} MB")
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise IngestError(f"{p.name} is not a UTF-8 text file") from exc

    name = p.name.lower()
    if name.endswith(".txt") or name.startswith("requirements"):
        found = requirements.parse(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise IngestError(f"{p.name} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise IngestError(f"{p.name}: expected a JSON object at the top level")
        if data.get("bomFormat") == "CycloneDX":
            found = cyclonedx.parse(data)
        elif "spdxVersion" in data:
            found = spdx.parse(data)
        elif "lockfileVersion" in data:
            found = npm_lock.parse(data)
        else:
            raise IngestError(
                f"Unrecognized format in {p.name}. Supported: CycloneDX JSON, SPDX JSON, "
                "requirements.txt, package-lock.json"
            )
    return sorted(found, key=lambda c: (c.ecosystem, c.name, c.version))
