from dataclasses import dataclass


class IngestError(ValueError):
    """Raised when an input file cannot be read or understood."""


@dataclass(frozen=True)
class Component:
    """One software package found in an input file."""

    name: str
    version: str
    ecosystem: str  # OSV ecosystem name: "PyPI" or "npm"
    purl: str
    direct: bool | None = None  # None means "unknown"
