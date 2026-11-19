import logging

from packaging.requirements import InvalidRequirement, Requirement

from .models import Component
from .purl import make_purl, normalize_name

log = logging.getLogger(__name__)


def parse(text: str) -> list[Component]:
    found: dict[tuple, Component] = {}
    # Join lines ending in a backslash (used for --hash options).
    text = text.replace("\r\n", "\n").replace("\\\n", " ")
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue  # blank, comment, or an option like -r / --index-url
        line = line.split(" --", 1)[0].strip()  # drop trailing --hash=...
        try:
            req = Requirement(line)
        except InvalidRequirement:
            log.warning("Skipping unparseable line: %s", line)
            continue
        specs = list(req.specifier)
        if (
            req.url
            or len(specs) != 1
            or specs[0].operator not in ("==", "===")
            or "*" in specs[0].version
        ):
            log.warning("Skipping %s: not pinned to one exact version", req.name)
            continue
        name = normalize_name("PyPI", req.name)
        version = specs[0].version
        found[(name, version)] = Component(name, version, "PyPI", make_purl("PyPI", name, version))
    return list(found.values())
