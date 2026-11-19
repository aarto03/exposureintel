import logging
from urllib.parse import unquote

from packaging.utils import canonicalize_name

from .models import Component

log = logging.getLogger(__name__)

_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}


def normalize_name(ecosystem: str, name: str) -> str:
    """PyPI names are case/underscore-insensitive, so normalize them."""
    return canonicalize_name(name) if ecosystem == "PyPI" else name


def make_purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "PyPI":
        return f"pkg:pypi/{name}@{version}"
    if name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:npm/{name}@{version}"


def component_from_purl(purl: object) -> Component | None:
    """Turn a package URL into a Component, or None if unsupported."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    ptype, _, rest = body.partition("/")
    ecosystem = _ECOSYSTEMS.get(ptype.lower())
    if ecosystem is None or "@" not in rest:
        log.warning("Skipping unsupported package: %s", purl)
        return None
    raw_name, _, raw_version = rest.rpartition("@")
    name = normalize_name(ecosystem, unquote(raw_name))
    version = unquote(raw_version)
    if not name or not version:
        return None
    return Component(name, version, ecosystem, make_purl(ecosystem, name, version))
