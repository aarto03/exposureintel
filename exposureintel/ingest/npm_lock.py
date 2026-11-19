from .models import Component, IngestError
from .purl import make_purl

_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies")
_MARKER = "node_modules/"


def parse(data: dict) -> list[Component]:
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise IngestError(
            "Unsupported lockfile: lockfileVersion 1 (npm 6 or older). "
            "Run `npm install --package-lock-only` with npm 7+ to upgrade it."
        )

    root = packages.get("") or {}
    direct_names: set[str] = set()
    for key in _DEP_KEYS:
        deps = root.get(key)
        if isinstance(deps, dict):
            direct_names.update(deps)

    found: dict[tuple, Component] = {}
    for path, meta in packages.items():
        if _MARKER not in path or not isinstance(meta, dict) or meta.get("link"):
            continue
        version = meta.get("version")
        if not isinstance(version, str) or not version[:1].isdigit():
            continue  # git/file dependencies have no registry version
        path_name = path.rsplit(_MARKER, 1)[-1]
        name = meta.get("name") or path_name
        direct = path == _MARKER + path_name and path_name in direct_names
        key = (name, version)
        if key in found and found[key].direct:
            continue
        found[key] = Component(name, version, "npm", make_purl("npm", name, version), direct)
    return list(found.values())
