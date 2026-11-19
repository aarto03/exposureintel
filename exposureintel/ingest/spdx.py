from .models import Component
from .purl import component_from_purl


def parse(data: dict) -> list[Component]:
    found: dict[tuple, Component] = {}
    packages = data.get("packages")
    if not isinstance(packages, list):
        return []
    for pkg in packages:
        refs = pkg.get("externalRefs") if isinstance(pkg, dict) else None
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                comp = component_from_purl(ref.get("referenceLocator"))
                if comp:
                    found[(comp.ecosystem, comp.name, comp.version)] = comp
    return list(found.values())
