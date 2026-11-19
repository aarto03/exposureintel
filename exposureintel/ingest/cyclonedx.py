from .models import Component
from .purl import component_from_purl


def parse(data: dict) -> list[Component]:
    found: dict[tuple, Component] = {}

    def walk(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            comp = component_from_purl(item.get("purl"))
            if comp:
                found[(comp.ecosystem, comp.name, comp.version)] = comp
            walk(item.get("components"))  # components can be nested

    walk(data.get("components"))
    return list(found.values())
