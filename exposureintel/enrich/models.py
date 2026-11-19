from dataclasses import dataclass

from exposureintel.ingest import Component
from exposureintel.ingest.purl import normalize_name


@dataclass(frozen=True)
class Vulnerability:
    """One advisory affecting one component, trimmed to what we use."""

    id: str
    aliases: tuple[str, ...]
    summary: str
    severity_vectors: tuple[tuple[str, str], ...]  # e.g. ("CVSS_V3", "CVSS:3.1/AV:N/...")
    db_severity: str | None  # label such as "HIGH", when the source provides one
    fixed_versions: tuple[str, ...]
    published: str | None
    modified: str | None

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids = (self.id, *self.aliases)
        return tuple(dict.fromkeys(i for i in ids if i.startswith("CVE-")))


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def _fixed_versions(body: dict, component: Component) -> tuple[str, ...]:
    fixed: list[str] = []
    for entry in body.get("affected") or []:
        pkg = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != component.ecosystem:
            continue
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        if normalize_name(component.ecosystem, name) != component.name:
            continue
        for rng in entry.get("ranges") or []:
            for event in (rng.get("events") or []) if isinstance(rng, dict) else []:
                version = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(version, str):
                    fixed.append(version)
    return tuple(dict.fromkeys(fixed))


def parse_record(body: dict, component: Component) -> Vulnerability | None:
    """Convert an OSV record into a Vulnerability, or None if it should be ignored."""
    if body.get("withdrawn"):
        return None  # the advisory was retracted
    vuln_id = body.get("id")
    if not isinstance(vuln_id, str):
        return None

    vectors = []
    for sev in body.get("severity") or []:
        if (
            isinstance(sev, dict)
            and isinstance(sev.get("type"), str)
            and isinstance(sev.get("score"), str)
        ):
            vectors.append((sev["type"], sev["score"]))

    specific = body.get("database_specific")
    label = specific.get("severity") if isinstance(specific, dict) else None

    def text(key: str) -> str | None:
        value = body.get(key)
        return value if isinstance(value, str) else None

    return Vulnerability(
        id=vuln_id,
        aliases=tuple(_strings(body.get("aliases"))),
        summary=text("summary") or "",
        severity_vectors=tuple(vectors),
        db_severity=label if isinstance(label, str) else None,
        fixed_versions=_fixed_versions(body, component),
        published=text("published"),
        modified=text("modified"),
    )
