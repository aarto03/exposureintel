import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Self

from exposureintel.ingest import Component

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    key TEXT PRIMARY KEY,
    vuln_ids TEXT NOT NULL,
    fetched_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    modified TEXT NOT NULL,
    body TEXT NOT NULL
);
"""


def default_cache_path() -> Path:
    override = os.environ.get("EXPOSUREINTEL_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "exposureintel" / "cache.sqlite"


def query_key(component: Component) -> str:
    return f"{component.ecosystem}|{component.name}|{component.version}"


class Cache:
    """Small SQLite cache: query results (with expiry) and full vulnerability records."""

    def __init__(self, path: str | Path):
        path = Path(path)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path))
        self._db.executescript(_SCHEMA)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    def get_query(self, key: str, max_age: float | None) -> dict[str, str] | None:
        """Return {vuln_id: modified} for a cached query, or None if missing/expired."""
        row = self._db.execute(
            "SELECT vuln_ids, fetched_at FROM queries WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if max_age is not None and time.time() - row[1] > max_age:
            return None
        try:
            ids = json.loads(row[0])
        except ValueError:
            return None
        return ids if isinstance(ids, dict) else None

    def put_query(self, key: str, ids: dict[str, str]) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO queries (key, vuln_ids, fetched_at) VALUES (?, ?, ?)",
                (key, json.dumps(ids), time.time()),
            )

    def get_record(self, vuln_id: str) -> tuple[str, dict] | None:
        """Return (modified, record) for a cached vulnerability record, or None."""
        row = self._db.execute(
            "SELECT modified, body FROM records WHERE id = ?", (vuln_id,)
        ).fetchone()
        if row is None:
            return None
        try:
            body = json.loads(row[1])
        except ValueError:
            return None
        return (row[0], body) if isinstance(body, dict) else None

    def put_record(self, vuln_id: str, modified: str, body: dict) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO records (id, modified, body) VALUES (?, ?, ?)",
                (vuln_id, modified, json.dumps(body)),
            )
