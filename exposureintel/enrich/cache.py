import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Self

from exposureintel.ingest import Component

# (epss, percentile, score_date); all None means "checked, no score published"
EpssRow = tuple[float | None, float | None, str | None]
# (date_added, due_date, known_ransomware_use)
KevRow = tuple[str, str, bool]

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
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    date_added TEXT NOT NULL,
    due_date TEXT NOT NULL,
    ransomware INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL,
    score_date TEXT,
    fetched_at REAL NOT NULL
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
    """Small SQLite cache for OSV results, KEV catalog entries, and EPSS scores."""

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

    # ---- OSV query results and records -------------------------------------------------

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

    # ---- CISA KEV catalog ---------------------------------------------------------------

    def _meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def kev_fetched_at(self) -> float | None:
        value = self._meta("kev_fetched_at")
        try:
            return float(value) if value is not None else None
        except ValueError:
            return None

    def kev_version(self) -> str | None:
        return self._meta("kev_version")

    def replace_kev(self, rows: list[tuple[str, str, str, int]], catalog_version: str) -> None:
        """Replace the whole KEV table with a fresh download, in one transaction."""
        with self._db:
            self._db.execute("DELETE FROM kev")
            self._db.executemany(
                "INSERT OR REPLACE INTO kev (cve, date_added, due_date, ransomware) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )
            self._db.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('kev_fetched_at', ?)",
                (str(time.time()),),
            )
            self._db.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('kev_version', ?)",
                (catalog_version,),
            )

    def get_kev(self, cves: list[str]) -> dict[str, KevRow]:
        found: dict[str, KevRow] = {}
        for cve in cves:
            row = self._db.execute(
                "SELECT date_added, due_date, ransomware FROM kev WHERE cve = ?", (cve,)
            ).fetchone()
            if row is not None:
                found[cve] = (row[0], row[1], bool(row[2]))
        return found

    # ---- EPSS scores --------------------------------------------------------------------

    def get_epss(self, cves: list[str], max_age: float | None) -> dict[str, EpssRow]:
        """Return cached EPSS rows that are fresh enough (any age if max_age is None)."""
        found: dict[str, EpssRow] = {}
        now = time.time()
        for cve in cves:
            row = self._db.execute(
                "SELECT epss, percentile, score_date, fetched_at FROM epss WHERE cve = ?",
                (cve,),
            ).fetchone()
            if row is None:
                continue
            if max_age is not None and now - row[3] > max_age:
                continue
            found[cve] = (row[0], row[1], row[2])
        return found

    def put_epss(self, rows: dict[str, EpssRow]) -> None:
        now = time.time()
        with self._db:
            self._db.executemany(
                "INSERT OR REPLACE INTO epss (cve, epss, percentile, score_date, fetched_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [(cve, r[0], r[1], r[2], now) for cve, r in rows.items()],
            )
