"""
nexsus/core/data_store.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Persistent storage layer backed by SQLite.

Provides:
  • Asset graph  (subdomains, endpoints, JS files, secrets, technologies)
  • Findings store with deduplication and CVSS scoring helpers
  • Thread-safe async-friendly API (asyncio.Lock guards writes)
  • JSON export / import for interoperability
  • In-memory cache for hot-path reads
"""
import asyncio
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional
from nexsus.config import Config


# ── Schema ─────────────────────────────────────────────────────────────────────
_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,         -- subdomain|endpoint|js_file|secret|tech
    value       TEXT NOT NULL,
    metadata    TEXT DEFAULT '{}',     -- JSON blob
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE NOT NULL,  -- SHA-256 dedup key
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,         -- Critical|High|Medium|Low|Info
    cvss        REAL DEFAULT 0.0,
    vuln_type   TEXT,
    url         TEXT,
    parameter   TEXT,
    payload     TEXT,
    evidence    TEXT,
    remediation TEXT,
    module      TEXT,
    confirmed   INTEGER DEFAULT 0,     -- 0=unconfirmed, 1=confirmed
    metadata    TEXT DEFAULT '{}',
    timestamp   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_assets_kind       ON assets(kind);
"""

_SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


def _fingerprint(finding: dict) -> str:
    """Stable dedup key for a finding."""
    key = "|".join([
        finding.get("vuln_type", ""),
        finding.get("url", ""),
        finding.get("parameter", ""),
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class DataStore:
    """
    Async-compatible data store.

    All mutating methods are safe to call from multiple coroutines;
    a single asyncio.Lock serialises SQLite writes.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = Path(db_path or Config.DB_PATH)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock    = asyncio.Lock()
        self._conn    = self._connect()

        # In-memory asset cache for hot-path reads
        self.assets: dict[str, set | list] = {
            "subdomains": set(),
            "endpoints":  set(),
            "js_files":   set(),
            "secrets":    [],
            "technologies": set(),
        }
        self._load_assets_cache()

    # ── SQLite helpers ─────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(_DDL)
        conn.commit()
        return conn

    @contextmanager
    def _cursor(self):
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # ── Asset management ───────────────────────────────────────────────────────

    def _load_assets_cache(self):
        """Populate in-memory sets from SQLite on startup."""
        with self._cursor() as cur:
            cur.execute("SELECT kind, value FROM assets")
            for row in cur.fetchall():
                kind, value = row["kind"], row["value"]
                if kind in ("subdomain", "subdomains"):
                    self.assets["subdomains"].add(value)
                elif kind == "endpoint":
                    self.assets["endpoints"].add(value)
                elif kind == "js_file":
                    self.assets["js_files"].add(value)
                elif kind == "secret":
                    self.assets["secrets"].append(json.loads(value))
                elif kind == "technology":
                    self.assets["technologies"].add(value)

    async def add_asset(self, kind: str, value: str, metadata: dict | None = None):
        """Insert or update an asset. Thread-safe."""
        now = int(time.time())
        meta_json = json.dumps(metadata or {})

        # Update in-memory cache immediately
        if kind == "subdomain":
            self.assets["subdomains"].add(value)
        elif kind == "endpoint":
            self.assets["endpoints"].add(value)
        elif kind == "js_file":
            self.assets["js_files"].add(value)
        elif kind == "technology":
            self.assets["technologies"].add(value)
        elif kind == "secret":
            self.assets["secrets"].append(json.loads(value) if value.startswith("{") else value)

        async with self._lock:
            with self._cursor() as cur:
                cur.execute("""
                    INSERT INTO assets (kind, value, metadata, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(kind, value) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        metadata  = excluded.metadata
                """, (kind, value, meta_json, now, now))

    async def add_assets_bulk(self, kind: str, values: list[str]):
        """Batch-insert assets; much faster for large wordlist results."""
        now = int(time.time())
        async with self._lock:
            with self._cursor() as cur:
                cur.executemany("""
                    INSERT INTO assets (kind, value, metadata, first_seen, last_seen)
                    VALUES (?, ?, '{}', ?, ?)
                    ON CONFLICT(kind, value) DO UPDATE SET last_seen = excluded.last_seen
                """, [(kind, v, now, now) for v in values])

        # Cache update
        cache_key = {
            "subdomain": "subdomains",
            "endpoint":  "endpoints",
            "js_file":   "js_files",
            "technology": "technologies",
        }.get(kind)
        if cache_key and isinstance(self.assets.get(cache_key), set):
            self.assets[cache_key].update(values)

    # ── Findings management ────────────────────────────────────────────────────

    @property
    def findings(self) -> list[dict]:
        """Read all findings from DB (fresh each call, no staleness)."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM findings ORDER BY cvss DESC, timestamp DESC")
            return [dict(r) for r in cur.fetchall()]

    async def save_finding(self, finding: dict) -> bool:
        """
        Persist a finding.
        Returns True if new, False if a duplicate was ignored.
        """
        fp = _fingerprint(finding)
        now = int(time.time())

        async with self._lock:
            with self._cursor() as cur:
                try:
                    cur.execute("""
                        INSERT INTO findings
                            (fingerprint, title, severity, cvss, vuln_type,
                             url, parameter, payload, evidence, remediation,
                             module, confirmed, metadata, timestamp)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        fp,
                        finding.get("title", "Unnamed"),
                        finding.get("severity", "Info"),
                        finding.get("cvss", 0.0),
                        finding.get("vuln_type", ""),
                        finding.get("url", ""),
                        finding.get("parameter", ""),
                        finding.get("payload", ""),
                        finding.get("evidence", ""),
                        finding.get("remediation", ""),
                        finding.get("module", ""),
                        int(finding.get("confirmed", False)),
                        json.dumps(finding.get("metadata", {})),
                        now,
                    ))
                    return True
                except sqlite3.IntegrityError:
                    # Duplicate fingerprint — update confirmed status if needed
                    if finding.get("confirmed"):
                        cur.execute(
                            "UPDATE findings SET confirmed=1 WHERE fingerprint=?",
                            (fp,)
                        )
                    return False

    # ── Reporting helpers ──────────────────────────────────────────────────────

    def findings_by_severity(self) -> dict[str, list[dict]]:
        out: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in self.findings:
            out.setdefault(f["severity"], []).append(f)
        return out

    def findings_count(self) -> dict[str, int]:
        counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        counts["total"] = 0
        with self._cursor() as cur:
            cur.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            )
            for row in cur.fetchall():
                counts[row["severity"]] = row["n"]
                counts["total"] += row["n"]
        return counts

    # ── Persistence helpers ────────────────────────────────────────────────────

    def export_json(self, path: Path):
        """Export everything to a single JSON file for reporting."""
        data = {
            "assets": {
                k: list(v) if isinstance(v, set) else v
                for k, v in self.assets.items()
            },
            "findings": self.findings,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    # Legacy compat: some modules call save_assets() directly
    def save_assets(self):
        pass   # no-op; SQLite keeps everything persisted automatically

    def close(self):
        self._conn.close()
