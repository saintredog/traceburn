"""
src/db.py — SQLite Database Gateway

Single access point for all database reads and writes. No raw sqlite3 calls
should appear elsewhere in the codebase. All queries are parameterized.

Tables:
    users, brokers, exposures, removal_requests, proof_records,
    scan_history, schema_version
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Iterator

DEFAULT_DB_PATH: Path = Path.home() / ".traceburn" / "traceburn.db"

# Bump this whenever the schema changes. Migrations keyed by (from, to).
CURRENT_SCHEMA_VERSION: int = 1

_CREATE_SCHEMA_VERSION = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  TEXT    NOT NULL
);
"""

_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_type TEXT    NOT NULL DEFAULT 'primary',
    display_name TEXT    NOT NULL,
    email_hash   TEXT    NOT NULL UNIQUE,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    is_active    INTEGER NOT NULL DEFAULT 1
);
"""

_CREATE_BROKERS = """
CREATE TABLE IF NOT EXISTS brokers (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    name                      TEXT    NOT NULL UNIQUE,
    domain                    TEXT    NOT NULL UNIQUE,
    region                    TEXT    NOT NULL DEFAULT 'US',
    removal_tier              INTEGER NOT NULL,
    opt_out_url               TEXT    NOT NULL,
    opt_out_email             TEXT,
    email_template            TEXT,
    playwright_script         TEXT,
    requires_email_verification  INTEGER NOT NULL DEFAULT 0,
    requires_phone_verification  INTEGER NOT NULL DEFAULT 0,
    requires_account_creation    INTEGER NOT NULL DEFAULT 0,
    captcha_detected             INTEGER NOT NULL DEFAULT 0,
    active                    INTEGER NOT NULL DEFAULT 1,
    last_verified             TEXT,
    re_listing_risk           TEXT    NOT NULL DEFAULT 'medium',
    reverification_days       TEXT    NOT NULL DEFAULT '[7,30,90]',
    robots_txt_allows_scan    INTEGER NOT NULL DEFAULT 1,
    notes                     TEXT
);
"""

_CREATE_EXPOSURES = """
CREATE TABLE IF NOT EXISTS exposures (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id              INTEGER NOT NULL REFERENCES users(id),
    broker_id            INTEGER NOT NULL REFERENCES brokers(id),
    broker_name          TEXT    NOT NULL,
    profile_url          TEXT    NOT NULL,
    normalized_url       TEXT    NOT NULL,
    first_seen           TEXT    NOT NULL,
    last_seen            TEXT    NOT NULL,
    matched_fields       TEXT    NOT NULL DEFAULT '[]',
    composite_confidence REAL    NOT NULL DEFAULT 0.0,
    status               TEXT    NOT NULL DEFAULT 'found',
    removal_request_id   INTEGER REFERENCES removal_requests(id),
    UNIQUE(user_id, normalized_url)
);
"""

_CREATE_REMOVAL_REQUESTS = """
CREATE TABLE IF NOT EXISTS removal_requests (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    exposure_id               INTEGER NOT NULL REFERENCES exposures(id),
    broker_id                 INTEGER NOT NULL REFERENCES brokers(id),
    tier                      INTEGER NOT NULL,
    method                    TEXT    NOT NULL,
    status                    TEXT    NOT NULL DEFAULT 'pending',
    submitted_at              TEXT,
    confirmed_at              TEXT,
    next_check_at             TEXT,
    retry_count               INTEGER NOT NULL DEFAULT 0,
    last_error                TEXT,
    sent_email_id             TEXT,
    email_delivery_status     TEXT,
    confirmation_url_clicked  INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_PROOF_RECORDS = """
CREATE TABLE IF NOT EXISTS proof_records (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    removal_request_id   INTEGER NOT NULL REFERENCES removal_requests(id),
    timestamp            TEXT    NOT NULL,
    screenshot_path      TEXT,
    screenshot_checksum  TEXT,
    http_response_code   INTEGER,
    confirmation_text    TEXT,
    proof_type           TEXT    NOT NULL DEFAULT 'screenshot',
    email_message_id     TEXT,
    email_subject        TEXT
);
"""

_CREATE_SCAN_HISTORY = """
CREATE TABLE IF NOT EXISTS scan_history (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                 INTEGER NOT NULL REFERENCES users(id),
    scan_type               TEXT    NOT NULL,
    started_at              TEXT    NOT NULL,
    completed_at            TEXT,
    brokers_checked         INTEGER NOT NULL DEFAULT 0,
    exposures_found         INTEGER NOT NULL DEFAULT 0,
    new_exposures           INTEGER NOT NULL DEFAULT 0,
    reappeared_exposures    INTEGER NOT NULL DEFAULT 0,
    removals_initiated      INTEGER NOT NULL DEFAULT 0,
    errors_encountered      INTEGER NOT NULL DEFAULT 0,
    scan_duration_seconds   REAL
);
"""

_ALL_TABLES = [
    _CREATE_SCHEMA_VERSION,
    _CREATE_USERS,
    _CREATE_BROKERS,
    # removal_requests before exposures so the FK reference resolves
    _CREATE_REMOVAL_REQUESTS,
    _CREATE_EXPOSURES,
    _CREATE_PROOF_RECORDS,
    _CREATE_SCAN_HISTORY,
]

# Fields that hold encrypted blobs (bytes stored as hex) — used by rekey
_ENCRYPTED_FIELDS: list[tuple[str, str]] = []  # (table, column) — extend as PII fields added


class Database:
    """
    SQLite gateway. All modules must use this class — no raw sqlite3 calls.

    Usage as context manager::

        with Database() as db:
            db.insert("users", {"display_name": "Alice", ...})

    Or kept open for a session::

        db = Database()
        db.connect()
        ...
        db.close()
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path: Path = db_path or DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None

    # ── Connection management ─────────────────────────────────────────────

    def connect(self) -> None:
        """Open the database connection and ensure the schema is initialised."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), detect_types=sqlite3.PARSE_DECLTYPES)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._initialise_schema()

    def close(self) -> None:
        """Commit pending work and close the connection."""
        if self._conn:
            self._conn.commit()
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Database:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is None:
            self._conn and self._conn.commit()
        else:
            self._conn and self._conn.rollback()
        self.close()

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Explicit savepoint-based nested transaction context manager."""
        conn = self._require_connection()
        conn.execute("SAVEPOINT traceburn_txn")
        try:
            yield
            conn.execute("RELEASE SAVEPOINT traceburn_txn")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT traceburn_txn")
            raise

    # ── Schema init & migrations ──────────────────────────────────────────

    def _initialise_schema(self) -> None:
        """Create tables and apply any pending migrations."""
        conn = self._require_connection()
        with conn:
            for ddl in _ALL_TABLES:
                conn.execute(ddl)

        version = self._get_schema_version()
        if version == 0:
            self._set_schema_version(CURRENT_SCHEMA_VERSION)
        elif version < CURRENT_SCHEMA_VERSION:
            self._run_migrations(version)

    def _get_schema_version(self) -> int:
        conn = self._require_connection()
        row = conn.execute(
            "SELECT version FROM schema_version ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return int(row["version"]) if row else 0

    def _set_schema_version(self, version: int) -> None:
        conn = self._require_connection()
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (version, _now()),
        )
        conn.commit()

    def _run_migrations(self, from_version: int) -> None:
        """Apply incremental migrations from *from_version* to CURRENT_SCHEMA_VERSION."""
        # Migrations registry: keyed as (from_version, to_version) -> callable
        migrations: dict[tuple[int, int], Any] = {
            # Example: (1, 2): self._migrate_1_to_2,
        }
        v = from_version
        while v < CURRENT_SCHEMA_VERSION:
            key = (v, v + 1)
            if key in migrations:
                migrations[key]()
            v += 1
        self._set_schema_version(CURRENT_SCHEMA_VERSION)

    # ── CRUD ──────────────────────────────────────────────────────────────

    def insert(self, table: str, data: dict[str, Any]) -> int:
        """
        Insert a row into *table* and return the new rowid.

        ``data`` is a mapping of column name → value. Values that are
        lists/dicts are JSON-serialised automatically.
        """
        _validate_table_name(table)
        serialised = _serialise_values(data)
        columns = ", ".join(serialised.keys())
        placeholders = ", ".join(["?"] * len(serialised))
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"  # noqa: S608
        conn = self._require_connection()
        cur = conn.execute(sql, list(serialised.values()))
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get(self, table: str, row_id: int) -> dict[str, Any] | None:
        """Fetch a single row by primary key; returns None if not found."""
        _validate_table_name(table)
        sql = f"SELECT * FROM {table} WHERE id = ?"  # noqa: S608
        conn = self._require_connection()
        row = conn.execute(sql, (row_id,)).fetchone()
        return _row_to_dict(row) if row else None

    def update(self, table: str, row_id: int, data: dict[str, Any]) -> None:
        """Update columns in *data* for the row identified by *row_id*."""
        _validate_table_name(table)
        serialised = _serialise_values(data)
        set_clause = ", ".join(f"{col} = ?" for col in serialised.keys())
        sql = f"UPDATE {table} SET {set_clause} WHERE id = ?"  # noqa: S608
        conn = self._require_connection()
        conn.execute(sql, [*serialised.values(), row_id])
        conn.commit()

    def list(
        self,
        table: str,
        filters: dict[str, Any] | None = None,
        order_by: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return all rows matching *filters* (AND-joined equality conditions).

        ``order_by`` is a raw SQL fragment like ``"created_at DESC"`` — only
        use trusted values here (no user input).
        """
        _validate_table_name(table)
        filters = filters or {}
        serialised = _serialise_values(filters)

        where = ""
        params: list[Any] = []
        if serialised:
            where = "WHERE " + " AND ".join(f"{col} = ?" for col in serialised.keys())
            params = list(serialised.values())

        order = f" ORDER BY {order_by}" if order_by else ""
        lim = f" LIMIT {int(limit)}" if limit is not None else ""
        sql = f"SELECT * FROM {table} {where}{order}{lim}"  # noqa: S608

        conn = self._require_connection()
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]

    def delete(self, table: str, row_id: int) -> None:
        """Delete the row with *row_id* from *table*."""
        _validate_table_name(table)
        sql = f"DELETE FROM {table} WHERE id = ?"  # noqa: S608
        conn = self._require_connection()
        conn.execute(sql, (row_id,))
        conn.commit()

    def execute(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """
        Run an arbitrary parameterised SELECT and return rows as dicts.

        Only use this for complex queries that can't be expressed via the
        higher-level CRUD methods. Never pass user input into *sql* directly.
        """
        conn = self._require_connection()
        rows = conn.execute(sql, params or []).fetchall()
        return [_row_to_dict(r) for r in rows]

    def execute_write(self, sql: str, params: list[Any] | None = None) -> int:
        """
        Run an arbitrary parameterised INSERT/UPDATE/DELETE.

        Returns lastrowid for INSERT statements; 0 otherwise.
        """
        conn = self._require_connection()
        cur = conn.execute(sql, params or [])
        conn.commit()
        return cur.lastrowid or 0

    # ── Rekey support ─────────────────────────────────────────────────────

    def get_all_encrypted_fields(self) -> list[tuple[str, int, str, bytes]]:
        """
        Return all (table, row_id, column, blob) tuples for encrypted fields.
        Used by the vault rekey procedure.
        """
        results: list[tuple[str, int, str, bytes]] = []
        conn = self._require_connection()
        for table, column in _ENCRYPTED_FIELDS:
            rows = conn.execute(
                f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"  # noqa: S608
            ).fetchall()
            for row in rows:
                blob = bytes.fromhex(row[column]) if isinstance(row[column], str) else row[column]
                results.append((table, row["id"], column, blob))
        return results

    def apply_rekey_updates(self, updates: list[tuple[str, int, str, bytes]]) -> None:
        """
        Write re-encrypted blobs in a single atomic transaction.
        *updates* is a list of (table, row_id, column, new_blob).
        """
        conn = self._require_connection()
        with conn:
            for table, row_id, column, new_blob in updates:
                _validate_table_name(table)
                conn.execute(
                    f"UPDATE {table} SET {column} = ? WHERE id = ?",  # noqa: S608
                    (new_blob.hex(), row_id),
                )

    # ── Internal helpers ──────────────────────────────────────────────────

    def _require_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError(
                "Database is not connected. Call connect() or use as a context manager."
            )
        return self._conn


# ── Module-level helpers ──────────────────────────────────────────────────────

_ALLOWED_TABLES: frozenset[str] = frozenset(
    {
        "users",
        "brokers",
        "exposures",
        "removal_requests",
        "proof_records",
        "scan_history",
        "schema_version",
    }
)


def _validate_table_name(table: str) -> None:
    """Guard against SQL injection via table name."""
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Unknown table '{table}'. Allowed: {sorted(_ALLOWED_TABLES)}")


def _serialise_values(data: dict[str, Any]) -> dict[str, Any]:
    """JSON-serialise any list/dict values so they can be stored as TEXT."""
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, (list, dict)):
            out[k] = json.dumps(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, bool):
            out[k] = int(v)
        else:
            out[k] = v
    return out


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict, deserialising JSON columns."""
    result: dict[str, Any] = {}
    for key in row.keys():
        val = row[key]
        if isinstance(val, str):
            stripped = val.strip()
            if stripped.startswith(("[", "{")):
                try:
                    val = json.loads(val)
                except (json.JSONDecodeError, ValueError):
                    pass
        result[key] = val
    return result


def _now() -> str:
    return datetime.utcnow().isoformat()
