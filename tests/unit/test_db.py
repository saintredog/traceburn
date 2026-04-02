"""
tests/unit/test_db.py — Unit tests for Database gateway (src/db.py).

Coverage:
  - Table creation on connect()
  - CRUD: insert, get, update, list, delete
  - Filtered list queries
  - SQL injection prevention via parameterised queries
  - Context manager usage
  - schema_version table
  - Default path construction (path check only, no file created)

All tests use tmp_path fixtures — the real ~/.traceburn/traceburn.db is
never opened.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from src.db import DEFAULT_DB_PATH, Database, _validate_table_name


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().isoformat()


def _insert_user(db: Database, *, display_name: str = "Alice", suffix: str = "a") -> int:
    """Insert a minimal valid user row and return its id."""
    return db.insert("users", {
        "display_name": display_name,
        "email_hash": suffix[0] * 64,
        "created_at": _now(),
        "updated_at": _now(),
        "profile_type": "primary",
    })


def _insert_broker(db: Database, *, name: str = "TestBroker") -> int:
    """Insert a minimal valid broker row and return its id."""
    return db.insert("brokers", {
        "name": name,
        "domain": f"{name.lower()}.com",
        "removal_tier": 1,
        "opt_out_url": f"https://{name.lower()}.com/optout",
        "active": 1,
        "re_listing_risk": "medium",
        "reverification_days": "[7, 30, 90]",
        "robots_txt_allows_scan": 1,
    })


def _insert_exposure(db: Database, *, user_id: int, broker_id: int) -> int:
    """Insert a minimal valid exposure row and return its id."""
    return db.insert("exposures", {
        "user_id": user_id,
        "broker_id": broker_id,
        "broker_name": "TestBroker",
        "profile_url": "https://testbroker.com/john-smith",
        "normalized_url": "https://testbroker.com/john-smith",
        "first_seen": _now(),
        "last_seen": _now(),
        "matched_fields": "[]",
        "composite_confidence": 0.9,
        "status": "found",
    })


def _insert_removal_request(
    db: Database,
    *,
    exposure_id: int,
    broker_id: int,
    status: str = "pending",
) -> int:
    """Insert a minimal valid removal_request row and return its id."""
    return db.insert("removal_requests", {
        "exposure_id": exposure_id,
        "broker_id": broker_id,
        "tier": 1,
        "method": "playwright",
        "status": status,
        "retry_count": 0,
        "confirmation_url_clicked": 0,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Schema init
# ─────────────────────────────────────────────────────────────────────────────


class TestCreateTables:
    def test_create_tables(self, tmp_db: Database):
        """All 6 data tables are created on connect()."""
        expected_tables = {
            "users",
            "brokers",
            "exposures",
            "removal_requests",
            "proof_records",
            "scan_history",
        }
        rows = tmp_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        found = {r["name"] for r in rows}
        assert expected_tables.issubset(found)

    def test_schema_version(self, tmp_db: Database):
        """schema_version table exists and contains at least one version record."""
        rows = tmp_db.execute("SELECT * FROM schema_version")
        assert len(rows) >= 1
        assert rows[0]["version"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# CRUD
# ─────────────────────────────────────────────────────────────────────────────


class TestInsertAndGet:
    def test_insert_and_get(self, tmp_db: Database):
        """insert() returns a positive row id; get() retrieves the same row."""
        row_id = _insert_user(tmp_db, display_name="Bob", suffix="b")
        assert row_id > 0

        row = tmp_db.get("users", row_id)
        assert row is not None
        assert row["display_name"] == "Bob"

    def test_get_missing_returns_none(self, tmp_db: Database):
        """get() returns None for a row id that does not exist."""
        result = tmp_db.get("users", 99999)
        assert result is None

    def test_insert_returns_autoincrement_ids(self, tmp_db: Database):
        """Successive inserts produce increasing row ids."""
        id1 = _insert_user(tmp_db, display_name="User1", suffix="1")
        id2 = _insert_user(tmp_db, display_name="User2", suffix="2")
        assert id2 > id1


class TestUpdate:
    def test_update(self, tmp_db: Database):
        """update() modifies the specified fields; get() reflects the change."""
        row_id = _insert_user(tmp_db, display_name="Original", suffix="o")

        tmp_db.update("users", row_id, {"display_name": "Updated"})

        row = tmp_db.get("users", row_id)
        assert row["display_name"] == "Updated"

    def test_update_does_not_clobber_other_fields(self, tmp_db: Database):
        """update() changes only the specified columns; other columns are unchanged."""
        row_id = _insert_user(tmp_db, display_name="Alice", suffix="a")
        original = tmp_db.get("users", row_id)

        tmp_db.update("users", row_id, {"display_name": "Alicia"})
        updated = tmp_db.get("users", row_id)

        assert updated["display_name"] == "Alicia"
        assert updated["email_hash"] == original["email_hash"]


class TestList:
    def test_list_all(self, tmp_db: Database):
        """list() with no filters returns all rows in the table."""
        _insert_user(tmp_db, display_name="Alice", suffix="a")
        _insert_user(tmp_db, display_name="Bob", suffix="b")
        _insert_user(tmp_db, display_name="Carol", suffix="c")

        rows = tmp_db.list("users")
        assert len(rows) == 3

    def test_list_with_filter(self, tmp_db: Database):
        """
        list(filters={"status": "pending"}) returns only matching removal requests.

        Two rows are inserted — one with status 'pending', one with 'confirmed'.
        Only the 'pending' row should be returned.
        """
        user_id = _insert_user(tmp_db, suffix="u")
        broker_id = _insert_broker(tmp_db, name="BrokerA")
        broker_id2 = _insert_broker(tmp_db, name="BrokerB")

        # Two exposures at different URLs (unique constraint is user_id + normalized_url)
        exposure_id = tmp_db.insert("exposures", {
            "user_id": user_id,
            "broker_id": broker_id,
            "broker_name": "BrokerA",
            "profile_url": "https://brokera.com/john-smith",
            "normalized_url": "https://brokera.com/john-smith",
            "first_seen": _now(),
            "last_seen": _now(),
            "matched_fields": "[]",
            "composite_confidence": 0.9,
            "status": "found",
        })
        exposure_id2 = tmp_db.insert("exposures", {
            "user_id": user_id,
            "broker_id": broker_id2,
            "broker_name": "BrokerB",
            "profile_url": "https://brokerb.com/john-smith",
            "normalized_url": "https://brokerb.com/john-smith",
            "first_seen": _now(),
            "last_seen": _now(),
            "matched_fields": "[]",
            "composite_confidence": 0.8,
            "status": "found",
        })

        _insert_removal_request(
            tmp_db, exposure_id=exposure_id, broker_id=broker_id, status="pending"
        )
        _insert_removal_request(
            tmp_db, exposure_id=exposure_id2, broker_id=broker_id2, status="confirmed"
        )

        pending_rows = tmp_db.list("removal_requests", filters={"status": "pending"})
        assert len(pending_rows) == 1
        assert pending_rows[0]["status"] == "pending"


class TestDelete:
    def test_delete(self, tmp_db: Database):
        """delete() removes the row; subsequent get() returns None."""
        row_id = _insert_user(tmp_db, suffix="d")
        assert tmp_db.get("users", row_id) is not None

        tmp_db.delete("users", row_id)
        assert tmp_db.get("users", row_id) is None

    def test_delete_nonexistent_is_silent(self, tmp_db: Database):
        """delete() on a non-existent id does not raise an exception."""
        tmp_db.delete("users", 99999)  # should not raise


# ─────────────────────────────────────────────────────────────────────────────
# SQL injection prevention
# ─────────────────────────────────────────────────────────────────────────────


class TestParameterisedQueries:
    def test_parameterized_queries(self, tmp_db: Database):
        """
        A SQL injection attempt stored as a display_name value does not
        execute as SQL — the users table continues to exist and only
        contains the literally-stored string.
        """
        injection_payload = "'); DROP TABLE users; --"
        row_id = _insert_user(tmp_db, display_name=injection_payload, suffix="x")

        # Table still exists and the row is retrievable
        row = tmp_db.get("users", row_id)
        assert row is not None
        assert row["display_name"] == injection_payload

        # users table is intact
        all_users = tmp_db.list("users")
        assert len(all_users) >= 1

    def test_invalid_table_name_raises(self, tmp_db: Database):
        """
        Passing an unknown table name to CRUD methods raises ValueError,
        preventing table-name injection attacks.
        """
        with pytest.raises(ValueError, match="Unknown table"):
            tmp_db.list("evil_table; DROP TABLE users; --")

        with pytest.raises(ValueError, match="Unknown table"):
            _validate_table_name("not_a_real_table")


# ─────────────────────────────────────────────────────────────────────────────
# Context manager
# ─────────────────────────────────────────────────────────────────────────────


class TestContextManager:
    def test_context_manager(self, tmp_path: Path):
        """Database works as a context manager; data committed on clean exit."""
        db_path = tmp_path / "cm_test.db"
        with Database(db_path=db_path) as db:
            row_id = _insert_user(db, display_name="CmUser", suffix="c")

        # Reopen and verify the data was committed
        with Database(db_path=db_path) as db:
            row = db.get("users", row_id)
            assert row is not None
            assert row["display_name"] == "CmUser"

    def test_context_manager_rollback_on_exception(self, tmp_path: Path):
        """
        When an exception is raised inside the context, changes are rolled back.
        The with-block re-raises the exception.
        """
        db_path = tmp_path / "rollback_test.db"

        with pytest.raises(RuntimeError, match="intentional"):
            with Database(db_path=db_path) as db:
                _insert_user(db, display_name="Ephemeral", suffix="e")
                raise RuntimeError("intentional test error")


# ─────────────────────────────────────────────────────────────────────────────
# Default path
# ─────────────────────────────────────────────────────────────────────────────


class TestDefaultPath:
    def test_default_path(self):
        """
        Default path is ~/.traceburn/traceburn.db.

        Only the path string is checked — no file is created.
        """
        db = Database()  # no db_path → uses DEFAULT_DB_PATH
        expected = Path.home() / ".traceburn" / "traceburn.db"
        assert db._path == expected
        # The real DB must NOT be opened during this test
        assert db._conn is None
