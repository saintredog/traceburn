"""
tests/conftest.py — Shared pytest fixtures for TraceBurn unit tests.

All fixtures use tmp_path so no real files are ever written to ~/.traceburn.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

import pytest

from src.db import Database
from src.models import (
    BrokerDefinition,
    BrokerRegion,
    Exposure,
    MatchedField,
    MatchType,
    RemovalMethod,
    RemovalRequest,
    RemovalStatus,
    RemovalTier,
)
from src.vault import PIIVault


@pytest.fixture
def sample_profile() -> dict:
    """
    Fake PII profile dict for John Smith.

    Contains all fields the scanner and report generator expect.  Uses
    entirely synthetic data — no real person.
    """
    return {
        "_user_id": 1,
        "display_name": "John Smith",
        "full_name": "John Smith",
        "email": "john.smith@example.com",
        "phone": "6195551234",
        "address": "123 Main St, Springfield, IL 62701",
        "dob": "1980-01-15",
    }


@pytest.fixture
def sample_broker() -> BrokerDefinition:
    """BrokerDefinition for TestBroker, Tier 1 (Playwright automation)."""
    return BrokerDefinition(
        id=1,
        name="TestBroker",
        domain="testbroker.com",
        removal_tier=RemovalTier.PLAYWRIGHT,
        opt_out_url="https://testbroker.com/optout",
        playwright_script="testbroker",
        region=BrokerRegion.US,
    )


@pytest.fixture
def sample_exposure(sample_broker: BrokerDefinition) -> Exposure:
    """
    Exposure record linked to sample_profile (user_id=1) and sample_broker.

    One matched field at 0.9 confidence → composite = 0.9.
    """
    return Exposure(
        id=1,
        user_id=1,
        broker_id=sample_broker.id,
        broker_name=sample_broker.name,
        profile_url="https://testbroker.com/people/john-smith-il",
        normalized_url="https://testbroker.com/people/john-smith-il",
        composite_confidence=0.9,
        matched_fields=[
            MatchedField(
                field_name="full_name",
                match_type=MatchType.EXACT,
                confidence=0.9,
                raw_value_found="John Smith",
            )
        ],
    )


@pytest.fixture
def sample_removal_request(
    sample_exposure: Exposure,
    sample_broker: BrokerDefinition,
) -> RemovalRequest:
    """RemovalRequest with status 'pending' for the sample exposure."""
    return RemovalRequest(
        id=1,
        exposure_id=sample_exposure.id,
        broker_id=sample_broker.id,
        tier=RemovalTier.PLAYWRIGHT,
        method=RemovalMethod.PLAYWRIGHT,
        status=RemovalStatus.PENDING,
    )


@pytest.fixture
def tmp_vault(tmp_path: Path) -> PIIVault:
    """PIIVault pointed at a temporary directory. Never touches ~/.traceburn."""
    return PIIVault(vault_path=tmp_path / "vault.enc")


@pytest.fixture
def tmp_db(tmp_path: Path):
    """
    Connected Database instance at tmp_path/test.db.

    Yields the open connection; closes on teardown.
    Never touches the real ~/.traceburn/traceburn.db.
    """
    db = Database(db_path=tmp_path / "test.db")
    db.connect()
    yield db
    db.close()
