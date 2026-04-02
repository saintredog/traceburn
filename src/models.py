"""
src/models.py — Pydantic v2 data models for TraceBurn.

All data structures shared across modules are defined here.
No PII is stored in these models — vault.py holds plaintext PII.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
)


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────


class RemovalTier(int, Enum):
    PLAYWRIGHT = 1
    EMAIL = 2
    MANUAL = 3


class RemovalMethod(str, Enum):
    PLAYWRIGHT = "playwright"
    EMAIL = "email"
    MANUAL = "manual"


class ExposureStatus(str, Enum):
    FOUND = "found"
    REMOVAL_PENDING = "removal_pending"
    REMOVED = "removed"
    REAPPEARED = "reappeared"
    DISMISSED = "dismissed"


class RemovalStatus(str, Enum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    RETRYING = "retrying"
    # Special states set by removal engine
    CAPTCHA_BLOCKED = "captcha_blocked"
    EMAIL_NOT_CONFIGURED = "email_not_configured"


class ScanType(str, Enum):
    FULL = "full"
    SPOT_CHECK = "spot_check"
    REVERIFICATION = "reverification"


class MatchType(str, Enum):
    EXACT = "exact"
    PARTIAL = "partial"
    FUZZY = "fuzzy"


class BrokerRegion(str, Enum):
    US = "US"
    EU = "EU"
    UK = "UK"
    GLOBAL = "global"


class ProfileType(str, Enum):
    PRIMARY = "primary"
    FAMILY_MEMBER = "family_member"


# ──────────────────────────────────────────────
# User
# ──────────────────────────────────────────────


class User(BaseModel):
    """
    Represents a person whose data is being scanned.

    PII fields here are placeholders — actual values live in vault.py.
    The model stores vault_key references, not plaintext.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: int | None = None
    profile_type: ProfileType = ProfileType.PRIMARY
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Non-PII display label, e.g. 'Primary Profile'",
    )
    email_hash: str = Field(
        ...,
        description="SHA-256 hex digest of primary email — used for DB lookup without storing plaintext",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

    @field_validator("email_hash")
    @classmethod
    def validate_email_hash(cls, v: str) -> str:
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError(
                "email_hash must be a 64-character lowercase hex SHA-256 digest"
            )
        return v.lower()

    @classmethod
    def make_email_hash(cls, email: str) -> str:
        """Hash an email address for safe DB storage."""
        return hashlib.sha256(email.strip().lower().encode()).hexdigest()


# ──────────────────────────────────────────────
# BrokerDefinition
# ──────────────────────────────────────────────


class BrokerDefinition(BaseModel):
    """
    Loaded from brokers.yaml. Describes how to interact with each data broker.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: int | None = None
    name: str = Field(..., min_length=1, max_length=200)
    domain: str = Field(..., description="e.g. 'spokeo.com'")
    removal_tier: RemovalTier
    opt_out_url: str = Field(..., description="URL of opt-out page or endpoint")
    opt_out_email: str | None = Field(
        default=None,
        description="Required for Tier 2; email address to send opt-out to",
    )
    email_template: str | None = Field(
        default=None,
        description="Jinja2 template filename for Tier 2 email",
    )
    playwright_script: str | None = Field(
        default=None,
        description="Module name in removal/brokers/ for Tier 1 automation script",
    )
    region: BrokerRegion = BrokerRegion.US
    requires_email_verification: bool = False
    requires_phone_verification: bool = False
    requires_account_creation: bool = False
    captcha_detected: bool = False
    active: bool = True
    last_verified: datetime | None = None
    re_listing_risk: str = Field(
        default="medium",
        description="'high' | 'medium' | 'low' — how aggressively this broker re-lists removed data",
    )
    reverification_days: list[int] = Field(
        default=[7, 30, 90],
        description="Days after removal to re-check this broker",
    )
    robots_txt_allows_scan: bool = True
    notes: str | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.lower().strip()
        if "/" in v or " " in v:
            raise ValueError("domain must be bare hostname without scheme or path")
        return v

    @field_validator("opt_out_url")
    @classmethod
    def validate_opt_out_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                "opt_out_url must be a full URL starting with http:// or https://"
            )
        return v

    @model_validator(mode="after")
    def validate_tier_requirements(self) -> BrokerDefinition:
        if self.removal_tier == RemovalTier.PLAYWRIGHT and not self.playwright_script:
            raise ValueError("Tier 1 broker must specify playwright_script")
        if self.removal_tier == RemovalTier.EMAIL and not self.opt_out_email:
            raise ValueError("Tier 2 broker must specify opt_out_email")
        return self


# ──────────────────────────────────────────────
# Exposure
# ──────────────────────────────────────────────


class MatchedField(BaseModel):
    """A single PII field found on a broker page."""

    field_name: str = Field(
        ...,
        description="e.g. 'full_name', 'phone_number', 'home_address'",
    )
    match_type: MatchType
    confidence: float = Field(..., ge=0.0, le=1.0)
    raw_value_found: str = Field(
        ...,
        description="The actual string found on the page (may be partial/obfuscated)",
    )


class Exposure(BaseModel):
    """
    A confirmed or candidate PII exposure at a specific broker.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: int | None = None
    user_id: int
    broker_id: int
    broker_name: str  # denormalized for fast display
    profile_url: str = Field(..., description="Direct URL to the found profile listing")
    normalized_url: str = Field(
        ...,
        description="Lowercased, query-stripped canonical URL for deduplication",
    )
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    matched_fields: list[MatchedField] = Field(default_factory=list)
    composite_confidence: float = Field(..., ge=0.0, le=1.0)
    status: ExposureStatus = ExposureStatus.FOUND
    removal_request_id: int | None = None

    @field_validator("normalized_url")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(v.lower().strip())
        return urlunparse(parsed._replace(query="", fragment=""))

    @model_validator(mode="after")
    def compute_composite_confidence(self) -> Exposure:
        if not self.matched_fields:
            return self
        individual_scores = [f.confidence for f in self.matched_fields]
        max_score = max(individual_scores)
        n_fields = len(individual_scores)
        composite = max_score + 0.1 * (n_fields - 1)
        self.composite_confidence = min(composite, 1.0)
        return self


# ──────────────────────────────────────────────
# RemovalRequest
# ──────────────────────────────────────────────


class RemovalRequest(BaseModel):
    """
    Tracks a single opt-out action for a given Exposure.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: int | None = None
    exposure_id: int
    broker_id: int
    tier: RemovalTier
    method: RemovalMethod
    status: RemovalStatus = RemovalStatus.PENDING
    submitted_at: datetime | None = None
    confirmed_at: datetime | None = None
    next_check_at: datetime | None = None
    retry_count: int = Field(default=0, ge=0)
    last_error: str | None = None
    # For Tier 2 email opt-outs
    sent_email_id: str | None = Field(
        default=None,
        description="SMTP message-id of the sent opt-out email",
    )
    email_delivery_status: str | None = None  # "sent" | "delivered" | "bounced"
    confirmation_url_clicked: bool = False

    @model_validator(mode="after")
    def validate_tier_method_consistency(self) -> RemovalRequest:
        expected = {
            RemovalTier.PLAYWRIGHT: RemovalMethod.PLAYWRIGHT,
            RemovalTier.EMAIL: RemovalMethod.EMAIL,
            RemovalTier.MANUAL: RemovalMethod.MANUAL,
        }
        if self.method != expected[self.tier]:
            raise ValueError(
                f"Tier {self.tier} must use method {expected[self.tier]}, not {self.method}"
            )
        return self


# ──────────────────────────────────────────────
# ProofRecord
# ──────────────────────────────────────────────


class ProofRecord(BaseModel):
    """
    Tamper-evident evidence record for a removal action.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: int | None = None
    removal_request_id: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    screenshot_path: str | None = Field(
        default=None,
        description="Absolute path to the encrypted screenshot file on disk",
    )
    screenshot_checksum: str | None = Field(
        default=None,
        description="SHA-256 hex digest of the raw (pre-encryption) screenshot bytes",
    )
    http_response_code: int | None = Field(
        default=None,
        description="HTTP status code of the final page response, if applicable",
    )
    confirmation_text: str | None = Field(
        default=None,
        description="Extracted confirmation message from the broker page",
    )
    proof_type: str = Field(
        default="screenshot",
        description="'screenshot' | 'email_sent' | 'manual_attestation'",
    )
    # For email proofs
    email_message_id: str | None = None
    email_subject: str | None = None

    @field_validator("screenshot_checksum")
    @classmethod
    def validate_checksum(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError(
                "screenshot_checksum must be a 64-character hex SHA-256 digest"
            )
        return v.lower()


# ──────────────────────────────────────────────
# ScanHistory
# ──────────────────────────────────────────────


class ScanHistory(BaseModel):
    """One record per completed scan run."""

    id: int | None = None
    user_id: int
    scan_type: ScanType
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    brokers_checked: int = Field(default=0, ge=0)
    exposures_found: int = Field(default=0, ge=0)
    new_exposures: int = Field(default=0, ge=0)
    reappeared_exposures: int = Field(default=0, ge=0)
    removals_initiated: int = Field(default=0, ge=0)
    errors_encountered: int = Field(default=0, ge=0)
    scan_duration_seconds: float | None = None


# ──────────────────────────────────────────────
# ScanResult (transient — not persisted directly)
# ──────────────────────────────────────────────


class ScanResult(BaseModel):
    """
    Transient output from a single broker scan pass.
    Aggregator converts these into Exposure records for persistence.
    """

    broker_id: int
    broker_name: str
    profile_url: str
    page_text_snippet: str = Field(
        ...,
        description="Relevant text snippet from the page for logging/debug (no PII stored)",
    )
    matched_fields: list[MatchedField]
    composite_confidence: float = Field(..., ge=0.0, le=1.0)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_error: str | None = Field(
        default=None,
        description="Set if the scan encountered an error (timeout, block, etc.)",
    )
    captcha_detected: bool = False
    anti_bot_detected: bool = False


# ──────────────────────────────────────────────
# RemovalResult — transient output from removal engine
# ──────────────────────────────────────────────


@dataclass
class RemovalResult:
    """
    Transient result returned by each removal tier after processing one exposure.
    Not persisted directly — the RemovalRequest record in the DB holds authoritative state.
    """

    exposure_id: int
    broker_name: str
    status: RemovalStatus
    removal_request_id: int | None = None
    confirmation_text: str = ""
    error: str | None = None
    proof_record_id: int | None = None
    requires_manual_followup: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def succeeded(self) -> bool:
        """True if the removal was submitted or confirmed (not failed/blocked)."""
        return self.status in (
            RemovalStatus.SUBMITTED,
            RemovalStatus.CONFIRMED,
            RemovalStatus.AWAITING_CONFIRMATION,
        )
