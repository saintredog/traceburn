"""
src/config.py — Configuration Loader

Loads TraceBurn configuration from:
  1. ~/.traceburn/config.yaml  (or path in TRACEBURN_CONFIG env var)
  2. config/email.env          (OPTOUT_EMAIL, OPTOUT_EMAIL_APP_PASSWORD)
  3. Environment variable overrides (prefix CLEARTRACE_)

Call get_config() to obtain the singleton TraceBurnConfig instance.
Call validate_on_startup() to surface missing/invalid settings early.

Security notes:
  - The vault passphrase is NEVER stored in this object; it must be
    supplied to vault.py directly at runtime.
  - Sensitive env vars (bot tokens, API keys) are stored as SecretStr
    and are never written to logs.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import dotenv_values
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_CONFIG_SINGLETON: TraceBurnConfig | None = None

# ── Permission helpers ────────────────────────────────────────────────────────

REQUIRED_FILE_MODE = 0o600
REQUIRED_DIR_MODE = 0o700


def check_file_permissions(path: str | Path) -> None:
    """Warn if a sensitive file has permissions more open than required."""
    path = Path(path)
    if not path.exists():
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        logger.warning(
            "SECURITY: %s has permissions %o — expected %o. Run: chmod 600 %s",
            path,
            mode,
            REQUIRED_FILE_MODE,
            path,
        )


# ── Sub-config models ─────────────────────────────────────────────────────────


class UserProfile(BaseModel):
    """Non-PII display label for the scanning profile."""

    display_name: str = Field(..., min_length=1, max_length=200)
    profile_type: Literal["primary", "family_member"] = "primary"


class VaultConfig(BaseModel):
    db_path: Path = Field(default_factory=lambda: Path("~/.traceburn/data.ctdb"))
    screenshots_dir: Path = Field(default_factory=lambda: Path("~/.traceburn/screenshots"))

    @field_validator("db_path", "screenshots_dir", mode="before")
    @classmethod
    def expand_home(cls, v: str | Path) -> Path:
        return Path(v).expanduser().resolve()


class BrokerConfig(BaseModel):
    list_path: Path = Field(default_factory=lambda: Path("config/brokers.yaml"))
    active_regions: list[str] = Field(default_factory=lambda: ["US"])

    @field_validator("list_path", mode="before")
    @classmethod
    def expand_path(cls, v: str | Path) -> Path:
        return Path(v).expanduser().resolve()

    @field_validator("active_regions")
    @classmethod
    def validate_regions(cls, v: list[str]) -> list[str]:
        allowed = {"US", "EU", "UK", "global"}
        for r in v:
            if r not in allowed:
                raise ValueError(f"Unknown region '{r}'. Allowed: {allowed}")
        return v


class ScanConfig(BaseModel):
    """Scanning behaviour settings."""

    schedule: str = Field(default="0 3 * * 0", description="Cron expression for scheduled scans")
    default_type: Literal["full", "spot_check"] = "full"
    concurrency: int = Field(default=3, ge=1, le=10)
    request_timeout_seconds: int = Field(default=30, ge=5, le=120)
    min_confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class TelegramConfig(BaseModel):
    bot_token: SecretStr | None = None
    chat_id: str | None = None


class NotificationConfig(BaseModel):
    enabled: bool = True
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    events: list[str] = Field(
        default_factory=lambda: [
            "scan_complete",
            "new_exposure_found",
            "removal_confirmed",
            "removal_failed",
            "relisting_detected",
        ]
    )

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: list[str]) -> list[str]:
        allowed = {
            "scan_complete",
            "new_exposure_found",
            "removal_confirmed",
            "removal_failed",
            "relisting_detected",
        }
        for e in v:
            if e not in allowed:
                raise ValueError(f"Unknown event '{e}'. Allowed: {allowed}")
        return v


class ReverificationConfig(BaseModel):
    intervals_days: list[int] = Field(default_factory=lambda: [7, 30, 90])

    @field_validator("intervals_days")
    @classmethod
    def validate_intervals(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("intervals_days must not be empty")
        if any(d <= 0 for d in v):
            raise ValueError("All intervals must be positive integers")
        return sorted(v)


class HIBPConfig(BaseModel):
    api_key: SecretStr | None = None
    enabled: bool = True


class ReportingConfig(BaseModel):
    output_dir: Path = Field(default_factory=lambda: Path("reports/"))
    include_pii_in_export: bool = False
    default_format: Literal["html", "pdf", "json"] = "html"

    @field_validator("output_dir", mode="before")
    @classmethod
    def expand_path(cls, v: str | Path) -> Path:
        return Path(v).expanduser().resolve()


class EmailOptOutConfig(BaseModel):
    """Credentials for automated opt-out emails, loaded from config/email.env."""

    address: str | None = None
    app_password: SecretStr | None = None


# ── Root config ───────────────────────────────────────────────────────────────


class TraceBurnConfig(BaseSettings):
    """
    Root configuration object. Loaded once at CLI startup.

    Merges config.yaml with CLEARTRACE_* environment variable overrides.
    The vault passphrase is NEVER stored here — it is passed to vault.py
    directly and must never be logged.
    """

    model_config = SettingsConfigDict(
        env_prefix="CLEARTRACE_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    profile: UserProfile
    vault: VaultConfig = Field(default_factory=VaultConfig)
    brokers: BrokerConfig = Field(default_factory=BrokerConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    reverification: ReverificationConfig = Field(default_factory=ReverificationConfig)
    hibp: HIBPConfig = Field(default_factory=HIBPConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    email_optout: EmailOptOutConfig = Field(default_factory=EmailOptOutConfig)

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> TraceBurnConfig:
        """
        Load config from *yaml_path*, then overlay CLEARTRACE_* env vars.

        Also reads config/email.env for opt-out email credentials.
        """
        data: dict[str, Any] = {}
        if yaml_path.exists():
            with open(yaml_path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}

        # Load email credentials from config/email.env if present
        email_env_path = Path("config/email.env")
        email_env: dict[str, str | None] = {}
        if email_env_path.exists():
            email_env = dotenv_values(str(email_env_path))

        if email_env:
            data.setdefault("email_optout", {})
            if email_env.get("OPTOUT_EMAIL"):
                data["email_optout"]["address"] = email_env["OPTOUT_EMAIL"]
            if email_env.get("OPTOUT_EMAIL_APP_PASSWORD"):
                data["email_optout"]["app_password"] = email_env["OPTOUT_EMAIL_APP_PASSWORD"]

        return cls(**data)


# ── Startup validation ────────────────────────────────────────────────────────

REQUIRED_ENV_VARS = ["CLEARTRACE_VAULT_PASS"]
OPTIONAL_ENV_VARS = [
    "CLEARTRACE_TELEGRAM_BOT_TOKEN",
    "CLEARTRACE_TELEGRAM_CHAT_ID",
    "CLEARTRACE_HIBP_API_KEY",
]


def validate_on_startup(config: TraceBurnConfig | None = None) -> None:
    """
    Validate required environment variables and config file permissions.

    Called once at CLI startup. Exits with a clear message if critical
    requirements are unmet. Does NOT print secret values.
    """
    missing = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]
    if missing:
        print("ERROR: The following required environment variables are not set:")
        for var in missing:
            print(f"  - {var}")
        print()
        print("Set them before running TraceBurn:")
        for var in missing:
            print(f"  export {var}='your_value_here'")
        print()
        print("For CLEARTRACE_VAULT_PASS, choose a strong, unique passphrase.")
        sys.exit(1)

    optional_present = [var for var in OPTIONAL_ENV_VARS if os.environ.get(var)]
    if optional_present:
        logger.debug("Optional features enabled: %s", ", ".join(optional_present))

    # Check file permissions on sensitive paths
    traceburn_dir = Path.home() / ".traceburn"
    for sensitive in [traceburn_dir / "config.yaml", traceburn_dir / "traceburn.db"]:
        check_file_permissions(sensitive)


# ── Singleton accessor ────────────────────────────────────────────────────────

def get_config(config_path: Path | None = None) -> TraceBurnConfig:
    """
    Return the TraceBurnConfig singleton, loading it on first call.

    Subsequent calls with a different *config_path* are ignored — the
    singleton is loaded exactly once per process.
    """
    global _CONFIG_SINGLETON
    if _CONFIG_SINGLETON is None:
        path = config_path or (Path.home() / ".traceburn" / "config.yaml")
        _CONFIG_SINGLETON = TraceBurnConfig.from_yaml(path)
    return _CONFIG_SINGLETON


def reset_config() -> None:
    """Clear the singleton. Useful in tests."""
    global _CONFIG_SINGLETON
    _CONFIG_SINGLETON = None
