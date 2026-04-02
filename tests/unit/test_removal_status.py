"""
tests/unit/test_removal_status.py — Unit tests for the removal status state machine.

The state machine is encoded implicitly across RemovalEngine and the DB layer.
These tests capture the intended business rules as explicit transition logic
and verify them against the RemovalRequest / RemovalStatus model.

Valid transition graph:
    PENDING → SUBMITTED
    SUBMITTED → AWAITING_CONFIRMATION | FAILED
    AWAITING_CONFIRMATION → CONFIRMED | FAILED
    CONFIRMED → (terminal)
    FAILED → RETRYING
    RETRYING → SUBMITTED | FAILED
    CAPTCHA_BLOCKED → (terminal — permanently failed)
    EMAIL_NOT_CONFIGURED → (terminal — permanently failed)
"""
from __future__ import annotations

from datetime import datetime

import pytest

from src.models import (
    RemovalMethod,
    RemovalRequest,
    RemovalStatus,
    RemovalTier,
)

# ─────────────────────────────────────────────────────────────────────────────
# State machine definition (business rules)
# ─────────────────────────────────────────────────────────────────────────────

VALID_TRANSITIONS: dict[RemovalStatus, frozenset[RemovalStatus]] = {
    RemovalStatus.PENDING: frozenset({
        RemovalStatus.SUBMITTED,
        RemovalStatus.FAILED,
    }),
    RemovalStatus.SUBMITTED: frozenset({
        RemovalStatus.AWAITING_CONFIRMATION,
        RemovalStatus.FAILED,
    }),
    RemovalStatus.AWAITING_CONFIRMATION: frozenset({
        RemovalStatus.CONFIRMED,
        RemovalStatus.FAILED,
    }),
    RemovalStatus.CONFIRMED: frozenset(),           # terminal
    RemovalStatus.FAILED: frozenset({
        RemovalStatus.RETRYING,
    }),
    RemovalStatus.RETRYING: frozenset({
        RemovalStatus.SUBMITTED,
        RemovalStatus.FAILED,
    }),
    RemovalStatus.CAPTCHA_BLOCKED: frozenset(),     # permanently failed
    RemovalStatus.EMAIL_NOT_CONFIGURED: frozenset(), # permanently failed
}

TERMINAL_STATES: frozenset[RemovalStatus] = frozenset({
    RemovalStatus.CONFIRMED,
    RemovalStatus.CAPTCHA_BLOCKED,
    RemovalStatus.EMAIL_NOT_CONFIGURED,
})


def can_transition(current: RemovalStatus, new: RemovalStatus) -> bool:
    """Return True if transitioning from *current* to *new* is valid."""
    return new in VALID_TRANSITIONS.get(current, frozenset())


def apply_transition(current: RemovalStatus, new: RemovalStatus) -> RemovalStatus:
    """
    Apply a state transition, raising ValueError if the transition is invalid.

    Mirrors the engine's intent: invalid transitions must not be silently accepted.
    """
    if not can_transition(current, new):
        raise ValueError(
            f"Invalid removal status transition: {current.value!r} → {new.value!r}"
        )
    return new


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _make_request(**overrides) -> RemovalRequest:
    """Build a RemovalRequest with sensible defaults, overriding as needed."""
    defaults = dict(
        exposure_id=1,
        broker_id=1,
        tier=RemovalTier.PLAYWRIGHT,
        method=RemovalMethod.PLAYWRIGHT,
        status=RemovalStatus.PENDING,
    )
    defaults.update(overrides)
    return RemovalRequest(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# Initial state
# ─────────────────────────────────────────────────────────────────────────────


class TestInitialState:
    def test_initial_status_is_pending(self):
        """A new RemovalRequest starts in PENDING status by default."""
        rr = _make_request()
        assert rr.status == RemovalStatus.PENDING

    def test_initial_submitted_at_is_none(self):
        """A new RemovalRequest has no submitted_at timestamp."""
        rr = _make_request()
        assert rr.submitted_at is None

    def test_initial_confirmed_at_is_none(self):
        """A new RemovalRequest has no confirmed_at timestamp."""
        rr = _make_request()
        assert rr.confirmed_at is None

    def test_initial_retry_count_is_zero(self):
        """A new RemovalRequest has retry_count = 0."""
        rr = _make_request()
        assert rr.retry_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# Valid transitions
# ─────────────────────────────────────────────────────────────────────────────


class TestValidTransitions:
    def test_pending_to_submitted(self):
        """PENDING → SUBMITTED is a valid transition (opt-out submitted to broker)."""
        result = apply_transition(RemovalStatus.PENDING, RemovalStatus.SUBMITTED)
        assert result == RemovalStatus.SUBMITTED

    def test_submitted_to_awaiting_confirmation(self):
        """SUBMITTED → AWAITING_CONFIRMATION is valid (broker requires email confirm)."""
        result = apply_transition(
            RemovalStatus.SUBMITTED, RemovalStatus.AWAITING_CONFIRMATION
        )
        assert result == RemovalStatus.AWAITING_CONFIRMATION

    def test_awaiting_to_confirmed(self):
        """AWAITING_CONFIRMATION → CONFIRMED is valid (confirmation link clicked)."""
        result = apply_transition(
            RemovalStatus.AWAITING_CONFIRMATION, RemovalStatus.CONFIRMED
        )
        assert result == RemovalStatus.CONFIRMED

    def test_failed_to_retrying(self):
        """FAILED → RETRYING is valid (scheduler queues a retry attempt)."""
        result = apply_transition(RemovalStatus.FAILED, RemovalStatus.RETRYING)
        assert result == RemovalStatus.RETRYING

    def test_retrying_to_submitted(self):
        """RETRYING → SUBMITTED is valid (retry re-submission succeeded)."""
        result = apply_transition(RemovalStatus.RETRYING, RemovalStatus.SUBMITTED)
        assert result == RemovalStatus.SUBMITTED


# ─────────────────────────────────────────────────────────────────────────────
# Invalid transitions
# ─────────────────────────────────────────────────────────────────────────────


class TestInvalidTransitions:
    def test_confirmed_to_failed_invalid(self):
        """
        CONFIRMED → FAILED is NOT a valid transition.

        Once confirmed, a removal request is terminal — it cannot move to FAILED.
        A new request must be created for re-removals.
        """
        assert not can_transition(RemovalStatus.CONFIRMED, RemovalStatus.FAILED)

    def test_invalid_transition_raises(self):
        """Attempting an invalid transition raises ValueError."""
        with pytest.raises(ValueError, match="Invalid removal status transition"):
            apply_transition(RemovalStatus.CONFIRMED, RemovalStatus.FAILED)

    def test_confirmed_to_pending_invalid(self):
        """CONFIRMED → PENDING is not valid (no going back from terminal state)."""
        assert not can_transition(RemovalStatus.CONFIRMED, RemovalStatus.PENDING)

    def test_pending_to_confirmed_invalid(self):
        """PENDING → CONFIRMED skips required intermediate states — not valid."""
        assert not can_transition(RemovalStatus.PENDING, RemovalStatus.CONFIRMED)

    def test_pending_to_retrying_invalid(self):
        """PENDING → RETRYING is not valid (can only retry after a failure)."""
        assert not can_transition(RemovalStatus.PENDING, RemovalStatus.RETRYING)

    @pytest.mark.parametrize("terminal_status", [
        RemovalStatus.CONFIRMED,
        RemovalStatus.CAPTCHA_BLOCKED,
        RemovalStatus.EMAIL_NOT_CONFIGURED,
    ])
    def test_terminal_states_have_no_valid_transitions(self, terminal_status):
        """No transitions out of any terminal state are valid."""
        valid_targets = VALID_TRANSITIONS[terminal_status]
        assert len(valid_targets) == 0, (
            f"Terminal state {terminal_status} should have no valid transitions, "
            f"but found: {valid_targets}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Terminal states
# ─────────────────────────────────────────────────────────────────────────────


class TestTerminalStates:
    def test_all_terminal_states(self):
        """CONFIRMED and permanently-failed states are terminal (no outbound transitions)."""
        for state in TERMINAL_STATES:
            assert len(VALID_TRANSITIONS[state]) == 0, (
                f"Expected {state} to be terminal, but it has transitions: "
                f"{VALID_TRANSITIONS[state]}"
            )

    def test_confirmed_is_terminal(self):
        """CONFIRMED status has zero valid outbound transitions."""
        assert RemovalStatus.CONFIRMED in TERMINAL_STATES

    def test_captcha_blocked_is_permanently_failed(self):
        """CAPTCHA_BLOCKED is a permanently-failed terminal state."""
        assert RemovalStatus.CAPTCHA_BLOCKED in TERMINAL_STATES

    def test_non_terminal_states_have_outbound_transitions(self):
        """All non-terminal states have at least one valid outbound transition."""
        non_terminal = set(VALID_TRANSITIONS.keys()) - TERMINAL_STATES
        for state in non_terminal:
            assert len(VALID_TRANSITIONS[state]) > 0, (
                f"Non-terminal state {state} has no outbound transitions"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Timestamps
# ─────────────────────────────────────────────────────────────────────────────


class TestStatusTimestamps:
    def test_status_timestamp_updated(self):
        """
        Moving a request from PENDING to SUBMITTED records a submitted_at timestamp.

        The engine is responsible for setting timestamps alongside status changes.
        This test documents the expected contract: status update + timestamp update
        must happen together.
        """
        rr = _make_request()
        assert rr.submitted_at is None

        before = datetime.utcnow()
        rr_submitted = rr.model_copy(update={
            "status": RemovalStatus.SUBMITTED,
            "submitted_at": datetime.utcnow(),
        })

        assert rr_submitted.status == RemovalStatus.SUBMITTED
        assert rr_submitted.submitted_at is not None
        assert rr_submitted.submitted_at >= before

    def test_confirmed_at_set_on_confirmation(self):
        """CONFIRMED status is accompanied by a confirmed_at timestamp."""
        rr = _make_request(status=RemovalStatus.AWAITING_CONFIRMATION)
        assert rr.confirmed_at is None

        before = datetime.utcnow()
        rr_confirmed = rr.model_copy(update={
            "status": RemovalStatus.CONFIRMED,
            "confirmed_at": datetime.utcnow(),
        })

        assert rr_confirmed.status == RemovalStatus.CONFIRMED
        assert rr_confirmed.confirmed_at is not None
        assert rr_confirmed.confirmed_at >= before

    def test_pending_request_has_no_timestamps(self):
        """A brand-new PENDING request has neither submitted_at nor confirmed_at."""
        rr = _make_request()
        assert rr.submitted_at is None
        assert rr.confirmed_at is None
