"""Individual hardware guard module simulation.

In real deployment each CyberPhysicalGuard is an STM32 / TPM 2.0 / FPGA
device sitting at exactly one trust-delegation edge.  Here we faithfully
replicate its decision logic so that the containment metrics are comparable
to what physical hardware would produce.

Key invariant: the guard is STATELESS about the edge's current risk score.
It only knows (a) its configured strictness level and (b) the token presented
to it.  Risk-aware strictness changes come from the feedback loop (Module 5),
not from the guard itself.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Set

from trustfield.verification.delegation_token import (
    DelegationToken,
    TokenGenerator,
    TokenValidationResult,
)


class StrictnessLevel(Enum):
    """Operating mode of a CyberPhysicalGuard.

    Attributes:
        NOMINAL: Standard validation — all four base token checks required.
        ELEVATED: Stricter depth limit (≤ max_depth − 1) and shorter token
            age window (≤ 60 s).  Triggered when ensemble risk is 40–75%.
        LOCKDOWN: Whitelist-only mode — origins must be pre-approved and
            all transitions are FLAGGED even if technically valid.
            Triggered when ensemble risk > 75%.
    """

    NOMINAL = "NOMINAL"
    ELEVATED = "ELEVATED"
    LOCKDOWN = "LOCKDOWN"


@dataclass
class GuardEvent:
    """Audit record for one validation attempt at a guard module.

    Attributes:
        event_id: UUID for this event.
        guard_id: ID of the guard that produced this record.
        edge: ``(source_node_id, target_node_id)`` pair.
        token: The ``DelegationToken`` that was presented.
        decision: ``"ALLOWED"``, ``"BLOCKED"``, or ``"FLAGGED"``.
        reason: Human-readable explanation of the decision.
        strictness_at_time: Strictness level active when this event occurred.
        timestamp: Wall-clock time of the event.
    """

    event_id: str
    guard_id: str
    edge: tuple
    token: DelegationToken
    decision: str
    reason: str
    strictness_at_time: StrictnessLevel
    timestamp: float


class CyberPhysicalGuard:
    """Simulates a hardware guard module at a single trust-delegation edge.

    Each guard instance owns its own ``TokenGenerator`` (same secret key as
    the issuing authority, independent nonce store) so that three co-located
    guards can each validate the same token signature while keeping separate
    replay-prevention state — matching real TPM behaviour.

    Strictness levels add checks on top of the four base token checks:
      NOMINAL:   signature, expiry, depth ≤ max_depth, nonce uniqueness.
      ELEVATED:  + depth ≤ max_depth − 1  + token age ≤ 60 s.
      LOCKDOWN:  + origin_node in approved_origins  + always FLAGGED if valid.

    Args:
        guard_id: Human-readable identifier (e.g. ``"guard_svc1_role1_0"``).
        edge: The ``(source, target)`` node pair this guard monitors.
        token_generator: A ``TokenGenerator`` sharing the issuing authority's
            secret key.  Used for signature verification and nonce tracking.
        initial_strictness: Starting strictness mode.

    Example::

        guard = CyberPhysicalGuard("g0", ("svc-1", "role-1"), gen)
        event = guard.validate_transition(token)
        assert event.decision in ("ALLOWED", "BLOCKED", "FLAGGED")
    """

    def __init__(
        self,
        guard_id: str,
        edge: tuple,
        token_generator: TokenGenerator,
        initial_strictness: StrictnessLevel = StrictnessLevel.NOMINAL,
    ) -> None:
        self.guard_id = guard_id
        self.edge = edge
        self._gen = token_generator
        self._strictness = initial_strictness
        self._event_log: List[GuardEvent] = []
        self.approved_origins: Set[str] = set()

    # ------------------------------------------------------------------
    # Primary validation
    # ------------------------------------------------------------------

    def validate_transition(self, token: DelegationToken) -> GuardEvent:
        """Validate a token and produce an audit GuardEvent.

        Checks are applied in strictness order; the first failure returns
        BLOCKED immediately.

        Args:
            token: The ``DelegationToken`` presented for this hop.

        Returns:
            A ``GuardEvent`` recording the decision, reason, and context.
        """
        now = time.time()

        # --- Base checks (all strictness levels) ---
        base: TokenValidationResult = self._gen.validate(token)
        if not base.valid:
            return self._make_event(token, "BLOCKED", f"base_check:{base.failure_reason}")

        # --- ELEVATED additional checks ---
        if self._strictness in (StrictnessLevel.ELEVATED, StrictnessLevel.LOCKDOWN):
            # Stricter depth limit
            if token.delegation_depth > token.max_depth - 1:
                return self._make_event(
                    token, "BLOCKED", "elevated:depth_exceeds_strict_limit"
                )
            # Shorter token age window (60 s)
            if now - token.timestamp > 60.0:
                return self._make_event(
                    token, "BLOCKED", "elevated:token_age_exceeds_60s"
                )

        # --- LOCKDOWN additional checks ---
        if self._strictness == StrictnessLevel.LOCKDOWN:
            if token.origin_node not in self.approved_origins:
                return self._make_event(
                    token, "BLOCKED", "lockdown:origin_not_in_whitelist"
                )
            # Even valid whitelisted transitions require manual review
            return self._make_event(token, "FLAGGED", "lockdown:flagged_for_review")

        # All checks passed in NOMINAL or ELEVATED
        return self._make_event(token, "ALLOWED", "all_checks_passed")

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_strictness(self, level: StrictnessLevel) -> None:
        """Update the guard's operating strictness level.

        Args:
            level: New ``StrictnessLevel`` to apply.
        """
        self._strictness = level

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def get_event_log(self) -> List[GuardEvent]:
        """Return a copy of all events recorded by this guard."""
        return list(self._event_log)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_event(
        self, token: DelegationToken, decision: str, reason: str
    ) -> GuardEvent:
        event = GuardEvent(
            event_id=str(uuid.uuid4()),
            guard_id=self.guard_id,
            edge=self.edge,
            token=token,
            decision=decision,
            reason=reason,
            strictness_at_time=self._strictness,
            timestamp=time.time(),
        )
        self._event_log.append(event)
        return event
