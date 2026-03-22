"""PropagationSensor — behavioral monitoring of guard event streams.

Detects anomalies in the pattern of trust-delegation requests by analyzing
guard event logs over a sliding time window.  The anomaly score drives the
feedback loop's decision to tighten guard strictness before the ensemble
even detects the threat — this is the early-warning component of the
hardware-software feedback loop.

Anomaly scoring weights (from spec):
  frequency=0.3, validation_rate=0.2, escalation=0.3, privilege_jump=0.2
Baseline: normal request frequency < 5 req/s, normal validation_rate > 0.80
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .guard_module import GuardEvent


@dataclass
class SensorReading:
    """Aggregated behavioral reading over one time window.

    Attributes:
        guard_id: ID of the guard (or ``"network"`` for aggregate reads).
        time_window_seconds: Duration of the monitoring window.
        delegation_request_frequency: Requests per second in this window.
        token_validation_rate: Fraction of requests that were ALLOWED.
        escalation_attempt_count: Events rejected due to depth violations.
        privilege_jump_count: ALLOWED transitions via high-privilege edge types
            (ASSUME_ROLE / AUTHENTICATE_AS) — proxy for privilege escalation.
        anomaly_score: Composite anomaly score in [0.0, 1.0].
        anomaly_detected: True when ``anomaly_score`` exceeds the threshold.
    """

    guard_id: str
    time_window_seconds: float
    delegation_request_frequency: float
    token_validation_rate: float
    escalation_attempt_count: int
    privilege_jump_count: int
    anomaly_score: float
    anomaly_detected: bool


class PropagationSensor:
    """Analyzes guard event logs to detect behavioral anomalies.

    Args:
        anomaly_threshold: Composite score above which ``anomaly_detected``
            is set to ``True``.  Default 0.6.

    Example::

        sensor = PropagationSensor()
        reading = sensor.analyze(guard_events, time_window=60.0)
        if reading.anomaly_detected:
            network.set_network_strictness(StrictnessLevel.ELEVATED)
    """

    # Baseline constants for Z-score normalisation
    _NORMAL_FREQUENCY: float = 5.0    # requests/sec considered normal
    _NORMAL_VALIDATION_RATE: float = 0.80
    _MAX_ESCALATION: float = 5.0      # ≥ 5 escalation attempts → score = 1.0
    _MAX_PRIVILEGE_JUMPS: float = 3.0  # ≥ 3 privilege jumps → score = 1.0

    # High-privilege edge types used as a proxy for privilege escalation
    _PRIVILEGE_EDGE_TYPES = frozenset({"ASSUME_ROLE", "AUTHENTICATE_AS"})

    def __init__(self, anomaly_threshold: float = 0.6) -> None:
        self._threshold = anomaly_threshold

    def analyze(
        self,
        guard_events: List[GuardEvent],
        time_window: float = 60.0,
    ) -> SensorReading:
        """Compute a SensorReading from a list of guard events.

        Args:
            guard_events: Events emitted by one or more guards over the window.
            time_window: Duration in seconds that the events cover.

        Returns:
            A fully-populated ``SensorReading`` including anomaly classification.
        """
        n = len(guard_events)
        tw = max(time_window, 1e-9)

        frequency = n / tw

        allowed_count = sum(1 for e in guard_events if e.decision == "ALLOWED")
        validation_rate = allowed_count / n if n > 0 else 1.0

        # Escalation attempts: depth-related rejection in base OR elevated checks
        escalation_count = sum(
            1
            for e in guard_events
            if "depth" in e.reason.lower() and e.decision == "BLOCKED"
        )

        # Privilege-jump proxy: ALLOWED transitions on high-privilege edge types
        privilege_jump_count = sum(
            1
            for e in guard_events
            if e.decision == "ALLOWED"
            and e.token.edge_type in self._PRIVILEGE_EDGE_TYPES
        )

        # Build partial reading to pass to compute_anomaly_score
        reading = SensorReading(
            guard_id="network",
            time_window_seconds=time_window,
            delegation_request_frequency=frequency,
            token_validation_rate=validation_rate,
            escalation_attempt_count=escalation_count,
            privilege_jump_count=privilege_jump_count,
            anomaly_score=0.0,
            anomaly_detected=False,
        )

        score = self.compute_anomaly_score(reading)
        reading.anomaly_score = round(score, 4)
        reading.anomaly_detected = score > self._threshold
        return reading

    def compute_anomaly_score(self, reading: SensorReading) -> float:
        """Compute the composite anomaly score for a SensorReading.

        Each metric is normalised to [0, 1] against its baseline, then
        combined with the specified weights:

            score = 0.3 * freq + 0.2 * rate + 0.3 * escalation + 0.2 * priv

        Args:
            reading: Partially or fully populated ``SensorReading``.

        Returns:
            Composite anomaly score in [0.0, 1.0].
        """
        # Frequency: 0 when at or below normal; 1 when at 2× normal or above
        freq_score = min(
            1.0, reading.delegation_request_frequency / self._NORMAL_FREQUENCY
        )

        # Validation rate: 0 when normal (≥0.8); 1 when 0%
        rate_score = max(
            0.0,
            (self._NORMAL_VALIDATION_RATE - reading.token_validation_rate)
            / self._NORMAL_VALIDATION_RATE,
        )

        # Escalation: normalised by _MAX_ESCALATION
        esc_score = min(
            1.0, reading.escalation_attempt_count / self._MAX_ESCALATION
        )

        # Privilege jump: normalised by _MAX_PRIVILEGE_JUMPS
        priv_score = min(
            1.0, reading.privilege_jump_count / self._MAX_PRIVILEGE_JUMPS
        )

        return (
            0.3 * freq_score
            + 0.2 * rate_score
            + 0.3 * esc_score
            + 0.2 * priv_score
        )
