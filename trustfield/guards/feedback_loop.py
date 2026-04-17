"""Hardware-software adaptive feedback loop.

This is the core novel contribution of Module 5: a closed loop where the
software ensemble's risk assessment drives hardware guard strictness, and
the guards' resulting blocks feed back into the next ensemble analysis.

Feedback direction:
  ensemble risk rises  →  guards tighten  →  edges blocked  →
  propagation paths removed  →  ensemble risk falls  →  guards relax
  (or stays high if attacker has diversified)

Each call to ``run_feedback_cycle`` models one attack scenario with n_cycles
iterations.  Within each cycle the attacker is simulated spreading one hop
further through unblocked edges, which drives the risk score upward until
the guards lock down.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal

from .guard_module import StrictnessLevel
from .guard_network import GuardNetwork
from .sensor import PropagationSensor, SensorReading


@dataclass
class FeedbackAction:
    """Records one strictness-level transition triggered by the feedback loop.

    Attributes:
        trigger: Human-readable cause (e.g. ``"risk_score_0.812"`` or
            ``"sensor_anomaly"``).
        old_strictness: Level before the transition.
        new_strictness: Level after the transition.
        risk_score_at_trigger: Ensemble risk value that caused the change.
        timestamp: Wall-clock time of the transition.
    """

    trigger: str
    old_strictness: StrictnessLevel
    new_strictness: StrictnessLevel
    risk_score_at_trigger: float
    timestamp: float


class HardwareSoftwareFeedback:
    """Closed-loop feedback between ensemble risk and guard strictness.

    Args:
        guard_network: The ``GuardNetwork`` whose strictness is controlled.
        orchestrator: The ``TrustFieldOrchestrator`` used for ensemble analysis
            in each feedback cycle.

    Example::

        feedback = HardwareSoftwareFeedback(guard_network, orchestrator)
        actions = feedback.run_feedback_cycle(graph, ["svc-001"], n_cycles=5)
        for a in actions:
            print(f"{a.trigger}: {a.old_strictness} → {a.new_strictness}")
    """

    RISK_THRESHOLDS = {
        StrictnessLevel.NOMINAL:   (0.00, 0.25),
        StrictnessLevel.ELEVATED:  (0.25, 0.50),
        StrictnessLevel.LOCKDOWN:  (0.50, 1.01),
    }

    def __init__(
        self,
        guard_network: GuardNetwork,
        orchestrator: TrustFieldOrchestrator,
    ) -> None:
        self._guard_network = guard_network
        self._orchestrator = orchestrator
        self.sensor_readings: List[SensorReading] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def determine_strictness(self, risk_score: float) -> StrictnessLevel:
        """Map a scalar risk score to the required StrictnessLevel.

        Args:
            risk_score: Mean ensemble risk over currently compromised nodes,
                in [0.0, 1.0].

        Returns:
            The appropriate ``StrictnessLevel`` for this risk level.
        """
        if risk_score >= 0.75:
            return StrictnessLevel.LOCKDOWN
        if risk_score >= 0.40:
            return StrictnessLevel.ELEVATED
        return StrictnessLevel.NOMINAL

    def run_feedback_cycle(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        n_cycles: int = 5,
        use_gnn: bool = True,
    ) -> List[FeedbackAction]:
        """Execute n_cycles of the hardware-software feedback loop.

        Each cycle:
          1. Run ensemble analysis on the current (potentially modified) graph.
          2. Compute risk_score = mean(ensemble_risk over compromised nodes).
          3. Determine required strictness from RISK_THRESHOLDS.
          4. If strictness changed: update guard network, log FeedbackAction.
          5. Simulate token attempts on guarded edges → populate sensor.
          6. If any sensor reading shows anomaly: force ELEVATED minimum.
          7. Block guarded edges in LOCKDOWN; partially block in ELEVATED.
          8. Expand attacker's footprint by one hop for the next cycle.

        Args:
            graph: Working graph (modified in-place as edges are blocked).
            seed_nodes: Initial attacker-controlled nodes.
            n_cycles: Number of feedback iterations to run.

        Returns:
            List of ``FeedbackAction`` objects recording every strictness
            transition that occurred.
        """
        sensor = PropagationSensor()
        current_seeds = list(seed_nodes)
        current_strictness = StrictnessLevel.NOMINAL
        actions: List[FeedbackAction] = []

        for _cycle in range(n_cycles):
            # --- 1. Ensemble analysis ---
            try:
                analysis = self._orchestrator.analyze(graph, current_seeds, use_gnn=use_gnn)
            except Exception:
                break

            # --- 2. Risk score ---
            pred = analysis.ensemble_prediction
            compromised = pred.compromised_nodes
            if compromised:
                risk_score = sum(
                    pred.ensemble_risk.get(n, 0.0) for n in compromised
                ) / len(compromised)
            else:
                risk_score = 0.0

            # --- 3-4. Strictness adjustment ---
            new_strictness = self.determine_strictness(risk_score)
            if new_strictness != current_strictness:
                actions.append(
                    FeedbackAction(
                        trigger=f"risk_score_{risk_score:.3f}",
                        old_strictness=current_strictness,
                        new_strictness=new_strictness,
                        risk_score_at_trigger=risk_score,
                        timestamp=time.time(),
                    )
                )
                self._guard_network.set_network_strictness(new_strictness)
                current_strictness = new_strictness

            # --- 5. Simulate guard events to feed sensor ---
            self._simulate_guard_events(graph, current_seeds)

            all_events = [
                evt
                for guards in self._guard_network._deployed_guards.values()
                for guard in guards
                for evt in guard.get_event_log()
            ]
            reading = sensor.analyze(all_events, time_window=60.0)
            self.sensor_readings.append(reading)

            # --- 6. Sensor anomaly: force ELEVATED minimum ---
            if (
                reading.anomaly_detected
                and current_strictness == StrictnessLevel.NOMINAL
            ):
                actions.append(
                    FeedbackAction(
                        trigger="sensor_anomaly",
                        old_strictness=current_strictness,
                        new_strictness=StrictnessLevel.ELEVATED,
                        risk_score_at_trigger=risk_score,
                        timestamp=time.time(),
                    )
                )
                self._guard_network.set_network_strictness(StrictnessLevel.ELEVATED)
                current_strictness = StrictnessLevel.ELEVATED

            # --- 7. Block guarded edges based on current strictness ---
            self._apply_guard_blocks(graph, current_strictness)

            # --- 8. Expand attacker footprint one hop (unblocked paths only) ---
            next_seeds = set(current_seeds)
            for seed in list(current_seeds):
                try:
                    for neighbor in graph.get_neighbors(seed, direction="out"):
                        edge_meta = graph.get_edge(seed, neighbor)
                        if edge_meta.weight > 0:
                            next_seeds.add(neighbor)
                except KeyError:
                    pass
            current_seeds = list(next_seeds)

        return actions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _simulate_guard_events(
        self, graph: TrustGraph, current_seeds: List[str]
    ) -> None:
        """Generate token attempts on guarded edges to populate sensor data.

        For each guarded edge, issue a token at the edge's full depth limit
        (which passes NOMINAL but may fail ELEVATED's stricter check) and
        run it through all three guards.  This produces realistic event logs
        for anomaly detection without requiring a full traversal.
        """
        sim_gen = TokenGenerator(
            secret_key=self._guard_network._token_generator.key
        )
        for edge, guards in self._guard_network._deployed_guards.items():
            src, tgt = edge
            if not graph._graph.has_edge(src, tgt):
                continue
            try:
                edge_meta = graph.get_edge(src, tgt)
            except KeyError:
                continue
            if edge_meta.weight == 0:
                continue

            # Token depth == max_depth triggers ELEVATED block (depth > max-1)
            depth = edge_meta.delegation_depth_limit
            token = sim_gen.generate(src, tgt, edge_meta, current_depth=depth)
            for guard in guards:
                guard.validate_transition(token)

    def _apply_guard_blocks(
        self, graph: TrustGraph, strictness: StrictnessLevel
    ) -> None:
        """Zero out edge weights based on current guard strictness.

        LOCKDOWN: all guarded edges → weight 0 (empty whitelist blocks all).
        ELEVATED: guarded edges with delegation_depth_limit ≤ 1 → weight 0
            (stricter depth check requires ≤ max−1, which is 0 for limit=1).
        NOMINAL:  no changes.
        """
        if strictness in (StrictnessLevel.LOCKDOWN, StrictnessLevel.ELEVATED):
            for edge in self._guard_network._deployed_guards:
                src, tgt = edge
                if graph._graph.has_edge(src, tgt):
                    graph._graph[src][tgt]["weight"] = 0.0
                    graph._graph[src][tgt]["metadata"].weight = 0.0

        if False:  # legacy ELEVATED partial-block path — kept for reference
            for edge in self._guard_network._deployed_guards:
                src, tgt = edge
                if graph._graph.has_edge(src, tgt):
                    try:
                        edge_meta = graph.get_edge(src, tgt)
                        if edge_meta.delegation_depth_limit <= 1:
                            graph._graph[src][tgt]["weight"] = 0.0
                            graph._graph[src][tgt]["metadata"].weight = 0.0
                    except KeyError:
                        pass
