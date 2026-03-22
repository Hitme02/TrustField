"""Temporal attack simulator for TrustField — adds dwell-time dynamics.

Current TrustField propagation models treat compromise as instantaneous.
Real attackers dwell at each node (running recon, dumping credentials,
pivoting) before moving to the next hop.  This module simulates that
temporal dimension and connects to the PropagationSensor to show that
dwell behaviour is detectable via token-request frequency patterns.

Key design insight:
  greedy   — always moves to the highest-privilege unvisited neighbour.
             It probes ALL outgoing edges during dwell (noisy).
             Reaches high-privilege nodes fastest, but generates high
             token frequency → sensor detects it sooner.

  stealthy — moves via the lowest-weight edge (avoiding high-trust hops).
             It probes ONLY the intended next-hop edge during dwell (quiet).
             Slower path to high-privilege nodes, but low token frequency
             → sensor anomaly score stays low longer.

  random   — random walk among unvisited neighbours.
             Probes ALL outgoing edges during dwell (same as greedy).
             Non-deterministic path; typically slower than greedy.

Integration with sensor.py:
  The dwell-phase token requests are accumulated into ``all_events``
  (List[GuardEvent]).  After the simulation finishes, callers can pass
  this list to ``PropagationSensor.analyze()`` to compare the anomaly
  signature across strategies.  The simulator itself uses
  ``detection_probability`` (random per-event check) as the live
  detection gate — sensor analysis is post-hoc.
"""

from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Set

from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification.delegation_token import DelegationToken, TokenGenerator

# Guards imports — guard_network and sensor do NOT import from propagation,
# so there is no circular dependency here.
from trustfield.guards.guard_module import GuardEvent, StrictnessLevel
from trustfield.guards.guard_network import GuardNetwork
from trustfield.guards.sensor import PropagationSensor

# Privilege threshold above which a node is considered "high-privilege"
_HIGH_PRIV_THRESHOLD = 0.8


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class TemporalStep:
    """A single time-step in the attacker's traversal timeline.

    Attributes:
        time_step: 1-indexed step counter.
        current_node: Node ID the attacker is currently at.
        action: One of ``"DWELL"``, ``"MOVE"``, ``"DETECTED"``,
            ``"CONTAINED"``.
        nodes_compromised_so_far: Snapshot of all compromised nodes at
            the end of this step.
        detection_triggered: True if detection fired during this step.
        strictness_level: Guard-network strictness at end of step
            (``"NOMINAL"``, ``"ELEVATED"``, or ``"LOCKDOWN"``),
            derived from the running sensor anomaly score.
    """

    time_step: int
    current_node: str
    action: str
    nodes_compromised_so_far: Set[str]
    detection_triggered: bool
    strictness_level: str


@dataclass
class TemporalResult:
    """Full outcome of one temporal attack simulation run.

    Attributes:
        total_time_steps: Total steps simulated (== ``len(timeline)``).
        time_to_first_detection: 1-indexed step at which detection first
            fired, or ``None`` if never detected.
        time_to_containment: 1-indexed step at which containment was
            achieved (defined as ``time_to_first_detection + dwell_time``),
            or ``None`` if never detected.
        nodes_compromised_at_detection: Snapshot of compromised nodes at
            the detection step; empty set if never detected.
        nodes_compromised_final: All nodes compromised by end of simulation.
        timeline: Per-step record of attacker progress.
        attacker_success: True when a high-privilege node
            (``privilege_level ≥ 0.8``) was compromised before detection,
            or was compromised and detection never occurred.
        mean_dwell_time: Mean dwell steps spent per node visited.
        mean_events_per_step: Mean number of probe GuardEvents generated
            per time-step.  Key metric for comparing strategy stealthiness:
            stealthy < greedy because stealthy probes only one edge per
            dwell step.
        all_events: Full list of GuardEvents from dwell probing (for
            post-hoc sensor analysis by the caller).
    """

    total_time_steps: int
    time_to_first_detection: Optional[int]
    time_to_containment: Optional[int]
    nodes_compromised_at_detection: Set[str]
    nodes_compromised_final: Set[str]
    timeline: List[TemporalStep]
    attacker_success: bool
    mean_dwell_time: float
    mean_events_per_step: float
    all_events: List[GuardEvent] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------


class TemporalAttackSimulator:
    """Simulates a dwell-and-move attacker traversal over a TrustGraph.

    Args:
        dwell_time: Steps to dwell at each node before attempting a move.
            Default 3.
        detection_probability: Per-event probability of random detection
            during the dwell phase.  ``0.0`` → never detected by this
            mechanism; ``1.0`` → detected at the first probe event.
            Default 0.1.
        move_strategy: ``"greedy"`` (highest-privilege neighbour),
            ``"stealthy"`` (lowest-weight edge), or ``"random"`` (random
            walk).  Default ``"greedy"``.
        seed: Random seed for reproducible random / stealthy / detection
            rolls.  Default 42.

    Example::

        sim = TemporalAttackSimulator(dwell_time=3, move_strategy="greedy")
        result = sim.simulate(graph, ["user-001"], guard_net, sensor)
        print(f"Detected at step: {result.time_to_first_detection}")
    """

    def __init__(
        self,
        dwell_time: int = 3,
        detection_probability: float = 0.1,
        move_strategy: str = "greedy",
        seed: int = 42,
    ) -> None:
        self._dwell_time = max(1, dwell_time)
        self._detection_probability = max(0.0, min(1.0, detection_probability))
        self._move_strategy = move_strategy
        self._seed = seed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def simulate(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        guard_network: GuardNetwork,
        sensor: PropagationSensor,
        max_steps: int = 100,
    ) -> TemporalResult:
        """Run the temporal attack simulation.

        Args:
            graph: The TrustGraph to traverse.
            seed_nodes: Initial attacker entry-point node IDs.  The
                simulation uses ``seed_nodes[0]`` as the starting node.
            guard_network: Deployed GuardNetwork for move validation.
            sensor: PropagationSensor used to derive running strictness
                (does not gate detection in the simulation loop).
            max_steps: Hard step limit.  Default 100.

        Returns:
            A fully-populated :class:`TemporalResult`.
        """
        rng = random.Random(self._seed)
        tgen = TokenGenerator()

        current_node: str = seed_nodes[0] if seed_nodes else ""
        compromised: Set[str] = set(seed_nodes)

        dwell_counter: int = 0
        all_events: List[GuardEvent] = []
        timeline: List[TemporalStep] = []

        detected_at: Optional[int] = None
        compromised_at_detection: Set[str] = set()
        high_priv_reached_at: Optional[int] = None

        total_dwell_steps: int = 0
        num_nodes_dwelled: int = len(seed_nodes)  # already at seed

        for t in range(max_steps):
            action = "DWELL"
            detection_this_step = False

            if detected_at is not None:
                # Post-detection: attacker is being contained
                action = "CONTAINED"
            elif dwell_counter < self._dwell_time:
                # ── Dwell phase ──────────────────────────────────────────
                dwell_counter += 1
                total_dwell_steps += 1
                action = "DWELL"

                step_events = self._probe(graph, current_node, tgen)
                all_events.extend(step_events)

                # Per-event random detection check
                for _ in step_events:
                    if rng.random() < self._detection_probability:
                        detection_this_step = True
                        break

                # Edge case: node has no outgoing edges but detection can still fire
                if not step_events and rng.random() < self._detection_probability:
                    detection_this_step = True

            else:
                # ── Move phase ────────────────────────────────────────────
                dwell_counter = 0

                unvisited = sorted(
                    n for n in graph.nx_graph.successors(current_node)
                    if n not in compromised
                )
                next_node = self._pick_next(graph, current_node, unvisited, rng)

                if next_node is None:
                    # Nowhere new — reset dwell, probe in place
                    dwell_counter = 0
                    total_dwell_steps += 1
                    action = "DWELL"
                    step_events = self._probe(graph, current_node, tgen)
                    all_events.extend(step_events)
                else:
                    edge_meta = graph.get_edge(current_node, next_node)
                    if edge_meta is not None:
                        move_token = tgen.generate(
                            current_node, next_node, edge_meta, current_depth=0
                        )
                        consensus = guard_network.validate_with_consensus(
                            (current_node, next_node), move_token
                        )
                        if consensus.consensus_decision == "ALLOWED":
                            current_node = next_node
                            compromised.add(current_node)
                            num_nodes_dwelled += 1
                            action = "MOVE"
                        else:
                            # Blocked — dwell longer before trying again
                            dwell_counter = 0
                            total_dwell_steps += 1
                            action = "DWELL"
                    else:
                        action = "DWELL"

            # ── Track milestones ─────────────────────────────────────────

            # High-privilege reached?
            if high_priv_reached_at is None:
                for node in compromised:
                    node_meta = graph.nx_graph.nodes.get(node, {}).get("metadata")
                    if node_meta and node_meta.privilege_level >= _HIGH_PRIV_THRESHOLD:
                        high_priv_reached_at = t + 1  # 1-indexed
                        break

            # Detection triggered this step?
            if detection_this_step and detected_at is None:
                detected_at = t + 1  # 1-indexed
                compromised_at_detection = set(compromised)
                action = "DETECTED"

            # Derive guard strictness from running sensor reading
            strictness = _compute_strictness(sensor, all_events, t + 1)

            timeline.append(TemporalStep(
                time_step=t + 1,
                current_node=current_node,
                action=action,
                nodes_compromised_so_far=set(compromised),
                detection_triggered=detection_this_step,
                strictness_level=strictness,
            ))

        total_steps = len(timeline)
        mean_dwell = (
            total_dwell_steps / num_nodes_dwelled
            if num_nodes_dwelled > 0 else float(self._dwell_time)
        )
        mean_events = (
            len(all_events) / total_steps if total_steps > 0 else 0.0
        )

        # attacker_success: reached high-privilege before detection (or no detection)
        if high_priv_reached_at is not None:
            if detected_at is None or high_priv_reached_at <= detected_at:
                attacker_success = True
            else:
                attacker_success = False
        else:
            attacker_success = False

        # containment = detection_step + dwell_time (guards lock down and block)
        containment_at: Optional[int] = (
            min(detected_at + self._dwell_time, total_steps)
            if detected_at is not None else None
        )

        return TemporalResult(
            total_time_steps=total_steps,
            time_to_first_detection=detected_at,
            time_to_containment=containment_at,
            nodes_compromised_at_detection=compromised_at_detection,
            nodes_compromised_final=set(compromised),
            timeline=timeline,
            attacker_success=attacker_success,
            mean_dwell_time=round(mean_dwell, 3),
            mean_events_per_step=round(mean_events, 3),
            all_events=all_events,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe(
        self,
        graph: TrustGraph,
        node: str,
        tgen: TokenGenerator,
    ) -> List[GuardEvent]:
        """Generate probe GuardEvents for the current dwell position.

        greedy / random: probe ALL outgoing edges (high frequency).
        stealthy:        probe ONLY the intended next-hop edge (1 event).
        """
        successors = sorted(graph.nx_graph.successors(node))
        if not successors:
            return []

        if self._move_strategy == "stealthy":
            # Probe only the lowest-weight outgoing edge
            def _weight(n: str) -> float:
                meta = graph.get_edge(node, n)
                return meta.weight if meta is not None else 1.0
            probe_targets = [min(successors, key=_weight)]
        else:
            probe_targets = successors

        events: List[GuardEvent] = []
        for target in probe_targets:
            edge_meta = graph.get_edge(node, target)
            if edge_meta is None:
                continue
            token = tgen.generate(node, target, edge_meta, current_depth=0)
            events.append(_make_probe_event(token, (node, target)))

        return events

    def _pick_next(
        self,
        graph: TrustGraph,
        current_node: str,
        unvisited: List[str],
        rng: random.Random,
    ) -> Optional[str]:
        """Select the next node to move to based on the configured strategy."""
        if not unvisited:
            return None

        if self._move_strategy == "greedy":
            def _priv(n: str) -> float:
                meta = graph.nx_graph.nodes.get(n, {}).get("metadata")
                return meta.privilege_level if meta else 0.0
            return max(unvisited, key=_priv)

        elif self._move_strategy == "stealthy":
            def _edge_weight(n: str) -> float:
                meta = graph.get_edge(current_node, n)
                return meta.weight if meta is not None else 1.0
            return min(unvisited, key=_edge_weight)

        else:  # random
            return rng.choice(unvisited)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _make_probe_event(token: DelegationToken, edge: tuple) -> GuardEvent:
    """Create a synthetic ALLOWED GuardEvent for a dwell-phase probe."""
    return GuardEvent(
        event_id=str(uuid.uuid4()),
        guard_id="temporal_probe",
        edge=edge,
        token=token,
        decision="ALLOWED",
        reason="dwell_probe",
        strictness_at_time=StrictnessLevel.NOMINAL,
        timestamp=time.time(),
    )


def _compute_strictness(
    sensor: PropagationSensor,
    all_events: List[GuardEvent],
    elapsed_steps: int,
) -> str:
    """Derive the current guard strictness from the running sensor reading."""
    if not all_events:
        return "NOMINAL"
    reading = sensor.analyze(all_events, time_window=float(elapsed_steps))
    if reading.anomaly_score > 0.8:
        return "LOCKDOWN"
    elif reading.anomaly_score > 0.6:
        return "ELEVATED"
    return "NOMINAL"
