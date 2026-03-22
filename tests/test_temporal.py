"""Tests for TrustField temporal attack simulator.

 1. Simulation terminates within max_steps
 2. seed_nodes in nodes_compromised_final
 3. time_to_first_detection <= total_time_steps if not None
 4. timeline length equals total_time_steps
 5. greedy reaches high-privilege nodes in fewer steps than random
 6. detection_probability=1.0 → detected at step 1
 7. detection_probability=0.0 → time_to_first_detection is None
 8. stealthy average token frequency < greedy average (lower detection signal)
"""

from __future__ import annotations

import pytest

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.guards.guard_network import GuardNetwork
from trustfield.guards.sensor import PropagationSensor
from trustfield.propagation.temporal_model import TemporalAttackSimulator
from trustfield.verification.delegation_token import TokenGenerator


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_guard_network(graph: TrustGraph) -> GuardNetwork:
    """GuardNetwork with no pre-deployed guards (all moves auto-ALLOWED)."""
    tgen = TokenGenerator()
    return GuardNetwork(graph, tgen)


def _sensor() -> PropagationSensor:
    return PropagationSensor(anomaly_threshold=0.6)


def _build_linear_graph() -> tuple[TrustGraph, list[str]]:
    """A → B → C chain; all edges weight=0.9."""
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER,    "Attacker",  0.1, 0.1))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "Service B", 0.5, 0.5))
    g.add_node(NodeMetadata("C", NodeType.ROLE,    "Admin C",   0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.AUTHENTICATE_AS, 0.9, 6))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.TOKEN_MINT, 0.9, 6))
    return g, ["A"]


def _build_fork_graph() -> tuple[TrustGraph, list[str]]:
    """
    Seed → A_high (priv=0.9)   [greedy picks this; 'A' < 'B' alphabetically]
    Seed → B_low  (priv=0.1)   [random(seed=42) picks this first]
    B_low  → (dead end)

    With sorted neighbor list ["A_high", "B_low"] and random.Random(42):
      random.Random(42).choice(["A_high", "B_low"]) picks index 1 = "B_low"
    so random gets stuck at B_low (no successors), never reaching A_high.
    Greedy immediately moves to A_high (privilege 0.9 > 0.1).
    """
    g = TrustGraph()
    g.add_node(NodeMetadata("seed",   NodeType.USER,    "Seed",   0.1, 0.1))
    g.add_node(NodeMetadata("A_high", NodeType.ROLE,    "Admin",  0.9, 0.9))
    g.add_node(NodeMetadata("B_low",  NodeType.SERVICE, "Svc",    0.1, 0.1))
    g.add_edge("seed",  "A_high", EdgeMetadata("e1", EdgeType.ASSUME_ROLE,     0.9, 6))
    g.add_edge("seed",  "B_low",  EdgeMetadata("e2", EdgeType.AUTHENTICATE_AS, 0.3, 6))
    # B_low has no successors → random is stuck there
    return g, ["seed"]


# ---------------------------------------------------------------------------
# 1. Simulation terminates within max_steps
# ---------------------------------------------------------------------------

class TestTerminatesWithinMaxSteps:
    def test_terminates(self):
        graph, seeds = _build_linear_graph()
        sim = TemporalAttackSimulator(dwell_time=2, detection_probability=0.0)
        result = sim.simulate(graph, seeds, _make_guard_network(graph), _sensor(), max_steps=20)
        assert result.total_time_steps <= 20


# ---------------------------------------------------------------------------
# 2. seed_nodes in nodes_compromised_final
# ---------------------------------------------------------------------------

class TestSeedNodesCompromised:
    def test_seeds_always_compromised(self):
        graph, seeds = _build_linear_graph()
        sim = TemporalAttackSimulator(dwell_time=2, detection_probability=0.0)
        result = sim.simulate(graph, seeds, _make_guard_network(graph), _sensor(), max_steps=20)
        for seed in seeds:
            assert seed in result.nodes_compromised_final, (
                f"seed node {seed!r} missing from nodes_compromised_final"
            )


# ---------------------------------------------------------------------------
# 3. time_to_first_detection <= total_time_steps if not None
# ---------------------------------------------------------------------------

class TestDetectionWithinBounds:
    def test_detection_step_within_total(self):
        graph, seeds = _build_linear_graph()
        sim = TemporalAttackSimulator(dwell_time=2, detection_probability=0.3, seed=0)
        result = sim.simulate(graph, seeds, _make_guard_network(graph), _sensor(), max_steps=30)
        if result.time_to_first_detection is not None:
            assert result.time_to_first_detection <= result.total_time_steps


# ---------------------------------------------------------------------------
# 4. timeline length equals total_time_steps
# ---------------------------------------------------------------------------

class TestTimelineLength:
    def test_timeline_length_matches_total(self):
        graph, seeds = _build_linear_graph()
        sim = TemporalAttackSimulator(dwell_time=2, detection_probability=0.0)
        result = sim.simulate(graph, seeds, _make_guard_network(graph), _sensor(), max_steps=15)
        assert len(result.timeline) == result.total_time_steps


# ---------------------------------------------------------------------------
# 5. greedy reaches high-privilege nodes in fewer steps than random
# ---------------------------------------------------------------------------

class TestGreedyFasterThanRandom:
    def _steps_to_high_priv(self, result, graph) -> int:
        """Return the first step at which a node with privilege >= 0.8 appears
        in compromised_so_far.  Returns total_time_steps + 1 if never reached."""
        for step in result.timeline:
            for nid in step.nodes_compromised_so_far:
                meta = graph.nx_graph.nodes.get(nid, {}).get("metadata")
                if meta and meta.privilege_level >= 0.8:
                    return step.time_step
        return result.total_time_steps + 1

    def test_greedy_reaches_high_priv_sooner(self):
        graph, seeds = _build_fork_graph()
        gn = _make_guard_network(graph)
        s = _sensor()

        # Both use seed=42 (same rng for fair comparison)
        greedy = TemporalAttackSimulator(
            dwell_time=1, detection_probability=0.0, move_strategy="greedy", seed=42
        ).simulate(graph, seeds, gn, s, max_steps=20)

        random_walk = TemporalAttackSimulator(
            dwell_time=1, detection_probability=0.0, move_strategy="random", seed=42
        ).simulate(graph, seeds, gn, s, max_steps=20)

        greedy_steps = self._steps_to_high_priv(greedy, graph)
        random_steps = self._steps_to_high_priv(random_walk, graph)

        # Greedy must reach high-priv strictly sooner than random
        assert greedy_steps < random_steps, (
            f"greedy={greedy_steps} steps, random={random_steps} steps; "
            "expected greedy to reach high-priv first"
        )


# ---------------------------------------------------------------------------
# 6. detection_probability=1.0 → detected at step 1
# ---------------------------------------------------------------------------

class TestFullDetectionProbability:
    def test_detected_at_step_one(self):
        graph, seeds = _build_linear_graph()
        sim = TemporalAttackSimulator(
            dwell_time=3, detection_probability=1.0, seed=42
        )
        result = sim.simulate(
            graph, seeds, _make_guard_network(graph), _sensor(), max_steps=50
        )
        assert result.time_to_first_detection == 1, (
            f"Expected detection at step 1 with p=1.0, "
            f"got {result.time_to_first_detection}"
        )


# ---------------------------------------------------------------------------
# 7. detection_probability=0.0 → time_to_first_detection is None
# ---------------------------------------------------------------------------

class TestZeroDetectionProbability:
    def test_never_detected(self):
        graph, seeds = _build_linear_graph()
        sim = TemporalAttackSimulator(
            dwell_time=3, detection_probability=0.0, seed=42
        )
        result = sim.simulate(
            graph, seeds, _make_guard_network(graph), _sensor(), max_steps=50
        )
        assert result.time_to_first_detection is None, (
            f"Expected no detection with p=0.0, "
            f"got step {result.time_to_first_detection}"
        )


# ---------------------------------------------------------------------------
# 8. stealthy average token frequency < greedy average
# ---------------------------------------------------------------------------

class TestStealthyLowerFrequency:
    def test_stealthy_fewer_events_per_step_than_greedy(self):
        """On hub topology (40 nodes), greedy probes all hub outbound edges
        during dwell (many events/step), while stealthy probes only 1
        outgoing edge per step."""
        from trustfield.graph.iam_simulator import IAMSimulator

        graph = IAMSimulator().generate("hub", num_nodes=40, seed=42)
        # Seed from the hub node (highest out-degree) so both strategies
        # immediately differ: greedy probes ALL outbound edges, stealthy just 1.
        hub_node = max(
            graph.nx_graph.nodes(),
            key=lambda n: graph.nx_graph.out_degree(n),
        )
        seed = [hub_node]
        gn = _make_guard_network(graph)
        s = _sensor()

        greedy = TemporalAttackSimulator(
            dwell_time=3, detection_probability=0.0, move_strategy="greedy", seed=42
        ).simulate(graph, seed, gn, s, max_steps=30)

        stealthy = TemporalAttackSimulator(
            dwell_time=3, detection_probability=0.0, move_strategy="stealthy", seed=42
        ).simulate(graph, seed, gn, s, max_steps=30)

        assert stealthy.mean_events_per_step < greedy.mean_events_per_step, (
            f"stealthy={stealthy.mean_events_per_step:.3f} events/step, "
            f"greedy={greedy.mean_events_per_step:.3f} events/step; "
            "expected stealthy < greedy"
        )
