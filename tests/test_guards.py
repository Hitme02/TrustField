"""Tests for TrustField Module 5 — Cyber-Physical Guard Simulation.

 1. Guard NOMINAL: valid token → ALLOWED
 2. Guard NOMINAL: invalid signature → BLOCKED
 3. Guard ELEVATED: depth == max_depth → BLOCKED (would pass in NOMINAL)
 4. Guard LOCKDOWN: whitelisted origin → FLAGGED (never ALLOWED)
 5. GuardNetwork: 2-of-3 consensus requires 2 approvals → ALLOWED
 6. GuardNetwork: 2 guards BLOCK → consensus BLOCKED even if 1 ALLOWS
 7. PropagationSensor: high escalation + high frequency → anomaly_detected=True
 8. FeedbackLoop: determine_strictness(0.8) == LOCKDOWN
 9. ContainmentEngine: containment_success_rate in [0.0, 1.0]
10. ContainmentEngine: contained_nodes ⊆ original VBR
11. compute_containment_metrics: combined_containment_rate accounts for natural + guard blocks
"""

from __future__ import annotations

import pytest

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.verification import (
    BlastRadiusCalculator,
    IAMTraversal,
    TokenGenerator,
    VerificationReport,
)
from trustfield.guards import (
    ContainmentEngine,
    CyberPhysicalGuard,
    FeedbackAction,
    GuardEvent,
    GuardNetwork,
    HardwareSoftwareFeedback,
    PropagationSensor,
    StrictnessLevel,
)
from trustfield.guards.guard_module import GuardEvent


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def simple_graph() -> TrustGraph:
    """A → B → C chain with weight-1.0 edges."""
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER, "User A", 0.3, 0.2))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "Svc B", 0.5, 0.5))
    g.add_node(NodeMetadata("C", NodeType.ROLE, "Admin C", 0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 1.0, 6))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.TOKEN_MINT, 1.0, 6))
    return g


@pytest.fixture
def gen() -> TokenGenerator:
    return TokenGenerator()


@pytest.fixture
def ab_edge(gen, simple_graph) -> EdgeMetadata:
    return simple_graph.get_edge("A", "B")


def _make_guard(guard_id, edge, gen, strictness=StrictnessLevel.NOMINAL):
    return CyberPhysicalGuard(guard_id, edge, gen, initial_strictness=strictness)


def _fresh_token(gen, src, tgt, edge_meta, depth=0):
    return gen.generate(src, tgt, edge_meta, current_depth=depth)


# ---------------------------------------------------------------------------
# 1. Guard NOMINAL: valid token → ALLOWED
# ---------------------------------------------------------------------------

class TestGuardNominalAllowed:
    def test_valid_token_allowed(self, gen, ab_edge):
        guard_gen = TokenGenerator(secret_key=gen.key)
        guard = _make_guard("g0", ("A", "B"), guard_gen)
        token = _fresh_token(gen, "A", "B", ab_edge, depth=0)
        event = guard.validate_transition(token)
        assert event.decision == "ALLOWED"


# ---------------------------------------------------------------------------
# 2. Guard NOMINAL: invalid signature → BLOCKED
# ---------------------------------------------------------------------------

class TestGuardNominalBlockedBadSig:
    def test_tampered_signature_blocked(self, gen, ab_edge):
        guard_gen = TokenGenerator(secret_key=gen.key)
        guard = _make_guard("g1", ("A", "B"), guard_gen)
        token = _fresh_token(gen, "A", "B", ab_edge, depth=0)
        token.signature = "0" * 64
        event = guard.validate_transition(token)
        assert event.decision == "BLOCKED"
        assert "invalid_signature" in event.reason


# ---------------------------------------------------------------------------
# 3. Guard ELEVATED: depth == max_depth → BLOCKED (passes NOMINAL)
# ---------------------------------------------------------------------------

class TestGuardElevatedDepthBlocked:
    def test_at_max_depth_blocked_in_elevated(self, gen, simple_graph):
        # Edge with delegation_depth_limit = 3
        edge_meta = EdgeMetadata("e3", EdgeType.ASSUME_ROLE, 1.0, 3)
        simple_graph.add_node(NodeMetadata("X", NodeType.USER, "X", 0.3, 0.2))
        simple_graph.add_node(NodeMetadata("Y", NodeType.SERVICE, "Y", 0.5, 0.5))
        simple_graph.add_edge("X", "Y", edge_meta)

        local_gen = TokenGenerator()
        # depth=3 == max_depth=3: passes NOMINAL (3 ≤ 3) but fails ELEVATED (3 > 3-1=2)
        token = local_gen.generate("X", "Y", edge_meta, current_depth=3)

        nominal_guard = CyberPhysicalGuard(
            "g_nom", ("X", "Y"), TokenGenerator(secret_key=local_gen.key),
            initial_strictness=StrictnessLevel.NOMINAL,
        )
        elevated_guard = CyberPhysicalGuard(
            "g_elev", ("X", "Y"), TokenGenerator(secret_key=local_gen.key),
            initial_strictness=StrictnessLevel.ELEVATED,
        )

        nom_event = nominal_guard.validate_transition(token)
        elev_event = elevated_guard.validate_transition(token)

        assert nom_event.decision == "ALLOWED", "depth=max_depth should pass NOMINAL"
        assert elev_event.decision == "BLOCKED", "depth=max_depth should fail ELEVATED"


# ---------------------------------------------------------------------------
# 4. Guard LOCKDOWN: whitelisted origin → FLAGGED
# ---------------------------------------------------------------------------

class TestGuardLockdownFlagged:
    def test_whitelisted_origin_flagged(self, ab_edge):
        local_gen = TokenGenerator()
        guard_gen = TokenGenerator(secret_key=local_gen.key)
        guard = CyberPhysicalGuard(
            "g_lock", ("A", "B"), guard_gen,
            initial_strictness=StrictnessLevel.LOCKDOWN,
        )
        guard.approved_origins.add("A")  # whitelist origin

        token = local_gen.generate("A", "B", ab_edge, current_depth=0)
        event = guard.validate_transition(token)
        assert event.decision == "FLAGGED"
        assert "flagged_for_review" in event.reason


# ---------------------------------------------------------------------------
# 5. GuardNetwork: 2-of-3 consensus → ALLOWED when all 3 agree
# ---------------------------------------------------------------------------

class TestGuardNetworkConsensus2of3:
    def test_all_three_allow_consensus_allowed(self, simple_graph, gen):
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], guards_per_edge=3)
        # Fresh token for the edge
        edge_meta = simple_graph.get_edge("A", "B")
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        result = network.validate_with_consensus(("A", "B"), token, required_approvals=2)
        assert result.consensus_decision == "ALLOWED"
        assert result.approval_count >= 2


# ---------------------------------------------------------------------------
# 6. GuardNetwork: 2 guards BLOCK → consensus BLOCKED even if 1 ALLOWS
# ---------------------------------------------------------------------------

class TestGuardNetworkConsensusBlocked:
    def test_two_blocks_overrides_one_allow(self, simple_graph, gen):
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], guards_per_edge=3)

        # Put 2 guards in LOCKDOWN (empty whitelist → BLOCKED)
        guards = network._deployed_guards[("A", "B")]
        guards[0].set_strictness(StrictnessLevel.LOCKDOWN)  # empty whitelist → BLOCKED
        guards[1].set_strictness(StrictnessLevel.LOCKDOWN)  # same
        # guards[2] stays NOMINAL → ALLOWED

        edge_meta = simple_graph.get_edge("A", "B")
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        result = network.validate_with_consensus(("A", "B"), token, required_approvals=2)

        assert result.consensus_decision == "BLOCKED"
        assert result.approval_count < 2


# ---------------------------------------------------------------------------
# 7. PropagationSensor: high escalation + high frequency → anomaly
# ---------------------------------------------------------------------------

class TestSensorAnomaly:
    def test_high_escalation_triggers_anomaly(self, simple_graph, gen):
        """10 events in 1 second, 8 with depth failures → high freq + high esc."""
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], guards_per_edge=1)
        guard = network._deployed_guards[("A", "B")][0]

        edge_meta = simple_graph.get_edge("A", "B")
        # Generate 8 tokens with depth = max_depth + 1 (fails NOMINAL depth check)
        events: list[GuardEvent] = []
        for _ in range(8):
            t = TokenGenerator(secret_key=gen.key)
            tok = t.generate("A", "B", edge_meta, current_depth=0)
            tok.delegation_depth = tok.max_depth + 1  # force depth failure
            evt = guard.validate_transition(tok)
            events.append(evt)

        # 2 valid tokens
        for _ in range(2):
            t = TokenGenerator(secret_key=gen.key)
            tok = t.generate("A", "B", edge_meta, current_depth=0)
            evt = guard.validate_transition(tok)
            events.append(evt)

        # time_window=1s → frequency = 10/s > baseline of 5/s
        sensor = PropagationSensor(anomaly_threshold=0.6)
        reading = sensor.analyze(events, time_window=1.0)

        assert reading.anomaly_detected, (
            f"Expected anomaly; score={reading.anomaly_score:.3f}, "
            f"esc={reading.escalation_attempt_count}, freq={reading.delegation_request_frequency:.1f}"
        )


# ---------------------------------------------------------------------------
# 8. FeedbackLoop: determine_strictness(0.8) == LOCKDOWN
# ---------------------------------------------------------------------------

class TestFeedbackLoopStrictnessMapping:
    def test_high_risk_maps_to_lockdown(self, simple_graph, gen):
        orch = TrustFieldOrchestrator(db_path=":memory:")
        network = GuardNetwork(simple_graph, gen)
        feedback = HardwareSoftwareFeedback(network, orch)
        assert feedback.determine_strictness(0.8) == StrictnessLevel.LOCKDOWN
        assert feedback.determine_strictness(0.5) == StrictnessLevel.ELEVATED
        assert feedback.determine_strictness(0.2) == StrictnessLevel.NOMINAL


# ---------------------------------------------------------------------------
# 9. ContainmentEngine: containment_success_rate in [0.0, 1.0]
# ---------------------------------------------------------------------------

class TestContainmentSuccessRateInRange:
    @pytest.fixture(scope="class")
    def containment_result(self, simple_graph):
        orch = TrustFieldOrchestrator(db_path=":memory:")
        analysis = orch.analyze(simple_graph, seed_nodes=["A"])
        tgen = TokenGenerator()
        traversal = IAMTraversal(tgen).traverse(
            simple_graph, ["A"], max_depth=6, respect_conditions=False
        )
        bra = BlastRadiusCalculator().compute(
            analysis.ensemble_prediction, traversal, simple_graph
        )
        report = VerificationReport(
            graph=simple_graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
        )
        engine = ContainmentEngine(orch, token_generator=TokenGenerator())
        return engine.execute(simple_graph, ["A"], report, n_feedback_cycles=3)

    def test_success_rate_in_range(self, containment_result):
        rate = containment_result.containment_success_rate
        assert 0.0 <= rate <= 1.0, f"Rate out of range: {rate}"


# ---------------------------------------------------------------------------
# 10. ContainmentEngine: contained_nodes ⊆ original VBR
# ---------------------------------------------------------------------------

class TestContainmentNodesSubsetOfVBR:
    @pytest.fixture(scope="class")
    def containment_and_vbr(self, simple_graph):
        orch = TrustFieldOrchestrator(db_path=":memory:")
        analysis = orch.analyze(simple_graph, seed_nodes=["A"])
        tgen = TokenGenerator()
        traversal = IAMTraversal(tgen).traverse(
            simple_graph, ["A"], max_depth=6, respect_conditions=False
        )
        bra = BlastRadiusCalculator().compute(
            analysis.ensemble_prediction, traversal, simple_graph
        )
        report = VerificationReport(
            graph=simple_graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
        )
        engine = ContainmentEngine(orch, token_generator=TokenGenerator())
        result = engine.execute(simple_graph, ["A"], report, n_feedback_cycles=3)
        original_vbr = traversal.verified_reachable
        return result, original_vbr

    def test_contained_subset_of_vbr(self, containment_and_vbr):
        result, original_vbr = containment_and_vbr
        assert result.contained_nodes.issubset(original_vbr), (
            f"contained_nodes not ⊆ VBR: extra={result.contained_nodes - original_vbr}"
        )


# ---------------------------------------------------------------------------
# 11. compute_containment_metrics: combined_containment_rate
# ---------------------------------------------------------------------------

class TestCombinedContainmentRate:
    """compute_containment_metrics accounts for natural IAM blocks + guard blocks."""

    def _engine(self):
        return ContainmentEngine(TrustFieldOrchestrator(db_path=":memory:"))

    def test_combined_rate_equals_natural_plus_guard_over_unconstrained(self):
        """combined_containment_rate = (natural_blocks + guard_blocks) / |unconstrained|."""
        engine = self._engine()

        # unconstrained: BFS sees {A, B, C, D}
        # original_vbr (after token conditions): {A, B} — C and D blocked by IAM
        # post_containment_vbr (after guards): {A} — B additionally blocked by guard
        unconstrained = {"A", "B", "C", "D"}
        original_vbr = {"A", "B"}
        post_vbr = {"A"}

        m = engine.compute_containment_metrics(original_vbr, post_vbr, unconstrained)

        # natural_blocks = |{C, D}| = 2
        # guard_blocks   = |{B}|   = 1
        # combined_rate  = (2 + 1) / 4 = 0.75
        assert m["natural_blocks"] == 2
        assert m["guard_blocks"] == 1
        assert m["combined_containment_rate"] == pytest.approx(0.75)

    def test_combined_rate_in_range(self):
        """combined_containment_rate must always be in [0.0, 1.0]."""
        engine = self._engine()
        unconstrained = {"A", "B", "C"}
        original_vbr = {"A", "B", "C"}
        post_vbr = {"A"}

        m = engine.compute_containment_metrics(original_vbr, post_vbr, unconstrained)
        assert 0.0 <= m["combined_containment_rate"] <= 1.0

    def test_combined_rate_zero_without_unconstrained(self):
        """Without unconstrained_pbr the combined fields default to zero."""
        engine = self._engine()
        m = engine.compute_containment_metrics({"A", "B"}, {"A"})
        assert m["natural_blocks"] == 0
        assert m["guard_blocks"] == 1
        assert m["combined_containment_rate"] == pytest.approx(0.0)

    def test_containment_result_exposes_combined_rate(self, simple_graph):
        """ContainmentEngine.execute() populates combined_containment_rate."""
        orch = TrustFieldOrchestrator(db_path=":memory:")
        analysis = orch.analyze(simple_graph, seed_nodes=["A"])
        tgen = TokenGenerator()
        traversal = IAMTraversal(tgen).traverse(
            simple_graph, ["A"], max_depth=6, respect_conditions=False
        )
        bra = BlastRadiusCalculator().compute(
            analysis.ensemble_prediction, traversal, simple_graph
        )
        report = VerificationReport(
            graph=simple_graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
        )
        result = ContainmentEngine(orch).execute(
            simple_graph, ["A"], report, n_feedback_cycles=2
        )
        assert 0.0 <= result.combined_containment_rate <= 1.0
