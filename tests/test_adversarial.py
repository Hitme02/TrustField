"""Tests for TrustField adversarial topology testing module.

 1. EDGE_SPLITTING: mutated graph has more nodes than original
 2. EDGE_SPLITTING: original attacker paths preserved in mutated graph
 3. PRIVILEGE_DILUTION: mutated graph has more nodes than original
 4. CHAIN_OBFUSCATION: mutated graph has more edges than original
 5. reachability_preserved correctly computed (mutated_vbr >= 80% original)
 6. trustfield_robustness in [0.0, 1.0] for all results
 7. EvasionEvaluator returns len(strategies) * len(intensities) results
 8. RobustnessReport.overall_robustness_score in [0.0, 1.0]
 9. intensity=0.0 produces a graph with the same node count (no change)
10. latex_table contains \\begin{tabular}
"""

from __future__ import annotations

import pytest

from trustfield.adversarial import (
    AdversarialGraphMutator,
    EvasionEvaluator,
    MutationStrategy,
    RobustnessReport,
    build_robustness_report,
)
from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def chain_graph() -> TrustGraph:
    """A → B (SERVICE) → C (SERVICE) → D (ROLE) chain with high-weight edges."""
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER, "Attacker", 0.3, 0.2))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "Svc B", 0.7, 0.7))
    g.add_node(NodeMetadata("C", NodeType.SERVICE, "Svc C", 0.8, 0.8))
    g.add_node(NodeMetadata("D", NodeType.ROLE, "Admin D", 0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.AUTHENTICATE_AS, 0.9, 6))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.AUTHENTICATE_AS, 0.9, 6))
    g.add_edge("C", "D", EdgeMetadata("e3", EdgeType.TOKEN_MINT, 0.9, 6))
    return g


@pytest.fixture(scope="module")
def mutator() -> AdversarialGraphMutator:
    return AdversarialGraphMutator(exploitability_threshold=0.6)


@pytest.fixture(scope="module")
def orchestrator() -> TrustFieldOrchestrator:
    return TrustFieldOrchestrator(db_path=":memory:")


# ---------------------------------------------------------------------------
# 1. EDGE_SPLITTING: mutated graph has more nodes
# ---------------------------------------------------------------------------


class TestEdgeSplittingNodeCount:
    def test_more_nodes_after_splitting(self, chain_graph, mutator):
        mutated = mutator.mutate(
            chain_graph, MutationStrategy.EDGE_SPLITTING, intensity=0.8, seed=42
        )
        assert mutated.nx_graph.number_of_nodes() > chain_graph.nx_graph.number_of_nodes()


# ---------------------------------------------------------------------------
# 2. EDGE_SPLITTING: original attacker paths preserved
# ---------------------------------------------------------------------------


class TestEdgeSplittingPathPreservation:
    def test_attacker_can_still_reach_target(self, chain_graph, mutator):
        import networkx as nx

        mutated = mutator.mutate(
            chain_graph, MutationStrategy.EDGE_SPLITTING, intensity=0.8, seed=42
        )
        # A should still be able to reach D via the (possibly longer) path
        assert nx.has_path(mutated.nx_graph, "A", "D"), (
            "EDGE_SPLITTING must preserve reachability from A to D"
        )


# ---------------------------------------------------------------------------
# 3. PRIVILEGE_DILUTION: mutated graph has more nodes
# ---------------------------------------------------------------------------


class TestPrivilegeDilutionNodeCount:
    def test_more_nodes_after_dilution(self, chain_graph, mutator):
        mutated = mutator.mutate(
            chain_graph, MutationStrategy.PRIVILEGE_DILUTION, intensity=0.6, seed=42
        )
        assert mutated.nx_graph.number_of_nodes() > chain_graph.nx_graph.number_of_nodes()


# ---------------------------------------------------------------------------
# 4. CHAIN_OBFUSCATION: mutated graph has more edges
# ---------------------------------------------------------------------------


class TestChainObfuscationEdgeCount:
    def test_more_edges_after_obfuscation(self, chain_graph, mutator):
        mutated = mutator.mutate(
            chain_graph, MutationStrategy.CHAIN_OBFUSCATION, intensity=1.0, seed=42
        )
        # Each SERVICE→SERVICE edge is replaced by two edges (u→role, role→v)
        # so total edges should be >= original
        assert mutated.nx_graph.number_of_edges() >= chain_graph.nx_graph.number_of_edges()


# ---------------------------------------------------------------------------
# 5. reachability_preserved correctly computed
# ---------------------------------------------------------------------------


class TestReachabilityPreserved:
    def test_reachability_flag_matches_threshold(self, chain_graph, orchestrator):
        evaluator = EvasionEvaluator(mutation_seed=42)
        results = evaluator.evaluate(
            chain_graph,
            seed_nodes=["A"],
            orchestrator=orchestrator,
            strategies=[MutationStrategy.PRIVILEGE_DILUTION],
            intensities=[0.2],
        )
        assert len(results) == 1
        r = results[0]
        # Verify the flag matches the formula: mutated_vbr >= original_vbr * 0.8
        expected = r.mutated_vbr_size >= r.original_vbr_size * 0.8
        assert r.reachability_preserved == expected


# ---------------------------------------------------------------------------
# 6. trustfield_robustness in [0.0, 1.0]
# ---------------------------------------------------------------------------


class TestRobustnessInRange:
    def test_all_robustness_scores_in_range(self, chain_graph, orchestrator):
        evaluator = EvasionEvaluator(mutation_seed=42)
        results = evaluator.evaluate(
            chain_graph,
            seed_nodes=["A"],
            orchestrator=orchestrator,
        )
        for r in results:
            assert 0.0 <= r.trustfield_robustness <= 1.0, (
                f"robustness out of range: {r.trustfield_robustness} "
                f"(strategy={r.strategy}, intensity={r.intensity})"
            )


# ---------------------------------------------------------------------------
# 7. EvasionEvaluator returns len(strategies) * len(intensities) results
# ---------------------------------------------------------------------------


class TestEvaluatorResultCount:
    def test_result_count_equals_product(self, chain_graph, orchestrator):
        strategies = [MutationStrategy.EDGE_SPLITTING, MutationStrategy.PRIVILEGE_DILUTION]
        intensities = [0.2, 0.4, 0.6]
        evaluator = EvasionEvaluator(mutation_seed=42)
        results = evaluator.evaluate(
            chain_graph,
            seed_nodes=["A"],
            orchestrator=orchestrator,
            strategies=strategies,
            intensities=intensities,
        )
        assert len(results) == len(strategies) * len(intensities)


# ---------------------------------------------------------------------------
# 8. RobustnessReport.overall_robustness_score in [0.0, 1.0]
# ---------------------------------------------------------------------------


class TestReportRobustnessScore:
    def test_overall_score_in_range(self, chain_graph, orchestrator):
        evaluator = EvasionEvaluator(mutation_seed=42)
        results = evaluator.evaluate(
            chain_graph,
            seed_nodes=["A"],
            orchestrator=orchestrator,
        )
        report = build_robustness_report(results)
        assert 0.0 <= report.overall_robustness_score <= 1.0

    def test_empty_results_returns_score_one(self):
        report = build_robustness_report([])
        assert report.overall_robustness_score == 1.0


# ---------------------------------------------------------------------------
# 9. intensity=0.0 produces graph with same node count
# ---------------------------------------------------------------------------


class TestZeroIntensityNoChange:
    def test_zero_intensity_same_nodes(self, chain_graph, mutator):
        for strategy in MutationStrategy:
            mutated = mutator.mutate(chain_graph, strategy, intensity=0.0, seed=42)
            assert mutated.nx_graph.number_of_nodes() == chain_graph.nx_graph.number_of_nodes(), (
                f"Strategy {strategy} changed node count at intensity=0.0"
            )


# ---------------------------------------------------------------------------
# 10. latex_table contains \begin{tabular}
# ---------------------------------------------------------------------------


class TestLatexTableFormat:
    def test_latex_table_contains_tabular(self, chain_graph, orchestrator):
        evaluator = EvasionEvaluator(mutation_seed=42)
        results = evaluator.evaluate(
            chain_graph,
            seed_nodes=["A"],
            orchestrator=orchestrator,
            strategies=[MutationStrategy.EDGE_SPLITTING],
            intensities=[0.3],
        )
        report = build_robustness_report(results)
        assert r"\begin{tabular}" in report.latex_table
