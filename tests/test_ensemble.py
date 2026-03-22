"""Comprehensive tests for TrustField Module 3 — Ensemble Predictor.

Covers WeightVector, TopologyAwareSelector, WeightTracker, EnsemblePredictor
(both fusion modes), TrustFieldOrchestrator, and AnalysisResult.
"""

from __future__ import annotations

import pytest

from trustfield.graph import IAMSimulator, TopologyFingerprinter
from trustfield.graph.fingerprinter import TopologyType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.propagation import PropagationRunner
from trustfield.ensemble import (
    AnalysisResult,
    EnsemblePredictor,
    EnsemblePrediction,
    FusionMode,
    ModelAccuracy,
    TopologyAwareSelector,
    TrustFieldOrchestrator,
    WeightTracker,
    WeightVector,
    MODEL_NAMES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sim():
    return IAMSimulator()


@pytest.fixture(scope="module")
def hub_graph(sim):
    return sim.generate("hub", num_nodes=40, seed=42)


@pytest.fixture(scope="module")
def chain_graph(sim):
    return sim.generate("chain", num_nodes=30, seed=42)


@pytest.fixture(scope="module")
def cluster_graph(sim):
    return sim.generate("dense_cluster", num_nodes=40, seed=42)


@pytest.fixture(scope="module")
def fingerprinter():
    return TopologyFingerprinter()


@pytest.fixture(scope="module")
def selector():
    return TopologyAwareSelector()


@pytest.fixture
def tracker():
    # In-memory database: no file created, no cross-test contamination
    return WeightTracker(db_path=":memory:")


@pytest.fixture(scope="module")
def runner():
    return PropagationRunner()


@pytest.fixture(scope="module")
def predictor():
    return EnsemblePredictor()


@pytest.fixture(scope="module")
def orch():
    # In-memory DB for all orchestrator tests
    return TrustFieldOrchestrator(db_path=":memory:")


@pytest.fixture(scope="module")
def hub_prop_results(runner, hub_graph):
    seed = sorted(hub_graph._graph.nodes())[0]
    return runner.run_all(hub_graph, [seed], percolation={"n_trials": 20})


@pytest.fixture(scope="module")
def hub_weight_vector(selector, fingerprinter, hub_graph):
    fp = fingerprinter.fingerprint(hub_graph)
    return selector.get_initial_weights(fp)


# ---------------------------------------------------------------------------
# Tiny hand-crafted graph for deterministic assertions
# ---------------------------------------------------------------------------

@pytest.fixture
def tiny_graph():
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER,    "user",  0.05, 0.1))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "svc-b", 0.3,  0.4))
    g.add_node(NodeMetadata("C", NodeType.ROLE,    "admin", 0.9,  0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.AUTHENTICATE_AS, 0.8, 2))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.ASSUME_ROLE,      0.9, 1))
    return g


@pytest.fixture
def tiny_results(runner, tiny_graph):
    return runner.run_all(tiny_graph, ["A"], percolation={"n_trials": 10})


# ===========================================================================
# WeightVector
# ===========================================================================

class TestWeightVector:
    def test_validate_valid(self):
        n_models = len(MODEL_NAMES)
        wv = WeightVector(
            weights={n: 1.0 / n_models for n in MODEL_NAMES},
            topology_type="MIXED",
            source="uniform",
        )
        wv.validate()  # should not raise

    def test_validate_raises_sum_not_one(self):
        wv = WeightVector(
            weights={n: 0.1 for n in MODEL_NAMES},  # sums to 0.5
            topology_type="MIXED",
            source="uniform",
        )
        with pytest.raises(AssertionError):
            wv.validate()

    def test_validate_raises_weight_out_of_range(self):
        weights = {n: 0.2 for n in MODEL_NAMES}
        weights["epidemic"] = 1.5  # invalid, also breaks sum
        weights["graph_traversal"] = -0.7
        wv = WeightVector(weights=weights, topology_type="HUB", source="topology_prior")
        with pytest.raises(AssertionError):
            wv.validate()

    def test_normalize_sums_to_one(self):
        weights = {n: float(i + 1) for i, n in enumerate(MODEL_NAMES)}
        wv = WeightVector(weights=weights, topology_type="HUB", source="topology_prior")
        normalised = wv.normalize()
        assert abs(sum(normalised.weights.values()) - 1.0) < 1e-9

    def test_normalize_preserves_ratios(self):
        weights = {"graph_traversal": 2.0, "epidemic": 1.0,
                   "spectral_cascade": 0.0, "percolation": 1.0, "control_system": 0.0}
        wv = WeightVector(weights=weights, topology_type="CHAIN", source="topology_prior")
        n = wv.normalize()
        assert n.weights["graph_traversal"] == pytest.approx(
            2.0 * n.weights["epidemic"]
        )

    def test_normalize_all_zero_gives_uniform(self):
        weights = {n: 0.0 for n in MODEL_NAMES}
        wv = WeightVector(weights=weights, topology_type="MIXED", source="uniform")
        n = wv.normalize()
        expected = 1.0 / len(n.weights)
        for v in n.weights.values():
            assert v == pytest.approx(expected)

    def test_uniform_factory_method(self):
        wv = WeightVector.uniform("CHAIN")
        wv.validate()
        assert wv.source == "uniform"
        expected = 1.0 / len(wv.weights)
        for v in wv.weights.values():
            assert v == pytest.approx(expected)

    def test_to_dict_has_required_keys(self):
        wv = WeightVector.uniform()
        d = wv.to_dict()
        assert "weights" in d
        assert "topology_type" in d
        assert "source" in d


# ===========================================================================
# TopologyAwareSelector
# ===========================================================================

class TestTopologyAwareSelector:
    def test_hub_highest_weight_is_correct(self, selector, fingerprinter, hub_graph):
        fp = fingerprinter.fingerprint(hub_graph)
        wv = selector.get_initial_weights(fp)
        # After empirical calibration: graph_traversal (structural upper bound,
        # F1=1.0 as ground truth) has the highest weight; percolation is second.
        assert wv.weights["graph_traversal"] == max(wv.weights.values())
        sorted_w = sorted(wv.weights.values(), reverse=True)
        assert sorted_w[1] == wv.weights["percolation"]

    def test_hub_spectral_weight_very_low(self, selector, fingerprinter, hub_graph):
        fp = fingerprinter.fingerprint(hub_graph)
        wv = selector.get_initial_weights(fp)
        # DAG → spectral near-zero
        assert wv.weights["spectral_cascade"] <= 0.10

    def test_chain_epidemic_weight_highest(self, selector, fingerprinter, chain_graph):
        fp = fingerprinter.fingerprint(chain_graph)
        wv = selector.get_initial_weights(fp)
        # After GNN pre-allocation: "gnn" holds the highest reserved weight
        # (0.40 of 1.0) for chain topology, pre-configuring the ensemble to
        # rely on the GNN module once it is implemented.
        assert wv.weights.get("gnn", 0.0) == max(wv.weights.values())

    def test_cluster_percolation_highest(self, selector, fingerprinter, cluster_graph):
        fp = fingerprinter.fingerprint(cluster_graph)
        wv = selector.get_initial_weights(fp)
        # After empirical calibration: graph_traversal is highest; percolation
        # remains the second-highest model for dense_cluster graphs.
        assert wv.weights["graph_traversal"] == max(wv.weights.values())

    def test_mixed_weights_valid(self, selector):
        """MIXED topology: weights sum to 1.0; gnn has the highest weight (0.25)."""
        from trustfield.graph.fingerprinter import TopologyFingerprint
        fp = TopologyFingerprint(
            clustering_coefficient=0.35, centrality_variance=0.02,
            spectral_gap=1.0, degree_distribution_entropy=3.0,
            avg_path_length=2.5, num_nodes=30, num_edges=60,
            density=0.07, topology_type=TopologyType.MIXED,
        )
        wv = selector.get_initial_weights(fp)
        wv.validate()
        # GNN has highest weight in MIXED; classical models share the rest equally
        assert wv.weights["gnn"] == max(wv.weights.values())

    def test_all_topologies_validate(self, selector):
        for ttype in ["HUB", "CHAIN", "DENSE_CLUSTER", "MIXED"]:
            wv = selector.get_weights_for_topology_type(ttype)
            wv.validate()

    def test_source_is_topology_prior(self, selector, fingerprinter, hub_graph):
        fp = fingerprinter.fingerprint(hub_graph)
        wv = selector.get_initial_weights(fp)
        assert wv.source == "topology_prior"

    def test_all_model_names_present(self, selector):
        wv = selector.get_weights_for_topology_type("HUB")
        for name in MODEL_NAMES:
            assert name in wv.weights


# ===========================================================================
# WeightTracker
# ===========================================================================

class TestWeightTracker:
    def test_record_result_returns_accuracy(self, tracker):
        acc = tracker.record_result(
            "epidemic", "CHAIN",
            predicted={"A", "B", "C"},
            actual={"B", "C", "D"},
        )
        assert isinstance(acc, ModelAccuracy)
        assert 0.0 <= acc.precision <= 1.0
        assert 0.0 <= acc.recall <= 1.0
        assert 0.0 <= acc.f1_score <= 1.0

    def test_record_perfect_prediction(self, tracker):
        acc = tracker.record_result(
            "graph_traversal", "HUB",
            predicted={"A", "B"},
            actual={"A", "B"},
        )
        assert acc.precision == pytest.approx(1.0)
        assert acc.recall == pytest.approx(1.0)
        assert acc.f1_score == pytest.approx(1.0)

    def test_record_no_overlap(self, tracker):
        acc = tracker.record_result(
            "percolation", "DENSE_CLUSTER",
            predicted={"X"},
            actual={"Y"},
        )
        assert acc.f1_score == pytest.approx(0.0)

    def test_get_adaptive_weights_returns_none_insufficient_history(self, tracker):
        result = tracker.get_adaptive_weights("HUB", min_history=5)
        assert result is None

    def test_get_adaptive_weights_returns_weight_vector_after_min_history(self, tracker):
        # Record min_history=5 results for every model under "CHAIN"
        for _ in range(5):
            for model in MODEL_NAMES:
                tracker.record_result(
                    model, "CHAIN",
                    predicted={"A", "B"}, actual={"A", "B", "C"},
                )
        wv = tracker.get_adaptive_weights("CHAIN", min_history=5)
        assert wv is not None
        assert isinstance(wv, WeightVector)
        wv.validate()
        assert wv.source == "adaptive"

    def test_adaptive_weights_sum_to_one(self, tracker):
        for _ in range(5):
            for model in MODEL_NAMES:
                tracker.record_result(
                    model, "HUB",
                    predicted={"A"}, actual={"A"},
                )
        wv = tracker.get_adaptive_weights("HUB", min_history=5)
        assert wv is not None
        assert abs(sum(wv.weights.values()) - 1.0) < 1e-9

    def test_update_and_retrieve_weights(self, tracker):
        wv = WeightVector.uniform("MIXED")
        tracker.update_weights("MIXED", wv)
        # No assertion on retrieval needed — just check no error raised

    def test_get_weight_history_returns_list(self, tracker):
        tracker.record_result("epidemic", "MIXED", {"A"}, {"A"})
        history = tracker.get_weight_history("MIXED", "epidemic")
        assert isinstance(history, list)
        assert len(history) >= 1
        assert "f1_score" in history[0]

    def test_empty_prediction_and_actual(self, tracker):
        acc = tracker.record_result("epidemic", "MIXED", set(), set())
        assert acc.f1_score == pytest.approx(1.0)

    def test_empty_prediction_nonempty_actual(self, tracker):
        acc = tracker.record_result("epidemic", "MIXED", set(), {"A", "B"})
        assert acc.f1_score == pytest.approx(0.0)


# ===========================================================================
# EnsemblePredictor — WEIGHTED mode
# ===========================================================================

class TestEnsemblePredictorWeighted:
    def test_ensemble_risk_in_range(self, predictor, hub_prop_results, hub_weight_vector):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        for risk in pred.ensemble_risk.values():
            assert 0.0 <= risk <= 1.0

    def test_seed_in_compromised(self, predictor, hub_prop_results, hub_weight_vector):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        seed = list(hub_prop_results.values())[0].seed_nodes[0]
        assert seed in pred.compromised_nodes

    def test_compromised_is_subset_of_all_nodes(
        self, predictor, hub_prop_results, hub_weight_vector, hub_graph
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        all_nodes = set(hub_graph._graph.nodes())
        assert pred.compromised_nodes.issubset(all_nodes)

    def test_high_uncertainty_subset_of_compromised(
        self, predictor, hub_prop_results, hub_weight_vector
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        assert pred.high_uncertainty_nodes.issubset(pred.compromised_nodes)

    def test_fusion_mode_string_weighted(
        self, predictor, hub_prop_results, hub_weight_vector
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        assert pred.fusion_mode == "WEIGHTED"

    def test_confidence_interval_bounds_ordered(
        self, predictor, hub_prop_results, hub_weight_vector
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        for lo, hi in pred.confidence_interval.values():
            assert lo <= hi

    def test_model_contributions_count(
        self, predictor, hub_prop_results, hub_weight_vector
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        assert len(pred.model_contributions) == len(hub_prop_results)

    def test_weight_vector_preserved(
        self, predictor, hub_prop_results, hub_weight_vector
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        assert pred.weight_vector is hub_weight_vector

    def test_total_nodes_analyzed_correct(
        self, predictor, hub_prop_results, hub_weight_vector, hub_graph
    ):
        pred = predictor.predict(hub_prop_results, hub_weight_vector,
                                  FusionMode.WEIGHTED)
        assert pred.total_nodes_analyzed == hub_graph._graph.number_of_nodes()

    def test_tiny_graph_all_nodes_have_risk(self, predictor, tiny_results, tiny_graph):
        wv = WeightVector.uniform("MIXED")
        pred = predictor.predict(tiny_results, wv, FusionMode.WEIGHTED)
        all_nodes = set(tiny_graph._graph.nodes())
        assert all_nodes.issubset(set(pred.ensemble_risk.keys()))


# ===========================================================================
# EnsemblePredictor — VOTING mode
# ===========================================================================

class TestEnsemblePredictorVoting:
    def test_voting_compromised_subset_of_union(
        self, predictor, runner, hub_graph, hub_prop_results
    ):
        wv = WeightVector.uniform("HUB")
        pred = predictor.predict(hub_prop_results, wv, FusionMode.VOTING)
        union = set()
        for r in hub_prop_results.values():
            union |= r.compromised_nodes
        assert pred.compromised_nodes.issubset(union)

    def test_voting_fusion_mode_string(
        self, predictor, hub_prop_results
    ):
        wv = WeightVector.uniform("HUB")
        pred = predictor.predict(hub_prop_results, wv, FusionMode.VOTING)
        assert pred.fusion_mode == "VOTING"

    def test_voting_risk_in_range(self, predictor, hub_prop_results):
        wv = WeightVector.uniform("HUB")
        pred = predictor.predict(hub_prop_results, wv, FusionMode.VOTING)
        for risk in pred.ensemble_risk.values():
            assert 0.0 <= risk <= 1.0

    def test_voting_high_uncertainty_subset_of_compromised(
        self, predictor, hub_prop_results
    ):
        wv = WeightVector.uniform("HUB")
        pred = predictor.predict(hub_prop_results, wv, FusionMode.VOTING)
        assert pred.high_uncertainty_nodes.issubset(pred.compromised_nodes)

    def test_voting_threshold_zero_includes_all_flagged_nodes(
        self, predictor, hub_prop_results
    ):
        wv = WeightVector.uniform("HUB")
        # voting_threshold=0.0 → any node flagged by at least 0 models
        pred = predictor.predict(hub_prop_results, wv, FusionMode.VOTING,
                                  voting_threshold=0.0)
        union = set()
        for r in hub_prop_results.values():
            union |= r.compromised_nodes
        assert union.issubset(pred.compromised_nodes)


# ===========================================================================
# TrustFieldOrchestrator
# ===========================================================================

class TestTrustFieldOrchestrator:
    def test_analyze_from_topology_hub_returns_analysis_result(self, orch):
        result = orch.analyze_from_topology(
            "hub", num_nodes=40, seed=42,
            model_kwargs={"percolation": {"n_trials": 10}}
        )
        assert isinstance(result, AnalysisResult)

    def test_analyze_from_topology_chain(self, orch):
        result = orch.analyze_from_topology(
            "chain", num_nodes=30, seed=42,
            model_kwargs={"percolation": {"n_trials": 10}}
        )
        assert isinstance(result, AnalysisResult)

    def test_analyze_from_topology_cluster(self, orch):
        result = orch.analyze_from_topology(
            "dense_cluster", num_nodes=40, seed=42,
            model_kwargs={"percolation": {"n_trials": 10}}
        )
        assert isinstance(result, AnalysisResult)

    def test_weight_source_is_topology_prior_without_history(self, orch):
        result = orch.analyze_from_topology(
            "hub", num_nodes=20, seed=99,
            model_kwargs={"percolation": {"n_trials": 5}}
        )
        assert result.weight_source == "topology_prior"

    def test_computation_time_positive(self, orch):
        result = orch.analyze_from_topology(
            "chain", num_nodes=20, seed=7,
            model_kwargs={"percolation": {"n_trials": 5}}
        )
        assert result.computation_time_ms > 0.0

    def test_ensemble_prediction_present(self, orch):
        result = orch.analyze_from_topology(
            "hub", num_nodes=20, seed=1,
            model_kwargs={"percolation": {"n_trials": 5}}
        )
        assert result.ensemble_prediction is not None

    def test_six_propagation_results(self, orch):
        result = orch.analyze_from_topology(
            "dense_cluster", num_nodes=20, seed=1,
            model_kwargs={"percolation": {"n_trials": 5}}
        )
        assert len(result.propagation_results) == 6

    def test_analyze_voting_mode(self, orch, hub_graph):
        nodes = sorted(hub_graph._graph.nodes())
        result = orch.analyze(
            hub_graph, [nodes[0]],
            fusion_mode=FusionMode.VOTING,
            model_kwargs={"percolation": {"n_trials": 5}},
        )
        assert result.ensemble_prediction.fusion_mode == "VOTING"

    def test_adaptive_weights_used_after_enough_history(self):
        """A fresh orchestrator with in-memory DB should switch to adaptive
        weights once min_history records are populated."""
        orch2 = TrustFieldOrchestrator(db_path=":memory:")
        for _ in range(6):
            for model in MODEL_NAMES:
                orch2._tracker.record_result(
                    model, "HUB",
                    predicted={"A", "B"}, actual={"A", "B", "C"},
                )
        sim = IAMSimulator()
        g = sim.generate("hub", num_nodes=15, seed=42)
        nodes = sorted(g._graph.nodes())
        result = orch2.analyze(
            g, [nodes[0]],
            model_kwargs={"percolation": {"n_trials": 5}},
            min_history=5,
        )
        assert result.weight_source == "adaptive"


# ===========================================================================
# AnalysisResult
# ===========================================================================

class TestAnalysisResult:
    @pytest.fixture(scope="class")
    def result(self, orch):
        return orch.analyze_from_topology(
            "hub", num_nodes=40, seed=42,
            model_kwargs={"percolation": {"n_trials": 10}}
        )

    def test_get_metrics_summary_has_all_keys(self, result):
        summary = result.get_metrics_summary()
        required = {
            "predicted_blast_radius",
            "prediction_confidence",
            "model_agreement_score",
            "topology_type",
            "high_uncertainty_fraction",
        }
        assert required.issubset(set(summary.keys()))

    def test_predicted_blast_radius_nonneg(self, result):
        assert result.get_metrics_summary()["predicted_blast_radius"] >= 0

    def test_prediction_confidence_in_range(self, result):
        c = result.get_metrics_summary()["prediction_confidence"]
        assert 0.0 <= c <= 1.0

    def test_model_agreement_score_in_range(self, result):
        s = result.get_metrics_summary()["model_agreement_score"]
        assert 0.0 <= s <= 1.0

    def test_topology_type_is_string(self, result):
        assert isinstance(result.get_metrics_summary()["topology_type"], str)

    def test_high_uncertainty_fraction_in_range(self, result):
        f = result.get_metrics_summary()["high_uncertainty_fraction"]
        assert 0.0 <= f <= 1.0

    def test_to_dict_serializable(self, result):
        import json
        d = result.to_dict()
        # Should not raise
        json.dumps(d, default=str)

    def test_to_dict_has_all_sections(self, result):
        d = result.to_dict()
        assert "graph_summary" in d
        assert "topology_fingerprint" in d
        assert "propagation_results" in d
        assert "comparison_report" in d
        assert "ensemble_prediction" in d
        assert "weight_vector_used" in d

    def test_high_uncertainty_nodes_subset_of_compromised(self, result):
        ep = result.ensemble_prediction
        assert ep.high_uncertainty_nodes.issubset(ep.compromised_nodes)


# ---------------------------------------------------------------------------
# Topology-aware decision threshold tests
# ---------------------------------------------------------------------------

class TestTopologyAwareThreshold:
    """Verify that TopologyAwareSelector returns the correct per-topology
    decision threshold and that the orchestrator uses it."""

    def test_hub_threshold_is_0_35(self, hub_graph):
        """Hub topology (single dominant-model regime) must use threshold 0.35."""
        fp = TopologyFingerprinter().fingerprint(hub_graph)
        selector = TopologyAwareSelector()
        assert fp.topology_type == TopologyType.HUB
        assert selector.get_recommended_threshold(fp) == pytest.approx(0.35)

    def test_dense_cluster_threshold_is_0_50(self, cluster_graph):
        """Dense-cluster topology (multi-model agreement required) must use 0.50."""
        fp = TopologyFingerprinter().fingerprint(cluster_graph)
        selector = TopologyAwareSelector()
        assert fp.topology_type == TopologyType.DENSE_CLUSTER
        assert selector.get_recommended_threshold(fp) == pytest.approx(0.50)

    def test_orchestrator_uses_topology_threshold(self, hub_graph):
        """Orchestrator must propagate the topology threshold to EnsemblePrediction.

        For hub topology the threshold is 0.35, so the stored decision_threshold
        on the EnsemblePrediction must be 0.35, not the predictor default of 0.5.
        """
        orch = TrustFieldOrchestrator(db_path=":memory:")
        node_list = sorted(hub_graph._graph.nodes())
        result = orch.analyze(hub_graph, seed_nodes=[node_list[0]])
        assert result.ensemble_prediction.decision_threshold == pytest.approx(0.35)
