"""Comprehensive tests for TrustField Module 2 — Multi-Model Propagation Engine.

Tests cover all five propagation models across all three topology types,
plus the PropagationRunner and ComparisonReport.
"""

from __future__ import annotations

import pytest

from trustfield.graph import IAMSimulator, TrustGraph
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.propagation import (
    ComparisonReport,
    ControlSystemModel,
    EpidemicModel,
    GraphTraversalModel,
    PercolationModel,
    PropagationResult,
    PropagationRunner,
    SpectralCascadeModel,
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
def runner():
    return PropagationRunner()


def _pick_seed(graph: TrustGraph, node_type=NodeType.SERVICE) -> str:
    """Pick a low-privilege node of the given type as the attack seed."""
    nodes = graph.get_nodes_by_type(node_type)
    if nodes:
        return min(nodes, key=lambda n: n.privilege_level).node_id
    # Fall back to any node
    return next(iter(graph._graph.nodes()))


def _seeds(graph: TrustGraph) -> list:
    return [_pick_seed(graph)]


@pytest.fixture(scope="module")
def hub_seeds(hub_graph):
    return _seeds(hub_graph)


@pytest.fixture(scope="module")
def chain_seeds(chain_graph):
    return _seeds(chain_graph)


@pytest.fixture(scope="module")
def cluster_seeds(cluster_graph):
    return _seeds(cluster_graph)


# ---------------------------------------------------------------------------
# Small hand-crafted graph for precise assertions
# ---------------------------------------------------------------------------

@pytest.fixture
def tiny_graph():
    """
    A → B → C → D(high-priv)
    """
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER,     "user",    0.05, 0.1))
    g.add_node(NodeMetadata("B", NodeType.SERVICE,  "svc-b",   0.2,  0.3))
    g.add_node(NodeMetadata("C", NodeType.SERVICE,  "svc-c",   0.4,  0.5))
    g.add_node(NodeMetadata("D", NodeType.ROLE,     "admin",   0.95, 0.95))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.AUTHENTICATE_AS, 0.8, 2))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.TOKEN_MINT,       0.7, 2))
    g.add_edge("C", "D", EdgeMetadata("e3", EdgeType.ASSUME_ROLE,      0.9, 1))
    return g


# ---------------------------------------------------------------------------
# Helper: validate a PropagationResult structurally
# ---------------------------------------------------------------------------

def validate_result(result: PropagationResult, graph: TrustGraph, seed_nodes: list):
    """Assert all structural invariants of a PropagationResult."""
    all_nodes = set(graph._graph.nodes())

    # 1. All compromised nodes exist in the graph
    for nid in result.compromised_nodes:
        assert nid in all_nodes, f"Compromised node '{nid}' not in graph"

    # 2. All seed nodes are in compromised_nodes
    for nid in seed_nodes:
        assert nid in result.compromised_nodes, (
            f"Seed '{nid}' not in compromised_nodes for {result.model_name}"
        )

    # 3. cascade_probability in [0, 1]
    assert 0.0 <= result.cascade_probability <= 1.0, (
        f"cascade_probability {result.cascade_probability} out of range"
    )

    # 4. per_node_risk values in [0, 1]
    for nid, risk in result.per_node_risk.items():
        assert 0.0 <= risk <= 1.0, (
            f"per_node_risk[{nid}] = {risk} out of range for {result.model_name}"
        )

    # 5. propagation_depth >= 0
    assert result.propagation_depth >= 0

    # 6. model_name is a non-empty string
    assert result.model_name

    # 7. computation_time_ms >= 0
    assert result.computation_time_ms >= 0.0


# ===========================================================================
# MODEL 1 — GraphTraversalModel
# ===========================================================================

class TestGraphTraversalModel:
    @pytest.fixture
    def model(self):
        return GraphTraversalModel()

    def test_model_name(self, model):
        assert model.model_name == "graph_traversal"

    @pytest.mark.parametrize("topo", ["hub", "chain", "cluster"])
    def test_runs_without_error(self, model, hub_graph, chain_graph, cluster_graph, topo):
        g = {"hub": hub_graph, "chain": chain_graph, "cluster": cluster_graph}[topo]
        seed = _seeds(g)
        result = model.run(g, seed)
        validate_result(result, g, seed)

    def test_tiny_chain_reachability(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        # A can reach B, C, D
        assert "B" in result.compromised_nodes
        assert "C" in result.compromised_nodes
        assert "D" in result.compromised_nodes

    def test_tiny_chain_depth(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert result.propagation_depth == 3

    def test_max_depth_limits_spread(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], max_depth=1)
        assert "B" in result.compromised_nodes
        assert "C" not in result.compromised_nodes
        assert "D" not in result.compromised_nodes

    def test_high_privilege_sets_cascade_prob_1(self, model, tiny_graph):
        # D has privilege 0.95, should be reachable → cascade_probability = 1.0
        result = model.run(tiny_graph, ["A"])
        assert result.cascade_probability == pytest.approx(1.0)

    def test_seed_always_compromised(self, model, hub_graph):
        seed = _seeds(hub_graph)
        result = model.run(hub_graph, seed)
        for nid in seed:
            assert nid in result.compromised_nodes

    def test_convergence_true(self, model, hub_graph):
        result = model.run(hub_graph, _seeds(hub_graph))
        assert result.convergence_achieved is True

    def test_invalid_seed_raises(self, model, tiny_graph):
        with pytest.raises(KeyError):
            model.run(tiny_graph, ["not-a-node"])

    def test_edge_type_filter(self, model, tiny_graph):
        # Filter to only ASSUME_ROLE edges — only C→D survives
        result = model.run(
            tiny_graph, ["A"],
            follow_edge_types=[EdgeType.ASSUME_ROLE]
        )
        # A has no AssumeRole edges so nothing reachable from A
        assert result.compromised_nodes == {"A"}

    def test_per_node_risk_seed_is_1(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert result.per_node_risk["A"] == pytest.approx(1.0)

    def test_per_node_risk_decreases_with_distance(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        # A=1.0, B=0.5, C=0.33, D=0.25
        assert result.per_node_risk["A"] > result.per_node_risk["B"]
        assert result.per_node_risk["B"] > result.per_node_risk["C"]

    def test_disconnected_seed_only_itself(self, model):
        g = TrustGraph()
        g.add_node(NodeMetadata("x", NodeType.USER, "user", 0.1, 0.1))
        g.add_node(NodeMetadata("y", NodeType.USER, "user2", 0.1, 0.1))
        result = model.run(g, ["x"])
        assert result.compromised_nodes == {"x"}


# ===========================================================================
# MODEL 2 — EpidemicModel
# ===========================================================================

class TestEpidemicModel:
    @pytest.fixture
    def model(self):
        return EpidemicModel()

    def test_model_name(self, model):
        assert model.model_name == "epidemic"

    @pytest.mark.parametrize("topo", ["hub", "chain", "cluster"])
    def test_runs_without_error(self, model, hub_graph, chain_graph, cluster_graph, topo):
        g = {"hub": hub_graph, "chain": chain_graph, "cluster": cluster_graph}[topo]
        seed = _seeds(g)
        result = model.run(g, seed)
        validate_result(result, g, seed)

    def test_beta_zero_only_seeds(self, model, tiny_graph):
        """With beta=0 no spread occurs — only seeds are compromised."""
        result = model.run(tiny_graph, ["A"], beta=0.0)
        assert result.compromised_nodes == {"A"}

    def test_beta_high_spreads_more(self, model, tiny_graph):
        r_low  = model.run(tiny_graph, ["A"], beta=0.1)
        r_high = model.run(tiny_graph, ["A"], beta=0.99)
        assert len(r_high.compromised_nodes) >= len(r_low.compromised_nodes)

    def test_seed_always_compromised(self, model, hub_graph):
        seed = _seeds(hub_graph)
        result = model.run(hub_graph, seed)
        for nid in seed:
            assert nid in result.compromised_nodes

    def test_convergence_achieved_typical(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], beta=0.3, max_steps=200)
        assert result.convergence_achieved is True

    def test_invalid_seed_raises(self, model, tiny_graph):
        with pytest.raises(KeyError):
            model.run(tiny_graph, ["ghost"])

    def test_per_node_risk_in_range(self, model, hub_graph):
        result = model.run(hub_graph, _seeds(hub_graph))
        for risk in result.per_node_risk.values():
            assert 0.0 <= risk <= 1.0

    def test_raw_output_has_beta(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], beta=0.42)
        assert result.raw_output["beta"] == pytest.approx(0.42)

    def test_cascade_probability_in_range(self, model, hub_graph):
        result = model.run(hub_graph, _seeds(hub_graph))
        assert 0.0 <= result.cascade_probability <= 1.0


# ===========================================================================
# MODEL 3 — SpectralCascadeModel
# ===========================================================================

class TestSpectralCascadeModel:
    @pytest.fixture
    def model(self):
        return SpectralCascadeModel()

    def test_model_name(self, model):
        assert model.model_name == "spectral_cascade"

    @pytest.mark.parametrize("topo", ["hub", "chain", "cluster"])
    def test_runs_without_error(self, model, hub_graph, chain_graph, cluster_graph, topo):
        g = {"hub": hub_graph, "chain": chain_graph, "cluster": cluster_graph}[topo]
        seed = _seeds(g)
        result = model.run(g, seed)
        validate_result(result, g, seed)

    def test_raw_output_has_lambda_max(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "lambda_max" in result.raw_output

    def test_raw_output_has_cascade_condition_met(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "cascade_condition_met" in result.raw_output
        assert isinstance(result.raw_output["cascade_condition_met"], bool)

    def test_raw_output_has_eigenvector_centrality(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "eigenvector_centrality" in result.raw_output
        assert isinstance(result.raw_output["eigenvector_centrality"], dict)

    def test_raw_output_has_spectral_gap(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "spectral_gap" in result.raw_output

    def test_seed_always_compromised(self, model, chain_graph):
        seed = _seeds(chain_graph)
        result = model.run(chain_graph, seed)
        for nid in seed:
            assert nid in result.compromised_nodes

    def test_convergence_true(self, model, hub_graph):
        result = model.run(hub_graph, _seeds(hub_graph))
        assert result.convergence_achieved is True

    def test_cascade_prob_in_range(self, model, hub_graph):
        result = model.run(hub_graph, _seeds(hub_graph))
        assert 0.0 <= result.cascade_probability <= 1.0

    def test_no_cascade_when_tau_tiny(self, model, tiny_graph):
        # With tau near 0, cascade condition tau > 1/lambda_max is very unlikely
        result = model.run(tiny_graph, ["A"], tau=1e-6)
        assert result.raw_output["cascade_condition_met"] is False

    def test_cascade_when_tau_large(self, model, cluster_graph):
        # dense_cluster has cycles → non-zero lambda_max.
        # hub/chain are DAGs (no cycles) and always have lambda_max=0.
        # With tau=10, cascade condition tau > 1/lambda_max must be met.
        result = model.run(cluster_graph, _seeds(cluster_graph), tau=10.0)
        assert result.raw_output["cascade_condition_met"] is True
        assert result.cascade_probability > 0.5

    def test_per_node_risk_seeds_present(self, model, hub_graph):
        seed = _seeds(hub_graph)
        result = model.run(hub_graph, seed)
        for nid in seed:
            assert nid in result.per_node_risk

    def test_invalid_seed_raises(self, model, tiny_graph):
        with pytest.raises(KeyError):
            model.run(tiny_graph, ["no-such-node"])


# ===========================================================================
# MODEL 4 — PercolationModel
# ===========================================================================

class TestPercolationModel:
    @pytest.fixture
    def model(self):
        return PercolationModel()

    def test_model_name(self, model):
        assert model.model_name == "percolation"

    @pytest.mark.parametrize("topo", ["hub", "chain", "cluster"])
    def test_runs_without_error(self, model, hub_graph, chain_graph, cluster_graph, topo):
        g = {"hub": hub_graph, "chain": chain_graph, "cluster": cluster_graph}[topo]
        seed = _seeds(g)
        result = model.run(g, seed, n_trials=20)  # fewer trials for speed
        validate_result(result, g, seed)

    def test_percolation_zero_only_seeds(self, model, tiny_graph):
        """With percolation_probability=0.0 no edges survive → only seeds."""
        result = model.run(tiny_graph, ["A"],
                           percolation_probability=0.0, n_trials=10)
        assert result.compromised_nodes == {"A"}

    def test_seed_always_compromised(self, model, hub_graph):
        seed = _seeds(hub_graph)
        result = model.run(hub_graph, seed, n_trials=20)
        for nid in seed:
            assert nid in result.compromised_nodes

    def test_raw_output_has_giant_component_probability(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], n_trials=10)
        assert "giant_component_probability" in result.raw_output
        assert 0.0 <= result.raw_output["giant_component_probability"] <= 1.0

    def test_raw_output_has_avg_giant_component_size(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], n_trials=10)
        assert "avg_giant_component_size" in result.raw_output

    def test_raw_output_has_critical_edges(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], n_trials=10)
        assert "critical_edges" in result.raw_output
        assert isinstance(result.raw_output["critical_edges"], list)

    def test_raw_output_has_cluster_size_distribution(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], n_trials=10)
        assert "cluster_size_distribution" in result.raw_output
        assert isinstance(result.raw_output["cluster_size_distribution"], dict)

    def test_cascade_prob_in_range(self, model, cluster_graph):
        result = model.run(cluster_graph, _seeds(cluster_graph), n_trials=20)
        assert 0.0 <= result.cascade_probability <= 1.0

    def test_time_steps_equals_n_trials(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"], n_trials=7)
        assert result.time_steps == 7

    def test_reproducibility(self, model, hub_graph):
        seed = _seeds(hub_graph)
        r1 = model.run(hub_graph, seed, n_trials=20, random_seed=99)
        r2 = model.run(hub_graph, seed, n_trials=20, random_seed=99)
        assert r1.compromised_nodes == r2.compromised_nodes

    def test_invalid_seed_raises(self, model, tiny_graph):
        with pytest.raises(KeyError):
            model.run(tiny_graph, ["ghost"], n_trials=5)


# ===========================================================================
# MODEL 5 — ControlSystemModel
# ===========================================================================

class TestControlSystemModel:
    @pytest.fixture
    def model(self):
        return ControlSystemModel()

    def test_model_name(self, model):
        assert model.model_name == "control_system"

    @pytest.mark.parametrize("topo", ["hub", "chain", "cluster"])
    def test_runs_without_error(self, model, hub_graph, chain_graph, cluster_graph, topo):
        g = {"hub": hub_graph, "chain": chain_graph, "cluster": cluster_graph}[topo]
        seed = _seeds(g)
        result = model.run(g, seed)
        validate_result(result, g, seed)

    def test_raw_output_has_system_stable(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "system_stable" in result.raw_output
        assert isinstance(result.raw_output["system_stable"], bool)

    def test_raw_output_has_stability_margin(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "stability_margin" in result.raw_output
        margin = result.raw_output["stability_margin"]
        assert isinstance(margin, float)

    def test_raw_output_has_eigenvalues(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "eigenvalues" in result.raw_output
        assert isinstance(result.raw_output["eigenvalues"], list)

    def test_raw_output_has_spectral_radius(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "spectral_radius" in result.raw_output

    def test_raw_output_has_state_trajectory(self, model, tiny_graph):
        result = model.run(tiny_graph, ["A"])
        assert "state_trajectory" in result.raw_output
        assert isinstance(result.raw_output["state_trajectory"], list)
        assert len(result.raw_output["state_trajectory"]) > 0

    def test_seed_always_compromised(self, model, hub_graph):
        seed = _seeds(hub_graph)
        result = model.run(hub_graph, seed)
        for nid in seed:
            assert nid in result.compromised_nodes

    def test_convergence_deterministic(self, model, tiny_graph):
        r1 = model.run(tiny_graph, ["A"])
        r2 = model.run(tiny_graph, ["A"])
        assert r1.compromised_nodes == r2.compromised_nodes
        assert r1.cascade_probability == pytest.approx(r2.cascade_probability)

    def test_cascade_prob_in_range(self, model, chain_graph):
        result = model.run(chain_graph, _seeds(chain_graph))
        assert 0.0 <= result.cascade_probability <= 1.0

    def test_normalised_system_is_stable(self, model, hub_graph):
        """After normalisation, spectral_radius must be < 1."""
        result = model.run(hub_graph, _seeds(hub_graph))
        assert result.raw_output["spectral_radius"] < 1.0 + 1e-6

    def test_invalid_seed_raises(self, model, tiny_graph):
        with pytest.raises(KeyError):
            model.run(tiny_graph, ["nope"])

    def test_per_node_risk_in_range(self, model, chain_graph):
        result = model.run(chain_graph, _seeds(chain_graph))
        for risk in result.per_node_risk.values():
            assert 0.0 <= risk <= 1.0


# ===========================================================================
# PropagationRunner
# ===========================================================================

class TestPropagationRunner:
    def test_run_all_returns_all_models(self, runner, hub_graph, hub_seeds):
        results = runner.run_all(hub_graph, hub_seeds,
                                 percolation={"n_trials": 10})
        assert set(results.keys()) == {
            "graph_traversal", "epidemic", "spectral_cascade",
            "percolation", "control_system", "gnn",
        }

    def test_run_all_all_results_valid(self, runner, hub_graph, hub_seeds):
        results = runner.run_all(hub_graph, hub_seeds,
                                 percolation={"n_trials": 10})
        for name, result in results.items():
            validate_result(result, hub_graph, hub_seeds)

    def test_run_single_returns_correct_model(self, runner, hub_graph, hub_seeds):
        for name in ["graph_traversal", "epidemic", "spectral_cascade",
                     "percolation", "control_system"]:
            result = runner.run_single(name, hub_graph, hub_seeds,
                                       n_trials=10)
            assert result.model_name == name

    def test_run_single_invalid_model_raises(self, runner, hub_graph, hub_seeds):
        with pytest.raises(ValueError):
            runner.run_single("quantum_tunnelling", hub_graph, hub_seeds)

    @pytest.mark.parametrize("topo", ["hub", "chain", "cluster"])
    def test_run_all_cross_topology(self, runner,
                                    hub_graph, chain_graph, cluster_graph,
                                    hub_seeds, chain_seeds, cluster_seeds,
                                    topo):
        mapping = {
            "hub":     (hub_graph,     hub_seeds),
            "chain":   (chain_graph,   chain_seeds),
            "cluster": (cluster_graph, cluster_seeds),
        }
        g, seeds = mapping[topo]
        results = runner.run_all(g, seeds, percolation={"n_trials": 10})
        assert len(results) == 6
        for result in results.values():
            validate_result(result, g, seeds)


# ===========================================================================
# ComparisonReport
# ===========================================================================

class TestComparisonReport:
    @pytest.fixture
    def all_results(self, runner, hub_graph, hub_seeds):
        return runner.run_all(hub_graph, hub_seeds,
                              percolation={"n_trials": 10})

    def test_agreement_score_in_range(self, runner, all_results):
        report = runner.compare_results(all_results)
        assert 0.0 <= report.agreement_score <= 1.0

    def test_union_is_superset_of_intersection(self, runner, all_results):
        report = runner.compare_results(all_results)
        assert report.intersection_compromised.issubset(report.union_compromised)

    def test_most_dangerous_nodes_max_5(self, runner, all_results):
        report = runner.compare_results(all_results)
        assert len(report.most_dangerous_nodes) <= 5

    def test_most_dangerous_nodes_in_union(self, runner, all_results, hub_graph):
        report = runner.compare_results(all_results)
        all_nodes = set(hub_graph._graph.nodes())
        for nid in report.most_dangerous_nodes:
            assert nid in all_nodes

    def test_per_node_consensus_values_valid(self, runner, all_results):
        report = runner.compare_results(all_results)
        for nid, count in report.per_node_consensus.items():
            assert 1 <= count <= 6

    def test_empty_results_returns_default(self, runner):
        report = runner.compare_results({})
        assert report.agreement_score == pytest.approx(1.0)
        assert len(report.union_compromised) == 0

    def test_single_model_agreement_is_1(self, runner, hub_graph, hub_seeds):
        results = {"graph_traversal": runner.run_single(
            "graph_traversal", hub_graph, hub_seeds
        )}
        report = runner.compare_results(results)
        assert report.agreement_score == pytest.approx(1.0)

    def test_model_names_populated(self, runner, all_results):
        report = runner.compare_results(all_results)
        assert len(report.model_names) == 6

    def test_cascade_probability_spread_nonneg(self, runner, all_results):
        report = runner.compare_results(all_results)
        assert report.cascade_probability_spread >= 0.0

    def test_avg_cascade_probability_in_range(self, runner, all_results):
        report = runner.compare_results(all_results)
        assert 0.0 <= report.avg_cascade_probability <= 1.0

    def test_seeds_in_union(self, runner, hub_graph, hub_seeds):
        results = runner.run_all(hub_graph, hub_seeds,
                                 percolation={"n_trials": 10})
        report = runner.compare_results(results)
        for seed in hub_seeds:
            assert seed in report.union_compromised

    def test_comparison_report_to_dict(self, runner, all_results):
        report = runner.compare_results(all_results)
        d = report.to_dict()
        assert "union_compromised" in d
        assert "intersection_compromised" in d
        assert "agreement_score" in d
        assert "most_dangerous_nodes" in d
        assert isinstance(d["union_compromised"], list)


# ===========================================================================
# PropagationResult serialization
# ===========================================================================

class TestPropagationResultSerialization:
    def test_to_dict_has_required_keys(self, runner, hub_graph, hub_seeds):
        result = runner.run_single("graph_traversal", hub_graph, hub_seeds)
        d = result.to_dict()
        required = {
            "model_name", "seed_nodes", "compromised_nodes",
            "propagation_depth", "cascade_probability", "model_confidence",
            "time_steps", "convergence_achieved", "per_node_risk",
            "raw_output", "computation_time_ms",
        }
        assert required.issubset(set(d.keys()))

    def test_compromised_nodes_is_sorted_list(self, runner, hub_graph, hub_seeds):
        result = runner.run_single("graph_traversal", hub_graph, hub_seeds)
        d = result.to_dict()
        assert isinstance(d["compromised_nodes"], list)
        assert d["compromised_nodes"] == sorted(d["compromised_nodes"])

    def test_summary_is_string(self, runner, hub_graph, hub_seeds):
        result = runner.run_single("epidemic", hub_graph, hub_seeds)
        s = result.summary()
        assert isinstance(s, str)
        assert "epidemic" in s
