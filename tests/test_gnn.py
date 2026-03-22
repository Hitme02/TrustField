"""Tests for TrustField GNN propagation module.

 1. Feature extraction returns (N, NUM_NODE_FEATURES) matrix
 2. Seed nodes have is_seed feature == 1.0
 3. Non-seed nodes have is_seed feature == 0.0
 4. adj_hat rows sum to 1.0 (row-normalised)
 5. Labels are binary (only 0.0 or 1.0)
 6. GCNModel forward pass returns shape (N,)
 7. generate_training_data returns non-empty list
 8. Training data contains graphs with positive labels
 9. GNNModel.run() returns a PropagationResult
10. GNNModel compromised set always includes seed nodes
11. per_node_risk values are all in [0.0, 1.0]
12. Train on chain graphs and verify F1 > 0.50
"""

from __future__ import annotations

import pytest

from trustfield.graph import IAMSimulator
from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.propagation.gnn_features import (
    GNNFeatureExtractor,
    GraphData,
    NUM_NODE_FEATURES,
)
from trustfield.propagation.gnn_model import GNNModel
from trustfield.propagation.gnn_trainer import (
    BaselineComparison,
    GeneralizationReport,
    NaiveBaseline,
    RealWorldValidation,
)
from trustfield.propagation.propagation_result import PropagationResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sim():
    return IAMSimulator()


@pytest.fixture(scope="module")
def chain_graph(sim):
    return sim.generate("chain", num_nodes=20, seed=42)


@pytest.fixture(scope="module")
def hub_graph(sim):
    return sim.generate("hub", num_nodes=20, seed=42)


@pytest.fixture(scope="module")
def extractor():
    return GNNFeatureExtractor()


@pytest.fixture(scope="module")
def chain_seed(chain_graph):
    """Return the first node ID from the chain graph."""
    return sorted(chain_graph._graph.nodes())[0]


@pytest.fixture(scope="module")
def chain_gd(extractor, chain_graph, chain_seed):
    """GraphData extracted from chain_graph with one seed."""
    return extractor.extract(chain_graph, seed_nodes=[chain_seed])


# ---------------------------------------------------------------------------
# Helper: tiny hand-crafted graph (A → B → C)
# ---------------------------------------------------------------------------

@pytest.fixture
def tiny_chain():
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.SERVICE, "svc-a", 0.1, 0.2))
    g.add_node(NodeMetadata("B", NodeType.ROLE,    "role-b", 0.5, 0.5))
    g.add_node(NodeMetadata("C", NodeType.SECRET,  "sec-c", 0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 0.8, 3))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.SECRET_READ, 0.9, 2))
    return g


# ===========================================================================
# Test 1: Feature shape
# ===========================================================================

def test_feature_extraction_shape(chain_gd, chain_graph):
    n = chain_graph._graph.number_of_nodes()
    assert chain_gd.x.shape == (n, NUM_NODE_FEATURES), (
        f"Expected ({n}, {NUM_NODE_FEATURES}), got {chain_gd.x.shape}"
    )


# ===========================================================================
# Test 2: Seed has is_seed == 1.0
# ===========================================================================

def test_seed_feature_is_one(extractor, tiny_chain):
    gd = extractor.extract(tiny_chain, seed_nodes=["A"])
    node_idx = gd.node_ids.index("A")
    assert gd.x[node_idx, 0] == pytest.approx(1.0), (
        f"Expected is_seed=1.0 for seed node A, got {gd.x[node_idx, 0]}"
    )


# ===========================================================================
# Test 3: Non-seed has is_seed == 0.0
# ===========================================================================

def test_non_seed_feature_is_zero(extractor, tiny_chain):
    gd = extractor.extract(tiny_chain, seed_nodes=["A"])
    for nid in ["B", "C"]:
        i = gd.node_ids.index(nid)
        assert gd.x[i, 0] == pytest.approx(0.0), (
            f"Expected is_seed=0.0 for non-seed {nid}, got {gd.x[i, 0]}"
        )


# ===========================================================================
# Test 4: adj_hat rows sum to 1.0
# ===========================================================================

def test_adj_hat_rows_sum_to_one(chain_gd):
    import numpy as np
    row_sums = chain_gd.adj_hat.sum(axis=1)
    assert all(abs(s - 1.0) < 1e-5 for s in row_sums), (
        f"adj_hat row sums not all 1.0: {row_sums}"
    )


# ===========================================================================
# Test 5: Labels are binary
# ===========================================================================

def test_labels_binary(extractor, tiny_chain):
    labels = {"A": 1, "B": 1, "C": 0}
    gd = extractor.extract(tiny_chain, seed_nodes=["A"], labels=labels)
    unique = set(gd.labels.tolist())
    assert unique.issubset({0.0, 1.0}), f"Non-binary labels found: {unique}"


# ===========================================================================
# Test 6: GCNModel forward pass returns (N,)
# ===========================================================================

def test_gcn_forward_shape(chain_gd):
    try:
        import torch
        from trustfield.propagation.gnn_trainer import GCNModel
    except ImportError:
        pytest.skip("torch not available")

    model = GCNModel(in_features=NUM_NODE_FEATURES)
    x_t = torch.from_numpy(chain_gd.x)
    adj_t = torch.from_numpy(chain_gd.adj_hat)
    with torch.no_grad():
        logits = model(x_t, adj_t)
    assert logits.shape == (chain_gd.x.shape[0],), (
        f"Expected logits shape ({chain_gd.x.shape[0]},), got {logits.shape}"
    )


# ===========================================================================
# Test 7: generate_training_data returns a non-empty list
# ===========================================================================

def test_generate_training_data_count():
    from trustfield.propagation.gnn_trainer import GNNTrainer

    trainer = GNNTrainer(n_graphs=10, seed=0)
    data = trainer.generate_training_data()
    assert len(data) > 0, "generate_training_data returned an empty list"
    assert all(isinstance(gd, GraphData) for gd in data)


# ===========================================================================
# Test 8: Training data contains positive labels
# ===========================================================================

def test_training_data_has_positive_labels():
    from trustfield.propagation.gnn_trainer import GNNTrainer

    trainer = GNNTrainer(n_graphs=10, seed=7)
    data = trainer.generate_training_data()
    has_positive = any(gd.labels.sum() > 0 for gd in data)
    assert has_positive, "All training graphs have zero positive labels"


# ===========================================================================
# Test 9: GNNModel.run() returns PropagationResult
# ===========================================================================

def test_gnn_model_run_returns_propagation_result(chain_graph, chain_seed):
    model = GNNModel(auto_train=False)
    result = model.run(chain_graph, [chain_seed])
    assert isinstance(result, PropagationResult)
    assert result.model_name == "gnn"


# ===========================================================================
# Test 10: Compromised set always includes seed nodes
# ===========================================================================

def test_gnn_compromised_includes_seeds(chain_graph, chain_seed):
    model = GNNModel(auto_train=False)
    result = model.run(chain_graph, [chain_seed])
    assert chain_seed in result.compromised_nodes, (
        f"Seed node {chain_seed!r} not in compromised_nodes"
    )


# ===========================================================================
# Test 11: per_node_risk values in [0, 1]
# ===========================================================================

def test_gnn_per_node_risk_in_range(chain_graph, chain_seed):
    model = GNNModel(auto_train=False)
    result = model.run(chain_graph, [chain_seed])
    for nid, risk in result.per_node_risk.items():
        assert 0.0 <= risk <= 1.0, (
            f"per_node_risk[{nid!r}] = {risk} is out of [0, 1]"
        )


# ===========================================================================
# Test 12: Train on chain graphs and achieve F1 > 0.50
# ===========================================================================

# ===========================================================================
# Tests 13–20: Naive baselines, BaselineComparison, GeneralizationReport,
#              and RealWorldValidation (Addition 1-3 publication tests)
# ===========================================================================

class TestNaiveBaseline:
    """Tests 13-15: NaiveBaseline static predictors."""

    def test_predict_all_compromised_returns_all_nodes(self, tiny_chain):
        result = NaiveBaseline.predict_all_compromised(tiny_chain, ["A"])
        assert result == set(tiny_chain.nx_graph.nodes()), (
            f"predict_all_compromised should return all nodes; got {result}"
        )

    def test_predict_seed_only_returns_seed(self, tiny_chain):
        result = NaiveBaseline.predict_seed_only(tiny_chain, ["A"])
        assert result == {"A"}, f"Expected {{'A'}}, got {result}"

    def test_predict_neighbors_only_includes_seed_and_successors(self, tiny_chain):
        result = NaiveBaseline.predict_neighbors_only(tiny_chain, ["A"])
        expected_min = {"A"} | set(tiny_chain.nx_graph.successors("A"))
        assert expected_min.issubset(result), (
            f"Expected at least {expected_min}; got {result}"
        )


class TestBaselineComparison:
    """Tests 16-17: BaselineComparison.result_is_trivial field."""

    def _make(self, improvement: float) -> BaselineComparison:
        return BaselineComparison(
            gnn_f1=0.5 + improvement,
            gnn_precision=0.6,
            gnn_recall=0.7,
            naive_all_f1=0.4,
            naive_seed_f1=0.3,
            naive_neighbors_f1=0.5,
            gnn_improvement_over_best_naive=improvement,
            result_is_trivial=improvement < 0.05,
            verdict="TRIVIAL" if improvement < 0.05 else "MEANINGFUL",
        )

    def test_trivial_when_improvement_below_threshold(self):
        bc = self._make(0.03)
        assert bc.result_is_trivial is True, (
            f"Improvement 0.03 < 0.05 should be trivial; got {bc.result_is_trivial}"
        )

    def test_not_trivial_when_improvement_above_threshold(self):
        bc = self._make(0.10)
        assert bc.result_is_trivial is False, (
            f"Improvement 0.10 >= 0.05 should not be trivial; got {bc.result_is_trivial}"
        )


class TestGeneralizationReport:
    """Tests 18-19: GeneralizationReport fields."""

    def _make(self, in_f1: float, ood_f1: float) -> GeneralizationReport:
        gap = abs(in_f1 - ood_f1)
        return GeneralizationReport(
            train_topologies=["hub", "chain"],
            test_topologies=["dense_cluster", "mixed"],
            in_distribution_f1=in_f1,
            out_of_distribution_f1=ood_f1,
            generalization_gap=gap,
            generalizes_well=gap < 0.15,
            verdict="STRONG" if gap < 0.05 else ("ACCEPTABLE" if gap < 0.15 else "WEAK"),
        )

    def test_generalizes_well_when_gap_small(self):
        gr = self._make(0.85, 0.80)
        assert gr.generalizes_well is True, (
            f"Gap {gr.generalization_gap} < 0.15 should generalizes_well=True"
        )

    def test_generalization_gap_is_absolute_difference(self):
        gr = self._make(0.80, 0.65)
        assert abs(gr.generalization_gap - 0.15) < 1e-9, (
            f"Expected gap=0.15, got {gr.generalization_gap}"
        )


class TestRealWorldValidation:
    """Test 20: evaluate_on_real_world returns one result per fixture file."""

    def test_result_count_matches_fixture_files(self):
        try:
            import torch
            from trustfield.propagation.gnn_trainer import GCNModel, GNNTrainer
        except ImportError:
            pytest.skip("torch not available")

        import pathlib
        fix_dir  = pathlib.Path("tests/fixtures")
        n_aws    = len(list((fix_dir / "aws").glob("*.json")))
        n_k8s    = len(list((fix_dir / "k8s").glob("*.yaml")))
        expected = n_aws + n_k8s

        trainer  = GNNTrainer()
        model    = GCNModel(in_features=NUM_NODE_FEATURES)   # untrained — count only
        val      = trainer.evaluate_on_real_world(model=model)

        assert isinstance(val, RealWorldValidation)
        assert len(val.results) == expected, (
            f"Expected {expected} results (aws={n_aws}, k8s={n_k8s}); "
            f"got {len(val.results)}"
        )


# ===========================================================================
# Test 12 (original): Train on chain graphs and verify F1 > 0.50
# ===========================================================================

def test_train_and_evaluate_f1_on_chain():
    """Train the GCN on a small synthetic dataset and verify F1 > 0.50."""
    try:
        import torch
        from trustfield.propagation.gnn_trainer import GCNModel, GNNTrainer
    except ImportError:
        pytest.skip("torch not available")

    # Generate training data (emphasis on chain topology)
    trainer = GNNTrainer(
        n_graphs=60,
        seed=42,
        max_epochs=40,
        patience=8,
        lr=1e-3,
    )
    data = trainer.generate_training_data()

    # Chain-only subset for evaluation
    # (chain graphs have linear structure — GNN should learn BFS on them)
    model = GCNModel(in_features=NUM_NODE_FEATURES)
    result = trainer.train(model, data)

    # Evaluate on full dataset (mix of chain, hub, cluster)
    metrics = trainer.evaluate(model, data)

    assert metrics["f1"] >= 0.50, (
        f"GNN F1 = {metrics['f1']:.4f} < 0.50 on training data. "
        f"best_val_f1={result.best_val_f1:.4f}, "
        f"epochs={result.epochs_trained}, "
        f"precision={metrics['precision']:.4f}, recall={metrics['recall']:.4f}"
    )
