"""Tests for TrustField baseline comparison module.

 1. BaselineResult: dataclass fields are set correctly
 2. ComparisonResult.all_methods(): returns all 4 entries
 3. NaiveBFSBaseline: containment_success_rate in [0, 1]
 4. NaiveBFSBaseline: guards_deployed <= top_k
 5. SingleBestModelBaseline: selects correct model per topology type
 6. SingleBestModelBaseline: containment_success_rate in [0, 1]
 7. RandomGuardBaseline: guards_deployed == trustfield_guard_count
 8. RandomGuardBaseline: containment_success_rate in [0, 1]
 9. BaselineComparison.run_one_topology(): returns ComparisonResult with all 4 methods
10. BaselineComparison: all methods share the same original_vbr ground truth
11. BaselineComparison.to_markdown(): contains all 4 topology labels
12. BaselineComparison.to_latex(): produces two LaTeX tabular environments
"""

from __future__ import annotations

import pytest

from trustfield.baselines import (
    BaselineComparison,
    BaselineResult,
    BFSGuardBaseline,
    ComparisonResult,
    NaiveBFSBaseline,
    RandomGuardBaseline,
    SingleBestModelBaseline,
)
from trustfield.baselines.baseline_comparison import (
    _BEST_MODEL_FOR_TOPOLOGY,
    _seed_node,
)
from trustfield.graph.iam_simulator import IAMSimulator


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def small_hub():
    """Small hub graph (15 nodes) for fast tests."""
    return IAMSimulator().generate("hub", num_nodes=15, seed=7)


@pytest.fixture(scope="module")
def small_chain():
    return IAMSimulator().generate("chain", num_nodes=15, seed=7)


@pytest.fixture(scope="module")
def small_dense():
    return IAMSimulator().generate("dense_cluster", num_nodes=15, seed=7)


@pytest.fixture(scope="module")
def hub_seed(small_hub):
    return [_seed_node(small_hub)]


@pytest.fixture(scope="module")
def chain_seed(small_chain):
    return [_seed_node(small_chain)]


# ---------------------------------------------------------------------------
# Test 1: BaselineResult dataclass
# ---------------------------------------------------------------------------

def test_baseline_result_fields():
    br = BaselineResult(
        method="Test",
        topology="hub",
        original_vbr=10,
        post_vbr=3,
        containment_success_rate=0.70,
        missed_containments=3,
        guards_deployed=5,
        final_strictness="ELEVATED",
        elapsed_seconds=1.23,
    )
    assert br.method == "Test"
    assert br.topology == "hub"
    assert br.original_vbr == 10
    assert br.post_vbr == 3
    assert br.guards_deployed == 5
    assert br.final_strictness == "ELEVATED"
    assert br.elapsed_seconds == pytest.approx(1.23)


# ---------------------------------------------------------------------------
# Test 2: ComparisonResult.all_methods()
# ---------------------------------------------------------------------------

def test_comparison_result_all_methods():
    dummy = BaselineResult("x", "hub", 5, 1, 0.8, 1, 3, "NOMINAL")
    cr = ComparisonResult(
        topology="hub",
        trustfield=dummy,
        naive_bfs=dummy,
        single_model=dummy,
        random_guards=dummy,
    )
    methods = cr.all_methods()
    assert len(methods) == 4
    labels = [m[0] for m in methods]
    assert "TrustField" in labels
    assert "Naive BFS" in labels
    assert "Single Model" in labels
    assert "Random Guards" in labels


# ---------------------------------------------------------------------------
# Test 3: NaiveBFSBaseline — containment rate in [0, 1]
# ---------------------------------------------------------------------------

def test_naive_bfs_rate_in_range(small_hub, hub_seed):
    bl = NaiveBFSBaseline(top_k=10, n_feedback_cycles=2, guards_per_edge=1)
    result = bl.run(small_hub, hub_seed, topology="hub")
    assert 0.0 <= result.containment_success_rate <= 1.0
    assert result.method == "Naive BFS"
    assert result.topology == "hub"


# ---------------------------------------------------------------------------
# Test 4: NaiveBFSBaseline — guards_deployed <= top_k
# ---------------------------------------------------------------------------

def test_naive_bfs_guard_count(small_hub, hub_seed):
    top_k = 8
    bl = NaiveBFSBaseline(top_k=top_k, n_feedback_cycles=1, guards_per_edge=1)
    result = bl.run(small_hub, hub_seed, topology="hub")
    assert result.guards_deployed <= top_k


# ---------------------------------------------------------------------------
# Test 5: SingleBestModelBaseline — correct model per topology
# ---------------------------------------------------------------------------

def test_single_best_model_mapping():
    bl = SingleBestModelBaseline()
    mapping = bl.best_model_for
    assert mapping["HUB"] == "spectral_cascade"
    assert mapping["CHAIN"] == "epidemic"
    assert mapping["DENSE_CLUSTER"] == "percolation"
    assert mapping["MIXED"] == "percolation"
    # Verify module-level constant matches
    assert mapping == _BEST_MODEL_FOR_TOPOLOGY


# ---------------------------------------------------------------------------
# Test 6: SingleBestModelBaseline — containment rate in [0, 1]
# ---------------------------------------------------------------------------

def test_single_best_model_rate_in_range(small_chain, chain_seed):
    bl = SingleBestModelBaseline(top_k=10, n_feedback_cycles=2, guards_per_edge=1)
    result = bl.run(small_chain, chain_seed, topology="chain")
    assert 0.0 <= result.containment_success_rate <= 1.0
    assert result.method == "Single Model"


# ---------------------------------------------------------------------------
# Test 7: RandomGuardBaseline — guard count matches trustfield_guard_count
# ---------------------------------------------------------------------------

def test_random_guard_count(small_hub, hub_seed):
    bl = RandomGuardBaseline(n_feedback_cycles=1, guards_per_edge=1, random_seed=99)
    budget = 7
    result = bl.run(
        small_hub, hub_seed, topology="hub",
        trustfield_guard_count=budget,
    )
    # Can be less than budget if graph has fewer edges
    n_edges = small_hub._graph.number_of_edges()
    assert result.guards_deployed == min(budget, n_edges)


# ---------------------------------------------------------------------------
# Test 8: RandomGuardBaseline — containment rate in [0, 1]
# ---------------------------------------------------------------------------

def test_random_guard_rate_in_range(small_dense):
    seed = [_seed_node(small_dense)]
    bl = RandomGuardBaseline(n_feedback_cycles=1, guards_per_edge=1)
    result = bl.run(small_dense, seed, topology="dense_cluster")
    assert 0.0 <= result.containment_success_rate <= 1.0
    assert result.method == "Random Guards"


# ---------------------------------------------------------------------------
# Test 9: BaselineComparison.run_one_topology() — all 4 methods present
# ---------------------------------------------------------------------------

def test_run_one_topology_returns_all_methods(small_hub, hub_seed):
    cmp = BaselineComparison(top_k=8, n_feedback_cycles=1, guards_per_edge=1)
    cr = cmp.run_one_topology(small_hub, hub_seed, "hub")
    assert isinstance(cr, ComparisonResult)
    assert cr.topology == "hub"
    assert isinstance(cr.trustfield, BaselineResult)
    assert isinstance(cr.naive_bfs, BaselineResult)
    assert isinstance(cr.single_model, BaselineResult)
    assert isinstance(cr.random_guards, BaselineResult)


# ---------------------------------------------------------------------------
# Test 10: Shared original_vbr — all methods report the same original_vbr
# ---------------------------------------------------------------------------

def test_shared_original_vbr(small_hub, hub_seed):
    cmp = BaselineComparison(top_k=8, n_feedback_cycles=1, guards_per_edge=1)
    cr = cmp.run_one_topology(small_hub, hub_seed, "hub")
    orig = cr.trustfield.original_vbr
    assert cr.naive_bfs.original_vbr == orig
    assert cr.single_model.original_vbr == orig
    assert cr.random_guards.original_vbr == orig


# ---------------------------------------------------------------------------
# Test 11: to_markdown() — contains all topology labels
# ---------------------------------------------------------------------------

def test_to_markdown_contains_topologies(small_hub, hub_seed):
    cmp = BaselineComparison(top_k=8, n_feedback_cycles=1, guards_per_edge=1)
    results = {"hub": cmp.run_one_topology(small_hub, hub_seed, "hub")}
    md = cmp.to_markdown(results)
    assert "Hub" in md
    assert "Naive BFS" in md
    assert "TrustField" in md
    assert "Random Guards" in md
    assert "Guards Deployed" in md


# ---------------------------------------------------------------------------
# Test 12: to_latex() — produces two LaTeX tabular environments
# ---------------------------------------------------------------------------

def test_to_latex_two_tables(small_hub, hub_seed):
    cmp = BaselineComparison(top_k=8, n_feedback_cycles=1, guards_per_edge=1)
    results = {"hub": cmp.run_one_topology(small_hub, hub_seed, "hub")}
    latex = cmp.to_latex(results)
    assert latex.count(r"\begin{tabular}") == 2
    assert latex.count(r"\end{tabular}") == 2
    assert r"\caption{Containment Success Rate" in latex
    assert r"\caption{Guards Deployed" in latex
    assert r"\label{tab:baselines}" in latex


# ---------------------------------------------------------------------------
# Test 13: BFSGuardBaseline — containment_rate in [0, 1]
# ---------------------------------------------------------------------------

def test_bfs_guard_containment_rate_in_range(small_hub, hub_seed):
    bl = BFSGuardBaseline(top_k=10, n_feedback_cycles=1, guards_per_edge=1)
    result = bl.run(small_hub, hub_seed, topology="hub")
    assert 0.0 <= result.containment_success_rate <= 1.0, (
        f"containment_success_rate {result.containment_success_rate} out of [0,1]"
    )
    assert result.method == "BFS+Guards"


# ---------------------------------------------------------------------------
# Test 14: BFSGuardBaseline — bfs_reachable_size >= verified_reachable_size
# ---------------------------------------------------------------------------

def test_bfs_reachable_gte_verified(small_hub, hub_seed):
    bl = BFSGuardBaseline(top_k=10, n_feedback_cycles=1, guards_per_edge=1)
    result = bl.run(small_hub, hub_seed, topology="hub")
    assert result.bfs_reachable_size >= result.verified_reachable_size, (
        f"BFS reachable ({result.bfs_reachable_size}) < verified "
        f"({result.verified_reachable_size}); BFS must be >= VBR"
    )


# ---------------------------------------------------------------------------
# Test 15: BFSGuardBaseline — false_positive_rate in [0, 1]
# ---------------------------------------------------------------------------

def test_bfs_guard_false_positive_rate_in_range(small_chain, chain_seed):
    bl = BFSGuardBaseline(top_k=8, n_feedback_cycles=1, guards_per_edge=1)
    result = bl.run(small_chain, chain_seed, topology="chain")
    assert 0.0 <= result.false_positive_rate <= 1.0, (
        f"false_positive_rate {result.false_positive_rate} out of [0,1]"
    )


# ---------------------------------------------------------------------------
# Test 16: BFSGuardBaseline — false_positive_edges <= top_k
# ---------------------------------------------------------------------------

def test_bfs_guard_false_positive_edges_bounded(small_hub, hub_seed):
    top_k = 10
    bl = BFSGuardBaseline(top_k=top_k, n_feedback_cycles=1, guards_per_edge=1)
    result = bl.run(small_hub, hub_seed, topology="hub")
    # false_positive_edges = fp_rate * guards_deployed (both capped by top_k)
    fp_edges = round(result.false_positive_rate * result.guards_deployed)
    assert fp_edges <= top_k, (
        f"false_positive_edges estimate {fp_edges} exceeds top_k {top_k}"
    )
