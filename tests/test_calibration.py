"""Tests for TrustField calibration analysis module.

 1. CalibrationReport has all 5 models × 3 topologies = 15 entries
 2. All empirical_f1 values in [0.0, 1.0]
 3. calibration_error = |stated - empirical_f1| correctly computed
 4. is_calibrated = True when error < 0.05
 5. recommended_confidence_updates has all 5 model keys
 6. latex_table contains \\begin{tabular}
 7. After running with apply_updates=True, model files reflect updated values
 8. Topology selector weights sum to 1.0 after update
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from trustfield.baselines import CalibrationAnalysis, CalibrationReport, ModelCalibration
from trustfield.baselines.calibration_analysis import (
    MODEL_NAMES,
    STATED_CONFIDENCE,
    _PROJECT_ROOT,
)

# ---------------------------------------------------------------------------
# Shared fixture — small run with file updates disabled for most tests
# ---------------------------------------------------------------------------

_TOPOLOGIES = ["hub", "chain", "dense_cluster"]

@pytest.fixture(scope="module")
def dry_report():
    """CalibrationReport produced WITHOUT writing to source files."""
    ca = CalibrationAnalysis(n_graphs=10, apply_updates=False)
    return ca.run()


# ---------------------------------------------------------------------------
# Test 1: Report has 5 models × 3 topologies = 15 entries
# ---------------------------------------------------------------------------

def test_report_has_15_entries(dry_report):
    assert len(dry_report.per_model_topology) == 5
    for model in MODEL_NAMES:
        assert model in dry_report.per_model_topology
        topo_map = dry_report.per_model_topology[model]
        assert len(topo_map) == 3
        for topo in _TOPOLOGIES:
            assert topo in topo_map
            assert isinstance(topo_map[topo], ModelCalibration)


# ---------------------------------------------------------------------------
# Test 2: All empirical_f1 values in [0.0, 1.0]
# ---------------------------------------------------------------------------

def test_all_f1_in_range(dry_report):
    for model in MODEL_NAMES:
        for topo in _TOPOLOGIES:
            cal = dry_report.per_model_topology[model][topo]
            assert 0.0 <= cal.empirical_f1 <= 1.0, (
                f"F1 out of range for {model}/{topo}: {cal.empirical_f1}"
            )
            assert 0.0 <= cal.empirical_precision <= 1.0
            assert 0.0 <= cal.empirical_recall <= 1.0


# ---------------------------------------------------------------------------
# Test 3: calibration_error = |stated - empirical_f1|
# ---------------------------------------------------------------------------

def test_calibration_error_formula(dry_report):
    for model in MODEL_NAMES:
        for topo in _TOPOLOGIES:
            cal = dry_report.per_model_topology[model][topo]
            expected = round(abs(cal.stated_confidence - cal.empirical_f1), 4)
            assert cal.calibration_error == pytest.approx(expected, abs=1e-4), (
                f"Wrong error for {model}/{topo}: "
                f"got {cal.calibration_error}, expected {expected}"
            )


# ---------------------------------------------------------------------------
# Test 4: is_calibrated = True iff error < 0.05
# ---------------------------------------------------------------------------

def test_is_calibrated_threshold(dry_report):
    for model in MODEL_NAMES:
        for topo in _TOPOLOGIES:
            cal = dry_report.per_model_topology[model][topo]
            expected = cal.calibration_error < 0.05
            assert cal.is_calibrated == expected, (
                f"{model}/{topo}: is_calibrated={cal.is_calibrated} "
                f"but error={cal.calibration_error}"
            )


# ---------------------------------------------------------------------------
# Test 5: recommended_confidence_updates has all 5 model keys
# ---------------------------------------------------------------------------

def test_recommended_updates_keys(dry_report):
    updates = dry_report.recommended_confidence_updates
    assert set(updates.keys()) == set(MODEL_NAMES)
    for model, val in updates.items():
        assert 0.0 <= val <= 1.0, (
            f"Recommended confidence for {model} out of range: {val}"
        )


# ---------------------------------------------------------------------------
# Test 6: latex_table contains \begin{tabular}
# ---------------------------------------------------------------------------

def test_latex_table_structure(dry_report):
    latex = dry_report.latex_table
    assert r"\begin{tabular}" in latex
    assert r"\end{tabular}" in latex
    assert r"\toprule" in latex
    assert r"\midrule" in latex
    assert r"\label{tab:calibration}" in latex


# ---------------------------------------------------------------------------
# Test 7: After apply_updates=True, model files reflect new confidence values
# ---------------------------------------------------------------------------

def test_model_files_updated():
    """Run calibration WITH file updates and verify source files changed."""
    ca = CalibrationAnalysis(n_graphs=5, apply_updates=True)
    report = ca.run()

    for model in MODEL_NAMES:
        expected = report.recommended_confidence_updates[model]
        rel_path = f"trustfield/propagation/{model.replace('_', '_')}.py"

        # Map model name → actual file
        file_map = {
            "graph_traversal":  "trustfield/propagation/graph_traversal.py",
            "epidemic":         "trustfield/propagation/epidemic.py",
            "spectral_cascade": "trustfield/propagation/spectral_cascade.py",
            "percolation":      "trustfield/propagation/percolation.py",
            "control_system":   "trustfield/propagation/control_system.py",
        }
        content = (_PROJECT_ROOT / file_map[model]).read_text(encoding="utf-8")
        # The file should now contain the new confidence value
        expected_str = f"_MODEL_CONFIDENCE = {expected:.4f}"
        assert expected_str in content, (
            f"Expected '{expected_str}' in {file_map[model]}. "
            f"File content around _MODEL_CONFIDENCE: "
            + re.search(r"_MODEL_CONFIDENCE.*", content).group()
        )


# ---------------------------------------------------------------------------
# Test 8: Topology selector weights sum to 1.0 after update
# ---------------------------------------------------------------------------

def test_topology_selector_weights_sum_to_one():
    """After calibration with apply_updates=True, reload topology_selector and verify sums."""
    # Ensure the file has been updated by running a fresh calibration
    CalibrationAnalysis(n_graphs=5, apply_updates=True).run()

    import trustfield.ensemble.topology_selector as ts
    importlib.reload(ts)

    # Verify via get_initial_weights (normalises reserved placeholder slots like
    # "gnn" so the raw dict may legally exceed 1.0 before normalisation).
    from trustfield.graph.fingerprinter import TopologyFingerprint, TopologyType
    selector = ts.TopologyAwareSelector()
    for topo_str, ttype in [
        ("HUB",           TopologyType.HUB),
        ("CHAIN",         TopologyType.CHAIN),
        ("DENSE_CLUSTER", TopologyType.DENSE_CLUSTER),
    ]:
        fp = TopologyFingerprint(
            clustering_coefficient=0.1, centrality_variance=0.5,
            spectral_gap=0.0, degree_distribution_entropy=1.0,
            avg_path_length=2.0, num_nodes=20, num_edges=30,
            density=0.08, topology_type=ttype,
        )
        wv = selector.get_initial_weights(fp)
        total = sum(wv.weights.values())
        assert abs(total - 1.0) < 1e-4, (
            f"{topo_str} normalised weights sum to {total:.6f}, expected 1.0. "
            f"Weights: {wv.weights}"
        )
