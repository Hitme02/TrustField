"""Tests for TrustField sensitivity analysis module.

 1. RunRecord: dataclass fields set correctly
 2. SensitivityAnalysis._run_one: returns valid RunRecord for hub
 3. run_seed_sweep: returns one record per seed with correct topology/beta
 4. run_beta_sweep: returns one record per beta value with correct seed
 5. run_seed_sweep: all containment_rate values in [0, 1]
 6. run(): SensitivityResult has stats for both topologies × all metrics
 7. to_markdown(): contains both sweep headings and topology names
 8. to_latex(): produces two LaTeX tabular environments with correct labels
"""

from __future__ import annotations

import pytest

from trustfield.baselines import (
    RunRecord,
    SensitivityAnalysis,
    SensitivityResult,
    SweepStats,
)
from trustfield.baselines.sensitivity_analysis import (
    DEFAULT_SEEDS,
    DEFAULT_BETAS,
    FIXED_BETA,
    FIXED_SEED,
    _METRIC_LABELS,
)


# ---------------------------------------------------------------------------
# Shared fast fixture — small graphs, minimal seeds/betas
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fast_sa():
    """SensitivityAnalysis configured for speed: 2 seeds, 3 betas, 15 nodes."""
    return SensitivityAnalysis(
        num_nodes=15,
        seeds=[42, 123],
        betas=[0.2, 0.5, 0.8],
        fixed_seed=42,
        fixed_beta=0.3,
        topologies=["hub", "chain"],
    )


@pytest.fixture(scope="module")
def fast_result(fast_sa):
    return fast_sa.run()


# ---------------------------------------------------------------------------
# Test 1: RunRecord dataclass
# ---------------------------------------------------------------------------

def test_run_record_fields():
    rec = RunRecord(
        topology="hub",
        seed=42,
        beta=0.3,
        pbr_size=20,
        vbr_size=18,
        gap_fraction=0.12,
        containment_rate=0.95,
        egd_score=0.10,
        elapsed_seconds=0.5,
    )
    assert rec.topology == "hub"
    assert rec.seed == 42
    assert rec.beta == pytest.approx(0.3)
    assert rec.pbr_size == 20
    assert rec.vbr_size == 18
    assert rec.gap_fraction == pytest.approx(0.12)
    assert rec.containment_rate == pytest.approx(0.95)
    assert 0.0 <= rec.egd_score <= 1.0


# ---------------------------------------------------------------------------
# Test 2: _run_one returns a valid RunRecord
# ---------------------------------------------------------------------------

def test_run_one_valid(fast_sa):
    rec = fast_sa._run_one("hub", seed=42, beta=0.3)
    assert isinstance(rec, RunRecord)
    assert rec.topology == "hub"
    assert rec.seed == 42
    assert rec.beta == pytest.approx(0.3)
    assert rec.pbr_size >= 0
    assert rec.vbr_size >= 0
    assert 0.0 <= rec.gap_fraction <= 1.0
    assert 0.0 <= rec.containment_rate <= 1.0
    assert 0.0 <= rec.egd_score <= 1.0
    assert rec.elapsed_seconds >= 0.0


# ---------------------------------------------------------------------------
# Test 3: run_seed_sweep — correct count and fixed beta
# ---------------------------------------------------------------------------

def test_run_seed_sweep_structure(fast_sa):
    records = fast_sa.run_seed_sweep("hub")
    assert len(records) == len(fast_sa._seeds)
    for rec, expected_seed in zip(records, fast_sa._seeds):
        assert rec.topology == "hub"
        assert rec.seed == expected_seed
        assert rec.beta == pytest.approx(fast_sa._fixed_beta)


# ---------------------------------------------------------------------------
# Test 4: run_beta_sweep — correct count and fixed seed
# ---------------------------------------------------------------------------

def test_run_beta_sweep_structure(fast_sa):
    records = fast_sa.run_beta_sweep("chain")
    assert len(records) == len(fast_sa._betas)
    for rec, expected_beta in zip(records, fast_sa._betas):
        assert rec.topology == "chain"
        assert rec.seed == fast_sa._fixed_seed
        assert rec.beta == pytest.approx(expected_beta)


# ---------------------------------------------------------------------------
# Test 5: run_seed_sweep — all containment rates in [0, 1]
# ---------------------------------------------------------------------------

def test_seed_sweep_containment_rates_in_range(fast_sa):
    for topo in ["hub", "chain"]:
        for rec in fast_sa.run_seed_sweep(topo):
            assert 0.0 <= rec.containment_rate <= 1.0, (
                f"containment_rate={rec.containment_rate} out of range "
                f"for {topo} seed={rec.seed}"
            )


# ---------------------------------------------------------------------------
# Test 6: run() — stats populated for both topologies × all metrics
# ---------------------------------------------------------------------------

def test_run_stats_complete(fast_result):
    for topo in ["hub", "chain"]:
        for metric in _METRIC_LABELS:
            assert (topo, metric) in fast_result.seed_stats, (
                f"Missing seed_stats[({topo!r}, {metric!r})]"
            )
            assert (topo, metric) in fast_result.beta_stats, (
                f"Missing beta_stats[({topo!r}, {metric!r})]"
            )
            s = fast_result.seed_stats[(topo, metric)]
            assert isinstance(s, SweepStats)
            assert s.minimum <= s.mean <= s.maximum or len(s.values) == 1


# ---------------------------------------------------------------------------
# Test 7: to_markdown() — contains required headings and topology names
# ---------------------------------------------------------------------------

def test_to_markdown_structure(fast_sa, fast_result):
    md = fast_sa.to_markdown(fast_result)
    assert "Seed Sweep Stability" in md
    assert "Beta Sweep Sensitivity" in md
    assert "hub" in md
    assert "chain" in md
    # Metric labels present
    assert "PBR size" in md
    assert "Containment rate" in md


# ---------------------------------------------------------------------------
# Test 8: to_latex() — two tabular environments, correct labels
# ---------------------------------------------------------------------------

def test_to_latex_structure(fast_sa, fast_result):
    latex = fast_sa.to_latex(fast_result)
    assert latex.count(r"\begin{tabular}") == 2
    assert latex.count(r"\end{tabular}") == 2
    assert r"\label{tab:sensitivity-seeds}" in latex
    assert r"\label{tab:sensitivity-beta}" in latex
    assert r"\caption{Result Stability" in latex
    assert r"\caption{Containment Rate vs Epidemic Beta" in latex
