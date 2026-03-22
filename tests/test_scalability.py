"""Tests for TrustField scalability benchmark (Module 4 empirical study).

 1. Results list length matches node_counts input
 2. All time values > 0
 3. meets_100ms_guard_target correct (guard_deployment_ms < 100)
 4. Total time increases monotonically with N
 5. complexity_estimate is one of O(N), O(N²), O(N^1.5), O(N log N)
 6. latex_table contains all N values from node_counts
"""

from __future__ import annotations

import pytest

from trustfield.baselines import ScalabilityBenchmark, ScalabilityReport


# ---------------------------------------------------------------------------
# Shared fixture: run the benchmark once across the module
# ---------------------------------------------------------------------------

_SMALL_NODE_COUNTS = [10, 20, 40, 80]


@pytest.fixture(scope="module")
def report() -> ScalabilityReport:
    """Small-scale benchmark fixture — fast enough for CI."""
    bench = ScalabilityBenchmark(topology="hub", seed=42)
    return bench.run(
        node_counts=_SMALL_NODE_COUNTS,
        n_runs=1,
        include_gnn=True,
    )


# ---------------------------------------------------------------------------
# 1. Results list length matches node_counts input
# ---------------------------------------------------------------------------

class TestResultsLength:
    def test_length_matches_node_counts(self, report):
        assert len(report.results) == len(_SMALL_NODE_COUNTS)


# ---------------------------------------------------------------------------
# 2. All time values > 0
# ---------------------------------------------------------------------------

class TestAllTimesPositive:
    def test_all_stage_times_positive(self, report):
        for r in report.results:
            assert r.fingerprint_ms > 0, f"fingerprint_ms=0 at N={r.n_nodes}"
            assert r.propagation_ms > 0, f"propagation_ms=0 at N={r.n_nodes}"
            assert r.ensemble_ms > 0, f"ensemble_ms=0 at N={r.n_nodes}"
            assert r.verification_ms > 0, f"verification_ms=0 at N={r.n_nodes}"
            assert r.guard_deployment_ms > 0, f"guard_deployment_ms=0 at N={r.n_nodes}"
            assert r.total_ms > 0, f"total_ms=0 at N={r.n_nodes}"


# ---------------------------------------------------------------------------
# 3. meets_100ms_guard_target correct
# ---------------------------------------------------------------------------

class TestGuardTarget:
    def test_flag_matches_threshold(self, report):
        for r in report.results:
            expected = r.guard_deployment_ms < 100.0
            assert r.meets_100ms_guard_target == expected, (
                f"N={r.n_nodes}: guard_ms={r.guard_deployment_ms:.3f}, "
                f"flag={r.meets_100ms_guard_target}, expected={expected}"
            )


# ---------------------------------------------------------------------------
# 4. Total time increases monotonically with N
# ---------------------------------------------------------------------------

class TestMonotonicTotalTime:
    # Allow up to 2 ms regression between adjacent sizes to tolerate OS
    # scheduling noise on small graphs where timing variance dominates.
    _TOLERANCE_MS = 2.0

    def test_total_time_monotonically_increases(self, report):
        totals = [r.total_ms for r in report.results]
        for i in range(1, len(totals)):
            assert totals[i] >= totals[i - 1] - self._TOLERANCE_MS, (
                f"total_ms not monotone: {totals[i - 1]:.1f} ms at N="
                f"{report.results[i - 1].n_nodes} > {totals[i]:.1f} ms at N="
                f"{report.results[i].n_nodes} (tolerance={self._TOLERANCE_MS} ms)"
            )


# ---------------------------------------------------------------------------
# 5. complexity_estimate is one of the valid labels
# ---------------------------------------------------------------------------

class TestComplexityLabel:
    _VALID = {"O(N)", "O(N²)", "O(N^1.5)", "O(N log N)"}

    def test_label_in_valid_set(self, report):
        assert report.complexity_estimate in self._VALID, (
            f"Unknown complexity label: {report.complexity_estimate!r}"
        )


# ---------------------------------------------------------------------------
# 6. latex_table contains all N values from node_counts
# ---------------------------------------------------------------------------

class TestLatexTableContainsAllN:
    def test_all_n_values_in_latex(self, report):
        for n in _SMALL_NODE_COUNTS:
            # The LaTeX table uses bold \textbf{N.0} or plain N.0
            # Check for the integer value as a string substring
            assert str(n) in report.latex_table, (
                f"N={n} not found in latex_table"
            )
