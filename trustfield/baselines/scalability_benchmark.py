"""Scalability benchmark for TrustField — empirical performance at N=20..1000.

Measures wall-clock time of each pipeline stage independently, averaged over
n_runs repetitions, for a hub topology (DAG structure, best-case traversal
speed).  Published results note:

  * Percolation Monte Carlo uses n_trials=20 throughout (not the default 100)
    to keep N=1000 benchmarks tractable on laptop hardware.
  * topology="hub" is used; chain would be 2-3× slower due to longer paths.
  * GNN inference is included when include_gnn=True (default); GCN forward
    pass scales O(N·E) and is typically fast relative to percolation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from statistics import mean
from typing import List, Optional

import numpy as np

from trustfield.ensemble.ensemble_predictor import EnsemblePredictor, FusionMode
from trustfield.ensemble.topology_selector import TopologyAwareSelector
from trustfield.graph.fingerprinter import TopologyFingerprinter
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.guards.guard_network import GuardNetwork
from trustfield.propagation.runner import PropagationRunner
from trustfield.verification.blast_radius import BlastRadiusCalculator
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ScalabilityResult:
    """Timing breakdown for one graph size N (mean over n_runs).

    Attributes:
        n_nodes: Requested node count passed to IAMSimulator.
        n_edges: Actual edge count of the generated graph.
        fingerprint_ms: Time for TopologyFingerprinter.fingerprint().
        propagation_ms: Time for PropagationRunner.run_all() (all 6 models).
        ensemble_ms: Time for weight selection + EnsemblePredictor.predict().
        verification_ms: Time for IAMTraversal + BlastRadiusCalculator.
        guard_deployment_ms: Time for GuardNetwork.get_high_risk_edges()
            + deploy_guards() (top-10 edges, 3 guards each).
        total_ms: Sum of all five stage timings.
        meets_100ms_guard_target: ``guard_deployment_ms < 100``.
    """

    n_nodes: int
    n_edges: int
    fingerprint_ms: float
    propagation_ms: float
    ensemble_ms: float
    verification_ms: float
    guard_deployment_ms: float
    total_ms: float
    meets_100ms_guard_target: bool


@dataclass
class ScalabilityReport:
    """Full scalability study output.

    Attributes:
        results: One :class:`ScalabilityResult` per node count.
        complexity_estimate: Empirical big-O label derived from
            ``polyfit(log N, log total_ms)``.
            One of ``"O(N)"``, ``"O(N log N)"``, ``"O(N^1.5)"``, ``"O(N²)"``.
        max_n_under_1s: Largest N whose ``total_ms`` is below 1 000 ms.
        max_n_under_5s: Largest N whose ``total_ms`` is below 5 000 ms.
        bottleneck_stage: Stage name with the highest mean time across all N.
        latex_table: Booktabs LaTeX table; rows exceeding 1 s are bold.
        notes: Implementation notes recorded at benchmark time.
    """

    results: List[ScalabilityResult]
    complexity_estimate: str
    max_n_under_1s: int
    max_n_under_5s: int
    bottleneck_stage: str
    latex_table: str
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

# Percolation trials: kept low for benchmark tractability (see module docstring)
_BENCH_N_TRIALS = 20
_TOP_K_GUARDS = 10
_TRAVERSAL_MAX_DEPTH = 8

_COMPLEXITY_LABELS = ["O(N)", "O(N log N)", "O(N^1.5)", "O(N²)"]


class ScalabilityBenchmark:
    """Empirical scalability study across a sweep of graph sizes.

    Example::

        bench = ScalabilityBenchmark()
        report = bench.run()
        print(report.complexity_estimate)
        print(report.latex_table)

    Args:
        topology: IAMSimulator topology to use. Defaults to ``"hub"``.
        seed: Random seed for graph generation. Defaults to ``42``.
    """

    def __init__(self, topology: str = "hub", seed: int = 42) -> None:
        self._topology = topology
        self._seed = seed
        self._sim = IAMSimulator()
        self._fingerprinter = TopologyFingerprinter()
        self._runner = PropagationRunner()
        self._selector = TopologyAwareSelector()
        self._predictor = EnsemblePredictor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        node_counts: Optional[List[int]] = None,
        topology: Optional[str] = None,
        n_runs: int = 3,
        include_gnn: bool = True,
    ) -> ScalabilityReport:
        """Benchmark TrustField pipeline across a sweep of graph sizes.

        Args:
            node_counts: List of N values to benchmark.
                Defaults to ``[20, 50, 100, 200, 500, 1000]``.
            topology: Override the topology set at construction time.
            n_runs: Number of timed repetitions per N (mean is reported).
            include_gnn: Whether the GNN model is included in propagation.
                Currently all six models always run; this flag is recorded
                in the report notes for documentation purposes.

        Returns:
            A fully-populated :class:`ScalabilityReport`.
        """
        if node_counts is None:
            node_counts = [20, 50, 100, 200, 500, 1000]
        if topology is not None:
            self._topology = topology

        notes: List[str] = [
            f"topology={self._topology} (hub=DAG, gives best-case traversal speed)",
            f"percolation n_trials={_BENCH_N_TRIALS} (reduced from default for benchmark tractability)",
            f"guard deployment: top-{_TOP_K_GUARDS} edges, 3 guards each",
            f"GNN included: {include_gnn}",
            f"n_runs={n_runs} (mean reported)",
        ]

        # Warm-up: one untimed pass to initialise torch, networkx caches, etc.
        self._benchmark_n(node_counts[0], n_runs=1)

        results: List[ScalabilityResult] = []
        for n in node_counts:
            result = self._benchmark_n(n, n_runs)
            results.append(result)

        complexity = _estimate_complexity(results)
        max_1s = _max_n_under_threshold(results, 1_000.0)
        max_5s = _max_n_under_threshold(results, 5_000.0)
        bottleneck = _find_bottleneck(results)
        latex = _build_latex_table(results)

        return ScalabilityReport(
            results=results,
            complexity_estimate=complexity,
            max_n_under_1s=max_1s,
            max_n_under_5s=max_5s,
            bottleneck_stage=bottleneck,
            latex_table=latex,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _benchmark_n(self, n_nodes: int, n_runs: int) -> ScalabilityResult:
        """Time all pipeline stages for graph size N, averaged over n_runs."""
        # Build graph once (graph generation is not part of the timed pipeline)
        graph = self._sim.generate(self._topology, num_nodes=n_nodes, seed=self._seed)
        node_list = sorted(graph._graph.nodes())
        seed_nodes = [node_list[0]]
        n_edges = graph._graph.number_of_edges()

        fp_times, prop_times, ens_times, ver_times, guard_times = [], [], [], [], []

        for _ in range(n_runs):
            # Stage 1: Fingerprinting
            t0 = time.perf_counter()
            fingerprint = self._fingerprinter.fingerprint(graph)
            fp_times.append((time.perf_counter() - t0) * 1000.0)

            # Stage 2: Propagation (all models, reduced percolation trials)
            t0 = time.perf_counter()
            prop_results = self._runner.run_all(
                graph, seed_nodes,
                percolation={"n_trials": _BENCH_N_TRIALS},
            )
            prop_times.append((time.perf_counter() - t0) * 1000.0)

            # Stage 3: Ensemble (weight selection + prediction)
            t0 = time.perf_counter()
            weight_vector = self._selector.get_initial_weights(fingerprint)
            prediction = self._predictor.predict(
                prop_results, weight_vector, FusionMode.WEIGHTED
            )
            ens_times.append((time.perf_counter() - t0) * 1000.0)

            # Stage 4: Verification (IAMTraversal + BlastRadiusCalculator)
            t0 = time.perf_counter()
            tgen = TokenGenerator()
            traversal = IAMTraversal(tgen).traverse(
                graph, seed_nodes,
                max_depth=_TRAVERSAL_MAX_DEPTH,
                respect_conditions=False,
            )
            bra = BlastRadiusCalculator().compute(prediction, traversal, graph)
            ver_times.append((time.perf_counter() - t0) * 1000.0)

            # Stage 5: Guard deployment (high-risk edge selection + deploy)
            t0 = time.perf_counter()
            guard_net = GuardNetwork(graph, tgen)
            top_k = min(_TOP_K_GUARDS, n_edges)
            high_risk_edges = guard_net.get_high_risk_edges(bra, top_k=top_k)
            guard_net.deploy_guards(high_risk_edges, guards_per_edge=3)
            guard_times.append((time.perf_counter() - t0) * 1000.0)

        fp_ms = mean(fp_times)
        prop_ms = mean(prop_times)
        ens_ms = mean(ens_times)
        ver_ms = mean(ver_times)
        guard_ms = mean(guard_times)
        total_ms = fp_ms + prop_ms + ens_ms + ver_ms + guard_ms

        return ScalabilityResult(
            n_nodes=n_nodes,
            n_edges=n_edges,
            fingerprint_ms=round(fp_ms, 3),
            propagation_ms=round(prop_ms, 3),
            ensemble_ms=round(ens_ms, 3),
            verification_ms=round(ver_ms, 3),
            guard_deployment_ms=round(guard_ms, 3),
            total_ms=round(total_ms, 3),
            meets_100ms_guard_target=guard_ms < 100.0,
        )


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


def _estimate_complexity(results: List[ScalabilityResult]) -> str:
    """Fit log(total_ms) ~ slope * log(N) and map slope to a big-O label."""
    if len(results) < 2:
        return "O(N)"
    n_vals = np.array([r.n_nodes for r in results], dtype=float)
    t_vals = np.array([max(r.total_ms, 0.001) for r in results], dtype=float)
    # Filter out any zero times (can happen at tiny N)
    valid = t_vals > 0
    if valid.sum() < 2:
        return "O(N)"
    slope, _ = np.polyfit(np.log(n_vals[valid]), np.log(t_vals[valid]), 1)
    if slope < 1.1:
        return "O(N)"
    elif slope < 1.25:
        return "O(N log N)"
    elif slope < 1.75:
        return "O(N^1.5)"
    else:
        return "O(N²)"


def _max_n_under_threshold(results: List[ScalabilityResult], threshold_ms: float) -> int:
    """Return the largest N whose total_ms is below the threshold."""
    eligible = [r.n_nodes for r in results if r.total_ms < threshold_ms]
    return max(eligible) if eligible else 0


def _find_bottleneck(results: List[ScalabilityResult]) -> str:
    """Return the stage name with the highest mean time across all N."""
    stages = {
        "propagation":    mean(r.propagation_ms    for r in results),
        "verification":   mean(r.verification_ms   for r in results),
        "guard_deploy":   mean(r.guard_deployment_ms for r in results),
        "ensemble":       mean(r.ensemble_ms        for r in results),
        "fingerprint":    mean(r.fingerprint_ms     for r in results),
    }
    return max(stages, key=lambda s: stages[s])


# ---------------------------------------------------------------------------
# LaTeX table builder
# ---------------------------------------------------------------------------


def _build_latex_table(results: List[ScalabilityResult]) -> str:
    rows = []
    for r in results:
        bold = r.total_ms > 1000.0
        guard_mark = r"$\checkmark$" if r.meets_100ms_guard_target else r"$\times$"

        def fmt(v: float) -> str:
            s = f"{v:.1f}"
            return rf"\textbf{{{s}}}" if bold else s

        rows.append(
            f"  {fmt(r.n_nodes)} & {r.n_edges} & "
            f"{fmt(r.fingerprint_ms)} & {fmt(r.propagation_ms)} & "
            f"{fmt(r.ensemble_ms)} & {fmt(r.verification_ms)} & "
            f"{fmt(r.guard_deployment_ms)} & {fmt(r.total_ms)} & "
            f"{guard_mark} \\\\"
        )
    body = "\n".join(rows)
    return (
        r"\begin{table}[ht]" "\n"
        r"\centering" "\n"
        r"\caption{TrustField Scalability Benchmark (hub topology, "
        r"percolation $n_{\text{trials}}=20$)}" "\n"
        r"\label{tab:scalability}" "\n"
        r"\begin{tabular}{rrccccccc}" "\n"
        r"\toprule" "\n"
        r"$N$ & $|E|$ & FP (ms) & Prop (ms) & Ens (ms) & "
        r"Ver (ms) & Guard (ms) & Total (ms) & $<$100ms \\" "\n"
        r"\midrule" "\n"
        + body + "\n"
        r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}"
    )
