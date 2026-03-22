"""Sensitivity analysis for TrustField paper reproducibility claims.

Runs the full TrustField pipeline (M1–M5) across two sweep dimensions:

  1. Random seeds — tests result stability across different graph instantiations
     and traversal stochasticity.  Five seeds: [42, 123, 456, 789, 1000].
     Fixed beta = 0.3 (epidemic model default).

  2. Beta values — tests sensitivity of containment to the epidemic spread
     parameter.  Nine values: [0.1, 0.2, …, 0.9].
     Fixed seed = 42.

Only hub and chain topologies are swept (the two structural extremes: maximum
fan-out vs. maximum depth), keeping runtime tractable.

Key metrics recorded per run:
  pbr_size          — predicted blast radius node count
  vbr_size          — verified blast radius node count
  gap_fraction      — |PBR Δ VBR| / |PBR ∪ VBR|
  containment_rate  — fraction of original VBR nodes contained
  egd_score         — exploitability gap distance (1 − Jaccard(PBR, VBR))

Usage::

    from trustfield.baselines.sensitivity_analysis import SensitivityAnalysis
    sa = SensitivityAnalysis(num_nodes=50)
    results = sa.run()
    print(sa.to_latex(results))
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.guards.containment_engine import ContainmentEngine
from trustfield.verification.blast_radius import BlastRadiusCalculator
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal
from trustfield.verification.verification_report import VerificationReport

# ---------------------------------------------------------------------------
# Default sweep parameters
# ---------------------------------------------------------------------------

DEFAULT_SEEDS = [42, 123, 456, 789, 1000]
DEFAULT_BETAS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
FIXED_SEED = 42
FIXED_BETA = 0.3
SWEEP_TOPOLOGIES = ["hub", "chain"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RunRecord:
    """Metrics from a single full-pipeline run.

    Attributes:
        topology:         Topology label (``"hub"`` or ``"chain"``).
        seed:             Random seed used for graph generation and traversal.
        beta:             Epidemic model beta value.
        pbr_size:         Predicted blast radius node count.
        vbr_size:         Verified blast radius node count.
        gap_fraction:     |PBR Δ VBR| / |PBR ∪ VBR| — 0 means perfect agreement.
        containment_rate: Fraction of VBR nodes successfully contained.
        egd_score:        Exploitability gap distance (1 − Jaccard).
        elapsed_seconds:  Wall-clock time for this run.
    """

    topology: str
    seed: int
    beta: float
    pbr_size: int
    vbr_size: int
    gap_fraction: float
    containment_rate: float
    egd_score: float
    elapsed_seconds: float = 0.0


@dataclass
class SweepStats:
    """Descriptive statistics across a sweep dimension.

    Attributes:
        metric:  Human-readable metric name.
        context: Sweep context label (e.g. ``"hub / seed sweep"``).
        mean:    Arithmetic mean.
        std:     Population standard deviation.
        minimum: Minimum observed value.
        maximum: Maximum observed value.
        values:  All observed values (in sweep order).
    """

    metric: str
    context: str
    mean: float
    std: float
    minimum: float
    maximum: float
    values: List[float] = field(default_factory=list)


@dataclass
class SensitivityResult:
    """All sweep results for both topologies.

    Attributes:
        seed_records:   One RunRecord per (topology × seed) at fixed beta.
        beta_records:   One RunRecord per (topology × beta) at fixed seed.
        seed_stats:     SweepStats for the seed sweep, per (topology, metric).
        beta_stats:     SweepStats for the beta sweep, per (topology, metric).
    """

    seed_records: List[RunRecord] = field(default_factory=list)
    beta_records: List[RunRecord] = field(default_factory=list)
    seed_stats: Dict[Tuple[str, str], SweepStats] = field(default_factory=dict)
    beta_stats: Dict[Tuple[str, str], SweepStats] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_METRIC_LABELS = {
    "pbr_size":         "PBR size",
    "vbr_size":         "VBR size",
    "gap_fraction":     "Gap fraction",
    "containment_rate": "Containment rate",
    "egd_score":        "EGD score",
}


def _get_metric(rec: RunRecord, metric: str) -> float:
    return getattr(rec, metric)


def _compute_stats(
    records: List[RunRecord],
    topology: str,
    metric: str,
    context: str,
) -> SweepStats:
    vals = [_get_metric(r, metric) for r in records if r.topology == topology]
    if not vals:
        return SweepStats(metric, context, 0.0, 0.0, 0.0, 0.0, [])
    mean = statistics.mean(vals)
    std = statistics.pstdev(vals)
    return SweepStats(
        metric=_METRIC_LABELS.get(metric, metric),
        context=context,
        mean=mean,
        std=std,
        minimum=min(vals),
        maximum=max(vals),
        values=vals,
    )


def _run_pipeline(
    graph: TrustGraph,
    seed_nodes: List[str],
    beta: float,
    random_seed: int,
) -> Tuple[int, int, float, float, float]:
    """Run M1–M5 and return (pbr_size, vbr_size, gap_fraction, containment_rate, egd_score)."""
    orch = TrustFieldOrchestrator(db_path=":memory:")
    analysis = orch.analyze(
        graph,
        seed_nodes=seed_nodes,
        model_kwargs={"epidemic": {"beta": beta}},
    )
    pred = analysis.ensemble_prediction

    token_gen = TokenGenerator()
    traversal = IAMTraversal(token_gen).traverse(
        graph,
        seed_nodes,
        max_depth=6,
        respect_conditions=True,
        random_seed=random_seed,
    )
    bra = BlastRadiusCalculator().compute(pred, traversal, graph)
    report = VerificationReport(
        graph=graph,
        analysis_result=analysis,
        traversal_result=traversal,
        blast_radius_analysis=bra,
    )

    engine = ContainmentEngine(orch, token_generator=TokenGenerator())
    cr = engine.execute(graph, seed_nodes, report, n_feedback_cycles=5)

    gap_fraction = bra.gap_fraction
    egd = bra.exploitability_gap_score
    containment_rate = cr.containment_success_rate

    return bra.pbr_size, bra.vbr_size, gap_fraction, containment_rate, egd


def _seed_node(graph: TrustGraph) -> str:
    node_list = sorted(graph._graph.nodes())
    return next(
        (n for n in node_list if graph._graph.out_degree(n) > 0),
        node_list[0],
    )


# ---------------------------------------------------------------------------
# SensitivityAnalysis
# ---------------------------------------------------------------------------

class SensitivityAnalysis:
    """Run TrustField sensitivity sweeps and report stability statistics.

    Args:
        num_nodes:    Nodes per generated graph (default 50).
        seeds:        List of random seeds for the seed sweep.
        betas:        List of beta values for the epidemic sensitivity sweep.
        fixed_seed:   Seed held constant during the beta sweep.
        fixed_beta:   Beta held constant during the seed sweep.
        topologies:   Topologies to sweep (default: hub and chain).

    Example::

        sa = SensitivityAnalysis(num_nodes=50)
        result = sa.run()
        print(sa.to_latex(result))
    """

    def __init__(
        self,
        num_nodes: int = 50,
        seeds: Optional[List[int]] = None,
        betas: Optional[List[float]] = None,
        fixed_seed: int = FIXED_SEED,
        fixed_beta: float = FIXED_BETA,
        topologies: Optional[List[str]] = None,
    ) -> None:
        self._num_nodes = num_nodes
        self._seeds = seeds if seeds is not None else DEFAULT_SEEDS
        self._betas = betas if betas is not None else DEFAULT_BETAS
        self._fixed_seed = fixed_seed
        self._fixed_beta = fixed_beta
        self._topologies = topologies if topologies is not None else SWEEP_TOPOLOGIES
        self._sim = IAMSimulator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> SensitivityResult:
        """Run both sweeps on all topologies.

        Returns:
            :class:`SensitivityResult` containing all records and stats.
        """
        result = SensitivityResult()

        # ── Seed sweep (fixed beta) ──────────────────────────────────────
        for topo in self._topologies:
            for seed in self._seeds:
                rec = self._run_one(topo, seed=seed, beta=self._fixed_beta)
                result.seed_records.append(rec)

        # ── Beta sweep (fixed seed) ──────────────────────────────────────
        for topo in self._topologies:
            for beta in self._betas:
                rec = self._run_one(topo, seed=self._fixed_seed, beta=beta)
                result.beta_records.append(rec)

        # ── Compute statistics ──────────────────────────────────────────
        for topo in self._topologies:
            for metric in _METRIC_LABELS:
                result.seed_stats[(topo, metric)] = _compute_stats(
                    result.seed_records, topo, metric,
                    f"{topo} / seed sweep (beta={self._fixed_beta})",
                )
                result.beta_stats[(topo, metric)] = _compute_stats(
                    result.beta_records, topo, metric,
                    f"{topo} / beta sweep (seed={self._fixed_seed})",
                )

        return result

    def run_seed_sweep(self, topology: str) -> List[RunRecord]:
        """Run only the seed sweep for one topology.

        Args:
            topology: ``"hub"`` or ``"chain"``.

        Returns:
            List of :class:`RunRecord`, one per seed.
        """
        return [self._run_one(topology, seed=s, beta=self._fixed_beta) for s in self._seeds]

    def run_beta_sweep(self, topology: str) -> List[RunRecord]:
        """Run only the beta sweep for one topology.

        Args:
            topology: ``"hub"`` or ``"chain"``.

        Returns:
            List of :class:`RunRecord`, one per beta value.
        """
        return [self._run_one(topology, seed=self._fixed_seed, beta=b) for b in self._betas]

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------

    def to_markdown(self, result: SensitivityResult) -> str:
        """Render stability tables as Markdown.

        Produces two sections:
          * Seed sweep stability (fixed beta)
          * Beta sweep sensitivity (fixed seed)

        Args:
            result: Output of :meth:`run`.

        Returns:
            Multi-section Markdown string.
        """
        lines = [
            f"## Seed Sweep Stability  (beta = {self._fixed_beta}, "
            f"seeds = {self._seeds})\n"
        ]
        lines.append("| Metric | Topology | Mean | Std | Min | Max |")
        lines.append("|--------|----------|------|-----|-----|-----|")
        for topo in self._topologies:
            for metric, label in _METRIC_LABELS.items():
                s = result.seed_stats.get((topo, metric))
                if s is None:
                    continue
                fmt = _fmt_metric(metric)
                lines.append(
                    f"| {label} | {topo} "
                    f"| {fmt(s.mean)} | {fmt(s.std)} "
                    f"| {fmt(s.minimum)} | {fmt(s.maximum)} |"
                )

        lines.append(
            f"\n## Beta Sweep Sensitivity  (seed = {self._fixed_seed}, "
            f"betas = {self._betas})\n"
        )
        lines.append("| Beta | Topology | PBR | VBR | Gap | Containment | EGD |")
        lines.append("|------|----------|-----|-----|-----|-------------|-----|")
        for topo in self._topologies:
            for rec in result.beta_records:
                if rec.topology != topo:
                    continue
                lines.append(
                    f"| {rec.beta:.1f} | {topo} "
                    f"| {rec.pbr_size} | {rec.vbr_size} "
                    f"| {rec.gap_fraction:.3f} "
                    f"| {rec.containment_rate:.1%} "
                    f"| {rec.egd_score:.3f} |"
                )

        return "\n".join(lines)

    def to_latex(self, result: SensitivityResult) -> str:
        r"""Render the stability statistics as a LaTeX table.

        Produces two tables:
          * Table A: seed sweep stability — mean ± std for each metric
          * Table B: beta sweep — containment rate vs beta

        Args:
            result: Output of :meth:`run`.

        Returns:
            LaTeX source string ready for direct paper inclusion.
        """
        # ── Table A: seed sweep stability ────────────────────────────────
        rows_a = []
        for topo in self._topologies:
            topo_label = topo.title()
            for metric, label in _METRIC_LABELS.items():
                s = result.seed_stats.get((topo, metric))
                if s is None:
                    continue
                fmt = _fmt_metric(metric)
                row_label = f"{label} ({topo_label})"
                # Bold row if std is very low (< 5% of mean) — marks stable metrics
                stable = s.std <= 0.05 * abs(s.mean) + 1e-9
                mean_str = fmt(s.mean)
                std_str = fmt(s.std)
                min_str = fmt(s.minimum)
                max_str = fmt(s.maximum)
                if stable:
                    mean_str = r"\textbf{" + mean_str + "}"
                rows_a.append(
                    f"{row_label} & {mean_str} & {std_str} & {min_str} & {max_str} \\\\"
                )

        body_a = "\n".join(rows_a)

        # ── Table B: beta sweep — containment rate ───────────────────────
        rows_b: Dict[float, Dict[str, str]] = {}
        for rec in result.beta_records:
            rows_b.setdefault(rec.beta, {})[rec.topology] = f"{rec.containment_rate:.1%}"

        body_b_lines = []
        for beta in self._betas:
            cells = rows_b.get(beta, {})
            parts = [f"{beta:.1f}"]
            for topo in self._topologies:
                parts.append(cells.get(topo, "--"))
            body_b_lines.append(" & ".join(parts) + " \\\\")
        body_b = "\n".join(body_b_lines)

        topo_cols = " & ".join(t.title() for t in self._topologies)

        return (
            "% === TrustField Sensitivity Analysis — Auto-Generated ===\n\n"
            r"\begin{table}[h]" + "\n"
            r"\centering" + "\n"
            r"\caption{Result Stability Across Random Seeds"
            r" (TrustField, $\beta=" + f"{self._fixed_beta}" + r"$)}" + "\n"
            r"\label{tab:sensitivity-seeds}" + "\n"
            r"\begin{tabular}{lrrrr}" + "\n"
            r"\hline" + "\n"
            r"Metric & Mean & Std & Min & Max \\" + "\n"
            r"\hline" + "\n"
            + body_a + "\n"
            r"\hline" + "\n"
            r"\end{tabular}" + "\n"
            r"\end{table}" + "\n\n"
            r"\begin{table}[h]" + "\n"
            r"\centering" + "\n"
            r"\caption{Containment Rate vs Epidemic Beta"
            r" (seed=" + str(self._fixed_seed) + ")}" + "\n"
            r"\label{tab:sensitivity-beta}" + "\n"
            r"\begin{tabular}{l" + "r" * len(self._topologies) + "}" + "\n"
            r"\hline" + "\n"
            r"$\beta$ & " + topo_cols + r" \\" + "\n"
            r"\hline" + "\n"
            + body_b + "\n"
            r"\hline" + "\n"
            r"\end{tabular}" + "\n"
            r"\end{table}"
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_one(self, topology: str, seed: int, beta: float) -> RunRecord:
        t0 = time.time()
        graph = self._sim.generate(topology, num_nodes=self._num_nodes, seed=seed)
        seed_node = _seed_node(graph)
        pbr, vbr, gap_f, cont, egd = _run_pipeline(
            graph, [seed_node], beta=beta, random_seed=seed
        )
        return RunRecord(
            topology=topology,
            seed=seed,
            beta=beta,
            pbr_size=pbr,
            vbr_size=vbr,
            gap_fraction=round(gap_f, 4),
            containment_rate=round(cont, 4),
            egd_score=round(egd, 4),
            elapsed_seconds=round(time.time() - t0, 2),
        )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_metric(metric: str):
    """Return a value→string formatter appropriate for the metric."""
    if metric in ("pbr_size", "vbr_size"):
        return lambda v: f"{v:.1f}"
    if metric == "containment_rate":
        return lambda v: f"{v:.1%}"
    # gap_fraction, egd_score
    return lambda v: f"{v:.3f}"
