"""ExploitabilityGapAnalyzer — cross-topology statistical analysis of the gap.

This class aggregates BlastRadiusAnalysis objects from multiple topology runs
and produces publication-ready output: LaTeX tabular environments and Markdown
tables suitable for a research paper's results section.

The ``GapAnalysisReport`` produced here is the primary artifact of TrustField's
empirical evaluation — it constitutes the results table for the prediction
accuracy component of the paper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .blast_radius import BlastRadiusAnalysis, GapClassification


@dataclass
class GapAnalysisReport:
    """Aggregated gap analysis across multiple topology scenarios.

    Attributes:
        per_topology_metrics: Dict mapping topology name to a metrics dict
            with keys: ``pbr``, ``vbr``, ``gap``, ``gap_fraction``,
            ``gap_classification``, ``missed_nodes``,
            ``exploitability_gap_score``.
        aggregate_gap_score: Mean gap fraction across all topologies.
        best_topology: Topology name with the lowest gap fraction
            (best ensemble calibration).
        worst_topology: Topology name with the highest gap fraction.
        critical_miss_count: Number of topologies where VBR > PBR (CRITICAL_MISS).
    """

    per_topology_metrics: Dict[str, dict]
    aggregate_gap_score: float
    best_topology: str
    worst_topology: str
    critical_miss_count: int


class ExploitabilityGapAnalyzer:
    """Produces the statistical analysis of the exploitability gap.

    Aggregates results across topology types and generates publication-ready
    tables in both LaTeX and Markdown format.

    Example::

        analyzer = ExploitabilityGapAnalyzer()
        report = analyzer.analyze_across_topologies({
            "hub":           hub_analysis,
            "chain":         chain_analysis,
            "dense_cluster": cluster_analysis,
        })
        print(analyzer.to_markdown_table(report))
        print(analyzer.to_latex_table(report))
    """

    def analyze_across_topologies(
        self, analyses: Dict[str, BlastRadiusAnalysis]
    ) -> GapAnalysisReport:
        """Aggregate gap metrics across multiple topology analyses.

        Args:
            analyses: Mapping of topology name (e.g. ``"hub"``) to its
                ``BlastRadiusAnalysis``.

        Returns:
            A ``GapAnalysisReport`` with per-topology metrics and aggregate
            statistics.
        """
        per_topology_metrics: Dict[str, dict] = {}
        for topo, analysis in analyses.items():
            per_topology_metrics[topo] = {
                "pbr": analysis.pbr_size,
                "vbr": analysis.vbr_size,
                "gap": analysis.gap_size,
                "gap_fraction": round(analysis.gap_fraction, 4),
                "gap_classification": analysis.gap_classification.value,
                "missed_nodes": len(analysis.missed_nodes),
                "exploitability_gap_score": round(
                    analysis.exploitability_gap_score, 4
                ),
            }

        gap_fractions = {
            t: m["gap_fraction"] for t, m in per_topology_metrics.items()
        }
        aggregate_gap_score = (
            sum(gap_fractions.values()) / len(gap_fractions)
            if gap_fractions
            else 0.0
        )

        best_topology = (
            min(gap_fractions, key=gap_fractions.__getitem__)
            if gap_fractions
            else ""
        )
        worst_topology = (
            max(gap_fractions, key=gap_fractions.__getitem__)
            if gap_fractions
            else ""
        )

        critical_miss_count = sum(
            1
            for a in analyses.values()
            if a.gap_classification == GapClassification.CRITICAL_MISS
        )

        return GapAnalysisReport(
            per_topology_metrics=per_topology_metrics,
            aggregate_gap_score=round(aggregate_gap_score, 4),
            best_topology=best_topology,
            worst_topology=worst_topology,
            critical_miss_count=critical_miss_count,
        )

    def to_latex_table(self, report: GapAnalysisReport) -> str:
        r"""Generate a LaTeX tabular environment ready for paper inclusion.

        Columns: Topology | PBR | VBR | Gap | Gap\% | Classification

        Args:
            report: A ``GapAnalysisReport`` from ``analyze_across_topologies``.

        Returns:
            A multi-line string containing a complete ``\begin{tabular}`` …
            ``\end{tabular}`` block.

        Example output::

            \begin{tabular}{lrrrrr}
            \hline
            Topology & PBR & VBR & Gap & Gap\% & Class. \\
            \hline
            Hub & 28 & 22 & 6 & 21.4\% & Over-Predicted \\
            \hline
            \end{tabular}
        """
        lines = [
            r"\begin{tabular}{lrrrrr}",
            r"\hline",
            r"Topology & PBR & VBR & Gap & Gap\% & Class. \\",
            r"\hline",
        ]
        for topo, m in report.per_topology_metrics.items():
            topo_label = topo.replace("_", "-").title()
            gap_pct = f"{m['gap_fraction'] * 100:.1f}\\%"
            cls_str = m["gap_classification"].replace("_", "-").title()
            lines.append(
                f"{topo_label} & {m['pbr']} & {m['vbr']} & "
                f"{m['gap']} & {gap_pct} & {cls_str} \\\\"
            )
        lines += [r"\hline", r"\end{tabular}"]
        return "\n".join(lines)

    def to_markdown_table(self, report: GapAnalysisReport) -> str:
        """Generate a Markdown table for the gap analysis results.

        Columns: Topology | PBR | VBR | Gap | Gap% | Classification

        Args:
            report: A ``GapAnalysisReport`` from ``analyze_across_topologies``.

        Returns:
            A multi-line Markdown string with header, separator, and data rows.
        """
        rows = [
            "| Topology | PBR | VBR | Gap | Gap% | Classification |",
            "|----------|-----|-----|-----|------|----------------|",
        ]
        for topo, m in report.per_topology_metrics.items():
            topo_label = topo.replace("_", " ").title()
            gap_pct = f"{m['gap_fraction'] * 100:.1f}%"
            cls_str = m["gap_classification"].replace("_", "-").title()
            rows.append(
                f"| {topo_label} | {m['pbr']} | {m['vbr']} | "
                f"{m['gap']} | {gap_pct} | {cls_str} |"
            )
        return "\n".join(rows)
