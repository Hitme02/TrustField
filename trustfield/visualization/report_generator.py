"""Publication-ready report generator for TrustField results.

Generates LaTeX and Markdown output tables suitable for inclusion in
IEEE/ACM/Springer papers.  All tables are produced from the pipeline's
aggregated metrics so every figure in the paper comes directly from the
live system output — no manual transcription required.

Tables produced
---------------
  Table 1  ExploitabilityGap results (per topology × PBR/VBR/Gap/Class.)
  Table 2  Containment effectiveness (per topology × success_rate/missed/blocked)
  Table 3  Model-weight breakdown (per topology × 5 model weights)
"""

from __future__ import annotations

from typing import Dict, List, Optional

from trustfield.guards.containment_engine import ContainmentResult
from trustfield.verification.gap_analyzer import ExploitabilityGapAnalyzer, GapAnalysisReport
from trustfield.verification.blast_radius import BlastRadiusAnalysis


class ReportGenerator:
    """Converts TrustField pipeline metrics into publication-ready tables.

    Example::

        gen = ReportGenerator()
        analyses = {"hub": hub_bra, "chain": chain_bra, "dense_cluster": cluster_bra}
        containments = {"hub": hub_cr, "chain": chain_cr, "dense_cluster": cluster_cr}
        weights = {"hub": hub_weights, "chain": chain_weights}

        print(gen.gap_table_markdown(analyses))
        print(gen.containment_table_markdown(containments))
        print(gen.weights_table_markdown(weights))
        full_latex = gen.full_latex_section(analyses, containments, weights)
    """

    # ------------------------------------------------------------------
    # ExploitabilityGap table (Table 1)
    # ------------------------------------------------------------------

    def gap_table_markdown(
        self, analyses: Dict[str, BlastRadiusAnalysis]
    ) -> str:
        """Return Markdown Table 1: ExploitabilityGap results."""
        analyzer = ExploitabilityGapAnalyzer()
        report = analyzer.analyze_across_topologies(analyses)
        rows = [
            "| Topology | PBR | VBR | Gap | Gap% | Egd Score | Classification |",
            "|----------|-----|-----|-----|------|-----------|----------------|",
        ]
        for topo, m in report.per_topology_metrics.items():
            label = topo.replace("_", " ").title()
            gap_pct = f"{m['gap_fraction'] * 100:.1f}%"
            cls = m["gap_classification"].replace("_", "-").title()
            rows.append(
                f"| {label} | {m['pbr']} | {m['vbr']} | {m['gap']} | "
                f"{gap_pct} | {m['exploitability_gap_score']:.4f} | {cls} |"
            )
        rows.append("")
        rows.append(
            f"**Aggregate gap score**: {report.aggregate_gap_score:.4f}  |  "
            f"**Critical-miss topologies**: {report.critical_miss_count}"
        )
        return "\n".join(rows)

    def gap_table_latex(self, analyses: Dict[str, BlastRadiusAnalysis]) -> str:
        """Return LaTeX Table 1: ExploitabilityGap results."""
        analyzer = ExploitabilityGapAnalyzer()
        report = analyzer.analyze_across_topologies(analyses)
        lines = [
            r"\begin{table}[h]",
            r"\centering",
            r"\caption{TrustField ExploitabilityGap Results by Topology}",
            r"\label{tab:gap}",
            r"\begin{tabular}{lrrrrrr}",
            r"\hline",
            r"Topology & PBR & VBR & Gap & Gap\% & EGD Score & Class. \\",
            r"\hline",
        ]
        for topo, m in report.per_topology_metrics.items():
            label = topo.replace("_", "-").title()
            gap_pct = f"{m['gap_fraction'] * 100:.1f}\\%"
            cls = m["gap_classification"].replace("_", "-").title()
            lines.append(
                f"{label} & {m['pbr']} & {m['vbr']} & {m['gap']} & "
                f"{gap_pct} & {m['exploitability_gap_score']:.4f} & {cls} \\\\"
            )
        lines += [
            r"\hline",
            r"\end{tabular}",
            r"\end{table}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Containment effectiveness table (Table 2)
    # ------------------------------------------------------------------

    def containment_table_markdown(
        self, containments: Dict[str, ContainmentResult]
    ) -> str:
        """Return Markdown Table 2: Containment effectiveness."""
        rows = [
            "| Topology | Success Rate | Contained | Missed | Blocked Edges | Final Strictness |",
            "|----------|-------------|-----------|--------|---------------|-----------------|",
        ]
        for topo, cr in containments.items():
            label = topo.replace("_", " ").title()
            icon = "✓" if cr.containment_success_rate >= 0.95 else "✗"
            rows.append(
                f"| {label} | {cr.containment_success_rate:.1%} {icon} | "
                f"{len(cr.contained_nodes)} | {len(cr.missed_containments)} | "
                f"{len(cr.blocked_transitions)} | {cr.final_strictness_level.value} |"
            )
        return "\n".join(rows)

    def containment_table_latex(
        self, containments: Dict[str, ContainmentResult]
    ) -> str:
        """Return LaTeX Table 2: Containment effectiveness."""
        lines = [
            r"\begin{table}[h]",
            r"\centering",
            r"\caption{TrustField Cyber-Physical Containment Effectiveness}",
            r"\label{tab:containment}",
            r"\begin{tabular}{lrrrrl}",
            r"\hline",
            r"Topology & Success Rate & Contained & Missed & Blocked & Strictness \\",
            r"\hline",
        ]
        for topo, cr in containments.items():
            label = topo.replace("_", "-").title()
            rate_str = f"{cr.containment_success_rate * 100:.1f}\\%"
            lines.append(
                f"{label} & {rate_str} & {len(cr.contained_nodes)} & "
                f"{len(cr.missed_containments)} & {len(cr.blocked_transitions)} & "
                f"{cr.final_strictness_level.value} \\\\"
            )
        lines += [
            r"\hline",
            r"\end{tabular}",
            r"\end{table}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Model weights table (Table 3)
    # ------------------------------------------------------------------

    def weights_table_markdown(
        self, weights_by_topology: Dict[str, Dict[str, float]]
    ) -> str:
        """Return Markdown Table 3: Ensemble model weight breakdown.

        Args:
            weights_by_topology: Mapping topology_name → {model_name → weight}.
        """
        model_names = ["traversal", "epidemic", "spectral", "percolation", "control"]
        header = "| Topology | " + " | ".join(m.title() for m in model_names) + " |"
        sep = "|----------|" + "|".join(["-------"] * len(model_names)) + "|"
        rows = [header, sep]
        for topo, weights in weights_by_topology.items():
            label = topo.replace("_", " ").title()
            cells = [f"{weights.get(m, 0.0):.3f}" for m in model_names]
            rows.append(f"| {label} | " + " | ".join(cells) + " |")
        return "\n".join(rows)

    def weights_table_latex(
        self, weights_by_topology: Dict[str, Dict[str, float]]
    ) -> str:
        """Return LaTeX Table 3: Ensemble model weight breakdown."""
        model_names = ["traversal", "epidemic", "spectral", "percolation", "control"]
        col_spec = "l" + "r" * len(model_names)
        header_cols = " & ".join(m.title() for m in model_names)
        lines = [
            r"\begin{table}[h]",
            r"\centering",
            r"\caption{Topology-Aware Ensemble Model Weights}",
            r"\label{tab:weights}",
            f"\\begin{{tabular}}{{{col_spec}}}",
            r"\hline",
            f"Topology & {header_cols} \\\\",
            r"\hline",
        ]
        for topo, weights in weights_by_topology.items():
            label = topo.replace("_", "-").title()
            cells = " & ".join(f"{weights.get(m, 0.0):.3f}" for m in model_names)
            lines.append(f"{label} & {cells} \\\\")
        lines += [
            r"\hline",
            r"\end{tabular}",
            r"\end{table}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Full LaTeX section
    # ------------------------------------------------------------------

    def full_latex_section(
        self,
        analyses: Dict[str, BlastRadiusAnalysis],
        containments: Dict[str, ContainmentResult],
        weights_by_topology: Optional[Dict[str, Dict[str, float]]] = None,
    ) -> str:
        """Combine all tables into a complete LaTeX results section.

        Returns a string that can be directly ``\\input{}`` in a paper.
        """
        parts = [
            r"% === TrustField Auto-Generated Results Section ===",
            r"% Generated by trustfield.visualization.ReportGenerator",
            "",
            self.gap_table_latex(analyses),
            "",
            self.containment_table_latex(containments),
        ]
        if weights_by_topology:
            parts += ["", self.weights_table_latex(weights_by_topology)]
        return "\n".join(parts)
