"""VerificationReport — full audit trail for a single Module 4 analysis run.

Bundles the Module 3 AnalysisResult together with the IAM traversal outcome
and blast-radius comparison into one exportable artifact.  The CSV and JSON
exports are designed to serve as supplementary material for publication.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from typing import Optional

from trustfield.ensemble.ensemble_result import AnalysisResult
from trustfield.graph.trust_graph import TrustGraph

from .blast_radius import BlastRadiusAnalysis
from .gap_analyzer import GapAnalysisReport
from .iam_traversal import TraversalResult


@dataclass
class VerificationReport:
    """Complete output of the TrustField Module 4 verification pipeline.

    Attributes:
        graph: The TrustGraph that was analysed (needed for node metadata
            during CSV export).
        analysis_result: Module 3 output (ensemble prediction + fingerprint).
        traversal_result: Output of ``IAMTraversal.traverse()``.
        blast_radius_analysis: PBR vs VBR comparison.
        gap_analysis_report: Cross-topology aggregation; ``None`` when only a
            single topology has been processed.
    """

    graph: TrustGraph
    analysis_result: AnalysisResult
    traversal_result: TraversalResult
    blast_radius_analysis: BlastRadiusAnalysis
    gap_analysis_report: Optional[GapAnalysisReport] = None

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def export_json(self, path: str) -> None:
        """Write a JSON summary of the verification run to ``path``.

        The exported fields cover graph summary, topology, weight source,
        blast-radius metrics, gap classification, critical paths, and
        traversal token statistics.

        Args:
            path: Filesystem path for the output ``.json`` file.
        """
        bra = self.blast_radius_analysis
        data = {
            "graph_summary": self.analysis_result.graph_summary,
            "topology_type": (
                self.analysis_result.topology_fingerprint.topology_type.value
            ),
            "weight_source": self.analysis_result.weight_source,
            "pbr_size": bra.pbr_size,
            "vbr_size": bra.vbr_size,
            "gap_size": bra.gap_size,
            "gap_fraction": bra.gap_fraction,
            "gap_classification": bra.gap_classification.value,
            "exploitability_gap_score": bra.exploitability_gap_score,
            "missed_nodes": sorted(bra.missed_nodes),
            "critical_paths": bra.critical_paths,
            "traversal_stats": {
                "total_tokens_generated": (
                    self.traversal_result.total_tokens_generated
                ),
                "total_tokens_validated": (
                    self.traversal_result.total_tokens_validated
                ),
                "total_tokens_rejected": (
                    self.traversal_result.total_tokens_rejected
                ),
                "max_depth_reached": self.traversal_result.max_depth_reached,
            },
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

    def export_csv(self, path: str) -> None:
        """Write a per-node CSV table to ``path``.

        Each row covers one graph node.  Columns:
            ``node_id``, ``type``, ``privilege``, ``in_pbr``, ``in_vbr``,
            ``exploitability_score``, ``gap_classification``

        The ``gap_classification`` column values:
            ``VERIFIED``      — in both PBR and VBR
            ``GAP``           — in PBR only (predicted but unverified)
            ``CRITICAL_MISS`` — in VBR only (verified but not predicted)
            ``SAFE``          — in neither

        Args:
            path: Filesystem path for the output ``.csv`` file.
        """
        bra = self.blast_radius_analysis
        fieldnames = [
            "node_id",
            "type",
            "privilege",
            "in_pbr",
            "in_vbr",
            "exploitability_score",
            "gap_classification",
        ]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for node_id in sorted(self.graph._graph.nodes()):
                try:
                    meta = self.graph.get_node(node_id)
                    node_type = meta.node_type.value
                    privilege = meta.privilege_level
                except KeyError:
                    node_type = "UNKNOWN"
                    privilege = 0.0

                in_pbr = node_id in bra.pbr_nodes
                in_vbr = node_id in bra.vbr_nodes
                exp_score = bra.per_node_exploitability.get(node_id, 0.0)

                if node_id in bra.missed_nodes:
                    node_cls = "CRITICAL_MISS"
                elif in_vbr and in_pbr:
                    node_cls = "VERIFIED"
                elif in_pbr and not in_vbr:
                    node_cls = "GAP"
                elif in_vbr and not in_pbr:
                    node_cls = "MISSED"
                else:
                    node_cls = "SAFE"

                writer.writerow(
                    {
                        "node_id": node_id,
                        "type": node_type,
                        "privilege": round(privilege, 3),
                        "in_pbr": in_pbr,
                        "in_vbr": in_vbr,
                        "exploitability_score": round(exp_score, 4),
                        "gap_classification": node_cls,
                    }
                )

    def get_executive_summary(self) -> str:
        """Return a human-readable one-paragraph summary of the analysis.

        Designed for API responses, reports, and quick review.

        Returns:
            A single-paragraph string describing PBR, VBR, gap size,
            gap percentage, classification, and whether any critical misses
            were found.

        Example::

            "Of 40 nodes, ensemble predicted 28 compromised (PBR=28).
            Controlled traversal verified 22 were reachable (VBR=22).
            ExploitabilityGap=6 (21.4%), classified as Over-Predicted.
            No critical misses detected."
        """
        bra = self.blast_radius_analysis
        n_total = self.analysis_result.ensemble_prediction.total_nodes_analyzed
        gap_pct = bra.gap_fraction * 100
        classification = bra.gap_classification.value.replace("_", "-").title()
        miss_str = (
            f" CRITICAL: {len(bra.missed_nodes)} node(s) verified reachable"
            " but NOT predicted by ensemble."
            if bra.missed_nodes
            else " No critical misses detected."
        )
        return (
            f"Of {n_total} nodes, ensemble predicted {bra.pbr_size} compromised"
            f" (PBR={bra.pbr_size}). "
            f"Controlled traversal verified {bra.vbr_size} were reachable"
            f" (VBR={bra.vbr_size}). "
            f"ExploitabilityGap={bra.gap_size} ({gap_pct:.1f}%),"
            f" classified as {classification}.{miss_str}"
        )
