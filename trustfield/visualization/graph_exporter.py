"""Graph exporter — writes JSON and CSV artefacts consumed by the web viewer.

Outputs
-------
  web/graph_data.json
      Raw JSON payload for fetch()-based loaders.
  web/graph_data.js
      Same data wrapped in ``const GRAPH_DATA = {...};`` so the Three.js
      viewer works when opened as a local ``file://`` URL (no CORS).
  analysis.csv
      Per-node tabular data for offline analysis / paper supplements.
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path
from typing import Dict, Optional

from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification.blast_radius import BlastRadiusAnalysis
from trustfield.verification.iam_traversal import TraversalResult
from trustfield.verification.verification_report import VerificationReport

from .layout_engine import Layout3DEngine, NodePosition3D


class GraphExporter:
    """Serializes a TrustGraph + analysis artefacts to web-ready files.

    Args:
        output_dir: Directory where all output files are written.
            Created automatically if it does not exist.

    Example::

        exporter = GraphExporter("web/")
        paths = exporter.export(graph, verification_report=report)
        print(paths)  # {'json': 'web/graph_data.json', ...}
    """

    def __init__(self, output_dir: str = "web") -> None:
        self._output_dir = Path(output_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export(
        self,
        graph: TrustGraph,
        verification_report: Optional[VerificationReport] = None,
        ensemble_risk: Optional[Dict[str, float]] = None,
        topology_label: str = "unknown",
        traversal_result: Optional[TraversalResult] = None,
        containment_result=None,
    ) -> Dict[str, str]:
        """Export graph data to all output formats.

        Args:
            graph: TrustGraph to export.
            verification_report: Optional Module 4 report; used for VBR/PBR
                state classification and per-node exploitability.
            ensemble_risk: Optional dict mapping node_id → risk score.
            topology_label: Human-readable topology name (e.g. ``"hub"``).

        Returns:
            Dictionary mapping format name → absolute file path:
            ``{"json": ..., "js": ..., "csv": ...}``.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)

        blast_radius = (
            verification_report.blast_radius_analysis
            if verification_report is not None
            else None
        )

        # --- Compute 3D layout ---
        engine = Layout3DEngine()
        positions = engine.compute_layout(
            graph, blast_radius=blast_radius, ensemble_risk=ensemble_risk
        )
        graph_dict = engine.to_dict(graph, positions)
        graph_dict["topology"] = topology_label
        graph_dict["metadata"] = self._build_metadata(
            graph, blast_radius, traversal_result, containment_result
        )

        # --- Write JSON ---
        json_path = self._output_dir / "graph_data.json"
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(graph_dict, fh, indent=2)

        # --- Write JS (file:// compatible) ---
        js_path = self._output_dir / "graph_data.js"
        with open(js_path, "w", encoding="utf-8") as fh:
            fh.write("const GRAPH_DATA = ")
            json.dump(graph_dict, fh, indent=2)
            fh.write(";\n")

        # --- Write CSV ---
        csv_path = self._output_dir / "analysis.csv"
        self._write_csv(csv_path, graph, positions, blast_radius)

        # --- Copy web viewer assets so the output dir is self-contained ---
        web_src = Path(__file__).parent.parent.parent / "web"
        for asset in ("index.html", "style.css", "trustfield.js"):
            src = web_src / asset
            dst = self._output_dir / asset
            if src.exists():
                shutil.copy2(src, dst)

        return {
            "json": str(json_path),
            "js": str(js_path),
            "csv": str(csv_path),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_metadata(
        graph: TrustGraph,
        blast_radius: Optional[BlastRadiusAnalysis],
        traversal_result: Optional[TraversalResult] = None,
        containment_result=None,
    ) -> dict:
        meta: dict = {
            "num_nodes": graph._graph.number_of_nodes(),
            "num_edges": graph._graph.number_of_edges(),
        }
        if blast_radius is not None:
            meta.update({
                "pbr_size": blast_radius.pbr_size,
                "vbr_size": blast_radius.vbr_size,
                "gap_size": blast_radius.gap_size,
                "gap_classification": blast_radius.gap_classification.value,
                "exploitability_gap_score": round(
                    blast_radius.exploitability_gap_score, 4
                ),
            })
        if containment_result is not None:
            meta["containment_success_rate"] = round(
                containment_result.containment_success_rate, 4
            )
            meta["final_strictness"] = containment_result.final_strictness_level.value
            meta["guard_events"] = [
                {
                    "guard_id": ev.guard_id,
                    "edge": list(ev.edge),
                    "decision": ev.decision,
                    "reason": ev.reason,
                    "strictness": ev.strictness_at_time.value,
                    "timestamp": round(ev.timestamp, 3),
                }
                for ev in containment_result.guard_events
            ]
        else:
            meta["guard_events"] = []

        if traversal_result is not None:
            meta["traversal_timeline"] = [
                {
                    "step": s.step_id,
                    "from_node": s.from_node,
                    "to_node": s.to_node,
                    "edge_type": s.edge_type,
                    "succeeded": s.succeeded,
                    "depth": s.depth,
                }
                for s in traversal_result.traversal_steps
            ]
            meta["seed_nodes"] = list(traversal_result.seed_nodes)
        else:
            meta["traversal_timeline"] = []
            meta["seed_nodes"] = []

        return meta

    @staticmethod
    def _write_csv(
        path: Path,
        graph: TrustGraph,
        positions: Dict[str, NodePosition3D],
        blast_radius: Optional[BlastRadiusAnalysis],
    ) -> None:
        vbr = blast_radius.vbr_nodes if blast_radius else set()
        pbr = blast_radius.pbr_nodes if blast_radius else set()
        exp = blast_radius.per_node_exploitability if blast_radius else {}

        fieldnames = [
            "node_id", "type", "privilege_level",
            "x", "y", "z",
            "risk_score", "state",
            "in_pbr", "in_vbr", "exploitability_score",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for node_id, pos in sorted(positions.items()):
                writer.writerow({
                    "node_id": node_id,
                    "type": pos.node_type,
                    "privilege_level": pos.privilege_level,
                    "x": pos.x,
                    "y": pos.y,
                    "z": pos.z,
                    "risk_score": pos.risk_score,
                    "state": pos.state,
                    "in_pbr": node_id in pbr,
                    "in_vbr": node_id in vbr,
                    "exploitability_score": round(exp.get(node_id, 0.0), 4),
                })
