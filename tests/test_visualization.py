"""Tests for TrustField Module 6 — Visualization, Pipeline, and Publication Output.

 1. Layout3DEngine: all nodes present in positions output
 2. Layout3DEngine: x/y coordinates in [-10, 10]
 3. Layout3DEngine: z = privilege_level * 10.0
 4. Layout3DEngine: node state classified correctly (compromised vs critical_miss)
 5. Layout3DEngine.to_dict: output has 'nodes' and 'edges' keys
 6. GraphExporter.export: creates json, js, and csv files
 7. GraphExporter.export: graph_data.js starts with 'const GRAPH_DATA'
 8. ReportGenerator.gap_table_markdown: contains topology name and PBR/VBR headers
 9. ReportGenerator.containment_table_markdown: shows success rate symbol
10. ReportGenerator.full_latex_section: contains \\begin{tabular}
11. TrustFieldPipeline.run: containment_success_rate in [0.0, 1.0]
12. TrustFieldPipeline.run: output_files dict has json/js/csv keys
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.verification import (
    BlastRadiusCalculator,
    IAMTraversal,
    TokenGenerator,
    VerificationReport,
)
from trustfield.guards.containment_engine import ContainmentEngine
from trustfield.visualization.layout_engine import Layout3DEngine
from trustfield.visualization.graph_exporter import GraphExporter
from trustfield.visualization.report_generator import ReportGenerator
from trustfield.pipeline import TrustFieldPipeline


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def simple_graph() -> TrustGraph:
    """A → B → C chain with varying privilege levels."""
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER,    "User A",   0.3, 0.2))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "Svc B",    0.5, 0.5))
    g.add_node(NodeMetadata("C", NodeType.ROLE,    "Admin C",  0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.ASSUME_ROLE,  1.0, 6))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.TOKEN_MINT,   1.0, 6))
    return g


@pytest.fixture(scope="module")
def full_pipeline_result(simple_graph):
    """Run the full pipeline once and share the result across tests."""
    orch = TrustFieldOrchestrator(db_path=":memory:")
    analysis = orch.analyze(simple_graph, seed_nodes=["A"])
    tgen = TokenGenerator()
    traversal = IAMTraversal(tgen).traverse(
        simple_graph, ["A"], max_depth=6, respect_conditions=False
    )
    bra = BlastRadiusCalculator().compute(
        analysis.ensemble_prediction, traversal, simple_graph
    )
    report = VerificationReport(
        graph=simple_graph,
        analysis_result=analysis,
        traversal_result=traversal,
        blast_radius_analysis=bra,
    )
    return analysis, bra, report


# ---------------------------------------------------------------------------
# 1. Layout3DEngine: all nodes present
# ---------------------------------------------------------------------------

class TestLayoutAllNodesPresent:
    def test_all_nodes_in_positions(self, simple_graph):
        engine = Layout3DEngine()
        positions = engine.compute_layout(simple_graph)
        node_ids = set(simple_graph._graph.nodes())
        assert set(positions.keys()) == node_ids


# ---------------------------------------------------------------------------
# 2. Layout3DEngine: x/y in [-10, 10]
# ---------------------------------------------------------------------------

class TestLayoutCoordinatesInRange:
    def test_xy_in_bounds(self, simple_graph):
        engine = Layout3DEngine()
        positions = engine.compute_layout(simple_graph)
        for pos in positions.values():
            assert -10.0 <= pos.x <= 10.0, f"{pos.node_id} x={pos.x} out of range"
            assert -10.0 <= pos.y <= 10.0, f"{pos.node_id} y={pos.y} out of range"


# ---------------------------------------------------------------------------
# 3. Layout3DEngine: z = privilege_level * 10
# ---------------------------------------------------------------------------

class TestLayoutZAxis:
    def test_z_equals_privilege_times_10(self, simple_graph):
        engine = Layout3DEngine()
        positions = engine.compute_layout(simple_graph)
        for pos in positions.values():
            meta = simple_graph.get_node(pos.node_id)
            expected_z = round(meta.privilege_level * 10.0, 4)
            assert abs(pos.z - expected_z) < 1e-3, (
                f"{pos.node_id}: z={pos.z} expected {expected_z}"
            )


# ---------------------------------------------------------------------------
# 4. Layout3DEngine: node state classification
# ---------------------------------------------------------------------------

class TestLayoutStateClassification:
    def test_node_in_both_sets_is_compromised(self, simple_graph, full_pipeline_result):
        _, bra, _ = full_pipeline_result
        engine = Layout3DEngine()
        positions = engine.compute_layout(simple_graph, blast_radius=bra)

        # Nodes in both VBR and PBR should be "compromised"
        both = bra.vbr_nodes & bra.pbr_nodes
        for node_id in both:
            if node_id in positions:
                assert positions[node_id].state == "compromised", (
                    f"{node_id} in VBR∩PBR but state={positions[node_id].state}"
                )

    def test_vbr_only_node_is_critical_miss(self, simple_graph, full_pipeline_result):
        _, bra, _ = full_pipeline_result
        only_vbr = bra.vbr_nodes - bra.pbr_nodes
        if not only_vbr:
            pytest.skip("No VBR-only nodes in this run")
        engine = Layout3DEngine()
        positions = engine.compute_layout(simple_graph, blast_radius=bra)
        for node_id in only_vbr:
            if node_id in positions:
                assert positions[node_id].state == "critical_miss"


# ---------------------------------------------------------------------------
# 5. Layout3DEngine.to_dict: has nodes and edges keys
# ---------------------------------------------------------------------------

class TestLayoutToDictStructure:
    def test_to_dict_has_nodes_edges(self, simple_graph):
        engine = Layout3DEngine()
        positions = engine.compute_layout(simple_graph)
        d = engine.to_dict(simple_graph, positions)
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == simple_graph._graph.number_of_nodes()
        assert len(d["edges"]) == simple_graph._graph.number_of_edges()


# ---------------------------------------------------------------------------
# 6. GraphExporter.export: creates json, js, csv
# ---------------------------------------------------------------------------

class TestExporterCreatesFiles:
    def test_export_creates_all_files(self, simple_graph, full_pipeline_result, tmp_path):
        _, _, report = full_pipeline_result
        exporter = GraphExporter(output_dir=str(tmp_path))
        paths = exporter.export(
            simple_graph,
            verification_report=report,
            topology_label="chain",
        )
        assert "json" in paths
        assert "js"   in paths
        assert "csv"  in paths
        assert Path(paths["json"]).exists()
        assert Path(paths["js"]).exists()
        assert Path(paths["csv"]).exists()


# ---------------------------------------------------------------------------
# 7. GraphExporter: graph_data.js starts with 'const GRAPH_DATA'
# ---------------------------------------------------------------------------

class TestExporterJsFormat:
    def test_js_file_starts_with_const(self, simple_graph, full_pipeline_result, tmp_path):
        _, _, report = full_pipeline_result
        exporter = GraphExporter(output_dir=str(tmp_path))
        paths = exporter.export(simple_graph, verification_report=report)
        js_content = Path(paths["js"]).read_text(encoding="utf-8")
        assert js_content.startswith("const GRAPH_DATA = ")


# ---------------------------------------------------------------------------
# 8. ReportGenerator: gap table markdown has expected headers
# ---------------------------------------------------------------------------

class TestReportGapMarkdown:
    def test_gap_markdown_headers(self, simple_graph, full_pipeline_result):
        _, bra, _ = full_pipeline_result
        reporter = ReportGenerator()
        md = reporter.gap_table_markdown({"chain": bra})
        assert "Topology" in md
        assert "PBR" in md
        assert "VBR" in md
        assert "Chain" in md  # topology name appears capitalised


# ---------------------------------------------------------------------------
# 9. ReportGenerator: containment table shows rate symbol
# ---------------------------------------------------------------------------

class TestReportContainmentMarkdown:
    def test_containment_table_has_rate(self, simple_graph, full_pipeline_result, tmp_path):
        _, _, report = full_pipeline_result
        orch = TrustFieldOrchestrator(db_path=":memory:")
        engine = ContainmentEngine(orch, token_generator=TokenGenerator())
        cr = engine.execute(simple_graph, ["A"], report, n_feedback_cycles=2)
        reporter = ReportGenerator()
        md = reporter.containment_table_markdown({"chain": cr})
        assert "%" in md
        assert "Topology" in md


# ---------------------------------------------------------------------------
# 10. ReportGenerator: LaTeX section contains \begin{tabular}
# ---------------------------------------------------------------------------

class TestReportLatexSection:
    def test_latex_contains_tabular(self, simple_graph, full_pipeline_result, tmp_path):
        _, bra, report = full_pipeline_result
        orch = TrustFieldOrchestrator(db_path=":memory:")
        engine = ContainmentEngine(orch, token_generator=TokenGenerator())
        cr = engine.execute(simple_graph, ["A"], report, n_feedback_cycles=2)
        reporter = ReportGenerator()
        latex = reporter.full_latex_section({"chain": bra}, {"chain": cr})
        assert r"\begin{tabular}" in latex
        assert r"\end{table}" in latex


# ---------------------------------------------------------------------------
# 11. TrustFieldPipeline.run: success_rate in [0, 1]
# ---------------------------------------------------------------------------

class TestPipelineSuccessRateInRange:
    def test_success_rate_valid(self, simple_graph, tmp_path):
        pipeline = TrustFieldPipeline(
            output_dir=str(tmp_path),
            n_feedback_cycles=2,
        )
        result = pipeline.run(simple_graph, ["A"], topology_label="chain")
        rate = result.containment_result.containment_success_rate
        assert 0.0 <= rate <= 1.0, f"Rate out of range: {rate}"


# ---------------------------------------------------------------------------
# 12. TrustFieldPipeline.run: output_files has json/js/csv
# ---------------------------------------------------------------------------

class TestPipelineOutputFiles:
    def test_output_files_dict_keys(self, simple_graph, tmp_path):
        pipeline = TrustFieldPipeline(
            output_dir=str(tmp_path),
            n_feedback_cycles=2,
        )
        result = pipeline.run(simple_graph, ["A"], topology_label="chain", export=True)
        assert "json" in result.output_files
        assert "js"   in result.output_files
        assert "csv"  in result.output_files
        for fpath in result.output_files.values():
            assert Path(fpath).exists(), f"Missing: {fpath}"
