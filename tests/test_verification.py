"""Tests for TrustField Module 4 — Verification Engine.

Covers:
  1-5.  TokenGenerator: round-trip, expiry, tamper, depth, replay.
  6-8.  IAMTraversal: VBR subset, seeds included, max_depth=0.
  9-10. BlastRadiusCalculator: missed_nodes, gap_fraction range.
  11.   GapAnalyzer: LaTeX table format.
  12.   VerificationReport: CSV export with correct columns.
"""

from __future__ import annotations

import csv
import tempfile
import time
from pathlib import Path
from typing import Set

import pytest

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.ensemble import TrustFieldOrchestrator, WeightVector
from trustfield.ensemble.ensemble_result import EnsemblePrediction, ModelContribution
from trustfield.verification import (
    BlastRadiusAnalysis,
    BlastRadiusCalculator,
    DelegationToken,
    ExploitabilityGapAnalyzer,
    GapClassification,
    GapAnalysisReport,
    IAMTraversal,
    TokenGenerator,
    TokenValidationResult,
    TraversalResult,
    VerificationReport,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def simple_graph() -> TrustGraph:
    """A→B→C with weight=1.0 edges, C has high privilege."""
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER, "User A", 0.3, 0.2))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "Svc B", 0.5, 0.5))
    g.add_node(NodeMetadata("C", NodeType.ROLE, "Admin C", 0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 1.0, 6))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.TOKEN_MINT, 1.0, 6))
    return g


@pytest.fixture
def gen() -> TokenGenerator:
    """Fresh TokenGenerator per test (independent nonce store)."""
    return TokenGenerator()


@pytest.fixture(scope="module")
def _min_edge():
    """Minimal edge metadata for token generation tests."""
    return EdgeMetadata("e0", EdgeType.ASSUME_ROLE, 1.0, 6)


# ---------------------------------------------------------------------------
# Helper: build a minimal EnsemblePrediction
# ---------------------------------------------------------------------------

def _make_prediction(compromised: Set[str], risk: dict) -> EnsemblePrediction:
    wv = WeightVector.uniform()
    return EnsemblePrediction(
        compromised_nodes=set(compromised),
        ensemble_risk=risk,
        confidence_interval={n: (0.0, 1.0) for n in risk},
        high_uncertainty_nodes=set(),
        model_contributions=[],
        fusion_mode="WEIGHTED",
        weight_vector=wv,
        decision_threshold=0.5,
        total_nodes_analyzed=len(risk),
    )


# ---------------------------------------------------------------------------
# Helper: build a minimal TraversalResult
# ---------------------------------------------------------------------------

def _make_traversal(
    seed_nodes, verified_reachable, all_nodes
) -> TraversalResult:
    vr = set(verified_reachable)
    return TraversalResult(
        seed_nodes=list(seed_nodes),
        verified_reachable=vr,
        traversal_steps=[],
        blocked_transitions=[],
        max_depth_reached=0,
        total_tokens_generated=0,
        total_tokens_validated=0,
        total_tokens_rejected=0,
        per_node_reachability={n: n in vr for n in all_nodes},
    )


# ---------------------------------------------------------------------------
# 1. TokenGenerator: generate + validate round-trip succeeds
# ---------------------------------------------------------------------------

class TestTokenGeneratorRoundTrip:
    def test_valid_token_passes(self, gen, _min_edge):
        token = gen.generate("A", "B", _min_edge, current_depth=0)
        result = gen.validate(token)
        assert result.valid
        assert result.failure_reason is None


# ---------------------------------------------------------------------------
# 2. TokenGenerator: expired token (ttl=0) fails validation
# ---------------------------------------------------------------------------

class TestTokenExpiry:
    def test_expired_token_fails(self, gen, _min_edge):
        token = gen.generate("A", "B", _min_edge, current_depth=0)
        token.ttl_seconds = 0.0  # force immediate expiry (signature stays valid)
        result = gen.validate(token)
        assert not result.valid
        assert result.failure_reason == "token_expired"


# ---------------------------------------------------------------------------
# 3. TokenGenerator: tampered signature fails validation
# ---------------------------------------------------------------------------

class TestTokenTamperedSignature:
    def test_tampered_signature_rejected(self, gen, _min_edge):
        token = gen.generate("A", "B", _min_edge, current_depth=0)
        token.signature = "0" * 64  # replace with garbage hex
        result = gen.validate(token)
        assert not result.valid
        assert result.failure_reason == "invalid_signature"


# ---------------------------------------------------------------------------
# 4. TokenGenerator: depth exceeded fails validation
# ---------------------------------------------------------------------------

class TestTokenDepthExceeded:
    def test_depth_too_deep_rejected(self, gen, _min_edge):
        token = gen.generate("A", "B", _min_edge, current_depth=0)
        # Depth fields are NOT part of the HMAC message, so we can modify freely
        token.delegation_depth = token.max_depth + 1
        result = gen.validate(token)
        assert not result.valid
        assert result.failure_reason == "depth_exceeded"


# ---------------------------------------------------------------------------
# 5. TokenGenerator: replayed nonce fails validation
# ---------------------------------------------------------------------------

class TestTokenNonceReplay:
    def test_replayed_nonce_rejected(self, gen, _min_edge):
        token = gen.generate("A", "B", _min_edge, current_depth=0)
        first = gen.validate(token)
        assert first.valid, "First validation should succeed"
        # Second validation of same token — nonce already consumed
        second = gen.validate(token)
        assert not second.valid
        assert second.failure_reason == "nonce_replayed"


# ---------------------------------------------------------------------------
# 6. IAMTraversal: VBR ⊆ graph nodes (no hallucinated nodes)
# ---------------------------------------------------------------------------

class TestIAMTraversalVBRSubset:
    def test_vbr_subset_of_graph_nodes(self, simple_graph):
        gen = TokenGenerator()
        traversal = IAMTraversal(gen)
        result = traversal.traverse(
            simple_graph, ["A"], max_depth=6, respect_conditions=False
        )
        graph_nodes = set(simple_graph._graph.nodes())
        assert result.verified_reachable.issubset(graph_nodes)


# ---------------------------------------------------------------------------
# 7. IAMTraversal: all seed nodes in verified_reachable
# ---------------------------------------------------------------------------

class TestIAMTraversalSeedsReachable:
    def test_seeds_always_in_vbr(self, simple_graph):
        gen = TokenGenerator()
        traversal = IAMTraversal(gen)
        seeds = ["A", "B"]
        result = traversal.traverse(
            simple_graph, seeds, max_depth=6, respect_conditions=False
        )
        for seed in seeds:
            assert seed in result.verified_reachable


# ---------------------------------------------------------------------------
# 8. IAMTraversal: with max_depth=0, only seed nodes reachable
# ---------------------------------------------------------------------------

class TestIAMTraversalMaxDepthZero:
    def test_only_seeds_reachable_at_depth_zero(self, simple_graph):
        gen = TokenGenerator()
        traversal = IAMTraversal(gen)
        result = traversal.traverse(
            simple_graph, ["A"], max_depth=0, respect_conditions=False
        )
        assert result.verified_reachable == {"A"}
        assert result.traversal_steps == []


# ---------------------------------------------------------------------------
# 9. BlastRadiusCalculator: missed_nodes = VBR - PBR correctly computed
# ---------------------------------------------------------------------------

class TestBlastRadiusMissedNodes:
    def test_missed_nodes_computation(self, simple_graph):
        # PBR = {A, B}, VBR = {A, B, C}  →  missed = {C}
        prediction = _make_prediction(
            {"A", "B"},
            {"A": 0.9, "B": 0.8, "C": 0.1},
        )
        traversal = _make_traversal(["A"], {"A", "B", "C"}, {"A", "B", "C"})
        calc = BlastRadiusCalculator()
        analysis = calc.compute(prediction, traversal, simple_graph)

        assert analysis.missed_nodes == {"C"}
        assert analysis.gap_nodes == set()  # VBR covers all of PBR
        assert analysis.gap_classification == GapClassification.CRITICAL_MISS


# ---------------------------------------------------------------------------
# 10. BlastRadiusCalculator: gap_fraction in [0.0, 1.0]
# ---------------------------------------------------------------------------

class TestBlastRadiusGapFraction:
    def test_gap_fraction_in_range(self, simple_graph):
        # PBR = {A, B, C}, VBR = {A}  →  large gap
        prediction = _make_prediction(
            {"A", "B", "C"},
            {"A": 0.9, "B": 0.7, "C": 0.6},
        )
        traversal = _make_traversal(["A"], {"A"}, {"A", "B", "C"})
        calc = BlastRadiusCalculator()
        analysis = calc.compute(prediction, traversal, simple_graph)

        assert 0.0 <= analysis.gap_fraction <= 1.0
        assert analysis.gap_nodes == {"B", "C"}


# ---------------------------------------------------------------------------
# 11. GapAnalyzer.to_latex_table(): output contains \begin{tabular}
# ---------------------------------------------------------------------------

class TestGapAnalyzerLatex:
    def test_latex_table_format(self):
        hub_bra = BlastRadiusAnalysis(
            pbr_nodes={"a", "b", "c"},
            vbr_nodes={"a", "b"},
            gap_nodes={"c"},
            missed_nodes=set(),
            pbr_size=3,
            vbr_size=2,
            gap_size=1,
            gap_fraction=1 / 3,
            exploitability_gap_score=0.2,
            gap_classification=GapClassification.OVER_PREDICTED,
            per_node_exploitability={},
            critical_paths=[],
        )
        chain_bra = BlastRadiusAnalysis(
            pbr_nodes={"x", "y"},
            vbr_nodes={"x", "y"},
            gap_nodes=set(),
            missed_nodes=set(),
            pbr_size=2,
            vbr_size=2,
            gap_size=0,
            gap_fraction=0.0,
            exploitability_gap_score=0.0,
            gap_classification=GapClassification.CALIBRATED,
            per_node_exploitability={},
            critical_paths=[],
        )
        analyzer = ExploitabilityGapAnalyzer()
        report = analyzer.analyze_across_topologies(
            {"hub": hub_bra, "chain": chain_bra}
        )
        latex = analyzer.to_latex_table(report)
        assert r"\begin{tabular}" in latex
        assert r"\hline" in latex
        assert r"\end{tabular}" in latex
        assert "Hub" in latex
        assert "Chain" in latex


# ---------------------------------------------------------------------------
# 12. VerificationReport.export_csv(): file is valid CSV with correct columns
# ---------------------------------------------------------------------------

class TestVerificationReportCSV:
    @pytest.fixture(scope="class")
    def full_report(self, simple_graph):
        orch = TrustFieldOrchestrator(db_path=":memory:")
        analysis = orch.analyze(simple_graph, seed_nodes=["A"])
        gen = TokenGenerator()
        traversal = IAMTraversal(gen).traverse(
            simple_graph, ["A"], max_depth=6, respect_conditions=False
        )
        bra = BlastRadiusCalculator().compute(
            analysis.ensemble_prediction, traversal, simple_graph
        )
        return VerificationReport(
            graph=simple_graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
        )

    def test_csv_has_correct_columns(self, full_report):
        with tempfile.NamedTemporaryFile(
            suffix=".csv", mode="w", delete=False
        ) as tmp:
            tmp_path = tmp.name

        full_report.export_csv(tmp_path)

        with open(tmp_path, newline="") as fh:
            reader = csv.DictReader(fh)
            expected_cols = {
                "node_id",
                "type",
                "privilege",
                "in_pbr",
                "in_vbr",
                "exploitability_score",
                "gap_classification",
            }
            assert set(reader.fieldnames) == expected_cols
            rows = list(reader)

        assert len(rows) == 3  # A, B, C
        node_ids = {r["node_id"] for r in rows}
        assert node_ids == {"A", "B", "C"}
