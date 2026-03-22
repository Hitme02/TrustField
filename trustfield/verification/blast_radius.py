"""BlastRadiusCalculator — PBR vs VBR comparison and exploitability gap analysis.

This module implements TrustField's core research contribution: computing and
classifying the ExploitabilityGap between:
  PBR (Predicted Blast Radius)  — the ensemble's theoretical upper bound
  VBR (Verified Blast Radius)   — what controlled traversal confirms reachable

ExploitabilityGap = PBR − VBR

A small gap means the ensemble is well-calibrated.  A large gap means many
predicted paths are not actually exploitable under realistic conditions.
A CRITICAL_MISS (VBR > PBR) means the ensemble missed live attack paths —
the most dangerous scenario.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from trustfield.ensemble.ensemble_result import EnsemblePrediction
from trustfield.graph.trust_graph import TrustGraph

from .iam_traversal import TraversalResult


class GapClassification(Enum):
    """Classification of the ExploitabilityGap.

    Attributes:
        CALIBRATED: Gap fraction < 10% — ensemble prediction closely matches
            what is actually exploitable.
        OVER_PREDICTED: Gap fraction 10–40% — ensemble moderately over-estimates
            the blast radius.
        UNDER_PREDICTED: Gap fraction >= 40% — traversal found far fewer nodes
            than predicted (traversal may be conservative, or the ensemble is
            severely over-estimating).
        CRITICAL_MISS: VBR contains nodes NOT in PBR — the ensemble missed
            verified attack paths.  Most dangerous classification.
    """

    OVER_PREDICTED = "OVER_PREDICTED"
    UNDER_PREDICTED = "UNDER_PREDICTED"
    CALIBRATED = "CALIBRATED"
    CRITICAL_MISS = "CRITICAL_MISS"


@dataclass
class BlastRadiusAnalysis:
    """Full comparison between the Predicted and Verified Blast Radii.

    Attributes:
        pbr_nodes: Predicted Blast Radius — nodes flagged by the ensemble.
        vbr_nodes: Verified Blast Radius — nodes confirmed by IAM traversal.
        gap_nodes: PBR − VBR: predicted but not verified (over-predictions).
        missed_nodes: VBR − PBR: verified but not predicted (dangerous misses).
        pbr_size: ``len(pbr_nodes)``.
        vbr_size: ``len(vbr_nodes)``.
        gap_size: ``len(gap_nodes)``.
        gap_fraction: ``gap_size / pbr_size`` (0 = perfect, 1 = all wrong).
            Zero when ``pbr_size == 0``.
        exploitability_gap_score: 1 − Jaccard(PBR, VBR).  Ranges [0, 1];
            0 = perfect overlap, 1 = disjoint sets.
        gap_classification: High-level ``GapClassification`` label.
        per_node_exploitability: Per-node exploitability score.
            VBR nodes → 1.0; gap nodes → ensemble_risk * 0.3; others → 0.0.
        critical_paths: Verified traversal paths that reach nodes with
            ``privilege_level >= 0.8``.  Empty list if none found.
    """

    pbr_nodes: Set[str]
    vbr_nodes: Set[str]
    gap_nodes: Set[str]
    missed_nodes: Set[str]
    pbr_size: int
    vbr_size: int
    gap_size: int
    gap_fraction: float
    exploitability_gap_score: float
    gap_classification: GapClassification
    per_node_exploitability: Dict[str, float]
    critical_paths: List[List[str]]


class BlastRadiusCalculator:
    """Computes the ``BlastRadiusAnalysis`` from ensemble and traversal results.

    Example::

        calc = BlastRadiusCalculator()
        analysis = calc.compute(ensemble_prediction, traversal_result, graph)
        print(analysis.gap_classification)
        print(f"Gap: {analysis.gap_fraction:.1%}")
    """

    def compute(
        self,
        ensemble_prediction: EnsemblePrediction,
        traversal_result: TraversalResult,
        graph: TrustGraph,
    ) -> BlastRadiusAnalysis:
        """Compare PBR (ensemble) and VBR (traversal) and classify the gap.

        Args:
            ensemble_prediction: Output of ``EnsemblePredictor.predict()``.
            traversal_result: Output of ``IAMTraversal.traverse()``.
            graph: The trust graph (used for node metadata lookups).

        Returns:
            A fully populated ``BlastRadiusAnalysis``.
        """
        pbr_nodes = set(ensemble_prediction.compromised_nodes)
        vbr_nodes = set(traversal_result.verified_reachable)

        gap_nodes = pbr_nodes - vbr_nodes
        missed_nodes = vbr_nodes - pbr_nodes

        pbr_size = len(pbr_nodes)
        vbr_size = len(vbr_nodes)
        gap_size = len(gap_nodes)

        gap_fraction = gap_size / pbr_size if pbr_size > 0 else 0.0

        # 1 - Jaccard similarity as the scalar gap metric
        union_size = len(pbr_nodes | vbr_nodes)
        intersection_size = len(pbr_nodes & vbr_nodes)
        exploitability_gap_score = (
            1.0 - intersection_size / union_size if union_size > 0 else 0.0
        )

        # Classification (order matters: CRITICAL_MISS checked first)
        if missed_nodes:
            classification = GapClassification.CRITICAL_MISS
        elif gap_fraction < 0.1:
            classification = GapClassification.CALIBRATED
        elif gap_fraction < 0.4:
            classification = GapClassification.OVER_PREDICTED
        else:
            classification = GapClassification.UNDER_PREDICTED

        # Per-node exploitability
        ensemble_risk = ensemble_prediction.ensemble_risk
        all_nodes: Set[str] = set(graph._graph.nodes())
        per_node_exploitability: Dict[str, float] = {}
        for node in all_nodes:
            if node in vbr_nodes:
                per_node_exploitability[node] = 1.0
            elif node in pbr_nodes:
                per_node_exploitability[node] = ensemble_risk.get(node, 0.0) * 0.3
            else:
                per_node_exploitability[node] = 0.0

        # Critical paths from traversal to high-privilege nodes
        critical_paths = self._find_critical_paths(traversal_result, graph)

        return BlastRadiusAnalysis(
            pbr_nodes=pbr_nodes,
            vbr_nodes=vbr_nodes,
            gap_nodes=gap_nodes,
            missed_nodes=missed_nodes,
            pbr_size=pbr_size,
            vbr_size=vbr_size,
            gap_size=gap_size,
            gap_fraction=round(gap_fraction, 6),
            exploitability_gap_score=round(exploitability_gap_score, 6),
            gap_classification=classification,
            per_node_exploitability=per_node_exploitability,
            critical_paths=critical_paths,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_critical_paths(
        self,
        traversal_result: TraversalResult,
        graph: TrustGraph,
        privilege_threshold: float = 0.8,
    ) -> List[List[str]]:
        """Reconstruct paths from the BFS tree to high-privilege nodes.

        Builds a parent map from succeeded traversal steps, then traces back
        from each high-privilege node in VBR to a seed node.
        """
        # BFS parent map: first-seen parent wins (shortest path)
        parents: Dict[str, str] = {}
        for step in traversal_result.traversal_steps:
            if step.succeeded and step.to_node not in parents:
                parents[step.to_node] = step.from_node

        seed_set = set(traversal_result.seed_nodes)
        critical_paths: List[List[str]] = []

        for node_id in traversal_result.verified_reachable:
            try:
                node_meta = graph.get_node(node_id)
            except KeyError:
                continue
            if node_meta.privilege_level >= privilege_threshold:
                path = self._reconstruct_path(node_id, parents, seed_set)
                if path is not None:
                    critical_paths.append(path)

        return critical_paths

    def _reconstruct_path(
        self,
        node: str,
        parents: Dict[str, str],
        seed_set: Set[str],
    ) -> Optional[List[str]]:
        """Trace back through the BFS parent map from ``node`` to a seed."""
        path = [node]
        current = node
        visited_in_path: Set[str] = {current}
        while current not in seed_set:
            if current not in parents:
                return None
            current = parents[current]
            if current in visited_in_path:
                return None  # cycle guard (shouldn't happen in DAG)
            visited_in_path.add(current)
            path.append(current)
        return list(reversed(path))
