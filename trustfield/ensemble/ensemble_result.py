"""EnsemblePrediction and AnalysisResult dataclasses for Module 3.

These dataclasses carry the outputs of the full TrustField analysis pipeline
(Modules 1–3) and are the primary inputs consumed by Module 4 (verification),
Module 5 (hardware guards), and Module 6 (visualization).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from trustfield.graph.fingerprinter import TopologyFingerprint
from trustfield.propagation.propagation_result import PropagationResult
from trustfield.propagation.runner import ComparisonReport

from .weight_vector import WeightVector


@dataclass
class ModelContribution:
    """Records the contribution of one model to the ensemble prediction.

    Attributes:
        model_name: Name of the propagation model.
        weight: Weight assigned to this model in the ensemble.
        contributed_nodes: Nodes this model flagged as compromised.
        weighted_risk_contribution: Per-node weighted risk contribution
            (model's per_node_risk × its weight).
    """

    model_name: str
    weight: float
    contributed_nodes: Set[str]
    weighted_risk_contribution: Dict[str, float]


@dataclass
class EnsemblePrediction:
    """The fused output of the five-model TrustField ensemble.

    Attributes:
        compromised_nodes: Final set of nodes predicted compromised after
            applying the decision threshold to the ensemble risk scores.
        ensemble_risk: Per-node blended risk score in [0.0, 1.0].
            Computed as Σᵢ wᵢ · risk_i(v) for WEIGHTED fusion, or
            votes(v) / n_models for VOTING fusion.
        confidence_interval: Per-node 95% confidence interval as
            ``{node_id: (lower, upper)}``, derived from the spread of
            individual model risk predictions.
        high_uncertainty_nodes: Subset of ``compromised_nodes`` where models
            disagree strongly (std_dev of per-model risks > 0.25).
        model_contributions: One ``ModelContribution`` per model.
        fusion_mode: ``"WEIGHTED"`` or ``"VOTING"``.
        weight_vector: The WeightVector used for this prediction.
        decision_threshold: Risk threshold above which a node is flagged
            as compromised.
        total_nodes_analyzed: Number of nodes in the input graph.
    """

    compromised_nodes: Set[str]
    ensemble_risk: Dict[str, float]
    confidence_interval: Dict[str, tuple]
    high_uncertainty_nodes: Set[str]
    model_contributions: List[ModelContribution]
    fusion_mode: str
    weight_vector: WeightVector
    decision_threshold: float
    total_nodes_analyzed: int

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary.

        Returns:
            Dictionary with all fields as JSON primitives.
        """
        return {
            "compromised_nodes": sorted(self.compromised_nodes),
            "ensemble_risk": self.ensemble_risk,
            "confidence_interval": {
                k: list(v) for k, v in self.confidence_interval.items()
            },
            "high_uncertainty_nodes": sorted(self.high_uncertainty_nodes),
            "model_contributions": [
                {
                    "model_name": mc.model_name,
                    "weight": mc.weight,
                    "contributed_nodes": sorted(mc.contributed_nodes),
                    "weighted_risk_contribution": mc.weighted_risk_contribution,
                }
                for mc in self.model_contributions
            ],
            "fusion_mode": self.fusion_mode,
            "weight_vector": self.weight_vector.to_dict(),
            "decision_threshold": self.decision_threshold,
            "total_nodes_analyzed": self.total_nodes_analyzed,
        }


@dataclass
class AnalysisResult:
    """Complete output of the TrustField Modules 1–3 analysis pipeline.

    This is the primary artifact produced by ``TrustFieldOrchestrator.analyze()``
    and consumed by all downstream modules.

    Attributes:
        graph_summary: Output of ``TrustGraph.summary()``.
        topology_fingerprint: Structural fingerprint from Module 1.
        propagation_results: Raw outputs from all five Module 2 models.
        comparison_report: Cross-model comparison from ``PropagationRunner``.
        ensemble_prediction: Fused prediction from Module 3.
        weight_vector_used: The WeightVector that governed this prediction.
        weight_source: ``"topology_prior"`` or ``"adaptive"``.
        computation_time_ms: Total wall-clock time for the full pipeline.
    """

    graph_summary: dict
    topology_fingerprint: TopologyFingerprint
    propagation_results: Dict[str, PropagationResult]
    comparison_report: ComparisonReport
    ensemble_prediction: EnsemblePrediction
    weight_vector_used: WeightVector
    weight_source: str
    computation_time_ms: float

    def to_dict(self) -> dict:
        """Full JSON-serialisable export of the analysis result.

        Returns:
            A nested dictionary representing the complete pipeline output.
        """
        return {
            "graph_summary": self.graph_summary,
            "topology_fingerprint": self.topology_fingerprint.to_dict(),
            "propagation_results": {
                name: r.to_dict()
                for name, r in self.propagation_results.items()
            },
            "comparison_report": self.comparison_report.to_dict(),
            "ensemble_prediction": self.ensemble_prediction.to_dict(),
            "weight_vector_used": self.weight_vector_used.to_dict(),
            "weight_source": self.weight_source,
            "computation_time_ms": self.computation_time_ms,
        }

    def get_metrics_summary(self) -> dict:
        """Return a publication-ready metrics dictionary.

        Suitable for tabulation in research papers or API responses.

        Returns:
            Dictionary with keys:
                - ``"predicted_blast_radius"``: number of compromised nodes.
                - ``"prediction_confidence"``: mean ensemble risk across all nodes.
                - ``"model_agreement_score"``: Jaccard similarity across models.
                - ``"topology_type"``: topology classification string.
                - ``"high_uncertainty_fraction"``: fraction of total nodes
                  that are in the high-uncertainty set.
        """
        ep = self.ensemble_prediction
        n_total = ep.total_nodes_analyzed
        mean_risk = (
            sum(ep.ensemble_risk.values()) / len(ep.ensemble_risk)
            if ep.ensemble_risk else 0.0
        )
        uncertainty_frac = (
            len(ep.high_uncertainty_nodes) / n_total
            if n_total > 0 else 0.0
        )
        return {
            "predicted_blast_radius": len(ep.compromised_nodes),
            "prediction_confidence": round(mean_risk, 4),
            "model_agreement_score": round(
                self.comparison_report.agreement_score, 4
            ),
            "topology_type": self.topology_fingerprint.topology_type.value,
            "high_uncertainty_fraction": round(uncertainty_frac, 4),
        }
