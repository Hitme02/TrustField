"""EnsemblePredictor — fuses five propagation model outputs into one prediction.

Implements the core ensemble equation from TrustField's research contribution:

    ensemble_risk[v] = Σᵢ wᵢ · per_node_risk_i[v]

Two fusion modes are supported:
  WEIGHTED — uses the weighted sum above with topology-aware weights.
  VOTING   — majority-vote: a node is compromised if ≥ threshold fraction of
             models flag it.

The WEIGHTED mode is the primary contribution. VOTING is provided as a
baseline for ablation studies in the paper.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Set

import numpy as np

from trustfield.propagation.propagation_result import PropagationResult

from .ensemble_result import EnsemblePrediction, ModelContribution
from .weight_vector import MODEL_NAMES, WeightVector


class FusionMode(Enum):
    """Ensemble fusion strategy.

    Attributes:
        WEIGHTED: Topology-aware weighted sum of per-node risk scores.
            Primary mode and core research contribution of TrustField.
        VOTING: Simple majority-vote fusion used as a comparison baseline.
    """

    WEIGHTED = "WEIGHTED"
    VOTING = "VOTING"


class EnsemblePredictor:
    """Fuses five propagation model outputs into a single ranked prediction.

    The predictor is stateless — all inputs are passed to ``predict()`` and
    a new ``EnsemblePrediction`` is returned each time.  State (weights,
    history) lives in the ``WeightTracker`` and ``WeightVector``.

    Example::

        predictor = EnsemblePredictor()
        prediction = predictor.predict(
            propagation_results,
            weight_vector,
            fusion_mode=FusionMode.WEIGHTED,
        )
        print(prediction.compromised_nodes)
        print(prediction.high_uncertainty_nodes)
    """

    def predict(
        self,
        propagation_results: Dict[str, PropagationResult],
        weight_vector: WeightVector,
        fusion_mode: FusionMode = FusionMode.WEIGHTED,
        decision_threshold: float = 0.5,
        voting_threshold: float = 0.6,
    ) -> EnsemblePrediction:
        """Fuse propagation model outputs into an ensemble prediction.

        Args:
            propagation_results: Dict mapping model name to its
                ``PropagationResult``, as returned by ``PropagationRunner.run_all()``.
            weight_vector: The topology-aware (or adaptive) weight distribution.
            fusion_mode: ``FusionMode.WEIGHTED`` (default) or
                ``FusionMode.VOTING``.
            decision_threshold: For WEIGHTED mode — nodes with ensemble risk
                >= this threshold are flagged as compromised.  Default 0.5.
            voting_threshold: For VOTING mode — fraction of models that must
                flag a node for it to be included.  Default 0.6 (3/5 models).

        Returns:
            A fully-populated ``EnsemblePrediction``.
        """
        if fusion_mode == FusionMode.WEIGHTED:
            return self._weighted_fusion(
                propagation_results, weight_vector, decision_threshold
            )
        else:
            return self._voting_fusion(
                propagation_results, weight_vector, voting_threshold
            )

    # ------------------------------------------------------------------
    # Weighted fusion
    # ------------------------------------------------------------------

    def _weighted_fusion(
        self,
        results: Dict[str, PropagationResult],
        wv: WeightVector,
        decision_threshold: float,
    ) -> EnsemblePrediction:
        """Compute topology-aware weighted ensemble prediction.

        Algorithm:
          1. Collect all nodes appearing in any model's per_node_risk.
          2. For each node: ensemble_risk[v] = Σᵢ wᵢ · risk_i[v]
             (risk_i defaults to 0.0 if model i has no score for v).
          3. compromised = {v : ensemble_risk[v] >= decision_threshold}.
          4. Compute 95% confidence intervals and high-uncertainty nodes.
        """
        # Universe of nodes with any risk score
        all_nodes: Set[str] = set()
        for r in results.values():
            all_nodes.update(r.per_node_risk.keys())

        total_nodes = len(all_nodes)
        weights = wv.weights

        # Compute weighted ensemble risk for every node
        ensemble_risk: Dict[str, float] = {}
        for node in all_nodes:
            risk = 0.0
            for model_name, result in results.items():
                w = weights.get(model_name, 0.0)
                r_v = result.per_node_risk.get(node, 0.0)
                risk += w * r_v
            ensemble_risk[node] = min(1.0, max(0.0, risk))

        # Decision
        compromised: Set[str] = {
            v for v, r in ensemble_risk.items() if r >= decision_threshold
        }
        # Seed nodes are always compromised (guaranteed by each model)
        for result in results.values():
            for seed in result.seed_nodes:
                compromised.add(seed)

        # Confidence intervals and uncertainty
        ci, high_uncertainty = self._compute_confidence(
            all_nodes, results, ensemble_risk
        )
        # High uncertainty only meaningful for compromised nodes
        high_uncertainty = high_uncertainty & compromised

        # Model contributions
        contributions = self._build_contributions(all_nodes, results, weights)

        return EnsemblePrediction(
            compromised_nodes=compromised,
            ensemble_risk=ensemble_risk,
            confidence_interval=ci,
            high_uncertainty_nodes=high_uncertainty,
            model_contributions=contributions,
            fusion_mode=FusionMode.WEIGHTED.value,
            weight_vector=wv,
            decision_threshold=decision_threshold,
            total_nodes_analyzed=total_nodes,
        )

    # ------------------------------------------------------------------
    # Voting fusion
    # ------------------------------------------------------------------

    def _voting_fusion(
        self,
        results: Dict[str, PropagationResult],
        wv: WeightVector,
        voting_threshold: float,
    ) -> EnsemblePrediction:
        """Majority-vote ensemble fusion.

        A node is compromised if at least ``voting_threshold`` fraction of
        models flag it.  ensemble_risk[v] = votes(v) / n_models.
        """
        all_nodes: Set[str] = set()
        for r in results.values():
            all_nodes.update(r.per_node_risk.keys())

        n_models = len(results)
        vote_count: Dict[str, int] = {v: 0 for v in all_nodes}
        for result in results.values():
            for nid in result.compromised_nodes:
                if nid in vote_count:
                    vote_count[nid] += 1
                else:
                    vote_count[nid] = 1
                all_nodes.add(nid)

        # Ensure all nodes have a vote count
        for nid in all_nodes:
            vote_count.setdefault(nid, 0)

        ensemble_risk: Dict[str, float] = {
            v: vote_count[v] / n_models for v in all_nodes
        }

        min_votes = voting_threshold * n_models
        compromised: Set[str] = {
            v for v, count in vote_count.items() if count >= min_votes
        }
        for result in results.values():
            for seed in result.seed_nodes:
                compromised.add(seed)

        ci, high_uncertainty = self._compute_confidence(
            all_nodes, results, ensemble_risk
        )
        high_uncertainty = high_uncertainty & compromised

        contributions = self._build_contributions(
            all_nodes, results, wv.weights
        )

        return EnsemblePrediction(
            compromised_nodes=compromised,
            ensemble_risk=ensemble_risk,
            confidence_interval=ci,
            high_uncertainty_nodes=high_uncertainty,
            model_contributions=contributions,
            fusion_mode=FusionMode.VOTING.value,
            weight_vector=wv,
            decision_threshold=voting_threshold,
            total_nodes_analyzed=len(all_nodes),
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _compute_confidence(
        self,
        all_nodes: Set[str],
        results: Dict[str, PropagationResult],
        ensemble_risk: Dict[str, float],
    ) -> tuple[Dict[str, tuple], Set[str]]:
        """Compute 95% confidence intervals and identify high-uncertainty nodes.

        For each node, collects per-model risk values and computes:
          - mean ± 1.96 · std  → 95% CI bounds, clamped to [0, 1]
          - high_uncertainty: nodes where std_dev > 0.25

        Args:
            all_nodes: Universe of node IDs.
            results: Raw propagation results.
            ensemble_risk: Already-computed ensemble risk scores.

        Returns:
            Tuple of (confidence_interval_dict, high_uncertainty_set).
        """
        ci: Dict[str, tuple] = {}
        high_uncertainty: Set[str] = set()

        for node in all_nodes:
            per_model_risks = [
                result.per_node_risk.get(node, 0.0)
                for result in results.values()
            ]
            arr = np.array(per_model_risks)
            mean = float(np.mean(arr))
            std = float(np.std(arr))
            margin = 1.96 * std
            lower = max(0.0, mean - margin)
            upper = min(1.0, mean + margin)
            ci[node] = (round(lower, 4), round(upper, 4))
            if std > 0.25:
                high_uncertainty.add(node)

        return ci, high_uncertainty

    def _build_contributions(
        self,
        all_nodes: Set[str],
        results: Dict[str, PropagationResult],
        weights: Dict[str, float],
    ) -> List[ModelContribution]:
        """Build one ModelContribution record per model.

        Args:
            all_nodes: Universe of node IDs.
            results: Raw propagation results.
            weights: Ensemble weight dict.

        Returns:
            List of ``ModelContribution`` objects.
        """
        contributions: List[ModelContribution] = []
        for model_name, result in results.items():
            w = weights.get(model_name, 0.0)
            weighted_contrib: Dict[str, float] = {
                node: w * result.per_node_risk.get(node, 0.0)
                for node in all_nodes
            }
            contributions.append(
                ModelContribution(
                    model_name=model_name,
                    weight=w,
                    contributed_nodes=set(result.compromised_nodes),
                    weighted_risk_contribution=weighted_contrib,
                )
            )
        return contributions

    def compute_confidence_interval(
        self,
        propagation_results: Dict[str, PropagationResult],
        ensemble_risk: Dict[str, float],
    ) -> Dict[str, tuple]:
        """Public API: compute 95% CI for all nodes.

        Args:
            propagation_results: Dict of model results.
            ensemble_risk: Already-computed ensemble risk scores.

        Returns:
            ``{node_id: (lower_bound, upper_bound)}`` at 95% confidence.
        """
        all_nodes = set(ensemble_risk.keys())
        ci, _ = self._compute_confidence(all_nodes, propagation_results, ensemble_risk)
        return ci
