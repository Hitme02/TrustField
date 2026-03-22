"""PropagationRunner — orchestrates all five TrustField propagation models.

Provides a single entry point to run the full Multi-Model Propagation Engine
(Module 2) and compare results across models. The ``ComparisonReport`` output
is fed into Module 3's ensemble predictor.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Set

from trustfield.graph.trust_graph import TrustGraph

from .control_system import ControlSystemModel
from .epidemic import EpidemicModel
from .gnn_model import GNNModel
from .graph_traversal import GraphTraversalModel
from .percolation import PercolationModel
from .propagation_result import PropagationResult
from .spectral_cascade import SpectralCascadeModel

_ALL_MODEL_NAMES = [
    "graph_traversal",
    "epidemic",
    "spectral_cascade",
    "percolation",
    "control_system",
    "gnn",
]


@dataclass
class ComparisonReport:
    """Cross-model comparison of propagation results.

    Summarises agreement and disagreement between the five propagation models.
    Used by Module 3's ensemble predictor to weight model contributions and by
    Module 4's verification engine to prioritise which predicted paths to verify.

    Attributes:
        union_compromised: All nodes flagged as compromised by ANY model.
            This is the pessimistic (worst-case) compromise surface.
        intersection_compromised: Nodes flagged by ALL models simultaneously.
            This is the high-confidence compromise core.
        agreement_score: Jaccard similarity coefficient across all model
            compromised sets — measures overall model consensus.
            0.0 = total disagreement, 1.0 = perfect agreement.
        per_node_consensus: Mapping from node_id to the count of models that
            flagged it as compromised. Range: 0 (no model) to 5 (all models).
        most_dangerous_nodes: Top 5 node IDs sorted by consensus count
            descending (ties broken by average per-node risk).
        model_names: Ordered list of model names included in this report.
        cascade_probability_spread: Stdev of cascade probabilities across models.
            High spread indicates models disagree on cascade likelihood.
        avg_cascade_probability: Mean cascade probability across all models.
    """

    union_compromised: Set[str]
    intersection_compromised: Set[str]
    agreement_score: float
    per_node_consensus: Dict[str, int]
    most_dangerous_nodes: List[str]
    model_names: List[str] = field(default_factory=list)
    cascade_probability_spread: float = 0.0
    avg_cascade_probability: float = 0.0

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dictionary.

        Returns:
            Dictionary representation of this report.
        """
        return {
            "union_compromised": sorted(self.union_compromised),
            "intersection_compromised": sorted(self.intersection_compromised),
            "agreement_score": self.agreement_score,
            "per_node_consensus": self.per_node_consensus,
            "most_dangerous_nodes": self.most_dangerous_nodes,
            "model_names": self.model_names,
            "cascade_probability_spread": self.cascade_probability_spread,
            "avg_cascade_probability": self.avg_cascade_probability,
        }


class PropagationRunner:
    """Orchestrates all five TrustField propagation models.

    Instantiates one instance of each model and provides convenience methods
    to run all models, run individual models, and compare results.

    Example::

        runner = PropagationRunner()
        results = runner.run_all(graph, seed_nodes=["svc-001"],
                                 epidemic={"beta": 0.4},
                                 percolation={"n_trials": 200})
        report = runner.compare_results(results)
        print(report.most_dangerous_nodes)
    """

    def __init__(self) -> None:
        """Initialise runner with one instance of each propagation model.

        GNNModel is instantiated with ``auto_train=False`` so that the runner
        does not trigger a slow training run on first import.  The GNN falls
        back to GraphTraversalModel output until weights are explicitly trained
        and saved to ``models/gnn.pt``.
        """
        self._models: Dict[str, object] = {
            "graph_traversal": GraphTraversalModel(),
            "epidemic": EpidemicModel(),
            "spectral_cascade": SpectralCascadeModel(),
            "percolation": PercolationModel(),
            "control_system": ControlSystemModel(),
            "gnn": GNNModel(auto_train=False),
        }

    def run_all(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        **model_kwargs,
    ) -> Dict[str, PropagationResult]:
        """Run all five propagation models on the trust graph.

        Args:
            graph: The trust graph to propagate through.
            seed_nodes: Initially compromised node IDs.
            **model_kwargs: Per-model keyword arguments, keyed by model name.
                For example::

                    runner.run_all(
                        graph, seed_nodes,
                        epidemic={"beta": 0.4},
                        percolation={"n_trials": 200},
                    )

                Any model not mentioned gets default kwargs.

        Returns:
            Dictionary mapping model name to its ``PropagationResult``.
        """
        results: Dict[str, PropagationResult] = {}
        for name, model in self._models.items():
            kwargs = model_kwargs.get(name, {})
            results[name] = model.run(graph, seed_nodes, **kwargs)
        return results

    def run_single(
        self,
        model_name: str,
        graph: TrustGraph,
        seed_nodes: List[str],
        **kwargs,
    ) -> PropagationResult:
        """Run a single propagation model by name.

        Args:
            model_name: One of ``"graph_traversal"``, ``"epidemic"``,
                ``"spectral_cascade"``, ``"percolation"``,
                ``"control_system"``.
            graph: The trust graph to propagate through.
            seed_nodes: Initially compromised node IDs.
            **kwargs: Model-specific keyword arguments passed directly.

        Returns:
            The ``PropagationResult`` from the specified model.

        Raises:
            ValueError: If ``model_name`` is not a recognised model.
            KeyError: If any seed node ID is not present in ``graph``.
        """
        if model_name not in self._models:
            raise ValueError(
                f"Unknown model '{model_name}'. "
                f"Choose from: {list(self._models.keys())}"
            )
        return self._models[model_name].run(graph, seed_nodes, **kwargs)

    def compare_results(
        self,
        results: Dict[str, PropagationResult],
    ) -> ComparisonReport:
        """Compute cross-model comparison statistics.

        Computes the union, intersection, Jaccard similarity, per-node
        consensus count, and most-dangerous-node ranking across all provided
        model results.

        The Jaccard similarity is computed as:
            |union| > 0: |intersection| / |union|
            |union| == 0: 1.0  (all models agree there are no compromised nodes)

        Args:
            results: Dictionary of model_name → ``PropagationResult`` as
                returned by ``run_all()``.

        Returns:
            A ``ComparisonReport`` summarising cross-model agreement.
        """
        if not results:
            return ComparisonReport(
                union_compromised=set(),
                intersection_compromised=set(),
                agreement_score=1.0,
                per_node_consensus={},
                most_dangerous_nodes=[],
            )

        compromised_sets = [r.compromised_nodes for r in results.values()]

        union_compromised: Set[str] = set()
        for s in compromised_sets:
            union_compromised |= s

        intersection_compromised: Set[str] = compromised_sets[0].copy()
        for s in compromised_sets[1:]:
            intersection_compromised &= s

        # Jaccard similarity
        union_size = len(union_compromised)
        intersection_size = len(intersection_compromised)
        agreement_score = (
            intersection_size / union_size if union_size > 0 else 1.0
        )

        # Per-node consensus: how many models flagged each node
        per_node_consensus: Dict[str, int] = {}
        for s in compromised_sets:
            for nid in s:
                per_node_consensus[nid] = per_node_consensus.get(nid, 0) + 1

        # Average per-node risk across models (for tie-breaking)
        avg_risk: Dict[str, float] = {}
        n_models = len(results)
        for result in results.values():
            for nid, risk in result.per_node_risk.items():
                avg_risk[nid] = avg_risk.get(nid, 0.0) + risk / n_models

        # Most dangerous nodes: top 5 by consensus count, ties broken by avg risk
        sorted_nodes = sorted(
            per_node_consensus.keys(),
            key=lambda nid: (per_node_consensus[nid], avg_risk.get(nid, 0.0)),
            reverse=True,
        )
        most_dangerous_nodes = sorted_nodes[:5]

        # Cascade probability statistics
        import numpy as np
        cascade_probs = [r.cascade_probability for r in results.values()]
        cascade_spread = float(np.std(cascade_probs)) if len(cascade_probs) > 1 else 0.0
        avg_cascade = float(np.mean(cascade_probs)) if cascade_probs else 0.0

        return ComparisonReport(
            union_compromised=union_compromised,
            intersection_compromised=intersection_compromised,
            agreement_score=agreement_score,
            per_node_consensus=per_node_consensus,
            most_dangerous_nodes=most_dangerous_nodes,
            model_names=list(results.keys()),
            cascade_probability_spread=cascade_spread,
            avg_cascade_probability=avg_cascade,
        )
