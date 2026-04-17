"""TrustFieldOrchestrator — main pipeline entry point for Modules 1–3.

The orchestrator wires together:
  Module 1: TopologyFingerprinter (structural analysis)
  Module 2: PropagationRunner     (5-model propagation simulation)
  Module 3: TopologyAwareSelector → WeightTracker → EnsemblePredictor

It is the primary public API that downstream modules (4 verification,
5 hardware guards, 6 visualization) call to obtain a full AnalysisResult.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from trustfield.graph.fingerprinter import TopologyFingerprinter
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.propagation.runner import PropagationRunner

from .ensemble_predictor import EnsemblePredictor, FusionMode
from .ensemble_result import AnalysisResult
from .topology_selector import TopologyAwareSelector
from .weight_tracker import WeightTracker
from .weight_vector import WeightVector


class TrustFieldOrchestrator:
    """Main entry point for the TrustField analysis pipeline (Modules 1–3).

    Instantiates and owns one instance of every pipeline component.
    Callers only need to interact with ``analyze()`` or
    ``analyze_from_topology()`` — all internal wiring is handled here.

    The weight-selection strategy is:
      1. Ask WeightTracker for adaptive weights (learned from history).
      2. If insufficient history: fall back to TopologyAwareSelector priors.

    Example::

        orch = TrustFieldOrchestrator()

        # Full analysis on an existing graph
        result = orch.analyze(graph, seed_nodes=["svc-001"])
        print(result.get_metrics_summary())

        # Convenience: generate a graph and analyse it in one call
        result = orch.analyze_from_topology("hub", num_nodes=40, seed=42)
        print(result.ensemble_prediction.compromised_nodes)
    """

    def __init__(self, db_path: str = "trustfield_weights.db") -> None:
        """Initialise all pipeline components.

        Args:
            db_path: Path for the SQLite weight history database.
                Use ``":memory:"`` for ephemeral testing sessions.
        """
        self._sim = IAMSimulator()
        self._fingerprinter = TopologyFingerprinter()
        self._runner = PropagationRunner()
        self._selector = TopologyAwareSelector()
        self._tracker = WeightTracker(db_path=db_path)
        self._predictor = EnsemblePredictor()

    # ------------------------------------------------------------------
    # Primary analysis entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        fusion_mode: FusionMode = FusionMode.WEIGHTED,
        model_kwargs: Optional[Dict] = None,
        min_history: int = 5,
        decision_threshold: Optional[float] = None,
        use_gnn: bool = True,
    ) -> AnalysisResult:
        """Run the full TrustField Modules 1–3 pipeline on a trust graph.

        Steps:
          1. Fingerprint the graph topology (Module 1).
          2. Select ensemble weights: adaptive if history available, else prior.
          3. Run all five propagation models (Module 2).
          4. Compute cross-model comparison report.
          5. Fuse model outputs into ensemble prediction (Module 3).
          6. Assemble and return the ``AnalysisResult``.

        Args:
            graph: The ``TrustGraph`` to analyse.
            seed_nodes: Initially-compromised node IDs (attacker entry points).
            fusion_mode: ``FusionMode.WEIGHTED`` (default) or
                ``FusionMode.VOTING``.
            model_kwargs: Optional per-model keyword overrides, e.g.::

                {"epidemic": {"beta": 0.4},
                 "percolation": {"n_trials": 200}}

            min_history: Minimum accuracy records before adaptive weights
                are used.  Default 5.
            decision_threshold: Override the topology-aware decision threshold.
                If ``None`` (default), the threshold recommended by
                ``TopologyAwareSelector`` for the detected topology is used.

        Returns:
            A fully-populated ``AnalysisResult``.
        """
        t_start = time.perf_counter()
        if model_kwargs is None:
            model_kwargs = {}

        # --- Step 1: Topology fingerprint ---
        fingerprint = self._fingerprinter.fingerprint(graph)
        topo_str = fingerprint.topology_type.value

        # --- Step 2: Weight selection ---
        adaptive_wv = self._tracker.get_adaptive_weights(
            topo_str, min_history=min_history
        )
        if adaptive_wv is not None:
            weight_vector = adaptive_wv
            weight_source = "adaptive"
        else:
            weight_vector = self._selector.get_initial_weights(fingerprint)
            weight_source = "topology_prior"

        # --- Step 2b: Topology-aware decision threshold ---
        threshold = (
            decision_threshold
            if decision_threshold is not None
            else self._selector.get_recommended_threshold(fingerprint)
        )

        # --- Step 3: Propagation ---
        prop_results = self._runner.run_all(graph, seed_nodes, use_gnn=use_gnn, **model_kwargs)

        # --- Step 4: Comparison report ---
        comparison = self._runner.compare_results(prop_results)

        # --- Step 5: Ensemble prediction ---
        prediction = self._predictor.predict(
            prop_results, weight_vector, fusion_mode,
            decision_threshold=threshold,
        )

        t_ms = (time.perf_counter() - t_start) * 1000.0

        return AnalysisResult(
            graph_summary=graph.summary(),
            topology_fingerprint=fingerprint,
            propagation_results=prop_results,
            comparison_report=comparison,
            ensemble_prediction=prediction,
            weight_vector_used=weight_vector,
            weight_source=weight_source,
            computation_time_ms=t_ms,
        )

    # ------------------------------------------------------------------
    # Convenience method
    # ------------------------------------------------------------------

    def analyze_from_topology(
        self,
        topology: str,
        num_nodes: int = 40,
        seed: int = 42,
        seed_node_index: int = 0,
        fusion_mode: FusionMode = FusionMode.WEIGHTED,
        model_kwargs: Optional[Dict] = None,
    ) -> AnalysisResult:
        """Generate a synthetic IAM graph and run the full analysis pipeline.

        Combines ``IAMSimulator.generate()`` + ``analyze()`` in a single call.
        Useful for benchmarking, demos, and unit tests.

        Args:
            topology: Topology preset for the IAM simulator:
                ``"hub"``, ``"chain"``, ``"dense_cluster"``, or ``"mixed"``.
            num_nodes: Target node count for the generated graph.
            seed: Random seed for reproducible graph generation.
            seed_node_index: Which node (by index in the sorted node list)
                to use as the attack entry point.
            fusion_mode: Ensemble fusion strategy.
            model_kwargs: Optional per-model kwargs (see ``analyze()``).

        Returns:
            A fully-populated ``AnalysisResult``.
        """
        graph = self._sim.generate(topology, num_nodes=num_nodes, seed=seed)
        node_list = sorted(graph._graph.nodes())
        idx = seed_node_index % len(node_list)
        seed_node = node_list[idx]
        return self.analyze(
            graph,
            seed_nodes=[seed_node],
            fusion_mode=fusion_mode,
            model_kwargs=model_kwargs,
        )
