"""Evasion evaluator for TrustField adversarial robustness testing.

Measures whether an adversarially-mutated graph evades TrustField's ensemble
detection while preserving the attacker's actual reachability.

Evasion success requires TWO conditions:
  1. reachability_preserved — the VBR on the mutated graph is >= 80% of the
     original VBR (the attacker still reaches their targets).
  2. EGD improvement > 0.1 — the exploitability gap (misalignment between
     the ensemble's PBR and the verified VBR) grew by more than 0.1,
     meaning TrustField became less accurate after the mutation.

trustfield_robustness = 1.0 − evasion_improvement  (clamped [0, 1])
A robustness score near 1.0 means TrustField correctly detected the
mutated graph; near 0.0 means the evasion fully succeeded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from trustfield.adversarial.graph_mutator import AdversarialGraphMutator, MutationStrategy
from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification import BlastRadiusCalculator, IAMTraversal
from trustfield.verification.delegation_token import TokenGenerator


@dataclass
class EvasionResult:
    """Outcome of a single evasion attempt.

    Attributes:
        strategy: Name of the mutation strategy applied.
        intensity: Mutation intensity in ``[0.0, 1.0]``.
        topology_type: Topology label of the original graph (e.g. ``"CHAIN"``).
        original_vbr_size: Number of verified-reachable nodes before mutation.
        mutated_vbr_size: Number of verified-reachable nodes after mutation.
        reachability_preserved: True when ``mutated_vbr_size >= original_vbr_size * 0.8``.
        original_pbr_size: Ensemble-predicted blast-radius size before mutation.
        mutated_pbr_size: Ensemble-predicted blast-radius size after mutation.
        original_egd_score: Exploitability-gap score (1 − Jaccard(PBR, VBR))
            before mutation.
        mutated_egd_score: Exploitability-gap score after mutation.
        evasion_success: True when reachability is preserved AND the EGD
            improvement exceeds 0.1.
        evasion_improvement: ``mutated_egd_score − original_egd_score``
            (positive = attacker gained ground, negative = TrustField improved).
        trustfield_robustness: ``clamp(1.0 − evasion_improvement, 0, 1)``.
    """

    strategy: str
    intensity: float
    topology_type: str
    original_vbr_size: int
    mutated_vbr_size: int
    reachability_preserved: bool
    original_pbr_size: int
    mutated_pbr_size: int
    original_egd_score: float
    mutated_egd_score: float
    evasion_success: bool
    evasion_improvement: float
    trustfield_robustness: float


_DEFAULT_STRATEGIES = [
    MutationStrategy.EDGE_SPLITTING,
    MutationStrategy.PRIVILEGE_DILUTION,
    MutationStrategy.CHAIN_OBFUSCATION,
]
_DEFAULT_INTENSITIES = [0.2, 0.4, 0.6]


class EvasionEvaluator:
    """Evaluates TrustField's robustness against each mutation strategy.

    For each (strategy, intensity) combination:
      1. Mutate the graph.
      2. Run TrustFieldOrchestrator on both the original and mutated graphs.
      3. Run IAMTraversal on both graphs to get VBR.
      4. Compute BlastRadiusAnalysis for both → EGD scores.
      5. Compute evasion metrics and return an ``EvasionResult``.

    Example::

        evaluator = EvasionEvaluator()
        results = evaluator.evaluate(graph, seed_nodes, orchestrator)
        for r in results:
            print(f"{r.strategy} @ {r.intensity}: "
                  f"evasion={r.evasion_success}, robustness={r.trustfield_robustness:.3f}")

    Args:
        mutator: ``AdversarialGraphMutator`` instance (created with defaults if
            not supplied).
        traversal_max_depth: Maximum BFS depth for IAMTraversal (default 8).
        percolation_n_trials: Number of Monte-Carlo trials for the percolation
            model inside the orchestrator (default 20 — low for speed).
        mutation_seed: Random seed passed to each mutator call.
    """

    def __init__(
        self,
        mutator: Optional[AdversarialGraphMutator] = None,
        traversal_max_depth: int = 8,
        percolation_n_trials: int = 20,
        mutation_seed: int = 42,
    ) -> None:
        self._mutator = mutator or AdversarialGraphMutator()
        self._max_depth = traversal_max_depth
        self._n_trials = percolation_n_trials
        self._seed = mutation_seed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        orchestrator: TrustFieldOrchestrator,
        strategies: Optional[List[MutationStrategy]] = None,
        intensities: Optional[List[float]] = None,
    ) -> List[EvasionResult]:
        """Run all (strategy, intensity) combinations and return results.

        Args:
            graph: Original TrustGraph to evaluate.
            seed_nodes: Attacker entry-point node IDs.
            orchestrator: TrustFieldOrchestrator for ensemble analysis.
            strategies: List of :class:`MutationStrategy` to evaluate.
                Defaults to all three strategies.
            intensities: List of intensity values to sweep.
                Defaults to ``[0.2, 0.4, 0.6]``.

        Returns:
            List of :class:`EvasionResult` — one per (strategy, intensity) pair.
        """
        if strategies is None:
            strategies = _DEFAULT_STRATEGIES
        if intensities is None:
            intensities = _DEFAULT_INTENSITIES

        # Compute original baseline once
        orig = self._analyse(graph, seed_nodes, orchestrator)

        results: List[EvasionResult] = []
        for strategy in strategies:
            for intensity in intensities:
                mutated = self._mutator.mutate(
                    graph, strategy, intensity=intensity, seed=self._seed
                )
                mut = self._analyse(mutated, seed_nodes, orchestrator)

                evasion_improvement = round(mut["egd"] - orig["egd"], 6)
                reachability_preserved = mut["vbr_size"] >= orig["vbr_size"] * 0.8
                evasion_success = (
                    reachability_preserved and evasion_improvement > 0.1
                )
                robustness = round(max(0.0, min(1.0, 1.0 - evasion_improvement)), 6)

                results.append(EvasionResult(
                    strategy=strategy.value,
                    intensity=intensity,
                    topology_type=orig["topology_type"],
                    original_vbr_size=orig["vbr_size"],
                    mutated_vbr_size=mut["vbr_size"],
                    reachability_preserved=reachability_preserved,
                    original_pbr_size=orig["pbr_size"],
                    mutated_pbr_size=mut["pbr_size"],
                    original_egd_score=orig["egd"],
                    mutated_egd_score=mut["egd"],
                    evasion_success=evasion_success,
                    evasion_improvement=evasion_improvement,
                    trustfield_robustness=robustness,
                ))

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _analyse(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        orchestrator: TrustFieldOrchestrator,
    ) -> dict:
        """Run the full TrustField pipeline on a graph and return key metrics."""
        # Filter seed_nodes to those present in this graph (mutations add nodes
        # but never remove them, so seed_nodes should always be present)
        valid_seeds = [n for n in seed_nodes if n in graph._graph]
        if not valid_seeds:
            valid_seeds = [list(graph._graph.nodes())[0]]

        # Ensemble prediction (PBR)
        analysis = orchestrator.analyze(
            graph,
            valid_seeds,
            model_kwargs={"percolation": {"n_trials": self._n_trials}},
        )
        topology_type = analysis.topology_fingerprint.topology_type.value

        # Verified traversal (VBR)
        tgen = TokenGenerator()
        traversal = IAMTraversal(tgen).traverse(
            graph, valid_seeds,
            max_depth=self._max_depth,
            respect_conditions=False,
        )

        # Exploitability gap (EGD)
        bra = BlastRadiusCalculator().compute(
            analysis.ensemble_prediction, traversal, graph
        )

        return {
            "pbr_size": bra.pbr_size,
            "vbr_size": bra.vbr_size,
            "egd": bra.exploitability_gap_score,
            "topology_type": topology_type,
        }
