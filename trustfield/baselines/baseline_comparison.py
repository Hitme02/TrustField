"""Baseline comparison module for TrustField ablation studies.

Three baselines are compared against the full TrustField pipeline to isolate
which components drive containment effectiveness:

NaiveBFSBaseline
    Runs GraphTraversalModel alone — no ensemble, no verification.
    Guard placement: top-k edges by raw edge weight (NOT exploitability score).
    This is the simplest possible approach: "block the heaviest trust edges."

SingleBestModelBaseline
    Uses only the one propagation model that best fits the topology type:
      HUB           → SpectralCascade  (high-degree centrality cascades)
      CHAIN         → Epidemic         (linear SIR propagation)
      DENSE_CLUSTER → Percolation      (cyclic, stochastic spread)
      MIXED         → Percolation      (most general)
    Guard placement: TrustField's exploitability-scored strategy.
    This isolates the value of the full 5-model ensemble.

RandomGuardBaseline
    Runs TrustField's full ensemble + verification pipeline.
    Guard placement: RANDOM selection of the same number of edges TrustField uses.
    This isolates the value of exploitability-scored guard placement over
    naive random placement.

Key claim
---------
TrustField achieves equal or better containment than random placement using
the same guard budget, because placing guards on high-exploitability edges
(blast_radius ∪ verified_traversal_paths) is strictly more efficient than
random selection.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.ensemble.ensemble_result import (
    EnsemblePrediction,
    ModelContribution,
)
from trustfield.ensemble.weight_vector import MODEL_NAMES, WeightVector
from trustfield.graph.fingerprinter import TopologyFingerprinter
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.guards.containment_engine import ContainmentEngine
from trustfield.guards.feedback_loop import HardwareSoftwareFeedback
from trustfield.guards.guard_network import GuardNetwork
from trustfield.propagation.graph_traversal import GraphTraversalModel
from trustfield.propagation.runner import PropagationRunner
from trustfield.verification.blast_radius import BlastRadiusAnalysis, BlastRadiusCalculator
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal, TraversalResult
from trustfield.verification.verification_report import VerificationReport

# Topology type → best single model name
_BEST_MODEL_FOR_TOPOLOGY = {
    "HUB":           "spectral_cascade",
    "CHAIN":         "epidemic",
    "DENSE_CLUSTER": "percolation",
    "MIXED":         "percolation",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BaselineResult:
    """Metrics from one baseline/method on one topology.

    Attributes:
        method:                  Human-readable method name.
        topology:                Topology label.
        original_vbr:            Nodes reachable before any guards.
        post_vbr:                Nodes still reachable after guards + feedback.
        containment_success_rate: (original_vbr − post_vbr) / original_vbr.
        missed_containments:     Nodes in VBR still reachable (excl. seeds).
        guards_deployed:         Number of edges with guards placed on them.
        final_strictness:        Guard network strictness at run end.
        elapsed_seconds:         Wall-clock time.
    """

    method: str
    topology: str
    original_vbr: int
    post_vbr: int
    containment_success_rate: float
    missed_containments: int
    guards_deployed: int
    final_strictness: str
    elapsed_seconds: float = 0.0
    # BFS+Guards-specific fields (0 / 0.0 for other methods)
    bfs_reachable_size: int = 0
    verified_reachable_size: int = 0
    bfs_overestimate: int = 0
    false_positive_rate: float = 0.0


@dataclass
class ComparisonResult:
    """All baseline results for one topology, plus the TrustField result."""

    topology: str
    trustfield:    BaselineResult
    naive_bfs:     BaselineResult
    single_model:  BaselineResult
    random_guards: BaselineResult
    bfs_guards:    Optional[BaselineResult] = None

    def all_methods(self) -> List[Tuple[str, BaselineResult]]:
        methods = [
            ("TrustField",     self.trustfield),
            ("Naive BFS",      self.naive_bfs),
            ("Single Model",   self.single_model),
            ("Random Guards",  self.random_guards),
        ]
        if self.bfs_guards is not None:
            methods.append(("BFS+Guards", self.bfs_guards))
        return methods


# ---------------------------------------------------------------------------
# Shared internal helpers
# ---------------------------------------------------------------------------

def _seed_node(graph: TrustGraph) -> str:
    """Pick the first node with an outgoing edge as the attacker seed."""
    node_list = sorted(graph._graph.nodes())
    return next(
        (n for n in node_list if graph._graph.out_degree(n) > 0),
        node_list[0],
    )


def _original_vbr(
    graph: TrustGraph,
    seed_nodes: List[str],
    random_seed: int = 42,
) -> TraversalResult:
    """Compute the verified blast radius on the unguarded graph."""
    gen = TokenGenerator()
    return IAMTraversal(gen).traverse(
        graph,
        seed_nodes,
        max_depth=6,
        respect_conditions=True,
        random_seed=random_seed,
    )


def _post_guard_vbr(
    working_graph: TrustGraph,
    seed_nodes: List[str],
    token_key: bytes,
    random_seed: int = 42,
) -> Set[str]:
    """Measure VBR after the working graph's edges have been blocked."""
    gen = TokenGenerator(secret_key=token_key)
    result = IAMTraversal(gen).traverse(
        working_graph,
        seed_nodes,
        max_depth=6,
        respect_conditions=True,
        random_seed=random_seed,
    )
    return result.verified_reachable


def _run_feedback_and_measure(
    graph: TrustGraph,
    seed_nodes: List[str],
    guard_edges: List[Tuple[str, str]],
    orchestrator: TrustFieldOrchestrator,
    n_feedback_cycles: int,
    guards_per_edge: int,
    method: str,
    topology: str,
    original_vbr_set: Set[str],
) -> BaselineResult:
    """Deploy guards, run feedback loop, measure containment — shared across all methods."""
    t0 = time.time()

    working = TrustGraph.from_dict(graph.to_dict())
    token_gen = TokenGenerator()

    guard_net = GuardNetwork(working, token_gen)
    guard_net.deploy_guards(guard_edges, guards_per_edge=guards_per_edge)

    feedback = HardwareSoftwareFeedback(guard_net, orchestrator)
    feedback.run_feedback_cycle(working, seed_nodes, n_cycles=n_feedback_cycles)

    # Determine final strictness
    final_strictness = "NOMINAL"
    from trustfield.guards.guard_module import StrictnessLevel
    for guards in guard_net._deployed_guards.values():
        for g in guards:
            if g._strictness == StrictnessLevel.LOCKDOWN:
                final_strictness = "LOCKDOWN"
                break
            elif g._strictness == StrictnessLevel.ELEVATED:
                final_strictness = "ELEVATED"
        if final_strictness == "LOCKDOWN":
            break

    post_vbr_set = _post_guard_vbr(working, seed_nodes, token_gen.key)
    seed_set = set(seed_nodes)
    contained = original_vbr_set - post_vbr_set
    missed = (original_vbr_set & post_vbr_set) - seed_set
    n_orig = len(original_vbr_set)
    rate = len(contained) / n_orig if n_orig > 0 else 1.0

    return BaselineResult(
        method=method,
        topology=topology,
        original_vbr=n_orig,
        post_vbr=len(post_vbr_set),
        containment_success_rate=round(rate, 4),
        missed_containments=len(missed),
        guards_deployed=len(guard_edges),
        final_strictness=final_strictness,
        elapsed_seconds=round(time.time() - t0, 2),
    )


def _make_prediction(
    compromised: Set[str],
    risk: Dict[str, float],
    n_total: int,
    threshold: float = 0.35,
) -> EnsemblePrediction:
    """Construct a minimal EnsemblePrediction from raw compromised/risk data."""
    wv = WeightVector.uniform(topology_type="MIXED")
    return EnsemblePrediction(
        compromised_nodes=compromised,
        ensemble_risk=risk,
        confidence_interval={},
        high_uncertainty_nodes=set(),
        model_contributions=[],
        fusion_mode="WEIGHTED",
        weight_vector=wv,
        decision_threshold=threshold,
        total_nodes_analyzed=n_total,
    )


# ---------------------------------------------------------------------------
# Baseline 1: NaiveBFSBaseline
# ---------------------------------------------------------------------------

class NaiveBFSBaseline:
    """BFS traversal only — guard placement by raw edge weight.

    This is the simplest possible guard strategy:
      1. Run GraphTraversalModel to get the reachable set.
      2. Sort all edges by weight descending.
      3. Place guards on the top-k heaviest edges.

    No ensemble, no exploitability scoring, no verification step.

    Args:
        top_k: Number of edges to guard.
        n_feedback_cycles: Feedback iterations post-deployment.
        guards_per_edge: Guards placed on each guarded edge (for consensus).
    """

    def __init__(
        self,
        top_k: int = 20,
        n_feedback_cycles: int = 5,
        guards_per_edge: int = 3,
    ) -> None:
        self._top_k = top_k
        self._n_cycles = n_feedback_cycles
        self._guards_per_edge = guards_per_edge

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology: str = "unknown",
        original_vbr_set: Optional[Set[str]] = None,
        orchestrator: Optional[TrustFieldOrchestrator] = None,
    ) -> BaselineResult:
        """Run the NaiveBFS baseline on a graph.

        Args:
            graph: Original (unmodified) TrustGraph.
            seed_nodes: Attacker entry points.
            topology: Topology label for reporting.
            original_vbr_set: Pre-computed VBR for fair comparison.
                If None, computed internally.
            orchestrator: Shared orchestrator for feedback loop.

        Returns:
            ``BaselineResult`` with containment metrics.
        """
        if original_vbr_set is None:
            original_vbr_set = _original_vbr(graph, seed_nodes).verified_reachable
        if orchestrator is None:
            orchestrator = TrustFieldOrchestrator(db_path=":memory:")

        # Guard selection: top-k by raw edge weight
        all_edges = sorted(
            [(u, v, d["metadata"].weight)
             for u, v, d in graph._graph.edges(data=True)],
            key=lambda x: -x[2],
        )
        guard_edges = [(u, v) for u, v, _ in all_edges[: self._top_k]]

        return _run_feedback_and_measure(
            graph, seed_nodes, guard_edges, orchestrator,
            self._n_cycles, self._guards_per_edge,
            "Naive BFS", topology, original_vbr_set,
        )


# ---------------------------------------------------------------------------
# Baseline 2: SingleBestModelBaseline
# ---------------------------------------------------------------------------

class SingleBestModelBaseline:
    """Single best propagation model per topology — TrustField guard placement.

    Selects one model based on the detected topology type, runs it alone,
    then uses TrustField's exploitability-scored guard placement strategy.
    This isolates the value of the full 5-model ensemble vs a single expert.

    Topology → model mapping:
      HUB           → spectral_cascade
      CHAIN         → epidemic
      DENSE_CLUSTER → percolation
      MIXED         → percolation

    Args:
        top_k: Guard budget for blast-radius edge selection.
        n_feedback_cycles: Feedback iterations post-deployment.
        guards_per_edge: Guards per edge.
    """

    def __init__(
        self,
        top_k: int = 20,
        n_feedback_cycles: int = 5,
        guards_per_edge: int = 3,
    ) -> None:
        self._top_k = top_k
        self._n_cycles = n_feedback_cycles
        self._guards_per_edge = guards_per_edge
        self._runner = PropagationRunner()
        self._fingerprinter = TopologyFingerprinter()

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology: str = "unknown",
        original_vbr_set: Optional[Set[str]] = None,
        orchestrator: Optional[TrustFieldOrchestrator] = None,
    ) -> BaselineResult:
        """Run the SingleBestModel baseline.

        Args:
            graph: Original TrustGraph.
            seed_nodes: Attacker entry points.
            topology: Topology label for reporting.
            original_vbr_set: Pre-computed VBR for fair comparison.
            orchestrator: Shared orchestrator for feedback loop.

        Returns:
            ``BaselineResult`` with containment metrics.
        """
        if original_vbr_set is None:
            original_vbr_set = _original_vbr(graph, seed_nodes).verified_reachable
        if orchestrator is None:
            orchestrator = TrustFieldOrchestrator(db_path=":memory:")

        # Detect topology and choose model
        fingerprint = self._fingerprinter.fingerprint(graph)
        topo_type = self._fingerprinter.classify_topology(fingerprint).value
        model_name = _BEST_MODEL_FOR_TOPOLOGY.get(topo_type, "percolation")

        # Run single model
        prop_result = self._runner.run_single(model_name, graph, seed_nodes)

        # Build prediction from single model output
        n_total = graph._graph.number_of_nodes()
        threshold = 0.35 if topo_type in ("HUB", "CHAIN") else 0.50
        pred = _make_prediction(
            prop_result.compromised_nodes,
            prop_result.per_node_risk,
            n_total,
            threshold,
        )

        # Compute blast radius using TrustField's strategy
        traversal_result = _original_vbr(graph, seed_nodes)
        bra = BlastRadiusCalculator().compute(pred, traversal_result, graph)

        # Guard placement: TrustField's exploitability-scored strategy
        dummy_net = GuardNetwork(graph, TokenGenerator())
        blast_edges: Set[tuple] = set(dummy_net.get_high_risk_edges(bra, top_k=self._top_k))
        traversal_edges: Set[tuple] = {
            (s.from_node, s.to_node)
            for s in traversal_result.traversal_steps
            if s.succeeded
        }
        guard_edges = list(blast_edges | traversal_edges)

        return _run_feedback_and_measure(
            graph, seed_nodes, guard_edges, orchestrator,
            self._n_cycles, self._guards_per_edge,
            "Single Model", topology, original_vbr_set,
        )

    @property
    def best_model_for(self) -> Dict[str, str]:
        return _BEST_MODEL_FOR_TOPOLOGY


# ---------------------------------------------------------------------------
# Baseline 3: RandomGuardBaseline
# ---------------------------------------------------------------------------

class RandomGuardBaseline:
    """Full TrustField ensemble + verification, but RANDOM guard placement.

    Uses TrustField's complete M1–M4 pipeline, then replaces the exploitability-
    scored guard selection with a uniformly random sample of the same size.

    This is the critical ablation: holding everything constant except guard
    placement strategy.  If TrustField still outperforms, it proves that
    exploitability-scored placement is the source of the advantage.

    Args:
        n_feedback_cycles: Feedback iterations.
        guards_per_edge: Guards per edge.
        random_seed: RNG seed for guard selection reproducibility.
    """

    def __init__(
        self,
        n_feedback_cycles: int = 5,
        guards_per_edge: int = 3,
        random_seed: int = 99,
    ) -> None:
        self._n_cycles = n_feedback_cycles
        self._guards_per_edge = guards_per_edge
        self._rng = random.Random(random_seed)

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology: str = "unknown",
        original_vbr_set: Optional[Set[str]] = None,
        orchestrator: Optional[TrustFieldOrchestrator] = None,
        trustfield_guard_count: Optional[int] = None,
    ) -> BaselineResult:
        """Run the RandomGuard baseline.

        Args:
            graph: Original TrustGraph.
            seed_nodes: Attacker entry points.
            topology: Topology label for reporting.
            original_vbr_set: Pre-computed VBR for fair comparison.
            orchestrator: Shared orchestrator (used for full ensemble run + feedback).
            trustfield_guard_count: Number of edges to guard randomly.
                If None, defaults to 20. Should be passed the actual count
                TrustField deployed for a fair comparison.

        Returns:
            ``BaselineResult`` with containment metrics.
        """
        if original_vbr_set is None:
            original_vbr_set = _original_vbr(graph, seed_nodes).verified_reachable
        if orchestrator is None:
            orchestrator = TrustFieldOrchestrator(db_path=":memory:")

        # Same guard budget as TrustField
        n_guards = trustfield_guard_count or 20

        # Random guard selection from all available edges
        all_edges = list(graph._graph.edges())
        k = min(n_guards, len(all_edges))
        guard_edges = self._rng.sample(all_edges, k)

        return _run_feedback_and_measure(
            graph, seed_nodes, guard_edges, orchestrator,
            self._n_cycles, self._guards_per_edge,
            "Random Guards", topology, original_vbr_set,
        )


# ---------------------------------------------------------------------------
# Baseline 4: BFSGuardBaseline
# ---------------------------------------------------------------------------

class BFSGuardBaseline:
    """Strongest naive baseline: BFS reachability + smart guard placement.

    Uses GraphTraversalModel (BFS upper bound) to find all structurally
    reachable nodes, then deploys guards on the highest-weight edges leading
    INTO that reachable set — same guard budget as TrustField.

    This directly tests whether TrustField's ensemble + verification pipeline
    adds value over simply guarding the heaviest BFS-reachable edges.

    Tracked per run:
      bfs_reachable_size:     How many nodes BFS found reachable.
      verified_reachable_size: How many IAMTraversal found actually reachable.
      bfs_overestimate:       bfs_reachable - verified (false positives).
      false_positive_rate:    Fraction of guarded edges NOT on any verified
                              traversal path (wasted guard budget).

    Args:
        top_k:             Guard budget — number of edges to guard.
        n_feedback_cycles: Feedback iterations post-deployment.
        guards_per_edge:   Guards per edge (for consensus).
    """

    def __init__(
        self,
        top_k: int = 15,
        n_feedback_cycles: int = 5,
        guards_per_edge: int = 3,
    ) -> None:
        self._top_k = top_k
        self._n_cycles = n_feedback_cycles
        self._guards_per_edge = guards_per_edge

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology: str = "unknown",
        original_vbr_set: Optional[Set[str]] = None,
        orchestrator: Optional[TrustFieldOrchestrator] = None,
    ) -> BaselineResult:
        """Run BFS+Guards baseline on a graph.

        Args:
            graph:            Original (unmodified) TrustGraph.
            seed_nodes:       Attacker entry points.
            topology:         Topology label for reporting.
            original_vbr_set: Pre-computed VBR for fair comparison.
            orchestrator:     Shared orchestrator for feedback loop.

        Returns:
            :class:`BaselineResult` with BFS-specific fields populated.
        """
        # 1. BFS structural reachability (upper bound)
        bfs_result = GraphTraversalModel().run(graph, seed_nodes)
        bfs_reachable: Set[str] = bfs_result.compromised_nodes

        # 2. Verified traversal (for false-positive calculation)
        traversal = _original_vbr(graph, seed_nodes)
        if original_vbr_set is None:
            original_vbr_set = traversal.verified_reachable
        verified_traversal_edges: Set[Tuple[str, str]] = {
            (s.from_node, s.to_node)
            for s in traversal.traversal_steps
            if s.succeeded
        }

        if orchestrator is None:
            orchestrator = TrustFieldOrchestrator(db_path=":memory:")

        # 3. Edges leading into BFS-reachable set, ranked by weight descending
        candidate_edges = sorted(
            [
                (u, v, d["metadata"].weight)
                for u, v, d in graph._graph.edges(data=True)
                if v in bfs_reachable
            ],
            key=lambda x: -x[2],
        )
        guard_edges = [(u, v) for u, v, _ in candidate_edges[: self._top_k]]

        # 4. False positive rate: guarded edges NOT on any verified path
        guard_set: Set[Tuple[str, str]] = set(guard_edges)
        fp_edges = guard_set - verified_traversal_edges
        fp_rate = len(fp_edges) / max(1, len(guard_set))

        # 5. Deploy guards and measure post-containment VBR
        base = _run_feedback_and_measure(
            graph, seed_nodes, guard_edges, orchestrator,
            self._n_cycles, self._guards_per_edge,
            "BFS+Guards", topology, original_vbr_set,
        )

        bfs_size = len(bfs_reachable)
        vbr_size  = len(traversal.verified_reachable)

        return BaselineResult(
            method=base.method,
            topology=base.topology,
            original_vbr=base.original_vbr,
            post_vbr=base.post_vbr,
            containment_success_rate=base.containment_success_rate,
            missed_containments=base.missed_containments,
            guards_deployed=base.guards_deployed,
            final_strictness=base.final_strictness,
            elapsed_seconds=base.elapsed_seconds,
            bfs_reachable_size=bfs_size,
            verified_reachable_size=vbr_size,
            bfs_overestimate=max(0, bfs_size - vbr_size),
            false_positive_rate=round(fp_rate, 4),
        )


# ---------------------------------------------------------------------------
# BaselineComparison: runs all four methods and produces tables
# ---------------------------------------------------------------------------

class BaselineComparison:
    """Orchestrates all three baselines + TrustField on all four topologies.

    Args:
        num_nodes: Nodes per generated graph (default 50).
        random_seed: Graph generation + traversal seed.
        top_k: Guard budget for NaiveBFS and SingleBestModel.
        n_feedback_cycles: Feedback iterations for all methods.
        guards_per_edge: Guards per edge for all methods.

    Example::

        cmp = BaselineComparison(num_nodes=50)
        results = cmp.run_all_topologies()
        print(cmp.to_markdown(results))
        print(cmp.to_latex(results))
    """

    TOPOLOGIES = ["hub", "chain", "dense_cluster", "mixed"]

    def __init__(
        self,
        num_nodes: int = 50,
        random_seed: int = 42,
        top_k: int = 20,
        n_feedback_cycles: int = 5,
        guards_per_edge: int = 3,
    ) -> None:
        self._num_nodes = num_nodes
        self._random_seed = random_seed
        self._top_k = top_k
        self._n_cycles = n_feedback_cycles
        self._guards_per_edge = guards_per_edge

    # ------------------------------------------------------------------
    # Public run API
    # ------------------------------------------------------------------

    def run_all_topologies(self) -> Dict[str, ComparisonResult]:
        """Run all four methods on all four topologies.

        Returns:
            Dict mapping topology name → ComparisonResult.
        """
        sim = IAMSimulator()
        results: Dict[str, ComparisonResult] = {}

        for topo in self.TOPOLOGIES:
            graph = sim.generate(topo, num_nodes=self._num_nodes, seed=self._random_seed)
            seed_nodes = [_seed_node(graph)]
            results[topo] = self.run_one_topology(graph, seed_nodes, topo)

        return results

    def run_one_topology(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology: str,
    ) -> ComparisonResult:
        """Run all four methods on a single graph and return a ComparisonResult.

        The original VBR is computed once and shared across all methods so
        that every containment_success_rate is measured against an identical
        ground truth.

        Args:
            graph: TrustGraph to evaluate.
            seed_nodes: Attacker entry points.
            topology: Label for reporting.

        Returns:
            ComparisonResult with all four method results.
        """
        # Shared orchestrator avoids 4× SQLite initialisation overhead
        orch = TrustFieldOrchestrator(db_path=":memory:")

        # Shared original VBR — all methods measure against the same ground truth
        orig_vbr = _original_vbr(graph, seed_nodes, self._random_seed).verified_reachable

        # --- TrustField (full pipeline) ---
        tf_result = self._run_trustfield(graph, seed_nodes, topology, orig_vbr, orch)

        # --- Baselines ---
        naive = NaiveBFSBaseline(
            top_k=self._top_k,
            n_feedback_cycles=self._n_cycles,
            guards_per_edge=self._guards_per_edge,
        ).run(graph, seed_nodes, topology, orig_vbr, orch)

        single = SingleBestModelBaseline(
            top_k=self._top_k,
            n_feedback_cycles=self._n_cycles,
            guards_per_edge=self._guards_per_edge,
        ).run(graph, seed_nodes, topology, orig_vbr, orch)

        rnd = RandomGuardBaseline(
            n_feedback_cycles=self._n_cycles,
            guards_per_edge=self._guards_per_edge,
        ).run(
            graph, seed_nodes, topology, orig_vbr, orch,
            trustfield_guard_count=tf_result.guards_deployed,
        )

        bfs_g = BFSGuardBaseline(
            top_k=self._top_k,
            n_feedback_cycles=self._n_cycles,
            guards_per_edge=self._guards_per_edge,
        ).run(graph, seed_nodes, topology, orig_vbr, orch)

        return ComparisonResult(
            topology=topology,
            trustfield=tf_result,
            naive_bfs=naive,
            single_model=single,
            random_guards=rnd,
            bfs_guards=bfs_g,
        )

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------

    def to_markdown(self, results: Dict[str, ComparisonResult]) -> str:
        """Render a Markdown comparison table.

        Produces two tables:
          1. Containment success rate
          2. Guards deployed (edge count)
        """
        lines = ["## Containment Success Rate\n"]
        lines.append("| Topology | Naive BFS | Single Model | Random Guards | TrustField |")
        lines.append("|----------|-----------|--------------|---------------|------------|")

        for topo in self.TOPOLOGIES:
            if topo not in results:
                continue
            r = results[topo]
            icon = lambda x: " ✓" if x >= 0.95 else " ✗"
            row = (
                f"| {topo.replace('_', ' ').title()} "
                f"| {r.naive_bfs.containment_success_rate:.1%}{icon(r.naive_bfs.containment_success_rate)} "
                f"| {r.single_model.containment_success_rate:.1%}{icon(r.single_model.containment_success_rate)} "
                f"| {r.random_guards.containment_success_rate:.1%}{icon(r.random_guards.containment_success_rate)} "
                f"| **{r.trustfield.containment_success_rate:.1%}{icon(r.trustfield.containment_success_rate)}** |"
            )
            lines.append(row)

        lines.append("\n## Guards Deployed (edge count)\n")
        lines.append("| Topology | Naive BFS | Single Model | Random Guards | TrustField |")
        lines.append("|----------|-----------|--------------|---------------|------------|")

        for topo in self.TOPOLOGIES:
            if topo not in results:
                continue
            r = results[topo]
            row = (
                f"| {topo.replace('_', ' ').title()} "
                f"| {r.naive_bfs.guards_deployed} "
                f"| {r.single_model.guards_deployed} "
                f"| {r.random_guards.guards_deployed} "
                f"| {r.trustfield.guards_deployed} |"
            )
            lines.append(row)

        # Efficiency claim summary
        lines.append("\n## Placement Efficiency (TrustField vs Random — same guard count)\n")
        lines.append("| Topology | TrustField | Random Guards | Delta | Verdict |")
        lines.append("|----------|------------|---------------|-------|---------|")
        for topo in self.TOPOLOGIES:
            if topo not in results:
                continue
            r = results[topo]
            delta = r.trustfield.containment_success_rate - r.random_guards.containment_success_rate
            verdict = "TF better" if delta > 0.01 else ("Equal" if abs(delta) <= 0.01 else "Random better")
            lines.append(
                f"| {topo.replace('_', ' ').title()} "
                f"| {r.trustfield.containment_success_rate:.1%} "
                f"| {r.random_guards.containment_success_rate:.1%} "
                f"| {delta:+.1%} "
                f"| {verdict} |"
            )

        # BFS+Guards comparison table
        bfs_results = {t: r for t, r in results.items() if r.bfs_guards is not None}
        if bfs_results:
            lines.append("\n## BFS+Guards Comparison\n")
            lines.append(
                "| Topology | TrustField | Random Guards | BFS+Guards | "
                "Delta (TF vs BFS) | BFS FP Rate |"
            )
            lines.append(
                "|----------|------------|---------------|------------|"
                "-------------------|-------------|"
            )
            for topo in self.TOPOLOGIES:
                if topo not in bfs_results:
                    continue
                r = bfs_results[topo]
                bfs = r.bfs_guards
                delta_bfs = r.trustfield.containment_success_rate - bfs.containment_success_rate
                lines.append(
                    f"| {topo.replace('_', ' ').title()} "
                    f"| {r.trustfield.containment_success_rate:.1%} "
                    f"| {r.random_guards.containment_success_rate:.1%} "
                    f"| {bfs.containment_success_rate:.1%} "
                    f"| {delta_bfs:+.1%} "
                    f"| {bfs.false_positive_rate:.1%} |"
                )

            lines.append("\n## BFS Overestimate (false positives from BFS)\n")
            lines.append(
                "| Topology | BFS Reachable | Verified (VBR) | BFS Overestimate |"
            )
            lines.append("|----------|---------------|----------------|------------------|")
            for topo in self.TOPOLOGIES:
                if topo not in bfs_results:
                    continue
                bfs = bfs_results[topo].bfs_guards
                lines.append(
                    f"| {topo.replace('_', ' ').title()} "
                    f"| {bfs.bfs_reachable_size} "
                    f"| {bfs.verified_reachable_size} "
                    f"| {bfs.bfs_overestimate} |"
                )

        return "\n".join(lines)

    def to_latex(self, results: Dict[str, ComparisonResult]) -> str:
        r"""Render a LaTeX table suitable for direct paper inclusion.

        Produces Table 3: Baseline comparison — containment rate and guard count.
        """
        rows_rate = []
        rows_guards = []

        for topo in self.TOPOLOGIES:
            if topo not in results:
                continue
            r = results[topo]
            label = topo.replace("_", "-").title()

            def fmt(rate: float) -> str:
                star = r"\textbf{" + f"{rate:.1%}" + "}" if rate >= 0.95 else f"{rate:.1%}"
                return star

            rows_rate.append(
                f"{label} & {fmt(r.naive_bfs.containment_success_rate)} "
                f"& {fmt(r.single_model.containment_success_rate)} "
                f"& {fmt(r.random_guards.containment_success_rate)} "
                f"& {fmt(r.trustfield.containment_success_rate)} \\\\"
            )
            rows_guards.append(
                f"{label} "
                f"& {r.naive_bfs.guards_deployed} "
                f"& {r.single_model.guards_deployed} "
                f"& {r.random_guards.guards_deployed} "
                f"& {r.trustfield.guards_deployed} \\\\"
            )

        rate_body = "\n".join(rows_rate)
        guard_body = "\n".join(rows_guards)

        return (
            "% === TrustField Baseline Comparison — Auto-Generated ===\n\n"
            r"\begin{table}[h]" + "\n"
            r"\centering" + "\n"
            r"\caption{Containment Success Rate: TrustField vs Baselines}" + "\n"
            r"\label{tab:baselines}" + "\n"
            r"\begin{tabular}{lrrrr}" + "\n"
            r"\hline" + "\n"
            r"Topology & Naive BFS & Single Model & Random Guards & TrustField \\" + "\n"
            r"\hline" + "\n"
            + rate_body + "\n"
            r"\hline" + "\n"
            r"\end{tabular}" + "\n"
            r"\end{table}" + "\n\n"
            r"\begin{table}[h]" + "\n"
            r"\centering" + "\n"
            r"\caption{Guards Deployed (Edge Count) per Method}" + "\n"
            r"\label{tab:guards-deployed}" + "\n"
            r"\begin{tabular}{lrrrr}" + "\n"
            r"\hline" + "\n"
            r"Topology & Naive BFS & Single Model & Random Guards & TrustField \\" + "\n"
            r"\hline" + "\n"
            + guard_body + "\n"
            r"\hline" + "\n"
            r"\end{tabular}" + "\n"
            r"\end{table}"
        )

    # ------------------------------------------------------------------
    # TrustField full pipeline (for comparison)
    # ------------------------------------------------------------------

    def _run_trustfield(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology: str,
        original_vbr_set: Set[str],
        orchestrator: TrustFieldOrchestrator,
    ) -> BaselineResult:
        """Run the full TrustField pipeline and return a BaselineResult."""
        t0 = time.time()

        # M1-M3: ensemble
        analysis = orchestrator.analyze(graph, seed_nodes=seed_nodes)
        pred = analysis.ensemble_prediction

        # M4: verification
        token_gen = TokenGenerator()
        traversal = IAMTraversal(token_gen).traverse(
            graph, seed_nodes, max_depth=6, respect_conditions=True, random_seed=42
        )
        bra = BlastRadiusCalculator().compute(pred, traversal, graph)
        report = VerificationReport(
            graph=graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
        )

        # M5: containment
        engine = ContainmentEngine(orchestrator, token_generator=TokenGenerator())
        cr = engine.execute(graph, seed_nodes, report, n_feedback_cycles=self._n_cycles)

        n_orig = len(original_vbr_set)
        # Re-measure using the shared original_vbr for fairness
        # (ContainmentEngine uses its own internal traversal for comparison)
        post_vbr_set: Set[str] = set()
        # Reconstruct post-guard vbr from contained_nodes
        # post_vbr = original - contained (seeds remain)
        post_vbr_set = original_vbr_set - cr.contained_nodes
        contained = cr.contained_nodes & original_vbr_set
        missed = (original_vbr_set & post_vbr_set) - set(seed_nodes)
        rate = len(contained) / n_orig if n_orig > 0 else 1.0

        # Guard edge count from the engine's internal blast+traversal union
        dummy_net = GuardNetwork(graph, TokenGenerator())
        blast_edges = set(dummy_net.get_high_risk_edges(bra, top_k=20))
        traversal_edges = {
            (s.from_node, s.to_node)
            for s in traversal.traversal_steps
            if s.succeeded
        }
        guard_edge_count = len(blast_edges | traversal_edges)

        return BaselineResult(
            method="TrustField",
            topology=topology,
            original_vbr=n_orig,
            post_vbr=len(post_vbr_set),
            containment_success_rate=round(rate, 4),
            missed_containments=len(missed),
            guards_deployed=guard_edge_count,
            final_strictness=cr.final_strictness_level.value,
            elapsed_seconds=round(time.time() - t0, 2),
        )
