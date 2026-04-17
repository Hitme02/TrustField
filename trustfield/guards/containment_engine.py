"""ContainmentEngine — full guard deployment, feedback, and containment reporting.

This is the top-level orchestrator for Module 5.  It wires together:
  - GuardNetwork (deploy guards on high-risk + verified-traversal edges)
  - HardwareSoftwareFeedback (adaptive tightening over n cycles)
  - Final IAMTraversal (measure post-containment blast radius)
  - ContainmentResult (publish-ready metrics)

The CRITICAL invariant enforced here (from Module 4):
  guard_edges = high_risk_from_blast_radius  ∪  edges_on_verified_traversal_paths

This ensures guards cover both ensemble-predicted AND confirmed live paths,
closing the CRITICAL_MISS gap identified by the Verification Engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.propagation.graph_traversal import GraphTraversalModel
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal
from trustfield.verification.verification_report import VerificationReport

from .feedback_loop import FeedbackAction, HardwareSoftwareFeedback
from .guard_module import GuardEvent, StrictnessLevel
from .guard_network import GuardNetwork
from .sensor import SensorReading


@dataclass
class ContainmentResult:
    """Full output of a ContainmentEngine.execute() run.

    Attributes:
        contained_nodes: Nodes in VBR_original that are no longer reachable
            after guards were deployed (VBR_original − VBR_after_guards).
        blocked_transitions: Edge tuples that were zeroed out by guards.
        containment_success_rate: Fraction of VBR_original nodes successfully
            isolated.  Target > 0.95 (95%).
        missed_containments: VBR_original nodes still reachable after guards
            (VBR_original ∩ VBR_after_guards, excluding seed nodes).
        guard_events: All GuardEvents emitted during this run.
        feedback_actions: All strictness-level transitions.
        sensor_readings: All SensorReadings from the feedback cycles.
        final_strictness_level: Guard network's strictness at run end.
    """

    contained_nodes: Set[str]
    blocked_transitions: List[tuple]
    containment_success_rate: float
    missed_containments: Set[str]
    guard_events: List[GuardEvent]
    feedback_actions: List[FeedbackAction]
    sensor_readings: List[SensorReading]
    final_strictness_level: StrictnessLevel
    combined_containment_rate: float = 0.0


class ContainmentEngine:
    """Executes the full cyber-physical containment pipeline.

    Args:
        orchestrator: TrustFieldOrchestrator used for ensemble re-analysis
            inside the feedback loop.
        token_generator: Session token authority.  If None, a fresh one is
            created (use the same generator as the original traversal to
            share the signing key).

    Example::

        engine = ContainmentEngine(orchestrator)
        result = engine.execute(graph, seed_nodes, verification_report)
        print(f"Containment success: {result.containment_success_rate:.1%}")
        print(f"Missed: {sorted(result.missed_containments)}")
    """

    def __init__(
        self,
        orchestrator: TrustFieldOrchestrator,
        token_generator: Optional[TokenGenerator] = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._token_gen = token_generator or TokenGenerator()

    # ------------------------------------------------------------------
    # Primary execution
    # ------------------------------------------------------------------

    def execute(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        verification_report: VerificationReport,
        n_feedback_cycles: int = 5,
        use_gnn: bool = True,
    ) -> ContainmentResult:
        """Run the full containment pipeline and return metrics.

        Steps:
          1. Compute guard edges = high-risk (blast radius) ∪ verified traversal.
          2. Deploy guards on all guard edges.
          3. Run n_feedback_cycles of hardware-software feedback on a copy.
          4. Run final IAMTraversal on the guard-blocked working graph.
          5. Compute containment_success_rate.
          6. Assemble and return ContainmentResult.

        Args:
            graph: Original trust graph (not modified).
            seed_nodes: Attacker entry points.
            verification_report: Output of Module 4 verification.
            n_feedback_cycles: Number of feedback iterations.

        Returns:
            A fully populated ``ContainmentResult``.
        """
        bra = verification_report.blast_radius_analysis
        tr = verification_report.traversal_result
        original_vbr: Set[str] = set(tr.verified_reachable)

        # --- Work on a copy so the caller's graph is never mutated ---
        working_graph = TrustGraph.from_dict(graph.to_dict())

        # --- Step 1: Guard edges = blast-radius top-k  ∪  verified paths ---
        guard_net = GuardNetwork(working_graph, self._token_gen)

        blast_edges: Set[tuple] = set(
            guard_net.get_high_risk_edges(bra, top_k=20)
        )
        # CRITICAL: guard every edge on a confirmed traversal path
        traversal_edges: Set[tuple] = {
            (step.from_node, step.to_node)
            for step in tr.traversal_steps
            if step.succeeded
        }
        # Also guard ALL edges out of any VBR node — catches critical-miss paths
        # the ensemble underestimated but IAM traversal confirmed reachable.
        vbr_outgoing: Set[tuple] = set()
        for node in original_vbr:
            for src, tgt in graph._graph.out_edges(node):
                vbr_outgoing.add((src, tgt))

        all_guard_edges = list(blast_edges | traversal_edges | vbr_outgoing)

        # Fallback: if the seed is a sink node (no outward reachability),
        # block all incoming edges to the seed — isolate the compromised resource.
        if not all_guard_edges:
            for seed in seed_nodes:
                for src, tgt in graph._graph.in_edges(seed):
                    all_guard_edges.append((src, tgt))

        # --- Step 2: Deploy guards ---
        guard_net.deploy_guards(all_guard_edges, guards_per_edge=3)

        # --- Step 3: Feedback loop (modifies working_graph weights) ---
        feedback = HardwareSoftwareFeedback(guard_net, self._orchestrator)
        actions = feedback.run_feedback_cycle(
            working_graph, seed_nodes, n_cycles=n_feedback_cycles, use_gnn=use_gnn
        )

        # Determine final strictness
        final_strictness = StrictnessLevel.NOMINAL
        if actions:
            final_strictness = actions[-1].new_strictness

        # --- Step 4: Final IAMTraversal on the blocked working graph ---
        final_gen = TokenGenerator(secret_key=self._token_gen.key)
        post_traversal = IAMTraversal(final_gen).traverse(
            working_graph,
            seed_nodes,
            max_depth=6,
            respect_conditions=True,
            random_seed=42,
        )
        post_vbr: Set[str] = post_traversal.verified_reachable

        # --- Step 5: Compute metrics ---
        # Structural upper bound (BFS, ignoring token conditions) for combined rate
        unconstrained_pbr: Set[str] = GraphTraversalModel().run(
            graph, seed_nodes
        ).compromised_nodes
        metrics = self.compute_containment_metrics(
            original_vbr, post_vbr, unconstrained_pbr=unconstrained_pbr
        )

        contained_nodes = original_vbr - post_vbr
        seed_set = set(seed_nodes)
        missed_containments = (original_vbr & post_vbr) - seed_set

        # Blocked transitions: edges that carried non-zero weight before but
        # now have weight 0 in the working graph
        blocked_transitions: List[tuple] = []
        for src, tgt, data in working_graph._graph.edges(data=True):
            if data.get("weight", 1.0) == 0.0:
                blocked_transitions.append((src, tgt))

        # --- Step 6: Collect all guard events and sensor readings ---
        all_guard_events: List[GuardEvent] = [
            evt
            for guards in guard_net._deployed_guards.values()
            for guard in guards
            for evt in guard.get_event_log()
        ]

        return ContainmentResult(
            contained_nodes=contained_nodes,
            blocked_transitions=blocked_transitions,
            containment_success_rate=metrics["containment_success_rate"],
            missed_containments=missed_containments,
            guard_events=all_guard_events,
            feedback_actions=actions,
            sensor_readings=feedback.sensor_readings,
            final_strictness_level=final_strictness,
            combined_containment_rate=metrics["combined_containment_rate"],
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def compute_containment_metrics(
        self,
        original_vbr: Set[str],
        post_containment_vbr: Set[str],
        unconstrained_pbr: Optional[Set[str]] = None,
    ) -> Dict[str, object]:
        """Compute containment effectiveness metrics.

        Args:
            original_vbr: Verified reachable set before guard deployment
                (IAMTraversal with token conditions — natural IAM controls
                already applied).
            post_containment_vbr: Verified reachable set after guards.
            unconstrained_pbr: Structural upper bound from GraphTraversalModel
                (BFS reachability ignoring token conditions).  When provided,
                enables the combined-containment metrics that account for both
                natural IAM controls and explicit guard controls.

        Returns:
            Dictionary with keys:
                ``"containment_success_rate"`` — guard-only rate: fraction of
                    original_vbr nodes isolated by guards.
                ``"nodes_contained"`` — count isolated by guards.
                ``"nodes_missed"`` — count still reachable after guards.
                ``"reduction_fraction"`` — VBR size reduction fraction.
                ``"natural_blocks"`` — nodes blocked by token validation
                    (unconstrained_pbr − original_vbr); 0 if not provided.
                ``"guard_blocks"`` — nodes blocked by guards
                    (original_vbr − post_containment_vbr).
                ``"combined_containment_rate"`` — (natural_blocks +
                    guard_blocks) / |unconstrained_pbr|; 0.0 if not provided.
        """
        n_original = len(original_vbr)
        contained = len(original_vbr - post_containment_vbr)
        missed = len(original_vbr & post_containment_vbr)

        success_rate = contained / n_original if n_original > 0 else 1.0
        reduction = (
            (n_original - len(post_containment_vbr)) / n_original
            if n_original > 0
            else 1.0
        )

        # Combined-containment: natural IAM controls + guard controls
        guard_blocks = contained  # same as nodes_contained
        if unconstrained_pbr is not None and len(unconstrained_pbr) > 0:
            natural_blocks = len(unconstrained_pbr - original_vbr)
            combined_rate = (natural_blocks + guard_blocks) / len(unconstrained_pbr)
        else:
            natural_blocks = 0
            combined_rate = 0.0

        return {
            "containment_success_rate": round(success_rate, 4),
            "nodes_contained": contained,
            "nodes_missed": missed,
            "reduction_fraction": round(max(0.0, reduction), 4),
            "natural_blocks": natural_blocks,
            "guard_blocks": guard_blocks,
            "combined_containment_rate": round(min(1.0, combined_rate), 4),
        }
