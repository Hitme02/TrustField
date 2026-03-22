"""GuardNetwork — multi-guard deployment with 2-of-3 consensus.

Deploys three virtual guard instances per high-risk edge and requires at
least two approvals before a transition is allowed through.  This mirrors a
real hardware TPM cluster where a single faulty or compromised module cannot
unilaterally override the security policy.

CRITICAL (from Module 4): guard_edges = high_risk_from_blast_radius UNION
edges_on_verified_traversal_paths.  This union is enforced in
ContainmentEngine.execute(); GuardNetwork.get_high_risk_edges() returns the
blast-radius scored edges, and ContainmentEngine adds the traversal edges
before calling deploy_guards().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification.blast_radius import BlastRadiusAnalysis
from trustfield.verification.delegation_token import DelegationToken, TokenGenerator

from .guard_module import CyberPhysicalGuard, GuardEvent, StrictnessLevel


@dataclass
class ConsensusResult:
    """Outcome of a 2-of-3 consensus validation.

    Attributes:
        edge: ``(source, target)`` node pair.
        token: Token that was evaluated.
        participating_guards: Guard IDs that were consulted.
        individual_decisions: Per-guard decision (``"ALLOWED"`` or ``"BLOCKED"``).
            FLAGGED decisions are mapped to ``"BLOCKED"`` for consensus counting.
        consensus_decision: Final decision (``"ALLOWED"`` or ``"BLOCKED"``).
        approval_count: Number of guards that returned ``"ALLOWED"``.
        required_approvals: Minimum approvals needed for a positive consensus.
    """

    edge: tuple
    token: DelegationToken
    participating_guards: List[str]
    individual_decisions: Dict[str, str]
    consensus_decision: str
    approval_count: int
    required_approvals: int


class GuardNetwork:
    """Deploys hardware guards across high-risk edges and enforces consensus.

    Args:
        graph: The trust graph being protected.
        token_generator: The session's token authority (used to derive per-guard
            generators with the same key but independent nonce stores).

    Example::

        network = GuardNetwork(graph, token_gen)
        edges = network.get_high_risk_edges(blast_analysis, top_k=10)
        network.deploy_guards(edges)
        result = network.validate_with_consensus(edge, token)
        print(result.consensus_decision)
    """

    def __init__(
        self,
        graph: TrustGraph,
        token_generator: TokenGenerator,
    ) -> None:
        self._graph = graph
        self._token_generator = token_generator
        self._deployed_guards: Dict[tuple, List[CyberPhysicalGuard]] = {}

    # ------------------------------------------------------------------
    # Guard deployment
    # ------------------------------------------------------------------

    def deploy_guards(
        self,
        high_risk_edges: List[tuple],
        guards_per_edge: int = 3,
    ) -> Dict[tuple, List[CyberPhysicalGuard]]:
        """Deploy ``guards_per_edge`` guard instances on each high-risk edge.

        Each guard gets its own ``TokenGenerator`` sharing the session secret
        key but with a fresh nonce store, replicating independent TPM state.

        Guard IDs follow the pattern
        ``"guard_{source}_{target}_{i}"`` (0-indexed).

        Args:
            high_risk_edges: List of ``(source, target)`` tuples to protect.
            guards_per_edge: Number of redundant guard instances per edge.

        Returns:
            Mapping of edge tuple to list of deployed guard instances.
        """
        for edge in high_risk_edges:
            src, tgt = edge
            guards: List[CyberPhysicalGuard] = []
            for i in range(guards_per_edge):
                guard_id = f"guard_{src}_{tgt}_{i}"
                # Same key, independent nonce store — mirrors physical TPM cluster
                guard_gen = TokenGenerator(secret_key=self._token_generator.key)
                guard = CyberPhysicalGuard(guard_id, edge, guard_gen)
                guards.append(guard)
            self._deployed_guards[edge] = guards

        return dict(self._deployed_guards)

    # ------------------------------------------------------------------
    # Consensus validation
    # ------------------------------------------------------------------

    def validate_with_consensus(
        self,
        edge: tuple,
        token: DelegationToken,
        required_approvals: int = 2,
    ) -> ConsensusResult:
        """Validate a token via 2-of-3 guard consensus.

        If the edge has no deployed guards it is auto-approved (unmonitored
        transition).  Otherwise all guards are consulted independently;
        FLAGGED decisions count as ``"BLOCKED"`` for the approval tally.

        Args:
            edge: ``(source, target)`` pair identifying the transition.
            token: Token to evaluate.
            required_approvals: Minimum ``"ALLOWED"`` votes needed.

        Returns:
            A ``ConsensusResult`` with the final decision and per-guard details.
        """
        guards = self._deployed_guards.get(edge, [])

        if not guards:
            return ConsensusResult(
                edge=edge,
                token=token,
                participating_guards=[],
                individual_decisions={},
                consensus_decision="ALLOWED",
                approval_count=0,
                required_approvals=required_approvals,
            )

        individual_decisions: Dict[str, str] = {}
        for guard in guards:
            event = guard.validate_transition(token)
            # FLAGGED is not an autonomous approval — treat as BLOCKED
            individual_decisions[guard.guard_id] = (
                "ALLOWED" if event.decision == "ALLOWED" else "BLOCKED"
            )

        approval_count = sum(
            1 for d in individual_decisions.values() if d == "ALLOWED"
        )
        consensus = "ALLOWED" if approval_count >= required_approvals else "BLOCKED"

        return ConsensusResult(
            edge=edge,
            token=token,
            participating_guards=[g.guard_id for g in guards],
            individual_decisions=individual_decisions,
            consensus_decision=consensus,
            approval_count=approval_count,
            required_approvals=required_approvals,
        )

    # ------------------------------------------------------------------
    # Network-wide configuration
    # ------------------------------------------------------------------

    def set_network_strictness(self, level: StrictnessLevel) -> None:
        """Apply a strictness level to every guard in the network.

        Args:
            level: ``StrictnessLevel`` to broadcast to all guards.
        """
        for guards in self._deployed_guards.values():
            for guard in guards:
                guard.set_strictness(level)

    # ------------------------------------------------------------------
    # Edge scoring
    # ------------------------------------------------------------------

    def get_high_risk_edges(
        self,
        blast_radius_analysis: BlastRadiusAnalysis,
        top_k: int = 10,
    ) -> List[tuple]:
        """Return the top-k graph edges most likely on a verified exploit path.

        Scoring: ``edge_score = avg(exploitability[source], exploitability[target])``
        using ``per_node_exploitability`` from the blast-radius analysis.

        Only edges that actually exist in the graph are considered.  Edges
        involving unscored nodes (score defaults to 0.0) are included so that
        seed-node outgoing edges are never silently omitted.

        Note: ContainmentEngine.execute() adds traversal-path edges before
        calling deploy_guards() to satisfy the CRITICAL union requirement.

        Args:
            blast_radius_analysis: Output of ``BlastRadiusCalculator.compute()``.
            top_k: Maximum number of edges to return.

        Returns:
            List of ``(source, target)`` tuples, highest score first.
        """
        exploitability = blast_radius_analysis.per_node_exploitability
        scored: List[tuple[tuple, float]] = []

        for src, tgt in self._graph._graph.edges():
            src_score = exploitability.get(src, 0.0)
            tgt_score = exploitability.get(tgt, 0.0)
            edge_score = (src_score + tgt_score) / 2.0
            scored.append(((src, tgt), edge_score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [edge for edge, _ in scored[:top_k]]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_guard_statistics(self) -> dict:
        """Aggregate event statistics across all deployed guards.

        Returns:
            Dictionary with keys:
                ``"total_events"``, ``"total_blocked"``, ``"total_allowed"``,
                ``"block_rate_per_edge"`` (mapping of ``str(edge)`` → float).
        """
        total_events = 0
        total_blocked = 0
        total_allowed = 0
        block_rate_per_edge: Dict[str, float] = {}

        for edge, guards in self._deployed_guards.items():
            edge_events: List[GuardEvent] = []
            for guard in guards:
                edge_events.extend(guard.get_event_log())

            n = len(edge_events)
            blocked = sum(
                1 for e in edge_events if e.decision in ("BLOCKED", "FLAGGED")
            )
            allowed = n - blocked

            block_rate_per_edge[str(edge)] = blocked / n if n > 0 else 0.0
            total_events += n
            total_blocked += blocked
            total_allowed += allowed

        return {
            "total_events": total_events,
            "total_blocked": total_blocked,
            "total_allowed": total_allowed,
            "block_rate_per_edge": block_rate_per_edge,
        }
