"""Adversarial graph mutator for TrustField robustness testing.

Models an attacker who knows TrustField is deployed and restructures their
privilege-escalation path to evade ensemble detection while preserving actual
reachability.

Three strategies:

EDGE_SPLITTING
    High-risk edges (exploitability > 0.6) are split via an intermediate
    WORKLOAD node.  Each resulting hop carries weight * 0.6, so neither hop
    individually looks high-risk, yet the full path is preserved.

PRIVILEGE_DILUTION
    Decoy SERVICE nodes (low privilege, low sensitivity) are injected and
    connected to high-privilege nodes via TOKEN_MINT edges.  This inflates
    the graph, spreading ensemble risk scores thin so that real attack-path
    nodes fall below the detection threshold.

CHAIN_OBFUSCATION
    SERVICE→SERVICE chain segments are broken up by inserting ROLE nodes
    with ASSUME_ROLE + TOKEN_MINT patterns.  This mimics a legitimate
    service-mesh role-assumption flow, confusing the epidemic and
    spectral-cascade models that track linear propagation.
"""

from __future__ import annotations

import random
from enum import Enum
from typing import List, Optional, Tuple

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph


class MutationStrategy(Enum):
    """Adversarial mutation strategies available to the attacker."""

    EDGE_SPLITTING = "EDGE_SPLITTING"
    PRIVILEGE_DILUTION = "PRIVILEGE_DILUTION"
    CHAIN_OBFUSCATION = "CHAIN_OBFUSCATION"


class AdversarialGraphMutator:
    """Produces adversarially-mutated copies of a TrustGraph.

    Each mutation preserves the original attacker's reachability while
    attempting to reduce TrustField's predicted blast radius (PBR) relative
    to the verified blast radius (VBR), thereby widening the exploitability
    gap and evading detection.

    Example::

        mutator = AdversarialGraphMutator()
        mutated = mutator.mutate(graph, MutationStrategy.EDGE_SPLITTING,
                                 intensity=0.4, seed=42)
        # mutated has more nodes; original attack paths still reachable

    Args:
        exploitability_threshold: Edge/node exploitability above which a
            component is considered "high risk" and targeted for mutation.
            Default 0.6.
    """

    def __init__(self, exploitability_threshold: float = 0.6) -> None:
        self._threshold = exploitability_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mutate(
        self,
        graph: TrustGraph,
        strategy: MutationStrategy,
        intensity: float = 0.3,
        seed: int = 42,
        blast_radius_analysis=None,
    ) -> TrustGraph:
        """Return an adversarially-mutated copy of ``graph``.

        The original graph is never modified.

        Args:
            graph: Source TrustGraph to mutate.
            strategy: Which mutation strategy to apply.
            intensity: Strength of mutation in ``[0.0, 1.0]``.
                ``0.0`` → no change; ``1.0`` → maximum mutation.
            seed: Random seed for reproducibility.
            blast_radius_analysis: Optional ``BlastRadiusAnalysis`` from a
                prior TrustField run.  When provided, ``per_node_exploitability``
                drives edge selection.  Falls back to raw edge weight otherwise.

        Returns:
            A new ``TrustGraph`` (deep copy) with the mutation applied.
        """
        intensity = max(0.0, min(1.0, intensity))
        rng = random.Random(seed)

        # Work on a deep copy
        working = TrustGraph.from_dict(graph.to_dict())

        if strategy == MutationStrategy.EDGE_SPLITTING:
            self._apply_edge_splitting(working, intensity, rng, blast_radius_analysis)
        elif strategy == MutationStrategy.PRIVILEGE_DILUTION:
            self._apply_privilege_dilution(working, intensity, rng, blast_radius_analysis)
        elif strategy == MutationStrategy.CHAIN_OBFUSCATION:
            self._apply_chain_obfuscation(working, intensity, rng)

        return working

    # ------------------------------------------------------------------
    # Strategy implementations
    # ------------------------------------------------------------------

    def _apply_edge_splitting(
        self,
        g: TrustGraph,
        intensity: float,
        rng: random.Random,
        bra,
    ) -> None:
        """Split high-risk edges via intermediate WORKLOAD nodes.

        Each high-risk edge u→v (weight w) becomes:
            u → X  (weight w*0.6, AUTHENTICATE_AS)
            X → v  (weight w*0.6, AUTHENTICATE_AS)
        where X is a new WORKLOAD node.  Neither hop individually triggers
        the high-risk threshold; the full path is preserved.
        """
        high_risk = self._get_high_risk_edges(g, bra)
        n_split = max(0, round(len(high_risk) * intensity))
        if n_split == 0:
            return

        to_split = rng.sample(high_risk, min(n_split, len(high_risk)))
        nx_g = g._graph
        counter = 0

        for u, v in to_split:
            if not nx_g.has_edge(u, v):
                continue
            orig_meta: EdgeMetadata = nx_g.edges[u, v]["metadata"]
            new_weight = round(orig_meta.weight * 0.6, 4)
            mid_id = f"wp_{u}_{v}_{counter}"
            counter += 1

            # Add intermediate WORKLOAD node
            mid_meta = NodeMetadata(
                node_id=mid_id,
                node_type=NodeType.WORKLOAD,
                name=f"wl-{counter}",
                privilege_level=0.1,
                sensitivity=0.1,
            )
            g.add_node(mid_meta)

            # u → mid
            g.add_edge(u, mid_id, EdgeMetadata(
                edge_id=f"{u}->{mid_id}",
                edge_type=EdgeType.AUTHENTICATE_AS,
                weight=new_weight,
                delegation_depth_limit=orig_meta.delegation_depth_limit,
            ))
            # mid → v
            g.add_edge(mid_id, v, EdgeMetadata(
                edge_id=f"{mid_id}->{v}",
                edge_type=EdgeType.AUTHENTICATE_AS,
                weight=new_weight,
                delegation_depth_limit=orig_meta.delegation_depth_limit,
            ))

            # Remove the original high-risk direct edge
            nx_g.remove_edge(u, v)

    def _apply_privilege_dilution(
        self,
        g: TrustGraph,
        intensity: float,
        rng: random.Random,
        bra,
    ) -> None:
        """Inject decoy SERVICE nodes to spread ensemble risk scores thin.

        Adds ``int(intensity * 10)`` decoy nodes (privilege=0.1) and
        connects them to randomly-selected high-privilege nodes via
        TOKEN_MINT edges (weight=0.15).  The ensemble now spreads risk
        across many low-privilege nodes; real attack-path nodes score
        below the detection threshold.
        """
        n_decoys = int(intensity * 10)
        if n_decoys == 0:
            return

        # High-privilege nodes are targets for decoy connections
        nx_g = g._graph
        high_priv_nodes = [
            nid for nid in nx_g.nodes()
            if (nx_g.nodes[nid].get("metadata") is not None
                and nx_g.nodes[nid]["metadata"].privilege_level >= 0.5)
        ]
        if not high_priv_nodes:
            high_priv_nodes = list(nx_g.nodes())

        for i in range(n_decoys):
            decoy_id = f"decoy_{i}_{rng.randint(0, 9999)}"
            g.add_node(NodeMetadata(
                node_id=decoy_id,
                node_type=NodeType.SERVICE,
                name=f"decoy-svc-{i}",
                privilege_level=0.1,
                sensitivity=0.1,
            ))
            target = rng.choice(high_priv_nodes)
            g.add_edge(decoy_id, target, EdgeMetadata(
                edge_id=f"{decoy_id}->{target}",
                edge_type=EdgeType.TOKEN_MINT,
                weight=0.15,
                delegation_depth_limit=1,
            ))

    def _apply_chain_obfuscation(
        self,
        g: TrustGraph,
        intensity: float,
        rng: random.Random,
    ) -> None:
        """Break SERVICE→SERVICE chain segments via inserted ROLE nodes.

        For each SERVICE→SERVICE edge targeted by intensity:
            u (SERVICE) → role_X (ROLE, ASSUME_ROLE)
            role_X      → v (SERVICE, TOKEN_MINT)
        This mimics legitimate service-mesh role-assumption, confusing
        the epidemic model's linear propagation detection.
        """
        nx_g = g._graph
        svc_svc_edges: List[Tuple[str, str]] = [
            (u, v)
            for u, v in list(nx_g.edges())
            if (
                nx_g.nodes[u].get("metadata") is not None
                and nx_g.nodes[v].get("metadata") is not None
                and nx_g.nodes[u]["metadata"].node_type == NodeType.SERVICE
                and nx_g.nodes[v]["metadata"].node_type == NodeType.SERVICE
            )
        ]

        n_obfuscate = max(0, round(len(svc_svc_edges) * intensity))
        if n_obfuscate == 0:
            return

        to_obf = rng.sample(svc_svc_edges, min(n_obfuscate, len(svc_svc_edges)))
        counter = 0

        for u, v in to_obf:
            if not nx_g.has_edge(u, v):
                continue
            orig_meta: EdgeMetadata = nx_g.edges[u, v]["metadata"]
            role_id = f"obf_role_{counter}_{u}"
            counter += 1

            g.add_node(NodeMetadata(
                node_id=role_id,
                node_type=NodeType.ROLE,
                name=f"obf-role-{counter}",
                privilege_level=0.4,
                sensitivity=0.3,
            ))

            # u → role_X (ASSUME_ROLE)
            g.add_edge(u, role_id, EdgeMetadata(
                edge_id=f"{u}->{role_id}",
                edge_type=EdgeType.ASSUME_ROLE,
                weight=round(orig_meta.weight * 0.9, 4),
                delegation_depth_limit=orig_meta.delegation_depth_limit,
            ))
            # role_X → v (TOKEN_MINT)
            g.add_edge(role_id, v, EdgeMetadata(
                edge_id=f"{role_id}->{v}",
                edge_type=EdgeType.TOKEN_MINT,
                weight=round(orig_meta.weight * 0.9, 4),
                delegation_depth_limit=orig_meta.delegation_depth_limit,
            ))

            nx_g.remove_edge(u, v)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_high_risk_edges(
        self,
        g: TrustGraph,
        bra,
    ) -> List[Tuple[str, str]]:
        """Return edges above the exploitability threshold.

        Uses ``bra.per_node_exploitability`` when available; falls back to
        raw edge weight otherwise.
        """
        nx_g = g._graph
        per_node_exp = {}
        if bra is not None and hasattr(bra, "per_node_exploitability"):
            per_node_exp = bra.per_node_exploitability

        high_risk = []
        for u, v, data in nx_g.edges(data=True):
            meta = data.get("metadata")
            edge_weight = float(meta.weight) if meta is not None else 1.0

            if per_node_exp:
                node_score = max(
                    per_node_exp.get(u, 0.0),
                    per_node_exp.get(v, 0.0),
                )
                if node_score > self._threshold:
                    high_risk.append((u, v))
            else:
                # Fallback: use edge weight
                if edge_weight > self._threshold:
                    high_risk.append((u, v))

        return high_risk
