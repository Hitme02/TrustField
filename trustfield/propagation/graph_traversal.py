"""Model 1 — Graph Traversal (BFS/DFS reachability) propagation model.

This model computes the STRUCTURAL UPPER BOUND on compromise spread: every node
reachable from any seed node via directed edges is flagged as compromised. This
is equivalent to asking "what COULD an attacker reach?" under the worst-case
assumption that every trust edge is exploitable.

Research role:
    Graph traversal provides the pessimistic envelope used by the ensemble to
    calibrate optimistic models. If all five models agree with the traversal
    result, the ensemble has maximum confidence. If the traversal result is much
    larger than the other models, the ensemble will discount it using topology
    weights from Module 1.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Set

import networkx as nx

from trustfield.graph.edge_types import EdgeType
from trustfield.graph.trust_graph import TrustGraph

from .base import PropagationModel
from .propagation_result import PropagationResult

_MODEL_NAME = "graph_traversal"
_MODEL_CONFIDENCE = 1.0000


class GraphTraversalModel(PropagationModel):
    """BFS/DFS reachability model — structural upper bound on compromise spread.

    Follows ALL directed edges from each seed node and collects every reachable
    descendant. The result is the worst-case compromise surface: an adversary
    who can exploit every trust relationship in the graph.

    Because it makes no probabilistic assumptions, this model is the most
    conservative (largest predicted compromise set) but also the most reliable
    for identifying which nodes are structurally at risk.

    Example::

        model = GraphTraversalModel()
        result = model.run(graph, seed_nodes=["svc-001"], max_depth=3)
        print(result.compromised_nodes)
    """

    @property
    def model_name(self) -> str:
        return _MODEL_NAME

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        max_depth: Optional[int] = None,
        follow_edge_types: Optional[List[EdgeType]] = None,
        **kwargs,
    ) -> PropagationResult:
        """Run BFS reachability from all seed nodes.

        Args:
            graph: The trust graph to traverse.
            seed_nodes: Initially compromised node IDs.
            max_depth: If set, limits BFS to this many hops from each seed.
                ``None`` means unlimited depth.
            follow_edge_types: If set, only traverse edges of these types.
                ``None`` means follow all edge types.
            **kwargs: Ignored (for interface compatibility).

        Returns:
            A ``PropagationResult`` with the structural upper bound on
            compromise spread.

        Raises:
            KeyError: If any seed node ID is not present in ``graph``.
        """
        t_start = time.perf_counter()

        G = graph._graph

        # Validate seeds
        for nid in seed_nodes:
            if nid not in G:
                raise KeyError(f"Seed node '{nid}' not found in graph.")

        # Build filtered subgraph if edge-type filter is requested
        if follow_edge_types is not None:
            edge_type_set = set(follow_edge_types)
            filtered_edges = [
                (u, v)
                for u, v, d in G.edges(data=True)
                if d["metadata"].edge_type in edge_type_set
            ]
            G_work = nx.DiGraph()
            G_work.add_nodes_from(G.nodes(data=True))
            G_work.add_edges_from(filtered_edges)
        else:
            G_work = G

        # BFS reachability from each seed
        compromised: Set[str] = set(seed_nodes)
        for seed in seed_nodes:
            if max_depth is None:
                reachable = nx.descendants(G_work, seed)
            else:
                # Use BFS with depth cutoff
                reachable = set()
                for node, depth in nx.single_source_shortest_path_length(
                    G_work, seed, cutoff=max_depth
                ).items():
                    if node != seed:
                        reachable.add(node)
            compromised |= reachable

        # --- Propagation depth: max shortest path from nearest seed ---
        node_list = list(G.nodes())
        per_node_dist: Dict[str, float] = {}

        # For each compromised node, find shortest distance from any seed
        for node in compromised:
            min_dist = float("inf")
            for seed in seed_nodes:
                try:
                    d = nx.shortest_path_length(G_work, seed, node)
                    if d < min_dist:
                        min_dist = d
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass
            per_node_dist[node] = min_dist if min_dist != float("inf") else 0.0

        propagation_depth = int(max(per_node_dist.values(), default=0))

        # --- Per-node risk: 1/(dist+1), closer = higher risk ---
        per_node_risk: Dict[str, float] = {}
        for nid in G.nodes():
            if nid in seed_nodes:
                per_node_risk[nid] = 1.0
            elif nid in compromised:
                dist = per_node_dist.get(nid, 1.0)
                per_node_risk[nid] = 1.0 / (dist + 1.0)
            else:
                per_node_risk[nid] = 0.0

        # --- Cascade probability ---
        high_priv_reachable = any(
            graph.get_node(nid).privilege_level >= 0.9
            for nid in compromised
            if nid not in seed_nodes
        )
        if high_priv_reachable:
            cascade_probability = 1.0
        else:
            n_total = G.number_of_nodes()
            cascade_probability = len(compromised) / n_total if n_total > 0 else 0.0

        t_ms = (time.perf_counter() - t_start) * 1000.0

        return PropagationResult(
            model_name=_MODEL_NAME,
            seed_nodes=list(seed_nodes),
            compromised_nodes=compromised,
            propagation_depth=propagation_depth,
            cascade_probability=min(1.0, cascade_probability),
            model_confidence=_MODEL_CONFIDENCE,
            time_steps=1,
            convergence_achieved=True,
            per_node_risk=per_node_risk,
            raw_output={
                "max_depth_applied": max_depth,
                "edge_type_filter": (
                    [et.value for et in follow_edge_types]
                    if follow_edge_types else None
                ),
                "high_privilege_reachable": high_priv_reachable,
                "reachable_count_per_seed": {
                    seed: len(nx.descendants(G_work, seed))
                    for seed in seed_nodes
                },
            },
            computation_time_ms=t_ms,
        )
