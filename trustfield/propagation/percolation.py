"""Model 4 — Bond Percolation propagation model.

Models the stochastic phase-transition behaviour of trust compromise using
Monte Carlo bond percolation. Each trust edge is independently included in a
"percolated subgraph" with probability proportional to its weight, simulating
the uncertainty over which edges are actually exploitable.

Research role:
    Percolation captures the PHASE-TRANSITION nature of trust compromise.
    Below a critical edge-retention probability, compromise remains local.
    Above it, a "giant connected component" forms encompassing most of the
    graph. Dense-cluster topologies are most susceptible to this transition
    because many redundant paths exist between nodes (if one edge is blocked,
    another route opens the same path). This is why Module 3's ensemble
    weights percolation highest for DENSE_CLUSTER topology.

Mathematical foundation:
    Bond percolation on a graph G=(V,E) retains each edge independently with
    probability p. The giant component transition occurs near a critical
    threshold p_c that depends on graph structure. Our p is edge.weight ×
    percolation_probability, so higher-trust edges are retained more often.
"""

from __future__ import annotations

import random
import time
from collections import Counter
from typing import Dict, List, Set, Tuple

import networkx as nx

from trustfield.graph.trust_graph import TrustGraph

from .base import PropagationModel
from .propagation_result import PropagationResult

_MODEL_NAME = "percolation"
_MODEL_CONFIDENCE = 0.7279


class PercolationModel(PropagationModel):
    """Monte Carlo bond percolation model for stochastic cascade detection.

    Runs ``n_trials`` independent percolation simulations. In each trial:
    1. Every edge is retained with probability = ``edge.weight * percolation_probability``
    2. Connected components of the retained subgraph are computed
    3. A "giant component" is detected if any component > ``giant_threshold * N``

    Per-node risk is the fraction of trials in which the node ends up in the
    giant component (or reachable from a seed in a large component).

    Example::

        model = PercolationModel()
        result = model.run(graph, seed_nodes=["svc-001"],
                           percolation_probability=0.7, n_trials=200)
        print(result.raw_output["giant_component_probability"])
    """

    @property
    def model_name(self) -> str:
        return _MODEL_NAME

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        percolation_probability: float = 0.6,
        n_trials: int = 100,
        giant_threshold: float = 0.3,
        random_seed: int = 42,
        **kwargs,
    ) -> PropagationResult:
        """Run Monte Carlo bond percolation.

        Args:
            graph: The trust graph to percolate.
            seed_nodes: Initially compromised node IDs. Used to identify
                which components are "seeded" and therefore at risk.
            percolation_probability: Base probability that any edge is
                included in a given trial. Actual per-edge probability is
                ``edge.weight * percolation_probability``. Default 0.6.
            n_trials: Number of Monte Carlo trials. Default 100.
                More trials = more stable estimates but slower.
            giant_threshold: Fraction of N above which a component is
                considered "giant". Default 0.3 (30% of nodes).
            random_seed: Seed for reproducibility. Default 42.
            **kwargs: Ignored.

        Returns:
            A ``PropagationResult`` with percolation statistics.

        Raises:
            KeyError: If any seed node ID is not in ``graph``.
        """
        t_start = time.perf_counter()

        G = graph._graph
        node_list = list(G.nodes())
        n = len(node_list)
        edges_with_weights: List[Tuple[str, str, float]] = [
            (u, v, d["metadata"].weight)
            for u, v, d in G.edges(data=True)
        ]

        for nid in seed_nodes:
            if nid not in G:
                raise KeyError(f"Seed node '{nid}' not found in graph.")

        seed_set = set(seed_nodes)
        giant_size_threshold = giant_threshold * n

        rng = random.Random(random_seed)
        np_rng = __import__("numpy").random.default_rng(random_seed)

        # Per-node counters
        node_in_giant: Dict[str, int] = {nid: 0 for nid in node_list}
        node_reachable_from_seed: Dict[str, int] = {nid: 0 for nid in node_list}

        giant_formed_count = 0
        giant_component_sizes: List[int] = []
        all_component_sizes: Counter = Counter()

        # Best trial: the one where largest component containing a seed is biggest
        best_trial_compromised: Set[str] = set(seed_nodes)
        best_seed_component_size = 0

        for trial in range(n_trials):
            # Build percolated subgraph for this trial
            # Use undirected for component analysis (compromise can flow either
            # way once a relationship is exploitable)
            H = nx.Graph()
            H.add_nodes_from(node_list)
            for u, v, w in edges_with_weights:
                retention_prob = min(1.0, w * percolation_probability)
                if rng.random() < retention_prob:
                    H.add_edge(u, v)

            # Find connected components
            components = list(nx.connected_components(H))
            sizes = [len(c) for c in components]

            max_size = max(sizes) if sizes else 0
            all_component_sizes.update(sizes)

            giant_formed = max_size > giant_size_threshold
            if giant_formed:
                giant_formed_count += 1

            # Track which nodes are in the giant component
            for comp in components:
                if len(comp) > giant_size_threshold:
                    for nid in comp:
                        node_in_giant[nid] += 1

            # Track reachability from seeds in this trial
            # Build directed subgraph for reachability
            H_dir = nx.DiGraph()
            H_dir.add_nodes_from(node_list)
            for u, v, w in edges_with_weights:
                retention_prob = min(1.0, w * percolation_probability)
                if rng.random() < retention_prob:
                    H_dir.add_edge(u, v)

            reachable_this_trial: Set[str] = set(seed_nodes)
            for seed in seed_nodes:
                reachable_this_trial |= nx.descendants(H_dir, seed)

            for nid in reachable_this_trial:
                node_reachable_from_seed[nid] += 1

            # Track best trial for compromised_nodes determination
            seed_comp_size = 0
            for comp in components:
                if seed_set & comp:
                    if len(comp) > seed_comp_size:
                        seed_comp_size = len(comp)
                        if seed_comp_size > best_seed_component_size:
                            best_seed_component_size = seed_comp_size
                            best_trial_compromised = set(comp) | reachable_this_trial

            giant_component_sizes.append(max_size)

        # --- Aggregate statistics ---
        giant_component_probability = giant_formed_count / n_trials if n_trials > 0 else 0.0
        avg_giant_size = (
            sum(giant_component_sizes) / len(giant_component_sizes)
            if giant_component_sizes else 0.0
        )

        # Per-node risk: combine giant-component membership + seed reachability
        per_node_risk: Dict[str, float] = {}
        for nid in node_list:
            giant_frac = node_in_giant[nid] / n_trials
            reach_frac = node_reachable_from_seed[nid] / n_trials
            # Weighted combination: reachability from seed is more direct risk
            per_node_risk[nid] = min(1.0, 0.4 * giant_frac + 0.6 * reach_frac)

        # Seed nodes always at full risk
        for nid in seed_nodes:
            per_node_risk[nid] = 1.0

        # Compromised: nodes in best trial + high-risk nodes
        risk_compromised = {
            nid for nid, risk in per_node_risk.items() if risk >= 0.5
        }
        compromised = best_trial_compromised | risk_compromised | seed_set

        # Propagation depth in best trial
        propagation_depth = 0
        for seed in seed_nodes:
            for node in compromised:
                if node == seed:
                    continue
                try:
                    d = nx.shortest_path_length(G, seed, node)
                    if d > propagation_depth:
                        propagation_depth = d
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass

        # Identify critical edges: edges whose removal drops giant_prob most
        # Approximation: edges between high-risk nodes that span clusters
        critical_edges = []
        for u, v, data in G.edges(data=True):
            u_risk = per_node_risk.get(u, 0.0)
            v_risk = per_node_risk.get(v, 0.0)
            if u_risk >= 0.4 and v_risk >= 0.4:
                critical_edges.append(f"{u}->{v}")
        critical_edges = critical_edges[:10]  # Top 10

        # Cluster size distribution
        cluster_size_dist = dict(all_component_sizes.most_common(20))

        cascade_probability = giant_component_probability

        t_ms = (time.perf_counter() - t_start) * 1000.0

        return PropagationResult(
            model_name=_MODEL_NAME,
            seed_nodes=list(seed_nodes),
            compromised_nodes=compromised,
            propagation_depth=propagation_depth,
            cascade_probability=min(1.0, cascade_probability),
            model_confidence=_MODEL_CONFIDENCE,
            time_steps=n_trials,
            convergence_achieved=True,
            per_node_risk=per_node_risk,
            raw_output={
                "giant_component_probability": giant_component_probability,
                "avg_giant_component_size": avg_giant_size,
                "critical_edges": critical_edges,
                "cluster_size_distribution": cluster_size_dist,
                "percolation_probability": percolation_probability,
                "n_trials": n_trials,
                "giant_threshold": giant_threshold,
            },
            computation_time_ms=t_ms,
        )
