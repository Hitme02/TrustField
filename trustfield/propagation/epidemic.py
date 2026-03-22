"""Model 2 — SIR Epidemic propagation model.

Adapts the Susceptible-Infected-Recovered (SIR) epidemic model from
epidemiology to trust-graph compromise propagation. The core equation
I(t+1) = β·A·I(t) treats each node's infection state as a probability that
evolves over discrete time steps, with the weighted adjacency matrix A encoding
how strongly trust relationships amplify spread.

Research role:
    Epidemic models capture temporal dynamics — how FAST compromise spreads and
    what the steady-state infection level is. They are most informative for
    chain topologies (where infection travels linearly along delegation paths)
    and are weighted highest for CHAIN topology in Module 3's ensemble.

Key insight (from spec):
    Using the WEIGHTED adjacency matrix means high-trust edges (weight ≈ 1.0)
    propagate compromise faster than low-trust conditional edges (weight ≈ 0.3).
    This accurately reflects the real-world intuition that an unconditional
    sts:AssumeRole relationship is a much more dangerous propagation path than
    a conditional, MFA-protected one.
"""

from __future__ import annotations

import time
from typing import Dict, List

import numpy as np

from trustfield.graph.trust_graph import TrustGraph

from .base import PropagationModel
from .propagation_result import PropagationResult

_MODEL_NAME = "epidemic"
_MODEL_CONFIDENCE = 0.2608


class EpidemicModel(PropagationModel):
    """SIR epidemic model adapted for trust-graph compromise propagation.

    Iterates the discrete-time infection equation::

        I(t+1) = clip(β · A · I(t), 0, 1)

    until convergence or ``max_steps`` is reached.

    Attributes that affect the result:
        - ``beta``: Higher β means faster, wider spread.
        - The adjacency matrix weight: high-trust edges amplify spread.
        - ``infection_threshold``: Controls how optimistic/pessimistic the
          binary compromise decision is.

    Example::

        model = EpidemicModel()
        result = model.run(graph, seed_nodes=["svc-001"], beta=0.4)
        print(result.cascade_probability)
    """

    @property
    def model_name(self) -> str:
        return _MODEL_NAME

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        beta: float = 0.3,
        infection_threshold: float = 0.5,
        max_steps: int = 50,
        **kwargs,
    ) -> PropagationResult:
        """Run SIR epidemic simulation on the trust graph.

        Args:
            graph: The trust graph. Weighted adjacency matrix is extracted via
                ``graph.to_adjacency_matrix()``.
            seed_nodes: Initially compromised node IDs (set to 1.0 in I(0)).
            beta: Infection rate in [0, 1]. Default 0.3. At β=0 only seeds
                are infected; at β=1 spread is maximally fast.
            infection_threshold: A node is marked as compromised when its
                infection state I[v] >= this value. Default 0.5.
            max_steps: Maximum iteration count. Default 50.
            **kwargs: Ignored.

        Returns:
            A ``PropagationResult`` with temporal infection dynamics.

        Raises:
            KeyError: If any seed node ID is not in ``graph``.
        """
        t_start = time.perf_counter()

        G = graph._graph
        node_list = list(G.nodes())
        n = len(node_list)
        node_index = {nid: i for i, nid in enumerate(node_list)}

        for nid in seed_nodes:
            if nid not in G:
                raise KeyError(f"Seed node '{nid}' not found in graph.")

        # Weighted adjacency matrix
        A = graph.to_adjacency_matrix()  # shape (n, n)

        # Initialize infection vector
        I = np.zeros(n, dtype=float)
        for nid in seed_nodes:
            I[node_index[nid]] = 1.0

        convergence_achieved = False
        steps_run = 0

        for step in range(max_steps):
            I_new = beta * (A @ I)
            I_new = np.clip(I_new, 0.0, 1.0)
            # Seeds remain infected throughout (persistent compromise)
            for nid in seed_nodes:
                I_new[node_index[nid]] = 1.0

            delta = float(np.linalg.norm(I_new - I, ord=2))
            I = I_new
            steps_run = step + 1
            if delta < 1e-4:
                convergence_achieved = True
                break

        # --- Build result fields ---
        per_node_risk: Dict[str, float] = {
            node_list[i]: float(I[i]) for i in range(n)
        }

        compromised = {
            nid for nid, risk in per_node_risk.items()
            if risk >= infection_threshold
        }
        # Seeds always compromised
        compromised.update(seed_nodes)

        # Propagation depth via BFS on the original directed graph
        import networkx as nx
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

        cascade_probability = float(
            np.sum(I >= infection_threshold) / n
        ) if n > 0 else 0.0

        t_ms = (time.perf_counter() - t_start) * 1000.0

        return PropagationResult(
            model_name=_MODEL_NAME,
            seed_nodes=list(seed_nodes),
            compromised_nodes=compromised,
            propagation_depth=propagation_depth,
            cascade_probability=min(1.0, cascade_probability),
            model_confidence=_MODEL_CONFIDENCE,
            time_steps=steps_run,
            convergence_achieved=convergence_achieved,
            per_node_risk=per_node_risk,
            raw_output={
                "beta": beta,
                "infection_threshold": infection_threshold,
                "final_infection_vector": I.tolist(),
                "max_infection_value": float(np.max(I)),
                "mean_infection_value": float(np.mean(I)),
            },
            computation_time_ms=t_ms,
        )
