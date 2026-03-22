"""Model 3 — Spectral Cascade analysis.

Uses the spectral radius (largest eigenvalue) of the weighted adjacency matrix
to determine whether a cascade is algebraically possible, and the principal
eigenvector to rank which nodes carry the highest cascade risk.

Research role:
    Spectral analysis is the most theoretically grounded model. The cascade
    condition τ > 1/λ_max gives a hard algebraic criterion for whether the
    trust graph's structure permits runaway compromise propagation. In hub
    topologies, λ_max is large (the hub concentrates spectral energy), meaning
    even a small propagation threshold triggers a full cascade. This is why
    Module 1's fingerprinter weights spectral analysis highest for HUB topology.

Mathematical foundation:
    The adjacency matrix A encodes trust weights. Its largest eigenvalue λ_max
    (spectral radius) characterizes how quickly information/compromise can
    amplify through the graph. The threshold condition τ > 1/λ_max comes from
    the stability analysis of the linear dynamical system x(t+1) = τ·A·x(t):
    the system grows unboundedly (cascade) when τ·λ_max > 1.
"""

from __future__ import annotations

import time
from typing import Dict, List

import numpy as np

from trustfield.graph.trust_graph import TrustGraph

from .base import PropagationModel
from .propagation_result import PropagationResult

_MODEL_NAME = "spectral_cascade"
_MODEL_CONFIDENCE = 0.2974


class SpectralCascadeModel(PropagationModel):
    """Spectral cascade analysis based on adjacency matrix eigenspectrum.

    Computes the cascade condition τ > 1/λ_max and uses the principal
    eigenvector to score each node's cascade risk.

    Example::

        model = SpectralCascadeModel()
        result = model.run(graph, seed_nodes=["svc-001"], tau=0.5)
        print(result.raw_output["lambda_max"])
        print(result.raw_output["cascade_condition_met"])
    """

    @property
    def model_name(self) -> str:
        return _MODEL_NAME

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        tau: float = 0.5,
        risk_threshold: float = 0.3,
        **kwargs,
    ) -> PropagationResult:
        """Run spectral cascade analysis.

        Args:
            graph: Trust graph. The weighted adjacency matrix is extracted.
            seed_nodes: Initially compromised node IDs.
            tau: Propagation threshold in [0, 1]. Default 0.5. The cascade
                condition is ``tau > 1/lambda_max``. Higher tau means the
                adversary has a more powerful exploit (higher per-edge spread).
            risk_threshold: Nodes with normalised eigenvector centrality >= this
                value are included in ``compromised_nodes`` when a cascade is
                possible. Default 0.3.
            **kwargs: Ignored.

        Returns:
            A ``PropagationResult`` with spectral cascade analysis.

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

        # --- Step 1: Weighted adjacency matrix and eigenspectrum ---
        A = graph.to_adjacency_matrix()  # shape (n, n)

        if n < 2 or A.sum() == 0:
            # Degenerate graph: no edges → no cascade possible
            per_node_risk = {nid: (1.0 if nid in seed_nodes else 0.0) for nid in node_list}
            t_ms = (time.perf_counter() - t_start) * 1000.0
            return PropagationResult(
                model_name=_MODEL_NAME,
                seed_nodes=list(seed_nodes),
                compromised_nodes=set(seed_nodes),
                propagation_depth=0,
                cascade_probability=0.0,
                model_confidence=_MODEL_CONFIDENCE,
                time_steps=1,
                convergence_achieved=True,
                per_node_risk=per_node_risk,
                raw_output={
                    "lambda_max": 0.0,
                    "eigenvector_centrality": per_node_risk,
                    "cascade_condition_met": False,
                    "spectral_gap": 0.0,
                    "tau": tau,
                },
                computation_time_ms=t_ms,
            )

        eigenvalues = np.linalg.eigvals(A)
        real_parts = np.real(eigenvalues)
        sorted_idx = np.argsort(real_parts)[::-1]
        lambda_max = float(real_parts[sorted_idx[0]])
        lambda_2 = float(real_parts[sorted_idx[1]]) if n >= 2 else 0.0
        spectral_gap = lambda_max - lambda_2

        # --- Step 2: Cascade condition ---
        # Avoid division by zero for graphs with zero spectral radius
        if lambda_max <= 0:
            cascade_possible = False
        else:
            cascade_possible = tau > (1.0 / lambda_max)

        # --- Step 3: Principal eigenvector for node risk ---
        # Use the eigenvector corresponding to the largest eigenvalue
        eigenvectors = np.linalg.eig(A)[1]  # columns are eigenvectors
        principal_vec = np.real(eigenvectors[:, sorted_idx[0]])
        abs_vec = np.abs(principal_vec)
        max_abs = abs_vec.max()
        if max_abs > 0:
            normalised_vec = abs_vec / max_abs
        else:
            normalised_vec = abs_vec

        per_node_risk: Dict[str, float] = {
            node_list[i]: float(normalised_vec[i]) for i in range(n)
        }
        eigenvector_centrality = dict(per_node_risk)  # copy for raw_output

        # --- Step 4: Compromised nodes ---
        if cascade_possible:
            compromised = {
                nid for nid, risk in per_node_risk.items()
                if risk >= risk_threshold
            }
        else:
            # No cascade: only seeds are compromised
            compromised = set(seed_nodes)

        compromised.update(seed_nodes)

        # --- Step 5: Cascade probability ---
        if lambda_max <= 0:
            cascade_probability = 0.0
        elif cascade_possible:
            cascade_probability = min(1.0, tau * lambda_max)
        else:
            cascade_probability = 0.1 * (tau * lambda_max)

        # --- Step 6: Propagation depth ---
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
                "lambda_max": lambda_max,
                "eigenvector_centrality": eigenvector_centrality,
                "cascade_condition_met": cascade_possible,
                "spectral_gap": spectral_gap,
                "tau": tau,
                "all_eigenvalues_real": sorted(real_parts.tolist(), reverse=True),
            },
            computation_time_ms=t_ms,
        )
