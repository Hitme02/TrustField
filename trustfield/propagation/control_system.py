"""Model 5 — Control System stability model.

Models trust-graph compromise propagation as a discrete-time linear control
system x(t+1) = A·x(t) + B·u(t). This framing allows applying the rich theory
of dynamical-systems stability to the cybersecurity problem: a stable system
(all eigenvalues inside the unit circle) will recover from an attack; an
unstable system will diverge (cascade).

Research role:
    Control-system analysis uniquely asks "does the system have the capacity
    to contain an attack?" rather than just predicting spread. The stability
    margin 1 - ρ(A) (where ρ is the spectral radius of the normalised matrix)
    measures how much room the security posture has before a cascade becomes
    inevitable. This is most informative for chain topologies, where a single
    attacker input propagates through the entire chain before dissipating.
    Module 3's ensemble weights this model highest for CHAIN topology (along
    with the epidemic model).

Control theory connection:
    The Schur stability criterion: a linear system x(t+1) = A·x(t) is stable
    iff all eigenvalues of A lie strictly inside the unit disk |λ| < 1.
    We normalize A to guarantee this, then simulate the impulse response.
    The shape of this response reveals how quickly / widely the attack input
    propagates before the system recovers.
"""

from __future__ import annotations

import time
from typing import Dict, List

import numpy as np

from trustfield.graph.trust_graph import TrustGraph

from .base import PropagationModel
from .propagation_result import PropagationResult

_MODEL_NAME = "control_system"
_MODEL_CONFIDENCE = 0.1267
_EPSILON = 1e-9


class ControlSystemModel(PropagationModel):
    """Discrete-time linear control system for trust-cascade stability analysis.

    Simulates the attack impulse response of the trust graph viewed as a
    discrete-time linear system. The stability margin of the normalised
    system matrix directly quantifies how close the infrastructure is to
    a runaway cascade.

    Example::

        model = ControlSystemModel()
        result = model.run(graph, seed_nodes=["svc-001"])
        print(result.raw_output["system_stable"])
        print(result.raw_output["stability_margin"])
    """

    @property
    def model_name(self) -> str:
        return _MODEL_NAME

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        max_steps: int = 50,
        convergence_threshold: float = 1e-4,
        **kwargs,
    ) -> PropagationResult:
        """Run discrete-time control system simulation.

        Args:
            graph: Trust graph. Weighted adjacency matrix is used as system
                matrix A, then normalised by (λ_max + ε).
            seed_nodes: Node IDs that are attacked at t=0 (u(0) = 1 for seeds).
            max_steps: Maximum simulation steps. Default 50.
            convergence_threshold: L2-norm change threshold for convergence.
                Default 1e-4.
            **kwargs: Ignored.

        Returns:
            A ``PropagationResult`` including the full state trajectory,
            eigenvalues, spectral radius, and stability margin.

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

        # --- Build system matrices ---
        A_raw = graph.to_adjacency_matrix()  # shape (n, n)

        # Eigenspectrum of raw adjacency
        eigenvalues_raw = np.linalg.eigvals(A_raw)
        spectral_radius_raw = float(np.max(np.abs(eigenvalues_raw)))

        # Normalise A so spectral radius < 1 (guarantees Schur stability)
        # This represents: security controls that scale down raw trust strengths
        A_norm = A_raw / (spectral_radius_raw + _EPSILON)

        # Eigenvalues of normalised A (all should have magnitude < 1)
        eigenvalues_norm = np.linalg.eigvals(A_norm)
        spectral_radius_norm = float(np.max(np.abs(eigenvalues_norm)))
        stability_margin = 1.0 - spectral_radius_norm
        system_stable = stability_margin > 0.0

        # B = identity (any node can be externally attacked)
        # B = I_n, so B @ u = u directly

        # Attack input vector u(0): seeds = 1, others = 0
        u = np.zeros(n, dtype=float)
        for nid in seed_nodes:
            u[node_index[nid]] = 1.0

        # --- Simulate x(t+1) = A_norm @ x(t) + B @ u(t) ---
        x = np.zeros(n, dtype=float)
        state_trajectory = []

        convergence_achieved = False
        steps_run = 0

        for step in range(max_steps):
            if step == 0:
                x_new = A_norm @ x + u  # Attack input at t=0 only
            else:
                x_new = A_norm @ x      # No further input after t=0

            x_new = np.clip(x_new, 0.0, 1.0)
            state_trajectory.append(x_new.tolist())

            delta = float(np.linalg.norm(x_new - x, ord=2))
            x = x_new
            steps_run = step + 1

            if delta < convergence_threshold:
                convergence_achieved = True
                break

        x_final = x

        # --- Build result fields ---
        per_node_risk: Dict[str, float] = {
            node_list[i]: float(x_final[i]) for i in range(n)
        }

        # Seed nodes always compromised
        compromise_threshold = 0.4
        compromised = {
            nid for nid, risk in per_node_risk.items()
            if risk >= compromise_threshold
        }
        compromised.update(seed_nodes)

        # Cascade probability based on stability margin
        if stability_margin < 0.1:
            cascade_probability = 0.9
        elif stability_margin > 0.5:
            cascade_probability = 0.2
        else:
            # Linear interpolation between 0.9 and 0.2 over [0.1, 0.5]
            t = (stability_margin - 0.1) / 0.4
            cascade_probability = 0.9 - t * (0.9 - 0.2)

        # Propagation depth
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
            time_steps=steps_run,
            convergence_achieved=convergence_achieved,
            per_node_risk=per_node_risk,
            raw_output={
                "eigenvalues": [complex(e) for e in eigenvalues_norm.tolist()],
                "spectral_radius": spectral_radius_norm,
                "stability_margin": stability_margin,
                "system_stable": system_stable,
                "state_trajectory": state_trajectory,
                "spectral_radius_raw": spectral_radius_raw,
                "normalisation_factor": spectral_radius_raw + _EPSILON,
            },
            computation_time_ms=t_ms,
        )
