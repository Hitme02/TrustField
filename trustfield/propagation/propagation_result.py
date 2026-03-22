"""Shared result dataclass for all TrustField propagation models.

Every model in the Multi-Model Propagation Engine (Module 2) returns a
``PropagationResult`` so that downstream components (Module 3 ensemble,
Module 4 verification, Module 6 visualization) can work with a uniform
interface regardless of which model produced the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class PropagationResult:
    """Unified output container for a single propagation model run.

    Attributes:
        model_name: Canonical identifier for the model that produced this
            result (e.g. ``"graph_traversal"``, ``"epidemic"``).
        seed_nodes: Node IDs that were marked as initially compromised
            (the attacker's entry points).
        compromised_nodes: Full set of node IDs predicted to be compromised
            after the model has run to completion.
        propagation_depth: Maximum hop-count from any seed node to any
            compromised node. Measures lateral movement distance.
        cascade_probability: Estimated probability [0.0, 1.0] that a
            full-graph cascade occurs from these seed nodes.
        model_confidence: Self-reported confidence [0.0, 1.0] of the model
            in its own output. Used by Module 3 to weight ensemble votes.
        time_steps: Number of simulation steps / iterations performed.
        convergence_achieved: Whether the model reached a stable fixed point
            before exhausting ``time_steps``.
        per_node_risk: Mapping from node_id to a risk score in [0.0, 1.0].
            Higher values indicate higher predicted probability of compromise.
        raw_output: Model-specific auxiliary data (eigenvalues, trajectories,
            cluster distributions, etc.) preserved for Module 4 verification
            and Module 6 visualization.
        computation_time_ms: Wall-clock time in milliseconds for this run.
    """

    model_name: str
    seed_nodes: List[str]
    compromised_nodes: Set[str]
    propagation_depth: int
    cascade_probability: float
    model_confidence: float
    time_steps: int
    convergence_achieved: bool
    per_node_risk: Dict[str, float]
    raw_output: Dict
    computation_time_ms: float = 0.0

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dictionary.

        Returns:
            Dictionary with all fields as JSON primitives.
            ``compromised_nodes`` is serialized as a sorted list.
        """
        return {
            "model_name": self.model_name,
            "seed_nodes": self.seed_nodes,
            "compromised_nodes": sorted(self.compromised_nodes),
            "propagation_depth": self.propagation_depth,
            "cascade_probability": self.cascade_probability,
            "model_confidence": self.model_confidence,
            "time_steps": self.time_steps,
            "convergence_achieved": self.convergence_achieved,
            "per_node_risk": self.per_node_risk,
            "raw_output": self.raw_output,
            "computation_time_ms": self.computation_time_ms,
        }

    def summary(self) -> str:
        """Return a compact one-line summary string for display.

        Returns:
            Human-readable summary of the result.
        """
        return (
            f"{self.model_name}: "
            f"{len(self.compromised_nodes)} compromised, "
            f"depth={self.propagation_depth}, "
            f"cascade_prob={self.cascade_probability:.3f}, "
            f"conf={self.model_confidence:.2f}, "
            f"t={self.computation_time_ms:.1f}ms"
        )
