"""WeightVector — normalised model weight assignment for the TrustField ensemble.

Every ensemble prediction is governed by a WeightVector that assigns a
reliability weight to each of the five propagation models. Weights are
topology-dependent (sourced from the TopologyAwareSelector prior) and
can be refined over time by the WeightTracker's adaptive mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

MODEL_NAMES = [
    "graph_traversal",
    "epidemic",
    "spectral_cascade",
    "percolation",
    "control_system",
    "gnn",
]

_UNIFORM_WEIGHT = 1.0 / len(MODEL_NAMES)


@dataclass
class WeightVector:
    """Normalised reliability weights for the five TrustField propagation models.

    Attributes:
        weights: Mapping from model name to its ensemble weight in [0, 1].
            Must sum to 1.0 (enforced by ``validate()``).
        topology_type: The topology classification string this vector was
            computed for (e.g. ``"HUB"``, ``"CHAIN"``).
        source: How these weights were derived:
            - ``"topology_prior"`` — from the TopologyAwareSelector based on
              graph-theoretic rationale.
            - ``"adaptive"`` — learned from historical model accuracy via the
              WeightTracker.
            - ``"uniform"`` — equal weight for all models (fallback).
    """

    weights: Dict[str, float]
    topology_type: str
    source: str  # "topology_prior" | "adaptive" | "uniform"

    def validate(self) -> None:
        """Assert that the weight vector is a valid probability distribution.

        Raises:
            AssertionError: If weights do not sum to 1.0 (tolerance 1e-6),
                or if any weight is outside [0.0, 1.0].
        """
        total = sum(self.weights.values())
        assert abs(total - 1.0) < 1e-6, (
            f"Weights must sum to 1.0, got {total:.8f}"
        )
        for name, w in self.weights.items():
            assert 0.0 <= w <= 1.0, (
                f"Weight for '{name}' is {w}, must be in [0.0, 1.0]"
            )

    def normalize(self) -> "WeightVector":
        """Return a new WeightVector with weights rescaled to sum to 1.0.

        Useful when raw scores (e.g. F1 values) are assigned as weights before
        normalisation.  If all weights are zero the result is a uniform vector.

        Returns:
            A new ``WeightVector`` with the same topology_type and source but
            with weights normalised to sum exactly to 1.0.
        """
        total = sum(self.weights.values())
        if total == 0.0:
            n = len(self.weights)
            normalised = {k: 1.0 / n for k in self.weights}
        else:
            normalised = {k: v / total for k, v in self.weights.items()}
        return WeightVector(
            weights=normalised,
            topology_type=self.topology_type,
            source=self.source,
        )

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary.

        Returns:
            Dictionary with ``weights``, ``topology_type``, and ``source``.
        """
        return {
            "weights": dict(self.weights),
            "topology_type": self.topology_type,
            "source": self.source,
        }

    @classmethod
    def uniform(cls, topology_type: str = "MIXED") -> "WeightVector":
        """Create a uniform weight vector (all models equally weighted).

        Args:
            topology_type: Optional topology label. Defaults to ``"MIXED"``.

        Returns:
            A ``WeightVector`` with equal weights summing to 1.0.
        """
        return cls(
            weights={name: _UNIFORM_WEIGHT for name in MODEL_NAMES},
            topology_type=topology_type,
            source="uniform",
        )

    def __repr__(self) -> str:
        w_str = ", ".join(f"{k}={v:.3f}" for k, v in self.weights.items())
        return f"WeightVector({w_str}, topo={self.topology_type}, src={self.source})"
