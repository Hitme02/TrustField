"""Abstract base class for all TrustField propagation models.

All five propagation models in Module 2 implement this interface so that the
PropagationRunner, Module 3 ensemble, and Module 4 verification can treat them
interchangeably.

Performance contract:
    Every model must complete in under 10 seconds for graphs up to 200 nodes.
    Every model must be deterministic given the same graph, seed_nodes, and kwargs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from trustfield.graph.trust_graph import TrustGraph

from .propagation_result import PropagationResult


class PropagationModel(ABC):
    """Abstract base for all TrustField trust-propagation models.

    Subclasses implement ``run()`` to simulate how compromise spreads through
    a ``TrustGraph`` starting from a set of initially-compromised seed nodes.

    Design constraints:
        - **Deterministic**: identical inputs must produce identical outputs.
        - **Self-contained**: the model receives all it needs in ``graph`` and
          ``kwargs``; it must not maintain mutable state between calls.
        - **Performance**: must complete within 10 seconds for N <= 200.
        - **Safe**: must never raise exceptions for valid inputs; degenerate
          inputs (empty graph, disconnected seeds) should return graceful results.

    Example::

        from trustfield.propagation import GraphTraversalModel

        model = GraphTraversalModel()
        result = model.run(graph, seed_nodes=["svc-001"])
        print(result.compromised_nodes)
    """

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Canonical string identifier for this model.

        Used as the key in ``PropagationRunner.run_all()`` output dict and
        as ``PropagationResult.model_name``.

        Returns:
            Lowercase underscore-separated model name string.
        """

    @abstractmethod
    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        **kwargs,
    ) -> PropagationResult:
        """Simulate trust-compromise propagation from ``seed_nodes``.

        Args:
            graph: The ``TrustGraph`` to propagate through. Must not be mutated.
            seed_nodes: List of node IDs that are initially compromised.
                All IDs must exist in ``graph``.
            **kwargs: Model-specific tuning parameters documented in each
                subclass.

        Returns:
            A fully populated ``PropagationResult``.

        Raises:
            KeyError: If any node ID in ``seed_nodes`` is not in ``graph``.
        """
