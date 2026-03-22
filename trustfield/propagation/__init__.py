"""TrustField propagation subpackage — Multi-Model Propagation Engine (Module 2).

Exports the six propagation models, the shared result type, and the runner.

    from trustfield.propagation import (
        PropagationRunner,
        PropagationResult,
        ComparisonReport,
        GraphTraversalModel,
        EpidemicModel,
        SpectralCascadeModel,
        PercolationModel,
        ControlSystemModel,
        GNNModel,
    )
"""

from .control_system import ControlSystemModel
from .epidemic import EpidemicModel
from .gnn_model import GNNModel
from .graph_traversal import GraphTraversalModel
from .percolation import PercolationModel
from .propagation_result import PropagationResult
from .runner import ComparisonReport, PropagationRunner
from .spectral_cascade import SpectralCascadeModel

# TemporalAttackSimulator is NOT re-exported here to avoid a circular import:
#   propagation.__init__ → temporal_model → guards.__init__ → containment_engine
#   → ensemble.__init__ → propagation.__init__
# Import directly: from trustfield.propagation.temporal_model import ...

__all__ = [
    "PropagationRunner",
    "ComparisonReport",
    "PropagationResult",
    "GraphTraversalModel",
    "EpidemicModel",
    "SpectralCascadeModel",
    "PercolationModel",
    "ControlSystemModel",
    "GNNModel",
]
