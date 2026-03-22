"""TrustField graph subpackage — trust graph construction layer (Module 1).

Exports the primary public API consumed by all downstream TrustField modules:

    from trustfield.graph import TrustGraph, IAMSimulator, TopologyFingerprinter
    from trustfield.graph import NodeType, NodeMetadata
    from trustfield.graph import EdgeType, EdgeMetadata
    from trustfield.graph import TopologyType, TopologyFingerprint
"""

from .edge_types import EdgeMetadata, EdgeType
from .fingerprinter import TopologyFingerprint, TopologyFingerprinter, TopologyType
from .iam_simulator import IAMSimulator
from .node_types import NodeMetadata, NodeType
from .trust_graph import TrustGraph

__all__ = [
    "TrustGraph",
    "IAMSimulator",
    "TopologyFingerprinter",
    "TopologyFingerprint",
    "TopologyType",
    "NodeType",
    "NodeMetadata",
    "EdgeType",
    "EdgeMetadata",
]
