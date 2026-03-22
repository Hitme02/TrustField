"""Core trust graph data structure for TrustField.

This module provides the ``TrustGraph`` class — a typed, serializable directed
graph that models trust-delegation relationships between infrastructure entities.
It wraps a ``networkx.DiGraph`` and enforces metadata schemas on all nodes and
edges, forming the foundational data structure consumed by all downstream
TrustField modules (propagation models, verification engine, visualization).
"""

from __future__ import annotations

from typing import List, Optional

import networkx as nx
import numpy as np

from .edge_types import EdgeMetadata
from .node_types import NodeMetadata, NodeType


class TrustGraph:
    """A typed, directed trust-propagation graph over infrastructure entities.

    All nodes carry ``NodeMetadata`` and all edges carry ``EdgeMetadata``.
    The underlying representation is a ``networkx.DiGraph`` stored at
    ``self._graph``, but callers should use the typed API rather than
    accessing NetworkX directly, so that downstream modules receive
    consistently structured data.

    Example::

        from trustfield.graph import TrustGraph
        from trustfield.graph.node_types import NodeMetadata, NodeType
        from trustfield.graph.edge_types import EdgeMetadata, EdgeType

        g = TrustGraph()
        svc = NodeMetadata("svc-1", NodeType.SERVICE, "auth-service", 0.4, 0.6)
        role = NodeMetadata("role-1", NodeType.ROLE, "admin-role", 0.9, 0.9)
        g.add_node(svc)
        g.add_node(role)
        edge = EdgeMetadata("e1", EdgeType.ASSUME_ROLE, weight=0.8,
                            delegation_depth_limit=2)
        g.add_edge("svc-1", "role-1", edge)
    """

    def __init__(self) -> None:
        """Initialize an empty TrustGraph."""
        self._graph: nx.DiGraph = nx.DiGraph()

    @property
    def nx_graph(self) -> nx.DiGraph:
        """Public read-only alias for the underlying ``networkx.DiGraph``."""
        return self._graph

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(self, node_metadata: NodeMetadata) -> str:
        """Add an infrastructure node to the graph.

        If a node with the same ``node_id`` already exists it will be
        overwritten with the new metadata.

        Args:
            node_metadata: Fully populated ``NodeMetadata`` for the new node.

        Returns:
            The ``node_id`` of the added node.
        """
        self._graph.add_node(node_metadata.node_id, metadata=node_metadata)
        return node_metadata.node_id

    def get_node(self, node_id: str) -> NodeMetadata:
        """Retrieve the metadata for a node by its ID.

        Args:
            node_id: The unique identifier of the node to look up.

        Returns:
            The ``NodeMetadata`` associated with ``node_id``.

        Raises:
            KeyError: If no node with ``node_id`` exists in the graph.
        """
        if node_id not in self._graph:
            raise KeyError(f"Node '{node_id}' not found in TrustGraph.")
        return self._graph.nodes[node_id]["metadata"]

    def get_nodes_by_type(self, node_type: NodeType) -> List[NodeMetadata]:
        """Return all nodes matching a given ``NodeType``.

        Args:
            node_type: The type to filter by.

        Returns:
            List of ``NodeMetadata`` instances whose ``node_type`` equals
            ``node_type``. May be empty if no such nodes exist.
        """
        return [
            data["metadata"]
            for _, data in self._graph.nodes(data=True)
            if data["metadata"].node_type == node_type
        ]

    def get_high_privilege_nodes(self, threshold: float = 0.7) -> List[NodeMetadata]:
        """Return all nodes whose ``privilege_level`` meets or exceeds a threshold.

        Args:
            threshold: Minimum privilege level to include (inclusive).
                Defaults to 0.7, which captures admin roles and root-equivalent
                identities while excluding standard users and services.

        Returns:
            List of ``NodeMetadata`` instances with
            ``privilege_level >= threshold``, sorted descending by privilege.
        """
        nodes = [
            data["metadata"]
            for _, data in self._graph.nodes(data=True)
            if data["metadata"].privilege_level >= threshold
        ]
        return sorted(nodes, key=lambda n: n.privilege_level, reverse=True)

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(
        self, source_id: str, target_id: str, edge_metadata: EdgeMetadata
    ) -> str:
        """Add a directed trust-delegation edge to the graph.

        Both ``source_id`` and ``target_id`` must already exist as nodes.
        If an edge between the same pair already exists it will be overwritten.

        Args:
            source_id: ID of the originating (delegating) node.
            target_id: ID of the receiving (trusted) node.
            edge_metadata: Fully populated ``EdgeMetadata`` for this edge.

        Returns:
            The ``edge_id`` from ``edge_metadata``.

        Raises:
            KeyError: If either ``source_id`` or ``target_id`` is not in the graph.
        """
        if source_id not in self._graph:
            raise KeyError(f"Source node '{source_id}' not found in TrustGraph.")
        if target_id not in self._graph:
            raise KeyError(f"Target node '{target_id}' not found in TrustGraph.")
        self._graph.add_edge(
            source_id, target_id, metadata=edge_metadata, weight=edge_metadata.weight
        )
        return edge_metadata.edge_id

    def get_edge(self, source_id: str, target_id: str) -> EdgeMetadata:
        """Retrieve edge metadata for a directed edge.

        Args:
            source_id: ID of the source node.
            target_id: ID of the target node.

        Returns:
            The ``EdgeMetadata`` for the edge from ``source_id`` to ``target_id``.

        Raises:
            KeyError: If no such edge exists.
        """
        if not self._graph.has_edge(source_id, target_id):
            raise KeyError(
                f"Edge '{source_id}' -> '{target_id}' not found in TrustGraph."
            )
        return self._graph.edges[source_id, target_id]["metadata"]

    # ------------------------------------------------------------------
    # Traversal / neighbourhood queries
    # ------------------------------------------------------------------

    def get_neighbors(
        self, node_id: str, direction: str = "out"
    ) -> List[str]:
        """Return the neighbouring node IDs of a given node.

        Args:
            node_id: The node whose neighbours are requested.
            direction: One of ``"out"`` (successors / reachable via trust),
                ``"in"`` (predecessors / who trusts this node), or ``"both"``
                (union of both sets).

        Returns:
            List of neighbouring node IDs. Order is not guaranteed.

        Raises:
            KeyError: If ``node_id`` is not in the graph.
            ValueError: If ``direction`` is not one of the valid options.
        """
        if node_id not in self._graph:
            raise KeyError(f"Node '{node_id}' not found in TrustGraph.")
        if direction == "out":
            return list(self._graph.successors(node_id))
        elif direction == "in":
            return list(self._graph.predecessors(node_id))
        elif direction == "both":
            return list(
                set(self._graph.successors(node_id))
                | set(self._graph.predecessors(node_id))
            )
        else:
            raise ValueError(
                f"Invalid direction '{direction}'. Use 'out', 'in', or 'both'."
            )

    # ------------------------------------------------------------------
    # Path analysis
    # ------------------------------------------------------------------

    def get_privilege_escalation_paths(
        self, source_id: str, target_privilege: float = 0.8
    ) -> List[List[str]]:
        """Find all simple paths from a source node to any high-privilege node.

        A privilege escalation path is any trust-delegation chain that leads
        from ``source_id`` to a node whose ``privilege_level >= target_privilege``.
        This is the primary input for the verification engine (Module 4).

        Uses ``networkx.all_simple_paths`` with a hop cutoff of 10 to prevent
        combinatorial explosion on large dense graphs.

        Args:
            source_id: Starting node for the path search.
            target_privilege: Minimum privilege level that qualifies a node as
                a high-privilege escalation target. Defaults to 0.8.

        Returns:
            List of paths, where each path is a list of node IDs from
            ``source_id`` to the target node (inclusive). Paths are only
            included if their final node meets the privilege threshold and
            the final node is not the source itself.
        """
        if source_id not in self._graph:
            raise KeyError(f"Source node '{source_id}' not found in TrustGraph.")

        high_priv_nodes = {
            nid
            for nid, data in self._graph.nodes(data=True)
            if data["metadata"].privilege_level >= target_privilege
            and nid != source_id
        }

        paths: List[List[str]] = []
        for target_id in high_priv_nodes:
            try:
                for path in nx.all_simple_paths(
                    self._graph, source_id, target_id, cutoff=10
                ):
                    paths.append(path)
            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue

        return paths

    # ------------------------------------------------------------------
    # Matrix representation
    # ------------------------------------------------------------------

    def to_adjacency_matrix(self) -> np.ndarray:
        """Return the weighted adjacency matrix of the trust graph.

        The matrix is ordered by the internal NetworkX node iteration order.
        Entry ``[i][j]`` holds the ``weight`` of the edge from node ``i`` to
        node ``j``, or 0.0 if no edge exists.

        Returns:
            A ``numpy.ndarray`` of shape ``(N, N)`` where ``N`` is the number
            of nodes. dtype is ``float64``.
        """
        return nx.to_numpy_array(self._graph, weight="weight")

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the entire graph to a JSON-compatible dictionary.

        The resulting dict can be stored as JSON, passed over a network, or
        fed to ``from_dict`` to reconstruct an identical graph.

        Returns:
            A dictionary with keys:
                - ``"nodes"``: list of serialized ``NodeMetadata`` dicts.
                - ``"edges"``: list of dicts, each containing
                  ``"source"``, ``"target"``, and the serialized
                  ``EdgeMetadata`` fields.
        """
        nodes = [
            data["metadata"].to_dict()
            for _, data in self._graph.nodes(data=True)
        ]
        edges = []
        for src, tgt, data in self._graph.edges(data=True):
            edge_dict = data["metadata"].to_dict()
            edge_dict["source"] = src
            edge_dict["target"] = tgt
            edges.append(edge_dict)
        return {"nodes": nodes, "edges": edges}

    @classmethod
    def from_dict(cls, data: dict) -> "TrustGraph":
        """Reconstruct a TrustGraph from a dictionary produced by ``to_dict``.

        Args:
            data: Dictionary with ``"nodes"`` and ``"edges"`` keys as produced
                by ``to_dict``.

        Returns:
            A fully populated ``TrustGraph`` instance.
        """
        from .edge_types import EdgeMetadata
        from .node_types import NodeMetadata

        g = cls()
        for node_dict in data["nodes"]:
            g.add_node(NodeMetadata.from_dict(node_dict))
        for edge_dict in data["edges"]:
            src = edge_dict.pop("source")
            tgt = edge_dict.pop("target")
            g.add_edge(src, tgt, EdgeMetadata.from_dict(edge_dict))
        return g

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Compute summary statistics for the trust graph.

        Useful for quick health checks and for feeding into the fingerprinter.

        Returns:
            A dictionary containing:
                - ``node_count`` (int): Total number of nodes.
                - ``edge_count`` (int): Total number of directed edges.
                - ``node_type_distribution`` (dict[str, int]): Count per
                  ``NodeType`` value string.
                - ``edge_type_distribution`` (dict[str, int]): Count per
                  ``EdgeType`` value string.
                - ``avg_privilege_level`` (float): Mean privilege across all nodes.
                - ``max_privilege_level`` (float): Maximum privilege level found.
                - ``num_high_privilege_nodes`` (int): Nodes with
                  ``privilege_level >= 0.7``.
        """
        nodes_meta = [
            data["metadata"] for _, data in self._graph.nodes(data=True)
        ]
        edges_meta = [
            data["metadata"] for _, _, data in self._graph.edges(data=True)
        ]

        node_type_dist: dict[str, int] = {}
        for nm in nodes_meta:
            key = nm.node_type.value
            node_type_dist[key] = node_type_dist.get(key, 0) + 1

        edge_type_dist: dict[str, int] = {}
        for em in edges_meta:
            key = em.edge_type.value
            edge_type_dist[key] = edge_type_dist.get(key, 0) + 1

        privilege_levels = [nm.privilege_level for nm in nodes_meta]
        avg_priv = float(np.mean(privilege_levels)) if privilege_levels else 0.0
        max_priv = float(np.max(privilege_levels)) if privilege_levels else 0.0
        num_high = sum(1 for p in privilege_levels if p >= 0.7)

        return {
            "node_count": self._graph.number_of_nodes(),
            "edge_count": self._graph.number_of_edges(),
            "node_type_distribution": node_type_dist,
            "edge_type_distribution": edge_type_dist,
            "avg_privilege_level": avg_priv,
            "max_privilege_level": max_priv,
            "num_high_privilege_nodes": num_high,
        }

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Return the number of nodes in the graph."""
        return self._graph.number_of_nodes()

    def __repr__(self) -> str:
        s = self.summary()
        return (
            f"TrustGraph(nodes={s['node_count']}, edges={s['edge_count']}, "
            f"avg_privilege={s['avg_privilege_level']:.2f})"
        )
