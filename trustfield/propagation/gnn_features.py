"""GNN feature extractor for the TrustField GNN propagation model.

Extracts a 13-dimensional node feature vector from a TrustGraph and builds
the row-normalised adjacency matrix required by the GCN forward pass.

Feature layout:
    [0]   is_seed              — 1.0 if this node is an initial seed, else 0.0
    [1]   privilege_level      — from NodeMetadata (0.0–1.0)
    [2]   sensitivity          — from NodeMetadata (0.0–1.0)
    [3]   node_type USER       — one-hot
    [4]   node_type SERVICE    — one-hot
    [5]   node_type ROLE       — one-hot
    [6]   node_type WORKLOAD   — one-hot
    [7]   node_type SECRET     — one-hot
    [8]   node_type DEPLOYMENT — one-hot
    [9]   in_degree            — normalised by (N-1)
    [10]  out_degree           — normalised by (N-1)
    [11]  betweenness_centrality
    [12]  clustering_coefficient (undirected)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import networkx as nx
import numpy as np

from trustfield.graph.node_types import NodeType
from trustfield.graph.trust_graph import TrustGraph

# Ordered list of NodeType values for one-hot encoding (positions 3-8)
_NODE_TYPE_ORDER = [
    NodeType.USER,
    NodeType.SERVICE,
    NodeType.ROLE,
    NodeType.WORKLOAD,
    NodeType.SECRET,
    NodeType.DEPLOYMENT,
]
_NODE_TYPE_IDX = {nt: i for i, nt in enumerate(_NODE_TYPE_ORDER)}

NUM_NODE_FEATURES = 13  # is_seed + privilege + sensitivity + 6×onehot + 4 structural


@dataclass
class GraphData:
    """Feature tensors extracted from a single TrustGraph.

    Attributes:
        node_ids: Ordered list of node IDs — index i maps to row i in ``x``
            and ``labels``.
        x: Node feature matrix, shape ``(N, NUM_NODE_FEATURES)``, dtype float32.
        adj_hat: Row-normalised adjacency with self-loops, shape ``(N, N)``,
            dtype float32.  Used for GCN message passing:
            ``A_hat = (A + I) / row_sum``.
        labels: Binary compromise labels, shape ``(N,)``, dtype float32.
            ``1.0`` = compromised, ``0.0`` = safe.  All zeros when no ground-truth
            labels are provided (inference mode).
        seed_indices: Integer indices into ``node_ids`` for the seed nodes.
    """

    node_ids: List[str]
    x: np.ndarray       # (N, NUM_NODE_FEATURES) float32
    adj_hat: np.ndarray  # (N, N) float32
    labels: np.ndarray   # (N,) float32
    seed_indices: List[int]


class GNNFeatureExtractor:
    """Extracts GCN-compatible feature tensors from a TrustGraph.

    Produces a 13-dimensional feature vector per node and a row-normalised
    adjacency matrix suitable for the two-layer GCN in
    :mod:`trustfield.propagation.gnn_trainer`.

    Example::

        extractor = GNNFeatureExtractor()
        gd = extractor.extract(graph, seed_nodes=["svc-001"])
        # gd.x.shape == (N, 13)
        # gd.adj_hat.shape == (N, N)
    """

    def extract(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        labels: Optional[Dict[str, int]] = None,
    ) -> GraphData:
        """Extract feature tensors from the graph.

        Args:
            graph: Input TrustGraph.
            seed_nodes: Initially compromised node IDs.  These nodes receive
                ``is_seed = 1.0`` in feature dimension 0.
            labels: Optional mapping ``node_id -> {0, 1}`` for supervised
                training.  If ``None`` all labels default to 0.0 (inference
                mode).

        Returns:
            A :class:`GraphData` instance with ``x``, ``adj_hat``,
            ``labels``, and ``seed_indices`` populated.
        """
        g: nx.DiGraph = graph._graph
        node_ids = list(g.nodes())
        n = len(node_ids)

        empty_x = np.zeros((0, NUM_NODE_FEATURES), dtype=np.float32)
        if n == 0:
            return GraphData(
                node_ids=[],
                x=empty_x,
                adj_hat=np.zeros((0, 0), dtype=np.float32),
                labels=np.zeros(0, dtype=np.float32),
                seed_indices=[],
            )

        idx: Dict[str, int] = {nid: i for i, nid in enumerate(node_ids)}
        seed_set = set(seed_nodes)

        # --- Structural features (computed once for the whole graph) ---
        max_deg = max(1, n - 1)
        in_deg = dict(g.in_degree())
        out_deg = dict(g.out_degree())
        betw = nx.betweenness_centrality(g, normalized=True)
        clust = nx.clustering(g.to_undirected())

        # --- Build feature matrix ---
        x = np.zeros((n, NUM_NODE_FEATURES), dtype=np.float32)
        for nid, i in idx.items():
            # [0] is_seed
            x[i, 0] = 1.0 if nid in seed_set else 0.0

            meta = g.nodes[nid].get("metadata")
            if meta is not None:
                # [1] privilege_level, [2] sensitivity
                x[i, 1] = float(meta.privilege_level)
                x[i, 2] = float(meta.sensitivity)
                # [3-8] node_type one-hot
                nt_idx = _NODE_TYPE_IDX.get(meta.node_type, 0)
                x[i, 3 + nt_idx] = 1.0

            # [9-10] degree features
            x[i, 9]  = in_deg.get(nid, 0) / max_deg
            x[i, 10] = out_deg.get(nid, 0) / max_deg
            # [11] betweenness centrality
            x[i, 11] = float(betw.get(nid, 0.0))
            # [12] clustering coefficient
            x[i, 12] = float(clust.get(nid, 0.0))

        # --- Row-normalised adjacency with self-loops ---
        # A_hat[u, v] is non-zero when there is an edge u→v in the trust graph.
        # Row-normalisation: each source node's outgoing weights sum to 1.
        A = np.zeros((n, n), dtype=np.float32)
        for u, v, edata in g.edges(data=True):
            meta = edata.get("metadata")
            w = float(meta.weight) if meta is not None else 1.0
            A[idx[u], idx[v]] = w

        # Add self-loops so every node aggregates its own features
        A_tilde = A + np.eye(n, dtype=np.float32)
        row_sum = A_tilde.sum(axis=1, keepdims=True)
        row_sum = np.where(row_sum == 0.0, 1.0, row_sum)
        adj_hat = A_tilde / row_sum

        # --- Labels ---
        lbl = np.zeros(n, dtype=np.float32)
        if labels is not None:
            for nid, lab in labels.items():
                if nid in idx:
                    lbl[idx[nid]] = float(lab)

        # --- Seed indices ---
        seed_indices = [idx[s] for s in seed_nodes if s in idx]

        return GraphData(
            node_ids=node_ids,
            x=x,
            adj_hat=adj_hat,
            labels=lbl,
            seed_indices=seed_indices,
        )
