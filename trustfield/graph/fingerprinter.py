"""Topology fingerprinting and classification for TrustField trust graphs.

This module computes structural metrics from a ``TrustGraph`` and uses them
to classify the topology into one of four canonical categories (HUB, CHAIN,
DENSE_CLUSTER, MIXED). The classification drives Module 3's ensemble model
weight selection: different topologies favour different propagation models.

The ``TopologyFingerprint`` dataclass is the key output — it bundles all
computed metrics together with the final classification and the model weight
hints consumed by the ensemble predictor.

Research context:
    The threshold values used in ``classify_topology`` are the primary
    research parameters for topology-aware ensemble tuning. They were derived
    empirically from synthetic IAM graph experiments and represent the
    decision boundaries between structural regimes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import networkx as nx
import numpy as np

from .trust_graph import TrustGraph


class TopologyType(Enum):
    """Canonical topology classification labels for TrustField graphs.

    Attributes:
        HUB: Star-shaped graph with a small number of high-centrality
            hub nodes. Worst-case for lateral movement on compromise.
        CHAIN: Linear delegation chain. High epidemic spread risk
            along the path from entry point to terminal node.
        DENSE_CLUSTER: Tightly connected clusters joined by sparse
            bridge edges. Bridge edges are the critical attack surface.
        MIXED: Enterprise-realistic blend of all three patterns.
            Assigned when no single pattern dominates.
    """

    HUB = "HUB"
    CHAIN = "CHAIN"
    DENSE_CLUSTER = "DENSE_CLUSTER"
    MIXED = "MIXED"


@dataclass
class TopologyFingerprint:
    """Structural metrics and classification for a TrustField trust graph.

    This dataclass bundles all computed topology metrics with the final
    classification label and the ensemble model weight hints derived from it.

    Attributes:
        clustering_coefficient: Average clustering coefficient of the
            underlying undirected projection of the graph
            (``networkx.average_clustering``). High values indicate
            tightly knit communities; low values indicate sparse connectivity.
        centrality_variance: Variance of betweenness-centrality scores
            across all nodes. High variance indicates a hub-spoke structure
            where a few nodes dominate all shortest paths.
        spectral_gap: Difference between the two largest eigenvalues of the
            adjacency matrix (λ₁ − λ₂). A large spectral gap indicates a
            well-connected graph with fast mixing; near-zero indicates a
            chain or disconnected structure.
        degree_distribution_entropy: Shannon entropy of the degree sequence.
            High entropy means uniform degree distribution (random-like);
            low entropy means highly skewed degree distribution (hub-like).
        avg_path_length: Average shortest path length computed on the
            largest weakly connected component.
        num_nodes: Total number of nodes in the graph.
        num_edges: Total number of directed edges in the graph.
        density: Graph density (``networkx.density``). Ratio of actual
            edges to possible edges.
        topology_type: Classified topology label from ``TopologyType``.
        model_weight_hints: Dictionary mapping propagation model names to
            their recommended ensemble weights for this topology type.
            Consumed by Module 3 (ensemble predictor).
    """

    clustering_coefficient: float
    centrality_variance: float
    spectral_gap: float
    degree_distribution_entropy: float
    avg_path_length: float
    num_nodes: int
    num_edges: int
    density: float
    topology_type: TopologyType
    model_weight_hints: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize this fingerprint to a JSON-compatible dictionary.

        Returns:
            Dictionary with all fields as primitives, with ``topology_type``
            converted to its string value.
        """
        return {
            "clustering_coefficient": self.clustering_coefficient,
            "centrality_variance": self.centrality_variance,
            "spectral_gap": self.spectral_gap,
            "degree_distribution_entropy": self.degree_distribution_entropy,
            "avg_path_length": self.avg_path_length,
            "num_nodes": self.num_nodes,
            "num_edges": self.num_edges,
            "density": self.density,
            "topology_type": self.topology_type.value,
            "model_weight_hints": self.model_weight_hints,
        }


class TopologyFingerprinter:
    """Computes structural fingerprints and classifies TrustField graph topologies.

    The fingerprinter is the bridge between the raw trust graph (Module 1)
    and the ensemble propagation models (Module 3). By computing a small set
    of graph-theoretic metrics, it determines which propagation model(s) are
    best suited for the current infrastructure topology.

    Example::

        from trustfield.graph import TrustGraph, IAMSimulator, TopologyFingerprinter

        sim = IAMSimulator()
        fp_engine = TopologyFingerprinter()

        hub_g = sim.generate("hub", seed=42)
        fp = fp_engine.fingerprint(hub_g)
        print(fp.topology_type)          # TopologyType.HUB
        print(fp.model_weight_hints)     # {"spectral": 0.5, ...}
    """

    def fingerprint(self, graph: TrustGraph) -> TopologyFingerprint:
        """Compute a full structural fingerprint for a trust graph.

        Metrics are computed on the NetworkX DiGraph directly. Where
        undirected metrics are required (clustering, betweenness), the graph
        is treated as undirected by converting with ``to_undirected()``.

        For average path length, the largest weakly connected component is
        used to handle disconnected graphs gracefully.

        Args:
            graph: The ``TrustGraph`` to fingerprint.

        Returns:
            A fully populated ``TopologyFingerprint`` instance including the
            topology classification and model weight hints.
        """
        G = graph._graph

        n = G.number_of_nodes()
        m = G.number_of_edges()

        # Undirected view for clustering and betweenness
        G_undirected = G.to_undirected()

        # 1. Clustering coefficient
        if n > 1:
            clustering_coeff = nx.average_clustering(G_undirected)
        else:
            clustering_coeff = 0.0

        # 2. Centrality variance
        if n > 1:
            bc = nx.betweenness_centrality(G, normalized=True)
            centrality_values = list(bc.values())
            centrality_var = float(np.var(centrality_values))
        else:
            centrality_var = 0.0

        # 3. Spectral gap (λ₁ - λ₂ of adjacency matrix)
        spectral_gap = self._compute_spectral_gap(graph)

        # 4. Degree distribution entropy (Shannon entropy of combined degree)
        degree_entropy = self._compute_degree_entropy(G)

        # 5. Average path length on largest weakly connected component
        avg_path_len = self._compute_avg_path_length(G)

        # 6. Density
        density = nx.density(G)

        # Classify
        fp_partial = TopologyFingerprint(
            clustering_coefficient=clustering_coeff,
            centrality_variance=centrality_var,
            spectral_gap=spectral_gap,
            degree_distribution_entropy=degree_entropy,
            avg_path_length=avg_path_len,
            num_nodes=n,
            num_edges=m,
            density=density,
            topology_type=TopologyType.MIXED,  # placeholder, filled below
        )
        topology_type = self.classify_topology(fp_partial)
        model_weights = self.get_model_weight_hints(topology_type)

        return TopologyFingerprint(
            clustering_coefficient=clustering_coeff,
            centrality_variance=centrality_var,
            spectral_gap=spectral_gap,
            degree_distribution_entropy=degree_entropy,
            avg_path_length=avg_path_len,
            num_nodes=n,
            num_edges=m,
            density=density,
            topology_type=topology_type,
            model_weight_hints=model_weights,
        )

    def classify_topology(self, fingerprint: TopologyFingerprint) -> TopologyType:
        """Classify a graph topology based on its structural fingerprint.

        Decision rules (research parameters — these are the key thresholds):

        +----------------+--------------------------------------+
        | Topology       | Rule                                 |
        +================+======================================+
        | CHAIN          | avg_path_length > 4.0                |
        |                | AND clustering_coefficient < 0.2     |
        +----------------+--------------------------------------+
        | HUB            | centrality_variance > 0.001          |
        |                | AND clustering_coefficient < 0.3     |
        +----------------+--------------------------------------+
        | DENSE_CLUSTER  | clustering_coefficient > 0.4         |
        |                | AND density > 0.15                   |
        +----------------+--------------------------------------+
        | MIXED          | everything else                      |
        +----------------+--------------------------------------+

        Rules are evaluated in the order shown above; the first matching
        rule wins. CHAIN is evaluated first because avg_path_length > 4.0 is
        the most unambiguous structural signature: a chain graph cannot be
        confused with a hub (hub graphs have short paths due to central
        routing). HUB is evaluated second using betweenness-centrality
        variance, which peaks for single-bottleneck star topologies.

        Args:
            fingerprint: A ``TopologyFingerprint`` (``topology_type`` field
                is ignored — this method computes it fresh).

        Returns:
            The classified ``TopologyType``.
        """
        cv = fingerprint.centrality_variance
        cc = fingerprint.clustering_coefficient
        apl = fingerprint.avg_path_length
        d = fingerprint.density

        # CHAIN: long paths AND zero triangles (pure linear DAG has cc exactly 0.0;
        # mixed graphs always carry triangles from the dense-cluster sub-component,
        # making this check N-invariant regardless of sub-topology dilution).
        if apl > 4.0 and cc < 1e-9:
            return TopologyType.CHAIN
        # HUB: centrality variance scaled by N (raw cv shrinks as 1/N on stars).
        if cv * fingerprint.num_nodes > 0.05 and cc < 0.3:
            return TopologyType.HUB
        if cc > 0.4 and d > 0.15:
            return TopologyType.DENSE_CLUSTER
        return TopologyType.MIXED

    def get_model_weight_hints(self, topology_type: TopologyType) -> dict:
        """Return recommended ensemble model weights for a topology type.

        These weights are the initial prior for Module 3's ensemble combiner.
        They encode the intuition that different topologies are best captured
        by different propagation models:

        - **HUB**: Spectral methods capture hub-spoke structure well; the
          adjacency matrix eigenspectrum reveals hub dominance.
        - **CHAIN**: Epidemic (SIR/SIS) models naturally simulate linear
          spread; control-system models capture choke-point dynamics.
        - **DENSE_CLUSTER**: Bond percolation captures intra-cluster
          saturation and the phase transition at bridge edges.
        - **MIXED**: Equal weight across all models reflects uncertainty.

        Args:
            topology_type: The classified topology.

        Returns:
            Dictionary mapping model name strings to float weights that sum
            to 1.0. Keys: ``"graph_traversal"``, ``"epidemic"``,
            ``"spectral"``, ``"percolation"``, ``"control_system"``.

        Raises:
            ValueError: If ``topology_type`` is not a recognised value.
        """
        weights = {
            TopologyType.HUB: {
                "graph_traversal": 0.1,
                "epidemic": 0.1,
                "spectral": 0.5,
                "percolation": 0.2,
                "control_system": 0.1,
            },
            TopologyType.CHAIN: {
                "graph_traversal": 0.15,
                "epidemic": 0.45,
                "spectral": 0.1,
                "percolation": 0.1,
                "control_system": 0.2,
            },
            TopologyType.DENSE_CLUSTER: {
                "graph_traversal": 0.1,
                "epidemic": 0.15,
                "spectral": 0.15,
                "percolation": 0.5,
                "control_system": 0.1,
            },
            TopologyType.MIXED: {
                "graph_traversal": 0.2,
                "epidemic": 0.2,
                "spectral": 0.2,
                "percolation": 0.2,
                "control_system": 0.2,
            },
        }
        if topology_type not in weights:
            raise ValueError(f"Unknown topology type: {topology_type}")
        return weights[topology_type]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_spectral_gap(self, graph: TrustGraph) -> float:
        """Compute λ₁ − λ₂ of the weighted adjacency matrix.

        For graphs with fewer than 2 nodes, or where the eigenvalue
        computation is numerically degenerate, returns 0.0.

        Args:
            graph: The trust graph.

        Returns:
            Spectral gap as a non-negative float.
        """
        adj = graph.to_adjacency_matrix()
        n = adj.shape[0]
        if n < 2:
            return 0.0
        try:
            eigenvalues = np.linalg.eigvalsh(adj)
            eigenvalues_sorted = np.sort(eigenvalues)[::-1]
            if len(eigenvalues_sorted) >= 2:
                gap = float(eigenvalues_sorted[0] - eigenvalues_sorted[1])
                return max(0.0, gap)
            return 0.0
        except np.linalg.LinAlgError:
            return 0.0

    def _compute_degree_entropy(self, G: nx.DiGraph) -> float:
        """Compute Shannon entropy of the total (in + out) degree sequence.

        High entropy → uniform degree distribution (random graph).
        Low entropy → skewed distribution (hub or chain).

        Args:
            G: The directed NetworkX graph.

        Returns:
            Shannon entropy in bits. Returns 0.0 for empty or singleton graphs.
        """
        n = G.number_of_nodes()
        if n == 0:
            return 0.0
        degrees = np.array([G.in_degree(v) + G.out_degree(v) for v in G.nodes()])
        total = degrees.sum()
        if total == 0:
            return 0.0
        probs = degrees / total
        # Filter zero probabilities to avoid log(0)
        probs = probs[probs > 0]
        entropy = float(-np.sum(probs * np.log2(probs)))
        return entropy

    def _compute_avg_path_length(self, G: nx.DiGraph) -> float:
        """Compute average shortest path length on the largest WCC.

        Falls back to 0.0 for trivially small components.

        Args:
            G: The directed NetworkX graph.

        Returns:
            Average shortest path length as a float.
        """
        if G.number_of_nodes() < 2:
            return 0.0

        # Find the largest weakly connected component
        wccs = list(nx.weakly_connected_components(G))
        if not wccs:
            return 0.0
        largest_wcc = max(wccs, key=len)
        sub = G.subgraph(largest_wcc)

        if sub.number_of_nodes() < 2:
            return 0.0

        try:
            return float(nx.average_shortest_path_length(sub))
        except nx.NetworkXError:
            # Graph is not strongly connected — use undirected projection
            sub_undirected = sub.to_undirected()
            try:
                return float(nx.average_shortest_path_length(sub_undirected))
            except nx.NetworkXError:
                return 0.0
