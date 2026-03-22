"""Topology-aware initial weight selector for the TrustField ensemble.

This module implements the topology-prior component of TrustField's core research
contribution: the insight that DIFFERENT propagation models are reliable for
DIFFERENT graph topologies, and these weights should be set analytically before
any data has been seen (the prior), then refined adaptively.

The weights below are calibrated using the results of Module 2's empirical
analysis on synthetic IAM graphs and ground-truth graph-theoretic reasoning.

Key correction vs. naive theoretical weights (see research note below):
  Hub and Chain topologies are Directed Acyclic Graphs (DAGs). Their adjacency
  matrices have all-zero eigenvalues, making the SpectralCascadeModel's cascade
  condition τ > 1/λ_max unsatisfiable. Spectral weights for these topologies
  are therefore dropped near zero and redistributed to the models that actually
  produce signal (GraphTraversal and Percolation for Hub; Epidemic for Chain).
"""

from __future__ import annotations

from trustfield.graph.fingerprinter import TopologyFingerprint
from trustfield.graph.fingerprinter import TopologyType

from .weight_vector import MODEL_NAMES, WeightVector

# ---------------------------------------------------------------------------
# Topology-aware weight priors
# ---------------------------------------------------------------------------
# All weight tables are documented with the theoretical justification.
# These tables constitute a primary research contribution of TrustField.

_HUB_WEIGHTS = {
    # Hub topologies are directed stars (DAG). Key observations:
    #
    # graph_traversal (0.41): BFS upper bound; highest-F1 model on hub graphs.
    #   Weight = 0.4567 × 0.90 (scaled to make room for gnn=0.10).
    #
    # epidemic (0.06): Rarely crosses SIR threshold on 2-hop stars. Low weight.
    #
    # spectral_cascade (0.06): DAG eigenvalues = 0 → cascade condition
    #   unsatisfiable. Near-zero weight retained.
    #
    # percolation (0.30): Monte Carlo is topology-agnostic; second-best model.
    #   Weight = 0.3327 × 0.90.
    #
    # control_system (0.06): DAG spectral radius = 0 → near-zero dynamics.
    #
    # gnn (0.10): GNN provides learned signal; lower weight than chain because
    #   classical models (graph_traversal + percolation) already perform well
    #   on hub topologies.
    "graph_traversal": 0.4110,
    "epidemic":        0.0632,
    "spectral_cascade": 0.0632,
    "percolation":     0.2994,
    "control_system":  0.0632,
    "gnn":             0.1000,
}

_CHAIN_WEIGHTS = {
    # Chain topologies are linear DAGs.
    # GNN holds the highest weight (0.35) because classical models under-perform:
    #
    # graph_traversal (0.33): F1=1.00 as ground truth; weight = 0.3005 × (0.65/0.60).
    #
    # epidemic        (0.04): F1=0.23, weakest on chain.  Weight scaled down.
    #
    # spectral_cascade (0.04): DAG eigenvalues = 0 → near-zero weight.
    #
    # percolation     (0.22): F1=0.58 on chain; moderate signal.
    #
    # control_system  (0.04): F1=0.13 on chain; attenuates fast on linear DAGs.
    #
    # gnn             (0.35): HIGHEST weight — trained specifically on chain
    #   topologies to replace under-performing epidemic model.  Accounts for
    #   the sequential delegation pattern the SIR model misses.
    "graph_traversal": 0.3256,
    "epidemic":        0.0354,
    "spectral_cascade": 0.0354,
    "percolation":     0.2182,
    "control_system":  0.0354,
    "gnn":             0.3500,
}

_DENSE_CLUSTER_WEIGHTS = {
    # Dense-cluster topologies have many intra-cluster cycles.
    # GNN has moderate weight (0.15) — classical models already informative here.
    # Weights = calibrated 5-model values × 0.85, plus gnn = 0.15.
    #
    # graph_traversal (0.28): Highest-F1 classical model; weight = 0.3277 × 0.85.
    #
    # epidemic        (0.14): Intra-cluster spread is fast; moderate weight.
    #
    # spectral_cascade (0.18): Dense clusters have non-zero λ_max (cycles).
    #   Cascade condition is meaningful; eigenvector centrality identifies
    #   bridge-adjacent nodes.  Weight = 0.2063 × 0.85.
    #
    # percolation     (0.22): Phase transitions most pronounced in dense graphs.
    #   Weight = 0.2572 × 0.85.
    #
    # control_system  (0.03): Dense spectral radius compresses dynamics.
    #
    # gnn             (0.15): Learned model provides complementary signal.
    "graph_traversal": 0.2785,
    "epidemic":        0.1448,
    "spectral_cascade": 0.1754,
    "percolation":     0.2186,
    "control_system":  0.0327,
    "gnn":             0.1500,
}

_MIXED_WEIGHTS = {
    # Mixed topologies contain hub, chain, and dense-cluster sub-graphs.
    # GNN gets slightly higher weight (0.25) to reflect its generality;
    # the 5 classical models share the remaining 0.75 equally (0.15 each),
    # reflecting maximum uncertainty among classical approaches.
    "graph_traversal": 0.15,
    "epidemic":        0.15,
    "spectral_cascade": 0.15,
    "percolation":     0.15,
    "control_system":  0.15,
    "gnn":             0.25,
}

_TOPOLOGY_WEIGHT_TABLE = {
    TopologyType.HUB:           _HUB_WEIGHTS,
    TopologyType.CHAIN:         _CHAIN_WEIGHTS,
    TopologyType.DENSE_CLUSTER: _DENSE_CLUSTER_WEIGHTS,
    TopologyType.MIXED:         _MIXED_WEIGHTS,
}

# ---------------------------------------------------------------------------
# Topology-aware decision thresholds
# ---------------------------------------------------------------------------
# HUB/CHAIN (DAG, single-dominant-model regime): lowered to 0.35 so that a
#   single high-weight model (e.g. percolation at w=0.40) can carry a node
#   across the threshold without requiring cross-model agreement.
#
# DENSE_CLUSTER (multiple strong models): keep 0.50 — genuine agreement
#   across spectral_cascade + percolation + epidemic required.
#
# MIXED (maximum uncertainty): 0.45 as a middle ground.

_TOPOLOGY_THRESHOLD_TABLE: dict[TopologyType, float] = {
    TopologyType.HUB:           0.35,
    TopologyType.CHAIN:         0.35,
    TopologyType.DENSE_CLUSTER: 0.50,
    TopologyType.MIXED:         0.45,
}


class TopologyAwareSelector:
    """Maps a TopologyFingerprint to topology-specific ensemble weight priors.

    This class encodes the analytical prior for Module 3's ensemble.  It is
    the first of two weight sources (the second being the WeightTracker's
    adaptive posterior).  When no historical accuracy data is available the
    orchestrator falls back to these priors.

    The priors are grounded in:
        - Graph-theoretic properties of each topology (see module docstring).
        - Empirical observations from Module 2 demo runs on synthetic IAM graphs
          (hub: percolation=35/40 nodes; chain: epidemic captures sequential
          dynamics; dense-cluster: spectral cascade detects phase transitions).
        - The DAG-eigenvalue correction: hub and chain graphs have λ_max=0,
          making spectral analysis uninformative for those topologies.

    Example::

        selector = TopologyAwareSelector()
        fp = TopologyFingerprinter().fingerprint(graph)
        wv = selector.get_initial_weights(fp)
        print(wv.weights)  # {"graph_traversal": 0.40, "percolation": 0.40, ...}
    """

    def get_initial_weights(
        self, fingerprint: TopologyFingerprint
    ) -> WeightVector:
        """Return the topology-prior WeightVector for a given fingerprint.

        Selects the pre-computed weight table that matches the fingerprint's
        topology classification.  Returns a validated WeightVector.

        Args:
            fingerprint: The ``TopologyFingerprint`` produced by Module 1's
                ``TopologyFingerprinter``.

        Returns:
            A ``WeightVector`` with ``source="topology_prior"`` containing
            weights calibrated for the detected topology type.
        """
        ttype = fingerprint.topology_type
        raw_weights = dict(_TOPOLOGY_WEIGHT_TABLE.get(ttype, _MIXED_WEIGHTS))

        # Ensure all model names are present (guard against schema drift)
        for name in MODEL_NAMES:
            raw_weights.setdefault(name, 0.0)

        # Normalise to sum exactly to 1.0.  This handles reserved placeholder
        # slots (e.g. "gnn": 0.40 in _CHAIN_WEIGHTS) whose presence can push
        # the raw sum above 1.0 during the transitional period before the
        # corresponding model module is implemented.
        total = sum(raw_weights.values())
        if total > 0 and abs(total - 1.0) > 1e-6:
            raw_weights = {k: round(v / total, 6) for k, v in raw_weights.items()}
            # Fix rounding residual on the largest entry
            diff = round(1.0 - sum(raw_weights.values()), 6)
            if abs(diff) > 1e-9:
                largest = max(raw_weights, key=raw_weights.__getitem__)
                raw_weights[largest] = round(raw_weights[largest] + diff, 6)

        wv = WeightVector(
            weights=raw_weights,
            topology_type=ttype.value,
            source="topology_prior",
        )
        wv.validate()
        return wv

    def get_recommended_threshold(
        self, fingerprint: TopologyFingerprint
    ) -> float:
        """Return the topology-aware decision threshold for a given fingerprint.

        The threshold governs when a node is considered compromised in the
        WEIGHTED ensemble fusion: nodes with ensemble_risk >= threshold are
        flagged. Lower thresholds are appropriate when a single dominant model
        drives most of the risk signal (hub/chain); higher thresholds require
        genuine cross-model agreement (dense_cluster).

        Args:
            fingerprint: The ``TopologyFingerprint`` produced by Module 1.

        Returns:
            Recommended decision threshold in (0, 1).
        """
        return _TOPOLOGY_THRESHOLD_TABLE.get(
            fingerprint.topology_type,
            _TOPOLOGY_THRESHOLD_TABLE[TopologyType.MIXED],
        )

    def get_weights_for_topology_type(
        self, topology_type_str: str
    ) -> WeightVector:
        """Convenience method: look up weights by topology type string.

        Args:
            topology_type_str: One of ``"HUB"``, ``"CHAIN"``,
                ``"DENSE_CLUSTER"``, ``"MIXED"``.

        Returns:
            Topology-prior ``WeightVector``.

        Raises:
            KeyError: If ``topology_type_str`` is not a valid topology.
        """
        ttype = TopologyType(topology_type_str)
        raw_weights = dict(_TOPOLOGY_WEIGHT_TABLE[ttype])
        wv = WeightVector(
            weights=raw_weights,
            topology_type=topology_type_str,
            source="topology_prior",
        )
        wv.validate()
        return wv
