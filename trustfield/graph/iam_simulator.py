"""Realistic IAM scenario generator for TrustField testing and benchmarking.

This module provides ``IAMSimulator``, which constructs synthetic but realistic
AWS-style IAM trust graphs across three canonical topology presets:

- **hub**: A monolithic, star-shaped IAM setup where a small number of
  privileged roles are assumed by many services. Worst-case scenario for
  lateral movement: compromise the hub and you own everything.

- **chain**: A microservice delegation chain where trust flows linearly from
  entry-point services to a high-privilege terminal node. High epidemic
  spread risk along the path.

- **dense_cluster**: A team-scoped IAM setup with tightly connected intra-cluster
  subgraphs joined by a small number of high-risk bridge edges.

- **mixed**: An enterprise-realistic blend of all three patterns.

Each topology is designed to exercise a different regime of the propagation
models in TrustField Module 2 and to produce distinct ``TopologyFingerprint``
classifications in Module 1's fingerprinter.
"""

from __future__ import annotations

import random
from typing import List, Tuple

from .edge_types import EdgeMetadata, EdgeType
from .node_types import NodeMetadata, NodeType
from .trust_graph import TrustGraph


# ---------------------------------------------------------------------------
# Realistic name pools
# ---------------------------------------------------------------------------

_SERVICE_NAMES = [
    "auth-service", "payment-api", "user-service", "data-pipeline",
    "notification-service", "order-service", "inventory-api", "search-service",
    "analytics-worker", "email-sender", "report-generator", "audit-logger",
    "session-manager", "gateway-proxy", "billing-service", "catalog-api",
    "recommendation-engine", "cache-warmer", "health-checker", "event-bus",
]

_ROLE_NAMES = [
    "deploy-role", "admin-role", "readonly-role", "ci-role",
    "cross-account-role", "data-access-role", "lambda-execution-role",
    "eks-node-role", "secrets-reader-role", "audit-role",
]

_SECRET_NAMES = [
    "db-credentials", "api-key-stripe", "jwt-signing-key",
    "oauth-client-secret", "encryption-master-key", "tls-private-key",
    "smtp-credentials", "datadog-api-key", "github-token", "vault-unseal-key",
]

_USER_NAMES = [
    "developer-alice", "ci-system", "monitoring-agent",
    "developer-bob", "oncall-engineer", "platform-admin",
    "security-scanner", "release-bot", "data-scientist-carol",
]

_WORKLOAD_NAMES = [
    "prod-k8s-cluster", "staging-env", "lambda-processor",
    "batch-job-runner", "canary-deployment", "blue-green-target",
    "ml-training-cluster", "integration-test-env",
]

_DEPLOYMENT_NAMES = [
    "prod-deploy-pipeline", "staging-deploy-pipeline",
    "canary-release-pipeline", "hotfix-pipeline", "dr-failover-pipeline",
]


def _make_node_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:03d}"


def _pick(pool: List[str], rng: random.Random, used: set) -> str:
    """Pick an unused name from pool; fall back to indexed name if exhausted."""
    candidates = [n for n in pool if n not in used]
    if candidates:
        choice = rng.choice(candidates)
        used.add(choice)
        return choice
    fallback = f"{pool[0]}-{len(used)}"
    used.add(fallback)
    return fallback


def _make_edge_id(src: str, tgt: str) -> str:
    return f"{src}->{tgt}"


class IAMSimulator:
    """Generates realistic AWS-style IAM trust graphs for TrustField testing.

    ``IAMSimulator`` produces ``TrustGraph`` instances that mimic real-world
    IAM configurations across three structurally distinct topology presets.
    The generated graphs are seeded for reproducibility.

    Example::

        sim = IAMSimulator()
        hub_graph = sim.generate("hub", num_nodes=40, seed=42)
        chain_graph = sim.generate("chain", num_nodes=20, seed=42)
    """

    def generate(
        self, topology: str, num_nodes: int = 40, seed: int = 42
    ) -> TrustGraph:
        """Generate a synthetic IAM trust graph with the requested topology.

        Args:
            topology: One of ``"hub"``, ``"chain"``, ``"dense_cluster"``,
                or ``"mixed"``.
            num_nodes: Approximate total node count. The actual count may
                differ slightly because topology builders snap to structural
                constraints (e.g., chain lengths must be integers).
            seed: Random seed for reproducibility.

        Returns:
            A fully populated ``TrustGraph`` with named, typed nodes and
            weighted, typed edges.

        Raises:
            ValueError: If ``topology`` is not one of the valid options.
        """
        rng = random.Random(seed)
        if topology == "hub":
            return self._build_hub(rng, num_nodes)
        elif topology == "chain":
            return self._build_chain(rng, num_nodes)
        elif topology == "dense_cluster":
            return self._build_dense_cluster(rng, num_nodes)
        elif topology == "mixed":
            return self._build_mixed(rng, num_nodes)
        else:
            raise ValueError(
                f"Unknown topology '{topology}'. "
                "Choose from: 'hub', 'chain', 'dense_cluster', 'mixed'."
            )

    # ------------------------------------------------------------------
    # Hub topology
    # ------------------------------------------------------------------

    def _build_hub(self, rng: random.Random, num_nodes: int) -> TrustGraph:
        """Build a star-shaped (hub-and-spoke) IAM trust graph.

        Architecture:
            - 1 single "god-mode" ROLE node (the hub) at privilege_level = 1.0
            - All other nodes are bidirectionally connected to the hub:
                * Inbound spokes (services, users, workloads) each send an
                  AssumeRole / AuthenticateAs edge INTO the hub.
                * Outbound spokes (secrets, deployments, services) each receive
                  a SECRET_READ / DEPLOY_TO / TOKEN_MINT edge FROM the hub.
            - No direct edges between non-hub nodes.

        Forcing all inter-node shortest paths to route through the hub makes it
        the sole betweenness-centrality bottleneck (normalized betweenness near
        1.0). This maximises centrality_variance, which the fingerprinter uses
        as the primary HUB classification signal.

        This represents the worst-case IAM scenario: one compromised hub role
        gives an attacker access to every resource in the graph.

        Args:
            rng: Seeded random instance.
            num_nodes: Approximate total node count.

        Returns:
            A populated ``TrustGraph``.
        """
        g = TrustGraph()
        used_names: set = set()
        node_counter = [0]

        def next_id(prefix: str) -> str:
            node_counter[0] += 1
            return _make_node_id(prefix, node_counter[0])

        # The single all-powerful hub role
        hub_id = next_id("role")
        g.add_node(NodeMetadata(
            node_id=hub_id,
            node_type=NodeType.ROLE,
            name=_pick(_ROLE_NAMES, rng, used_names),
            privilege_level=1.0,
            sensitivity=1.0,
            tags={"hub": "true"},
        ))

        # Split remaining quota: half inbound spokes, half outbound spokes
        remaining = num_nodes - 1
        num_inbound = remaining // 2
        num_outbound = remaining - num_inbound

        # Inbound spokes: entities that ASSUME the hub role
        inbound_configs = [
            (NodeType.SERVICE,  _SERVICE_NAMES,  "svc",    0.05, 0.45, EdgeType.ASSUME_ROLE),
            (NodeType.USER,     _USER_NAMES,     "user",   0.05, 0.30, EdgeType.AUTHENTICATE_AS),
            (NodeType.WORKLOAD, _WORKLOAD_NAMES, "wl",     0.10, 0.50, EdgeType.ASSUME_ROLE),
        ]
        for i in range(num_inbound):
            ntype, pool, prefix, plo, phi, etype = inbound_configs[i % len(inbound_configs)]
            nid = next_id(prefix)
            g.add_node(NodeMetadata(
                node_id=nid,
                node_type=ntype,
                name=_pick(pool, rng, used_names),
                privilege_level=rng.uniform(plo, phi),
                sensitivity=rng.uniform(0.1, 0.5),
            ))
            g.add_edge(
                nid, hub_id,
                EdgeMetadata(
                    edge_id=_make_edge_id(nid, hub_id),
                    edge_type=etype,
                    weight=rng.uniform(0.6, 0.95),
                    delegation_depth_limit=rng.randint(1, 3),
                    requires_mfa=rng.random() < 0.35,
                )
            )

        # Outbound spokes: resources the hub can access
        outbound_configs = [
            (NodeType.SECRET,     _SECRET_NAMES,     "secret", 0.50, 0.90, EdgeType.SECRET_READ),
            (NodeType.DEPLOYMENT, _DEPLOYMENT_NAMES, "deploy", 0.55, 0.90, EdgeType.DEPLOY_TO),
            (NodeType.SERVICE,    _SERVICE_NAMES,    "svc",    0.30, 0.70, EdgeType.TOKEN_MINT),
        ]
        for i in range(num_outbound):
            ntype, pool, prefix, plo, phi, etype = outbound_configs[i % len(outbound_configs)]
            nid = next_id(prefix)
            g.add_node(NodeMetadata(
                node_id=nid,
                node_type=ntype,
                name=_pick(pool, rng, used_names),
                privilege_level=rng.uniform(plo, phi),
                sensitivity=rng.uniform(0.4, 1.0),
            ))
            g.add_edge(
                hub_id, nid,
                EdgeMetadata(
                    edge_id=_make_edge_id(hub_id, nid),
                    edge_type=etype,
                    weight=rng.uniform(0.7, 1.0),
                    delegation_depth_limit=1,
                    is_conditional=rng.random() < 0.3,
                )
            )

        return g

    # ------------------------------------------------------------------
    # Chain topology
    # ------------------------------------------------------------------

    def _build_chain(self, rng: random.Random, num_nodes: int) -> TrustGraph:
        """Build a linear delegation chain IAM trust graph.

        Architecture:
            - A backbone linear chain of 8-15 SERVICE nodes connected by
              TOKEN_MINT edges, ending at a high-privilege SECRET or DEPLOYMENT.
            - 2-3 USER nodes that authenticate to the chain head.
            - 1-2 ROLE nodes inserted as stepping stones mid-chain.
            - Additional SERVICE nodes branching off the chain to fill quota.

        This topology produces long average path lengths and low clustering —
        the fingerprinter's key signatures for CHAIN classification.

        Args:
            rng: Seeded random instance.
            num_nodes: Approximate total node count.

        Returns:
            A populated ``TrustGraph``.
        """
        g = TrustGraph()
        used_names: set = set()
        node_counter = [0]

        def next_id(prefix: str) -> str:
            node_counter[0] += 1
            return _make_node_id(prefix, node_counter[0])

        chain_len = rng.randint(8, min(15, num_nodes - 5))
        chain_ids: List[str] = []

        # Build the backbone chain of services
        for i in range(chain_len):
            nid = next_id("svc")
            # Gradually increasing privilege along the chain
            privilege = 0.1 + 0.06 * i
            meta = NodeMetadata(
                node_id=nid,
                node_type=NodeType.SERVICE,
                name=_pick(_SERVICE_NAMES, rng, used_names),
                privilege_level=min(privilege, 0.7),
                sensitivity=rng.uniform(0.2, 0.6),
                tags={"chain_position": str(i)},
            )
            g.add_node(meta)
            chain_ids.append(nid)
            if i > 0:
                src = chain_ids[i - 1]
                g.add_edge(
                    src, nid,
                    EdgeMetadata(
                        edge_id=_make_edge_id(src, nid),
                        edge_type=EdgeType.TOKEN_MINT,
                        weight=rng.uniform(0.7, 0.95),
                        delegation_depth_limit=chain_len,
                    )
                )

        # Terminal high-privilege node (SECRET or DEPLOYMENT)
        terminal_type = rng.choice([NodeType.SECRET, NodeType.DEPLOYMENT])
        terminal_id = next_id("terminal")
        if terminal_type == NodeType.SECRET:
            name = _pick(_SECRET_NAMES, rng, used_names)
        else:
            name = _pick(_DEPLOYMENT_NAMES, rng, used_names)
        terminal_meta = NodeMetadata(
            node_id=terminal_id,
            node_type=terminal_type,
            name=name,
            privilege_level=rng.uniform(0.85, 1.0),
            sensitivity=rng.uniform(0.9, 1.0),
            tags={"chain_terminal": "true"},
        )
        g.add_node(terminal_meta)
        last_chain = chain_ids[-1]
        edge_type = EdgeType.SECRET_READ if terminal_type == NodeType.SECRET else EdgeType.DEPLOY_TO
        g.add_edge(
            last_chain, terminal_id,
            EdgeMetadata(
                edge_id=_make_edge_id(last_chain, terminal_id),
                edge_type=edge_type,
                weight=rng.uniform(0.8, 1.0),
                delegation_depth_limit=1,
            )
        )

        # Insert 1-2 ROLE stepping stones mid-chain
        num_roles = rng.randint(1, 2)
        mid_points = rng.sample(range(1, len(chain_ids) - 1), min(num_roles, len(chain_ids) - 2))
        for pos in mid_points:
            role_id = next_id("role")
            role_meta = NodeMetadata(
                node_id=role_id,
                node_type=NodeType.ROLE,
                name=_pick(_ROLE_NAMES, rng, used_names),
                privilege_level=rng.uniform(0.5, 0.75),
                sensitivity=rng.uniform(0.4, 0.7),
            )
            g.add_node(role_meta)
            pivot = chain_ids[pos]
            g.add_edge(
                pivot, role_id,
                EdgeMetadata(
                    edge_id=_make_edge_id(pivot, role_id),
                    edge_type=EdgeType.ASSUME_ROLE,
                    weight=rng.uniform(0.6, 0.9),
                    delegation_depth_limit=2,
                )
            )

        # Entry-point USER nodes (2-3)
        num_users = rng.randint(2, 3)
        chain_head = chain_ids[0]
        for _ in range(num_users):
            uid = next_id("user")
            user_meta = NodeMetadata(
                node_id=uid,
                node_type=NodeType.USER,
                name=_pick(_USER_NAMES, rng, used_names),
                privilege_level=rng.uniform(0.05, 0.25),
                sensitivity=rng.uniform(0.1, 0.3),
            )
            g.add_node(user_meta)
            g.add_edge(
                uid, chain_head,
                EdgeMetadata(
                    edge_id=_make_edge_id(uid, chain_head),
                    edge_type=EdgeType.AUTHENTICATE_AS,
                    weight=rng.uniform(0.4, 0.8),
                    delegation_depth_limit=1,
                    requires_mfa=rng.random() < 0.4,
                )
            )

        # Fill remaining quota with extra service nodes branching off mid-chain
        current_count = g._graph.number_of_nodes()
        remaining = num_nodes - current_count
        for _ in range(max(0, remaining)):
            nid = next_id("svc")
            meta = NodeMetadata(
                node_id=nid,
                node_type=NodeType.SERVICE,
                name=_pick(_SERVICE_NAMES, rng, used_names),
                privilege_level=rng.uniform(0.1, 0.4),
                sensitivity=rng.uniform(0.1, 0.4),
            )
            g.add_node(meta)
            attach = rng.choice(chain_ids)
            g.add_edge(
                attach, nid,
                EdgeMetadata(
                    edge_id=_make_edge_id(attach, nid),
                    edge_type=EdgeType.TOKEN_MINT,
                    weight=rng.uniform(0.3, 0.7),
                    delegation_depth_limit=2,
                )
            )

        return g

    # ------------------------------------------------------------------
    # Dense cluster topology
    # ------------------------------------------------------------------

    def _build_dense_cluster(
        self, rng: random.Random, num_nodes: int
    ) -> TrustGraph:
        """Build a team-scoped IAM trust graph with dense intra-cluster connectivity.

        Architecture:
            - 3-4 clusters of 8-12 nodes each (SERVICE, ROLE, SECRET mix).
            - Within each cluster: high edge density (each node connects to
              several cluster-mates via ASSUME_ROLE, TOKEN_MINT, SECRET_READ).
            - Between clusters: 1-2 bridge edges (ASSUME_ROLE or DEPLOY_TO).

        The bridge edges are the critical risk surface: compromise one cluster
        and the bridge is the lateral movement path to the next cluster.

        This topology produces high clustering coefficient and high density —
        the fingerprinter's signatures for DENSE_CLUSTER classification.

        Args:
            rng: Seeded random instance.
            num_nodes: Approximate total node count.

        Returns:
            A populated ``TrustGraph``.
        """
        g = TrustGraph()
        used_names: set = set()
        node_counter = [0]

        def next_id(prefix: str) -> str:
            node_counter[0] += 1
            return _make_node_id(prefix, node_counter[0])

        num_clusters = rng.randint(3, 4)
        nodes_per_cluster = max(8, num_nodes // num_clusters)

        cluster_node_ids: List[List[str]] = []

        for c in range(num_clusters):
            cluster_ids: List[str] = []
            cluster_size = rng.randint(8, min(12, nodes_per_cluster + 2))

            for i in range(cluster_size):
                # Mix of SERVICE (60%), ROLE (20%), SECRET (20%)
                roll = rng.random()
                if roll < 0.6:
                    ntype = NodeType.SERVICE
                    name = _pick(_SERVICE_NAMES, rng, used_names)
                    nid = next_id("svc")
                    priv = rng.uniform(0.1, 0.55)
                elif roll < 0.8:
                    ntype = NodeType.ROLE
                    name = _pick(_ROLE_NAMES, rng, used_names)
                    nid = next_id("role")
                    priv = rng.uniform(0.5, 0.85)
                else:
                    ntype = NodeType.SECRET
                    name = _pick(_SECRET_NAMES, rng, used_names)
                    nid = next_id("secret")
                    priv = rng.uniform(0.4, 0.8)

                meta = NodeMetadata(
                    node_id=nid,
                    node_type=ntype,
                    name=name,
                    privilege_level=priv,
                    sensitivity=rng.uniform(0.3, 0.9),
                    tags={"cluster": str(c)},
                )
                g.add_node(meta)
                cluster_ids.append(nid)

            # Dense intra-cluster edges: each node connects to ~50-70% of cluster
            intra_edge_types = [
                EdgeType.ASSUME_ROLE,
                EdgeType.TOKEN_MINT,
                EdgeType.SECRET_READ,
                EdgeType.AUTHENTICATE_AS,
            ]
            for i, src in enumerate(cluster_ids):
                # Each node forms edges to several cluster mates
                num_connections = rng.randint(
                    max(1, len(cluster_ids) // 3),
                    max(2, int(len(cluster_ids) * 0.65))
                )
                targets = rng.sample(
                    [n for n in cluster_ids if n != src],
                    min(num_connections, len(cluster_ids) - 1)
                )
                for tgt in targets:
                    if g._graph.has_edge(src, tgt):
                        continue
                    etype = rng.choice(intra_edge_types)
                    g.add_edge(
                        src, tgt,
                        EdgeMetadata(
                            edge_id=_make_edge_id(src, tgt),
                            edge_type=etype,
                            weight=rng.uniform(0.6, 0.95),
                            delegation_depth_limit=rng.randint(1, 3),
                            is_conditional=rng.random() < 0.2,
                        )
                    )

            cluster_node_ids.append(cluster_ids)

        # Bridge edges between clusters (1-2 per cluster pair)
        for i in range(len(cluster_node_ids) - 1):
            num_bridges = rng.randint(1, 2)
            for _ in range(num_bridges):
                src = rng.choice(cluster_node_ids[i])
                tgt = rng.choice(cluster_node_ids[i + 1])
                if g._graph.has_edge(src, tgt):
                    continue
                bridge_type = rng.choice([EdgeType.ASSUME_ROLE, EdgeType.DEPLOY_TO])
                g.add_edge(
                    src, tgt,
                    EdgeMetadata(
                        edge_id=_make_edge_id(src, tgt),
                        edge_type=bridge_type,
                        weight=rng.uniform(0.5, 0.8),
                        delegation_depth_limit=1,
                        tags={"bridge": "true"},
                    )
                )

        return g

    # ------------------------------------------------------------------
    # Mixed topology
    # ------------------------------------------------------------------

    def _build_mixed(self, rng: random.Random, num_nodes: int) -> TrustGraph:
        """Build an enterprise-realistic mixed IAM trust graph.

        Combines elements from hub, chain, and dense_cluster topologies to
        simulate the heterogeneous IAM configurations found in real
        multi-team cloud environments.

        Args:
            rng: Seeded random instance.
            num_nodes: Approximate total node count.

        Returns:
            A populated ``TrustGraph``.
        """
        third = max(10, num_nodes // 3)

        # Build each sub-topology at reduced scale
        hub_g = self._build_hub(rng, third)
        chain_g = self._build_chain(rng, third)
        cluster_g = self._build_dense_cluster(rng, third)

        # Merge into a single graph by adding all nodes/edges
        merged = TrustGraph()
        used_ids: set = set()

        def _import_graph(source: TrustGraph, prefix: str) -> List[str]:
            id_map: dict[str, str] = {}
            imported_ids: List[str] = []
            for nid, data in source._graph.nodes(data=True):
                orig_meta = data["metadata"]
                new_id = f"{prefix}_{nid}"
                while new_id in used_ids:
                    new_id = f"{prefix}_{new_id}"
                id_map[nid] = new_id
                used_ids.add(new_id)
                new_meta = NodeMetadata(
                    node_id=new_id,
                    node_type=orig_meta.node_type,
                    name=orig_meta.name,
                    privilege_level=orig_meta.privilege_level,
                    sensitivity=orig_meta.sensitivity,
                    compromise_status=orig_meta.compromise_status,
                    cascade_risk=orig_meta.cascade_risk,
                    tags={**orig_meta.tags, "origin": prefix},
                )
                merged.add_node(new_meta)
                imported_ids.append(new_id)
            for src, tgt, data in source._graph.edges(data=True):
                orig_edge = data["metadata"]
                new_src = id_map[src]
                new_tgt = id_map[tgt]
                new_edge = EdgeMetadata(
                    edge_id=_make_edge_id(new_src, new_tgt),
                    edge_type=orig_edge.edge_type,
                    weight=orig_edge.weight,
                    delegation_depth_limit=orig_edge.delegation_depth_limit,
                    requires_mfa=orig_edge.requires_mfa,
                    is_conditional=orig_edge.is_conditional,
                    conditions=orig_edge.conditions,
                )
                merged.add_edge(new_src, new_tgt, new_edge)
            return imported_ids

        hub_ids = _import_graph(hub_g, "hub")
        chain_ids = _import_graph(chain_g, "chain")
        cluster_ids = _import_graph(cluster_g, "cluster")

        # Cross-topology bridge edges to simulate real inter-team trust
        bridge_pairs: List[Tuple[List[str], List[str]]] = [
            (hub_ids, chain_ids),
            (chain_ids, cluster_ids),
        ]
        for src_pool, tgt_pool in bridge_pairs:
            src = rng.choice(src_pool)
            tgt = rng.choice(tgt_pool)
            if not merged._graph.has_edge(src, tgt):
                merged.add_edge(
                    src, tgt,
                    EdgeMetadata(
                        edge_id=_make_edge_id(src, tgt),
                        edge_type=EdgeType.ASSUME_ROLE,
                        weight=rng.uniform(0.4, 0.75),
                        delegation_depth_limit=2,
                        tags={"cross_topology_bridge": "true"},
                    )
                )

        return merged
