"""Comprehensive unit tests for TrustField Module 1 — Trust Graph Construction.

Tests cover:
    1. Node/edge creation and metadata retrieval
    2. Topology generators produce graphs with correct structural properties
    3. Fingerprinter correctly classifies each topology type
    4. to_dict() / from_dict() round-trip produces identical graph
    5. get_privilege_escalation_paths() returns only high-privilege endpoints
    6. Adjacency matrix shape matches node count
    7. Summary statistics accuracy
"""

import math
import pytest

from trustfield.graph import (
    EdgeMetadata,
    EdgeType,
    IAMSimulator,
    NodeMetadata,
    NodeType,
    TopologyFingerprinter,
    TopologyType,
    TrustGraph,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def simple_graph():
    """A small manually constructed graph for unit-level tests."""
    g = TrustGraph()
    user = NodeMetadata("u1", NodeType.USER, "developer-alice", 0.1, 0.2)
    svc = NodeMetadata("s1", NodeType.SERVICE, "auth-service", 0.4, 0.5)
    role = NodeMetadata("r1", NodeType.ROLE, "admin-role", 0.9, 0.9)
    secret = NodeMetadata("sec1", NodeType.SECRET, "db-credentials", 0.7, 0.85)
    for node in [user, svc, role, secret]:
        g.add_node(node)
    g.add_edge("u1", "s1", EdgeMetadata("e1", EdgeType.AUTHENTICATE_AS, 0.6, 1, requires_mfa=True))
    g.add_edge("s1", "r1", EdgeMetadata("e2", EdgeType.ASSUME_ROLE, 0.8, 2))
    g.add_edge("r1", "sec1", EdgeMetadata("e3", EdgeType.SECRET_READ, 0.9, 1, is_conditional=True))
    return g


@pytest.fixture
def sim():
    return IAMSimulator()


@pytest.fixture
def fingerprinter():
    return TopologyFingerprinter()


@pytest.fixture
def hub_graph(sim):
    return sim.generate("hub", num_nodes=40, seed=42)


@pytest.fixture
def chain_graph(sim):
    return sim.generate("chain", num_nodes=30, seed=42)


@pytest.fixture
def cluster_graph(sim):
    return sim.generate("dense_cluster", num_nodes=40, seed=42)


@pytest.fixture
def mixed_graph(sim):
    return sim.generate("mixed", num_nodes=50, seed=42)


# ---------------------------------------------------------------------------
# 1. Node/edge creation and metadata retrieval
# ---------------------------------------------------------------------------

class TestNodeCreation:
    def test_add_and_get_node(self, simple_graph):
        node = simple_graph.get_node("u1")
        assert node.node_id == "u1"
        assert node.node_type == NodeType.USER
        assert node.name == "developer-alice"
        assert node.privilege_level == pytest.approx(0.1)
        assert node.sensitivity == pytest.approx(0.2)
        assert node.compromise_status is False
        assert node.cascade_risk == pytest.approx(0.0)

    def test_node_tags_default_empty(self, simple_graph):
        node = simple_graph.get_node("u1")
        assert node.tags == {}

    def test_node_with_tags(self):
        g = TrustGraph()
        meta = NodeMetadata("n1", NodeType.SERVICE, "svc", 0.5, 0.5, tags={"env": "prod"})
        g.add_node(meta)
        assert g.get_node("n1").tags == {"env": "prod"}

    def test_get_nonexistent_node_raises(self, simple_graph):
        with pytest.raises(KeyError):
            simple_graph.get_node("does-not-exist")

    def test_add_node_returns_id(self):
        g = TrustGraph()
        meta = NodeMetadata("n1", NodeType.SERVICE, "svc", 0.5, 0.5)
        returned_id = g.add_node(meta)
        assert returned_id == "n1"

    def test_overwrite_existing_node(self):
        g = TrustGraph()
        g.add_node(NodeMetadata("n1", NodeType.SERVICE, "old-name", 0.3, 0.3))
        g.add_node(NodeMetadata("n1", NodeType.SERVICE, "new-name", 0.7, 0.7))
        assert g.get_node("n1").name == "new-name"

    def test_get_nodes_by_type(self, simple_graph):
        roles = simple_graph.get_nodes_by_type(NodeType.ROLE)
        assert len(roles) == 1
        assert roles[0].node_id == "r1"

        secrets = simple_graph.get_nodes_by_type(NodeType.SECRET)
        assert len(secrets) == 1

        deployments = simple_graph.get_nodes_by_type(NodeType.DEPLOYMENT)
        assert len(deployments) == 0

    def test_all_node_types_representable(self):
        g = TrustGraph()
        for i, nt in enumerate(NodeType):
            g.add_node(NodeMetadata(f"n{i}", nt, f"name-{i}", 0.5, 0.5))
        for nt in NodeType:
            assert len(g.get_nodes_by_type(nt)) == 1


class TestEdgeCreation:
    def test_add_and_get_edge(self, simple_graph):
        edge = simple_graph.get_edge("u1", "s1")
        assert edge.edge_id == "e1"
        assert edge.edge_type == EdgeType.AUTHENTICATE_AS
        assert edge.weight == pytest.approx(0.6)
        assert edge.delegation_depth_limit == 1
        assert edge.requires_mfa is True
        assert edge.is_conditional is False

    def test_edge_conditional_flag(self, simple_graph):
        edge = simple_graph.get_edge("r1", "sec1")
        assert edge.is_conditional is True

    def test_get_nonexistent_edge_raises(self, simple_graph):
        with pytest.raises(KeyError):
            simple_graph.get_edge("u1", "r1")

    def test_add_edge_missing_source_raises(self):
        g = TrustGraph()
        g.add_node(NodeMetadata("t", NodeType.SERVICE, "target", 0.5, 0.5))
        with pytest.raises(KeyError):
            g.add_edge("missing", "t", EdgeMetadata("e", EdgeType.TOKEN_MINT, 0.5, 1))

    def test_add_edge_missing_target_raises(self):
        g = TrustGraph()
        g.add_node(NodeMetadata("s", NodeType.SERVICE, "source", 0.5, 0.5))
        with pytest.raises(KeyError):
            g.add_edge("s", "missing", EdgeMetadata("e", EdgeType.TOKEN_MINT, 0.5, 1))

    def test_add_edge_returns_edge_id(self, simple_graph):
        g = TrustGraph()
        g.add_node(NodeMetadata("a", NodeType.SERVICE, "a", 0.5, 0.5))
        g.add_node(NodeMetadata("b", NodeType.SERVICE, "b", 0.5, 0.5))
        eid = g.add_edge("a", "b", EdgeMetadata("my-edge", EdgeType.TOKEN_MINT, 0.7, 2))
        assert eid == "my-edge"

    def test_all_edge_types_representable(self):
        g = TrustGraph()
        nodes = []
        for i in range(len(EdgeType) + 1):
            nid = f"n{i}"
            g.add_node(NodeMetadata(nid, NodeType.SERVICE, f"svc-{i}", 0.5, 0.5))
            nodes.append(nid)
        for i, et in enumerate(EdgeType):
            g.add_edge(nodes[i], nodes[i + 1], EdgeMetadata(f"e{i}", et, 0.5, 1))
        for i, et in enumerate(EdgeType):
            assert g.get_edge(nodes[i], nodes[i + 1]).edge_type == et


class TestNeighbours:
    def test_outgoing_neighbours(self, simple_graph):
        out = simple_graph.get_neighbors("u1", direction="out")
        assert out == ["s1"]

    def test_incoming_neighbours(self, simple_graph):
        inc = simple_graph.get_neighbors("r1", direction="in")
        assert inc == ["s1"]

    def test_both_neighbours(self, simple_graph):
        both = simple_graph.get_neighbors("s1", direction="both")
        assert set(both) == {"u1", "r1"}

    def test_invalid_direction_raises(self, simple_graph):
        with pytest.raises(ValueError):
            simple_graph.get_neighbors("u1", direction="sideways")

    def test_missing_node_raises(self, simple_graph):
        with pytest.raises(KeyError):
            simple_graph.get_neighbors("ghost")

    def test_isolated_node_has_no_neighbours(self):
        g = TrustGraph()
        g.add_node(NodeMetadata("lone", NodeType.USER, "alone", 0.1, 0.1))
        assert g.get_neighbors("lone", "both") == []


# ---------------------------------------------------------------------------
# 2. Topology generator structural properties
# ---------------------------------------------------------------------------

class TestHubTopology:
    def test_hub_has_enough_nodes(self, hub_graph):
        assert hub_graph._graph.number_of_nodes() >= 10

    def test_hub_has_edges(self, hub_graph):
        assert hub_graph._graph.number_of_edges() > 0

    def test_hub_contains_high_privilege_roles(self, hub_graph):
        roles = hub_graph.get_nodes_by_type(NodeType.ROLE)
        high_priv_roles = [r for r in roles if r.privilege_level >= 0.85]
        assert len(high_priv_roles) >= 1, "Hub must have at least one hub role with privilege >= 0.85"

    def test_hub_centrality_variance_high(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        assert fp.centrality_variance > 0.001, (
            f"Hub should have centrality_variance > 0.001, got {fp.centrality_variance:.6f}"
        )

    def test_hub_clustering_low(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        assert fp.clustering_coefficient < 0.3, (
            f"Hub should have clustering < 0.3, got {fp.clustering_coefficient:.4f}"
        )

    def test_hub_has_services(self, hub_graph):
        services = hub_graph.get_nodes_by_type(NodeType.SERVICE)
        assert len(services) >= 3

    def test_hub_has_secrets(self, hub_graph):
        secrets = hub_graph.get_nodes_by_type(NodeType.SECRET)
        assert len(secrets) >= 3


class TestChainTopology:
    def test_chain_has_enough_nodes(self, chain_graph):
        assert chain_graph._graph.number_of_nodes() >= 10

    def test_chain_avg_path_length_high(self, chain_graph, fingerprinter):
        fp = fingerprinter.fingerprint(chain_graph)
        assert fp.avg_path_length > 2.0, (
            f"Chain should have avg_path_length > 2.0, got {fp.avg_path_length:.4f}"
        )

    def test_chain_clustering_low(self, chain_graph, fingerprinter):
        fp = fingerprinter.fingerprint(chain_graph)
        assert fp.clustering_coefficient < 0.3, (
            f"Chain should have low clustering, got {fp.clustering_coefficient:.4f}"
        )

    def test_chain_has_terminal_high_privilege(self, chain_graph):
        high_priv = chain_graph.get_high_privilege_nodes(threshold=0.85)
        assert len(high_priv) >= 1, "Chain must have a high-privilege terminal node"

    def test_chain_has_token_mint_edges(self, chain_graph):
        token_mint_count = sum(
            1 for _, _, d in chain_graph._graph.edges(data=True)
            if d["metadata"].edge_type == EdgeType.TOKEN_MINT
        )
        assert token_mint_count >= 5, "Chain should have multiple TOKEN_MINT edges"

    def test_chain_has_users_at_entry(self, chain_graph):
        users = chain_graph.get_nodes_by_type(NodeType.USER)
        assert len(users) >= 2


class TestDenseClusterTopology:
    def test_cluster_has_enough_nodes(self, cluster_graph):
        assert cluster_graph._graph.number_of_nodes() >= 20

    def test_cluster_high_clustering(self, cluster_graph, fingerprinter):
        fp = fingerprinter.fingerprint(cluster_graph)
        assert fp.clustering_coefficient > 0.3, (
            f"Dense cluster should have clustering > 0.3, got {fp.clustering_coefficient:.4f}"
        )

    def test_cluster_has_multiple_node_types(self, cluster_graph):
        types_present = {
            d["metadata"].node_type
            for _, d in cluster_graph._graph.nodes(data=True)
        }
        assert NodeType.SERVICE in types_present
        assert NodeType.ROLE in types_present

    def test_cluster_has_bridge_edges(self, cluster_graph):
        bridge_edges = [
            (s, t) for s, t, d in cluster_graph._graph.edges(data=True)
            if d["metadata"].tags.get("bridge") == "true"
        ]
        assert len(bridge_edges) >= 2, "Dense cluster must have inter-cluster bridge edges"


# ---------------------------------------------------------------------------
# 3. Fingerprinter topology classification
# ---------------------------------------------------------------------------

class TestFingerprinterClassification:
    def test_hub_classifies_as_hub(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        assert fp.topology_type == TopologyType.HUB, (
            f"Expected HUB, got {fp.topology_type.value}. "
            f"cv={fp.centrality_variance:.4f}, cc={fp.clustering_coefficient:.4f}"
        )

    def test_chain_classifies_as_chain(self, chain_graph, fingerprinter):
        fp = fingerprinter.fingerprint(chain_graph)
        assert fp.topology_type == TopologyType.CHAIN, (
            f"Expected CHAIN, got {fp.topology_type.value}. "
            f"apl={fp.avg_path_length:.4f}, cc={fp.clustering_coefficient:.4f}"
        )

    def test_dense_cluster_classifies_correctly(self, cluster_graph, fingerprinter):
        fp = fingerprinter.fingerprint(cluster_graph)
        assert fp.topology_type == TopologyType.DENSE_CLUSTER, (
            f"Expected DENSE_CLUSTER, got {fp.topology_type.value}. "
            f"cc={fp.clustering_coefficient:.4f}, density={fp.density:.4f}"
        )

    def test_model_weight_hints_sum_to_one(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        total = sum(fp.model_weight_hints.values())
        assert total == pytest.approx(1.0), f"Weights should sum to 1.0, got {total}"

    def test_model_weight_hints_have_all_keys(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        expected_keys = {"graph_traversal", "epidemic", "spectral", "percolation", "control_system"}
        assert set(fp.model_weight_hints.keys()) == expected_keys

    def test_hub_spectral_weight_dominant(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        assert fp.model_weight_hints["spectral"] == pytest.approx(0.5)

    def test_chain_epidemic_weight_dominant(self, chain_graph, fingerprinter):
        fp = fingerprinter.fingerprint(chain_graph)
        assert fp.model_weight_hints["epidemic"] == pytest.approx(0.45)

    def test_cluster_percolation_weight_dominant(self, cluster_graph, fingerprinter):
        fp = fingerprinter.fingerprint(cluster_graph)
        assert fp.model_weight_hints["percolation"] == pytest.approx(0.5)

    def test_mixed_equal_weights(self, fingerprinter):
        # Build a manufactured fingerprint that would classify as MIXED
        from trustfield.graph import TopologyFingerprint
        fp_input = TopologyFingerprint(
            clustering_coefficient=0.35,
            centrality_variance=0.02,
            spectral_gap=1.0,
            degree_distribution_entropy=3.0,
            avg_path_length=2.5,
            num_nodes=30,
            num_edges=60,
            density=0.07,
            topology_type=TopologyType.MIXED,
        )
        ttype = fingerprinter.classify_topology(fp_input)
        assert ttype == TopologyType.MIXED
        hints = fingerprinter.get_model_weight_hints(TopologyType.MIXED)
        assert all(v == pytest.approx(0.2) for v in hints.values())

    def test_fingerprint_fields_are_finite(self, hub_graph, fingerprinter):
        fp = fingerprinter.fingerprint(hub_graph)
        assert math.isfinite(fp.clustering_coefficient)
        assert math.isfinite(fp.centrality_variance)
        assert math.isfinite(fp.spectral_gap)
        assert math.isfinite(fp.degree_distribution_entropy)
        assert math.isfinite(fp.avg_path_length)
        assert math.isfinite(fp.density)


# ---------------------------------------------------------------------------
# 4. to_dict / from_dict round-trip
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_roundtrip_node_count(self, simple_graph):
        d = simple_graph.to_dict()
        g2 = TrustGraph.from_dict(d)
        assert g2._graph.number_of_nodes() == simple_graph._graph.number_of_nodes()

    def test_roundtrip_edge_count(self, simple_graph):
        d = simple_graph.to_dict()
        g2 = TrustGraph.from_dict(d)
        assert g2._graph.number_of_edges() == simple_graph._graph.number_of_edges()

    def test_roundtrip_node_metadata(self, simple_graph):
        d = simple_graph.to_dict()
        g2 = TrustGraph.from_dict(d)
        orig_node = simple_graph.get_node("r1")
        new_node = g2.get_node("r1")
        assert orig_node.node_type == new_node.node_type
        assert orig_node.name == new_node.name
        assert orig_node.privilege_level == pytest.approx(new_node.privilege_level)
        assert orig_node.sensitivity == pytest.approx(new_node.sensitivity)

    def test_roundtrip_edge_metadata(self, simple_graph):
        d = simple_graph.to_dict()
        g2 = TrustGraph.from_dict(d)
        orig_edge = simple_graph.get_edge("s1", "r1")
        new_edge = g2.get_edge("s1", "r1")
        assert orig_edge.edge_type == new_edge.edge_type
        assert orig_edge.weight == pytest.approx(new_edge.weight)
        assert orig_edge.requires_mfa == new_edge.requires_mfa
        assert orig_edge.is_conditional == new_edge.is_conditional

    def test_roundtrip_large_graph(self, hub_graph):
        d = hub_graph.to_dict()
        g2 = TrustGraph.from_dict(d)
        assert g2._graph.number_of_nodes() == hub_graph._graph.number_of_nodes()
        assert g2._graph.number_of_edges() == hub_graph._graph.number_of_edges()

    def test_dict_has_nodes_and_edges_keys(self, simple_graph):
        d = simple_graph.to_dict()
        assert "nodes" in d
        assert "edges" in d

    def test_dict_edges_have_source_target(self, simple_graph):
        d = simple_graph.to_dict()
        for edge in d["edges"]:
            assert "source" in edge
            assert "target" in edge

    def test_node_metadata_to_dict_from_dict(self):
        meta = NodeMetadata("n1", NodeType.ROLE, "admin-role", 0.9, 0.85,
                            compromise_status=True, cascade_risk=0.7,
                            tags={"env": "prod"})
        d = meta.to_dict()
        restored = NodeMetadata.from_dict(d)
        assert restored.node_id == meta.node_id
        assert restored.node_type == meta.node_type
        assert restored.compromise_status is True
        assert restored.cascade_risk == pytest.approx(0.7)
        assert restored.tags == {"env": "prod"}

    def test_edge_metadata_to_dict_from_dict(self):
        meta = EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 0.8, 3,
                            requires_mfa=True, is_conditional=True,
                            conditions={"src_ip": "10.0.0.0/8"})
        d = meta.to_dict()
        restored = EdgeMetadata.from_dict(d)
        assert restored.edge_type == EdgeType.ASSUME_ROLE
        assert restored.weight == pytest.approx(0.8)
        assert restored.requires_mfa is True
        assert restored.conditions == {"src_ip": "10.0.0.0/8"}


# ---------------------------------------------------------------------------
# 5. Privilege escalation paths
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    def test_finds_path_to_high_privilege_node(self, simple_graph):
        paths = simple_graph.get_privilege_escalation_paths("u1", target_privilege=0.8)
        # u1 -> s1 -> r1 (0.9) and u1 -> s1 -> r1 -> sec1 (0.7) — only r1 >= 0.8
        assert len(paths) >= 1
        # All paths must end at a node with privilege >= 0.8
        for path in paths:
            terminal_meta = simple_graph.get_node(path[-1])
            assert terminal_meta.privilege_level >= 0.8

    def test_no_path_returns_empty(self):
        g = TrustGraph()
        g.add_node(NodeMetadata("a", NodeType.USER, "alice", 0.1, 0.1))
        g.add_node(NodeMetadata("b", NodeType.ROLE, "admin", 0.95, 0.95))
        # No edge between them
        paths = g.get_privilege_escalation_paths("a", target_privilege=0.8)
        assert paths == []

    def test_source_not_in_paths_as_terminal(self, simple_graph):
        # Add a high-privilege source and check it's not returned as its own target
        g = TrustGraph()
        g.add_node(NodeMetadata("hp", NodeType.ROLE, "admin", 0.95, 0.95))
        g.add_node(NodeMetadata("lp", NodeType.SERVICE, "svc", 0.2, 0.2))
        g.add_edge("lp", "hp", EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 0.8, 1))
        paths = g.get_privilege_escalation_paths("hp", target_privilege=0.8)
        # hp itself should not be a target of paths starting from hp
        for path in paths:
            assert path[-1] != "hp"

    def test_nonexistent_source_raises(self, simple_graph):
        with pytest.raises(KeyError):
            simple_graph.get_privilege_escalation_paths("ghost")

    def test_paths_are_lists_of_node_ids(self, hub_graph):
        nodes = list(hub_graph._graph.nodes())
        source = nodes[0]
        paths = hub_graph.get_privilege_escalation_paths(source, target_privilege=0.7)
        for path in paths:
            assert isinstance(path, list)
            for nid in path:
                assert isinstance(nid, str)
                assert nid in hub_graph._graph

    def test_all_paths_reachable_in_graph(self, hub_graph):
        import networkx as nx
        nodes = list(hub_graph._graph.nodes())
        source = nodes[0]
        paths = hub_graph.get_privilege_escalation_paths(source, target_privilege=0.7)
        for path in paths:
            for i in range(len(path) - 1):
                assert hub_graph._graph.has_edge(path[i], path[i + 1])


# ---------------------------------------------------------------------------
# 6. Adjacency matrix
# ---------------------------------------------------------------------------

class TestAdjacencyMatrix:
    def test_shape_matches_node_count(self, simple_graph):
        import numpy as np
        mat = simple_graph.to_adjacency_matrix()
        n = simple_graph._graph.number_of_nodes()
        assert mat.shape == (n, n)

    def test_matrix_is_ndarray(self, simple_graph):
        import numpy as np
        mat = simple_graph.to_adjacency_matrix()
        assert isinstance(mat, np.ndarray)

    def test_matrix_weights_match_edges(self, simple_graph):
        import numpy as np
        mat = simple_graph.to_adjacency_matrix()
        node_order = list(simple_graph._graph.nodes())
        i = node_order.index("u1")
        j = node_order.index("s1")
        assert mat[i, j] == pytest.approx(0.6)

    def test_empty_entry_is_zero(self, simple_graph):
        mat = simple_graph.to_adjacency_matrix()
        node_order = list(simple_graph._graph.nodes())
        i = node_order.index("u1")
        j = node_order.index("r1")
        assert mat[i, j] == pytest.approx(0.0)

    def test_large_graph_shape(self, hub_graph):
        mat = hub_graph.to_adjacency_matrix()
        n = hub_graph._graph.number_of_nodes()
        assert mat.shape == (n, n)

    def test_matrix_non_negative(self, hub_graph):
        import numpy as np
        mat = hub_graph.to_adjacency_matrix()
        assert np.all(mat >= 0)


# ---------------------------------------------------------------------------
# 7. Summary statistics
# ---------------------------------------------------------------------------

class TestSummaryStatistics:
    def test_node_count(self, simple_graph):
        s = simple_graph.summary()
        assert s["node_count"] == 4

    def test_edge_count(self, simple_graph):
        s = simple_graph.summary()
        assert s["edge_count"] == 3

    def test_node_type_distribution(self, simple_graph):
        s = simple_graph.summary()
        dist = s["node_type_distribution"]
        assert dist["USER"] == 1
        assert dist["SERVICE"] == 1
        assert dist["ROLE"] == 1
        assert dist["SECRET"] == 1

    def test_edge_type_distribution(self, simple_graph):
        s = simple_graph.summary()
        dist = s["edge_type_distribution"]
        assert dist["AUTHENTICATE_AS"] == 1
        assert dist["ASSUME_ROLE"] == 1
        assert dist["SECRET_READ"] == 1

    def test_avg_privilege_level_correct(self, simple_graph):
        # u1=0.1, s1=0.4, r1=0.9, sec1=0.7 → mean=0.525
        s = simple_graph.summary()
        assert s["avg_privilege_level"] == pytest.approx(0.525)

    def test_max_privilege_level(self, simple_graph):
        s = simple_graph.summary()
        assert s["max_privilege_level"] == pytest.approx(0.9)

    def test_num_high_privilege_nodes(self, simple_graph):
        # r1 (0.9) and sec1 (0.7) both >= 0.7
        s = simple_graph.summary()
        assert s["num_high_privilege_nodes"] == 2

    def test_summary_keys_present(self, simple_graph):
        s = simple_graph.summary()
        required_keys = {
            "node_count", "edge_count", "node_type_distribution",
            "edge_type_distribution", "avg_privilege_level",
            "max_privilege_level", "num_high_privilege_nodes",
        }
        assert required_keys.issubset(set(s.keys()))

    def test_summary_empty_graph(self):
        g = TrustGraph()
        s = g.summary()
        assert s["node_count"] == 0
        assert s["edge_count"] == 0
        assert s["avg_privilege_level"] == pytest.approx(0.0)
        assert s["max_privilege_level"] == pytest.approx(0.0)
        assert s["num_high_privilege_nodes"] == 0

    def test_get_high_privilege_nodes_sorted(self, simple_graph):
        high = simple_graph.get_high_privilege_nodes(threshold=0.5)
        privs = [n.privilege_level for n in high]
        assert privs == sorted(privs, reverse=True)

    def test_get_high_privilege_nodes_threshold(self, simple_graph):
        # Only r1 (0.9) above 0.85
        high = simple_graph.get_high_privilege_nodes(threshold=0.85)
        assert len(high) == 1
        assert high[0].node_id == "r1"


# ---------------------------------------------------------------------------
# Extra: IAMSimulator seed reproducibility and validity
# ---------------------------------------------------------------------------

class TestIAMSimulatorReproducibility:
    def test_same_seed_same_graph(self, sim):
        g1 = sim.generate("hub", seed=99)
        g2 = sim.generate("hub", seed=99)
        assert g1._graph.number_of_nodes() == g2._graph.number_of_nodes()
        assert g1._graph.number_of_edges() == g2._graph.number_of_edges()

    def test_different_seed_may_differ(self, sim):
        g1 = sim.generate("hub", seed=1)
        g2 = sim.generate("hub", seed=2)
        # They could still be the same by chance, but sizes are very likely different
        # Just check both produce valid graphs
        assert g1._graph.number_of_nodes() > 0
        assert g2._graph.number_of_nodes() > 0

    def test_invalid_topology_raises(self, sim):
        with pytest.raises(ValueError):
            sim.generate("star_wars")

    def test_mixed_graph_combines_topology_elements(self, mixed_graph):
        s = mixed_graph.summary()
        assert s["node_count"] > 20
        assert s["edge_count"] > 10
        # Should have a variety of node types
        dist = s["node_type_distribution"]
        assert len(dist) >= 2
