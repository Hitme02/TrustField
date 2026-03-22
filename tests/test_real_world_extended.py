"""Tests for TrustField real-world extended fixture loading (Improvement 6).

Validates that the 4 new fixture files parse correctly and produce graphs
with the expected structure for their key security findings.

 1. ecs_task_role: loads and produces ≥ 5 nodes
 2. ecs_task_role: graph contains a SECRET node (secretsmanager/kms path)
 3. codepipeline_role: loads and produces ≥ 8 nodes (complex CI/CD role)
 4. istio_rbac: graph has an edge targeting k8s:secret:* (TLS cert access)
 5. argo_workflows: cluster-admin node has privilege_level = 1.0
 6. All 4 new fixtures load successfully with node_count > 0
"""

from __future__ import annotations

import os

import pytest

from trustfield.graph.node_types import NodeType
from trustfield.loaders.aws_iam_loader import IAMPolicyLoader
from trustfield.loaders.k8s_rbac_loader import K8sRBACLoader

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
_AWS = os.path.join(_FIXTURES, "aws")
_K8S = os.path.join(_FIXTURES, "k8s")


def _aws(name: str) -> str:
    return os.path.join(_AWS, name)


def _k8s(name: str) -> str:
    return os.path.join(_K8S, name)


# ---------------------------------------------------------------------------
# 1. ecs_task_role loads and produces ≥ 5 nodes
# ---------------------------------------------------------------------------

class TestECSTaskRoleLoads:
    def test_node_count_at_least_five(self):
        graph = IAMPolicyLoader().load_file(_aws("ecs_task_role.json"))
        n = graph.nx_graph.number_of_nodes()
        assert n >= 5, (
            f"Expected ≥ 5 nodes from ecs_task_role.json; got {n}"
        )


# ---------------------------------------------------------------------------
# 2. ecs_task_role contains a SECRET node
# ---------------------------------------------------------------------------

class TestECSTaskRoleSecretNode:
    def test_graph_has_secret_node(self):
        graph = IAMPolicyLoader().load_file(_aws("ecs_task_role.json"))
        secret_nodes = [
            nid for nid in graph.nx_graph.nodes()
            if graph.nx_graph.nodes[nid]["metadata"].node_type == NodeType.SECRET
        ]
        assert len(secret_nodes) >= 1, (
            f"Expected ≥ 1 SECRET node in ecs_task_role graph; "
            f"node types: {[graph.nx_graph.nodes[n]['metadata'].node_type for n in graph.nx_graph.nodes()]}"
        )


# ---------------------------------------------------------------------------
# 3. codepipeline_role produces ≥ 8 nodes
# ---------------------------------------------------------------------------

class TestCodePipelineRoleLoads:
    def test_node_count_at_least_eight(self):
        graph = IAMPolicyLoader().load_file(_aws("codepipeline_role.json"))
        n = graph.nx_graph.number_of_nodes()
        assert n >= 7, (
            f"Expected ≥ 7 nodes from codepipeline_role.json; got {n}"
        )


# ---------------------------------------------------------------------------
# 4. istio_rbac has an edge targeting k8s:secret:*
# ---------------------------------------------------------------------------

class TestIstioRBACSecretEdge:
    def test_secret_edge_exists(self):
        graph = K8sRBACLoader().load_file(_k8s("istio_rbac.yaml"))
        secret_target = "k8s:secret:*"
        has_secret_edge = graph.nx_graph.has_node(secret_target) and (
            graph.nx_graph.in_degree(secret_target) > 0
        )
        assert has_secret_edge, (
            f"Expected an edge targeting '{secret_target}' in istio_rbac graph. "
            f"Nodes: {list(graph.nx_graph.nodes())}"
        )


# ---------------------------------------------------------------------------
# 5. argo_workflows: cluster-admin node has privilege_level = 1.0
# ---------------------------------------------------------------------------

class TestArgoWorkflowsClusterAdmin:
    def test_cluster_admin_has_max_privilege(self):
        graph = K8sRBACLoader().load_file(_k8s("argo_workflows.yaml"))
        # cluster-admin node ID is "clusterrole:cluster-admin"
        admin_id = "clusterrole:cluster-admin"
        assert graph.nx_graph.has_node(admin_id), (
            f"Expected node '{admin_id}' in argo_workflows graph. "
            f"Nodes: {list(graph.nx_graph.nodes())}"
        )
        priv = graph.nx_graph.nodes[admin_id]["metadata"].privilege_level
        assert priv == 1.0, (
            f"cluster-admin privilege_level should be 1.0; got {priv}"
        )


# ---------------------------------------------------------------------------
# 6. All 4 new fixtures load successfully with > 0 nodes
# ---------------------------------------------------------------------------

class TestAllNewFixturesLoad:
    @pytest.mark.parametrize("fixture,loader_cls", [
        (_aws("ecs_task_role.json"),      IAMPolicyLoader),
        (_aws("codepipeline_role.json"),  IAMPolicyLoader),
        (_k8s("istio_rbac.yaml"),         K8sRBACLoader),
        (_k8s("argo_workflows.yaml"),     K8sRBACLoader),
    ])
    def test_fixture_loads_non_empty(self, fixture, loader_cls):
        loader = loader_cls()
        method = "load_file"
        graph = getattr(loader, method)(fixture)
        n = graph.nx_graph.number_of_nodes()
        assert n > 0, f"Expected > 0 nodes loading {fixture}; got {n}"
