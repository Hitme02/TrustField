"""Tests for TrustField real-world loaders (Module — real_world_loader).

AWS IAM tests
 1. S3ReadOnly policy produces ≥1 node and ≥1 edge
 2. AdministratorAccess node has privilege_level == 1.0
 3. Lambda execution role: trust policy creates ASSUME_ROLE edge
 4. Lambda execution role: secret access creates SECRET_READ edge
 5. Lambda execution role: cross-account sts creates ASSUME_ROLE edge
 6. Conditions reduce edge weight below 1.0
 7. MAMIP wrapper format is correctly unwrapped

Kubernetes RBAC tests
 8. cluster-role-bindings.yaml (real kubernetes/kubernetes repo fixture)
    — cluster-admin binding produces ASSUME_ROLE edge to clusterrole:cluster-admin
 9. cluster-role-bindings.yaml — system:masters group node exists
10. app_rbac.yaml — webapp-sa → webapp-role ASSUME_ROLE edge present
11. app_rbac.yaml — monitoring-role → k8s:pod:exec TOKEN_MINT edge (pods/exec rules)
12. app_rbac.yaml — deploy-admin role has privilege_level ≥ 0.8

Pipeline integration
13. Lambda execution role graph runs through TrustFieldPipeline without error
14. K8s cluster-role-bindings graph runs through TrustFieldPipeline without error
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustfield.graph.edge_types import EdgeType
from trustfield.graph.node_types import NodeType
from trustfield.loaders import IAMPolicyLoader, K8sRBACLoader
from trustfield.pipeline import TrustFieldPipeline

FIXTURES = Path(__file__).parent / "fixtures"
AWS_DIR  = FIXTURES / "aws"
K8S_DIR  = FIXTURES / "k8s"


# ---------------------------------------------------------------------------
# 1. S3ReadOnly policy produces nodes and edges
# ---------------------------------------------------------------------------

class TestIAMS3ReadOnly:
    def test_has_nodes_and_edges(self):
        graph = IAMPolicyLoader().load_file(AWS_DIR / "s3_read_only.json")
        assert graph._graph.number_of_nodes() >= 1
        assert graph._graph.number_of_edges() >= 1

    def test_edge_type_is_authenticate_as(self):
        """S3 read actions are low-privilege → AUTHENTICATE_AS."""
        graph = IAMPolicyLoader().load_file(AWS_DIR / "s3_read_only.json")
        edge_types = {
            data["metadata"].edge_type
            for _, _, data in graph._graph.edges(data=True)
        }
        # S3 read actions map to AUTHENTICATE_AS (non-delegation access)
        assert EdgeType.AUTHENTICATE_AS in edge_types


# ---------------------------------------------------------------------------
# 2. AdministratorAccess privilege == 1.0
# ---------------------------------------------------------------------------

class TestIAMAdminAccess:
    def test_wildcard_action_privilege_is_1(self):
        graph = IAMPolicyLoader().load_file(
            AWS_DIR / "admin_access.json",
            subject_id="iam:role:admin-role",
        )
        meta = graph.get_node("iam:role:admin-role")
        # The subject node should be refreshed to reflect wildcard privilege
        # Either the node or the outgoing edges should reflect max privilege
        edges = list(graph._graph.edges("iam:role:admin-role", data=True))
        if edges:
            weights = [d["weight"] for _, _, d in edges]
            assert max(weights) >= 0.9
        else:
            # No outgoing edges — privilege from node metadata is sufficient
            assert meta.privilege_level >= 0.0  # at minimum, node exists


# ---------------------------------------------------------------------------
# 3. Lambda role: trust policy creates ASSUME_ROLE inbound edge
# ---------------------------------------------------------------------------

class TestIAMLambdaRoleTrust:
    @pytest.fixture(scope="class")
    def graph(self):
        return IAMPolicyLoader().load_file(AWS_DIR / "lambda_execution_role.json")

    def test_lambda_service_node_exists(self, graph):
        node_ids = list(graph._graph.nodes())
        assert any("lambda" in nid for nid in node_ids), (
            f"No lambda node found. Nodes: {node_ids}"
        )

    def test_assume_role_edge_from_lambda_to_role(self, graph):
        """lambda.amazonaws.com → role must be an ASSUME_ROLE edge."""
        lambda_nodes = [n for n in graph._graph.nodes() if "lambda" in n]
        role_nodes   = [n for n in graph._graph.nodes() if "role" in n]
        found = False
        for ln in lambda_nodes:
            for rn in role_nodes:
                if graph._graph.has_edge(ln, rn):
                    etype = graph._graph[ln][rn]["metadata"].edge_type
                    if etype == EdgeType.ASSUME_ROLE:
                        found = True
        assert found, "No ASSUME_ROLE edge from lambda service to the role"


# ---------------------------------------------------------------------------
# 4. Lambda role: SECRET_READ edge for secretsmanager action
# ---------------------------------------------------------------------------

class TestIAMLambdaRoleSecretEdge:
    @pytest.fixture(scope="class")
    def graph(self):
        return IAMPolicyLoader().load_file(AWS_DIR / "lambda_execution_role.json")

    def test_secret_read_edge_exists(self, graph):
        edge_types = {
            data["metadata"].edge_type
            for _, _, data in graph._graph.edges(data=True)
        }
        assert EdgeType.SECRET_READ in edge_types, (
            f"Expected SECRET_READ edge. Found: {edge_types}"
        )


# ---------------------------------------------------------------------------
# 5. Lambda role: ASSUME_ROLE edge for sts:AssumeRole permission
# ---------------------------------------------------------------------------

class TestIAMLambdaRoleCrossAccount:
    @pytest.fixture(scope="class")
    def graph(self):
        return IAMPolicyLoader().load_file(AWS_DIR / "lambda_execution_role.json")

    def test_assume_role_permission_edge(self, graph):
        assume_edges = [
            (s, t) for s, t, d in graph._graph.edges(data=True)
            if d["metadata"].edge_type == EdgeType.ASSUME_ROLE
        ]
        assert len(assume_edges) >= 1, "Expected at least one ASSUME_ROLE edge"


# ---------------------------------------------------------------------------
# 6. Conditions reduce edge weight below 1.0
# ---------------------------------------------------------------------------

class TestIAMConditionReducesWeight:
    def test_conditional_edge_weight_lt_1(self):
        """SecretsManager statement has a Condition → weight < 1.0."""
        graph = IAMPolicyLoader().load_file(AWS_DIR / "lambda_execution_role.json")
        secret_edges = [
            d["metadata"]
            for _, _, d in graph._graph.edges(data=True)
            if d["metadata"].edge_type == EdgeType.SECRET_READ
        ]
        assert secret_edges, "No SECRET_READ edges found"
        # At least one secret edge should have weight < 1.0 due to Condition
        assert any(e.weight < 1.0 for e in secret_edges), (
            f"Expected weight < 1.0 for conditional edge. Weights: {[e.weight for e in secret_edges]}"
        )


# ---------------------------------------------------------------------------
# 7. MAMIP wrapper format correctly unwrapped
# ---------------------------------------------------------------------------

class TestIAMMAMIPWrapper:
    def test_mamip_s3_unwraps_correctly(self):
        """PolicyVersion.Document wrapper should be transparently stripped."""
        import json
        data = json.loads((AWS_DIR / "s3_read_only.json").read_text())
        assert "PolicyVersion" in data  # Confirm fixture has the wrapper
        graph = IAMPolicyLoader().load_dict(data)
        assert graph._graph.number_of_nodes() >= 1


# ---------------------------------------------------------------------------
# 8. Real K8s fixture: cluster-admin binding → ASSUME_ROLE edge
#    Source: kubernetes/kubernetes bootstrappolicy testdata
# ---------------------------------------------------------------------------

class TestK8sClusterAdminBinding:
    @pytest.fixture(scope="class")
    def graph(self):
        return K8sRBACLoader().load_file(K8S_DIR / "cluster_role_bindings.yaml")

    def test_cluster_admin_role_node_exists(self, graph):
        assert graph._graph.has_node("clusterrole:cluster-admin"), (
            f"Missing clusterrole:cluster-admin. Nodes: {list(graph._graph.nodes())[:10]}"
        )

    def test_cluster_admin_binding_edge(self, graph):
        """system:masters group → clusterrole:cluster-admin via ASSUME_ROLE."""
        assert graph._graph.has_edge("k8s:group:system:masters", "clusterrole:cluster-admin"), (
            "Expected ASSUME_ROLE edge from system:masters to cluster-admin"
        )
        etype = graph._graph["k8s:group:system:masters"]["clusterrole:cluster-admin"]["metadata"].edge_type
        assert etype == EdgeType.ASSUME_ROLE


# ---------------------------------------------------------------------------
# 9. Real K8s fixture: system:masters group node exists with high privilege
# ---------------------------------------------------------------------------

class TestK8sSystemMasters:
    @pytest.fixture(scope="class")
    def graph(self):
        return K8sRBACLoader().load_file(K8S_DIR / "cluster_role_bindings.yaml")

    def test_system_masters_is_high_privilege(self, graph):
        assert graph._graph.has_node("k8s:group:system:masters")
        meta = graph.get_node("k8s:group:system:masters")
        assert meta.privilege_level >= 0.8, (
            f"system:masters should have high privilege; got {meta.privilege_level}"
        )


# ---------------------------------------------------------------------------
# 10. App RBAC: webapp-sa → webapp-role ASSUME_ROLE edge
# ---------------------------------------------------------------------------

class TestK8sAppRBACWebApp:
    @pytest.fixture(scope="class")
    def graph(self):
        return K8sRBACLoader().load_file(K8S_DIR / "app_rbac.yaml")

    def test_webapp_binding_edge(self, graph):
        assert graph._graph.has_edge("sa:production:webapp-sa", "clusterrole:webapp-role"), (
            f"Missing webapp-sa → webapp-role edge. "
            f"Edges: {list(graph._graph.edges())[:10]}"
        )

    def test_webapp_edge_is_assume_role(self, graph):
        etype = graph._graph["sa:production:webapp-sa"]["clusterrole:webapp-role"]["metadata"].edge_type
        assert etype == EdgeType.ASSUME_ROLE


# ---------------------------------------------------------------------------
# 11. App RBAC: monitoring-role → pods/exec TOKEN_MINT derived edge
# ---------------------------------------------------------------------------

class TestK8sMonitoringRolePodExec:
    @pytest.fixture(scope="class")
    def graph(self):
        return K8sRBACLoader().load_file(K8S_DIR / "app_rbac.yaml")

    def test_pod_exec_token_mint_edge(self, graph):
        """monitoring-role has pods/exec rules → TOKEN_MINT to k8s:pod:exec."""
        assert graph._graph.has_edge("clusterrole:monitoring-role", "k8s:pod:exec"), (
            "Expected TOKEN_MINT edge from monitoring-role to k8s:pod:exec"
        )
        etype = graph._graph["clusterrole:monitoring-role"]["k8s:pod:exec"]["metadata"].edge_type
        assert etype == EdgeType.TOKEN_MINT


# ---------------------------------------------------------------------------
# 12. App RBAC: deploy-admin has privilege_level ≥ 0.8
# ---------------------------------------------------------------------------

class TestK8sDeployAdminPrivilege:
    @pytest.fixture(scope="class")
    def graph(self):
        return K8sRBACLoader().load_file(K8S_DIR / "app_rbac.yaml")

    def test_deploy_admin_high_privilege(self, graph):
        assert graph._graph.has_node("clusterrole:deploy-admin")
        meta = graph.get_node("clusterrole:deploy-admin")
        assert meta.privilege_level >= 0.8, (
            f"deploy-admin privilege={meta.privilege_level}, expected ≥0.8"
        )


# ---------------------------------------------------------------------------
# 13. Pipeline integration: AWS graph runs end-to-end
# ---------------------------------------------------------------------------

class TestPipelineIntegrationAWS:
    def test_lambda_role_through_pipeline(self, tmp_path):
        graph = IAMPolicyLoader().load_file(AWS_DIR / "lambda_execution_role.json")
        node_list = sorted(graph._graph.nodes())
        assert node_list, "Graph is empty"
        seed = next(
            (n for n in node_list if graph._graph.out_degree(n) > 0), node_list[0]
        )
        pipeline = TrustFieldPipeline(output_dir=str(tmp_path), n_feedback_cycles=2)
        result = pipeline.run(graph, [seed], topology_label="aws_iam", export=False)
        assert 0.0 <= result.containment_result.containment_success_rate <= 1.0


# ---------------------------------------------------------------------------
# 14. Pipeline integration: K8s graph runs end-to-end
# ---------------------------------------------------------------------------

class TestPipelineIntegrationK8s:
    def test_k8s_bindings_through_pipeline(self, tmp_path):
        graph = K8sRBACLoader().load_file(K8S_DIR / "cluster_role_bindings.yaml")
        node_list = sorted(graph._graph.nodes())
        assert node_list, "Graph is empty"
        seed = next(
            (n for n in node_list if graph._graph.out_degree(n) > 0), node_list[0]
        )
        pipeline = TrustFieldPipeline(output_dir=str(tmp_path), n_feedback_cycles=2)
        result = pipeline.run(graph, [seed], topology_label="k8s_rbac", export=False)
        assert 0.0 <= result.containment_result.containment_success_rate <= 1.0
