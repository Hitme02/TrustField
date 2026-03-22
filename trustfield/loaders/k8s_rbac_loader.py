"""Kubernetes RBAC YAML loader — parses K8s RBAC resources into TrustGraph.

Supported resource kinds
------------------------
- ``ServiceAccount``       → USER node (workload identity)
- ``Role`` / ``ClusterRole`` → ROLE node
- ``RoleBinding`` / ``ClusterRoleBinding`` → ASSUME_ROLE edges (subject → role)

Additionally, ClusterRole rules are inspected to derive resource-access edges:
- Rules granting ``secrets`` access   → SECRET_READ edge (role → k8s:secret:*)
- Rules granting ``pods/exec`` access → TOKEN_MINT edge  (role → k8s:pod:exec)
- Rules granting ``rolebindings`` write → ASSUME_ROLE edge (role → k8s:rbac:*)

Multi-document YAML and Kubernetes ``List`` wrappers are both supported.

Node IDs
--------
- ClusterRole:   ``clusterrole:{name}``
- Role:          ``role:{namespace}:{name}``
- ServiceAccount:``sa:{namespace}:{name}``
- User:          ``k8s:user:{name}``
- Group:         ``k8s:group:{name}``
- Derived secret target: ``k8s:secret:*``
- Derived exec   target: ``k8s:pod:exec``
- Derived RBAC   target: ``k8s:rbac:*``
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterator, List, Optional, Union

import yaml

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph

from ._common import (
    privilege_from_k8s_rules,
    sensitivity_from_k8s_rules,
)

# ── well-known cluster-admin and near-admin role names ──────────────────────
_ADMIN_ROLE_NAMES = {
    "cluster-admin", "admin", "system:masters",
}
_KNOWN_PRIVILEGE: Dict[str, float] = {
    "cluster-admin":                1.0,
    "admin":                        0.9,
    "edit":                         0.7,
    "view":                         0.25,
    "system:kube-controller-manager": 0.85,
    "system:kube-scheduler":        0.6,
    "system:kube-proxy":            0.4,
    "system:kube-dns":              0.35,
    "system:node":                  0.5,
    "system:monitoring":            0.3,
    "system:basic-user":            0.1,
    "system:discovery":             0.1,
    "system:public-info-viewer":    0.1,
    "system:service-account-issuer-discovery": 0.2,
}

# ── resource → edge type mapping for derived edges ──────────────────────────
_RESOURCE_EDGE_MAP = {
    "secrets":                   (EdgeType.SECRET_READ,   "k8s:secret:*",  0.8),
    "serviceaccounts/token":     (EdgeType.TOKEN_MINT,    "k8s:sa:token",  0.85),
    "pods/exec":                 (EdgeType.TOKEN_MINT,    "k8s:pod:exec",  0.75),
    "pods/attach":               (EdgeType.TOKEN_MINT,    "k8s:pod:exec",  0.7),
    "pods/portforward":          (EdgeType.TOKEN_MINT,    "k8s:pod:pf",    0.6),
    "clusterrolebindings":       (EdgeType.ASSUME_ROLE,   "k8s:rbac:*",    0.9),
    "rolebindings":              (EdgeType.ASSUME_ROLE,   "k8s:rbac:*",    0.8),
}


class K8sRBACLoader:
    """Parses Kubernetes RBAC YAML files into a TrustField ``TrustGraph``.

    Handles multi-document YAML, Kubernetes ``List`` wrappers, and all four
    RBAC resource kinds.  Two-pass parsing ensures nodes are registered before
    bindings try to reference them.

    Args:
        infer_resource_edges: If True (default), analyse role rules and add
            derived edges for secret/exec/RBAC resource access.  Set False for
            a pure binding-only graph.

    Example::

        loader = K8sRBACLoader()

        # From a YAML file
        graph = loader.load_file("tests/fixtures/k8s/app_rbac.yaml")

        # From a YAML string
        graph = loader.loads(yaml_content)
    """

    def __init__(self, infer_resource_edges: bool = True) -> None:
        self._infer_resource_edges = infer_resource_edges
        self._edge_counter = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_file(self, path: Union[str, Path]) -> TrustGraph:
        """Parse a YAML file (single or multi-document) into a TrustGraph.

        Args:
            path: Path to the YAML file.

        Returns:
            A populated ``TrustGraph``.
        """
        return self.loads(Path(path).read_text(encoding="utf-8"))

    def loads(self, yaml_content: str) -> TrustGraph:
        """Parse a YAML string into a TrustGraph.

        Args:
            yaml_content: Raw YAML text (single or multi-document).

        Returns:
            A populated ``TrustGraph``.
        """
        self._edge_counter = 0
        graph = TrustGraph()

        docs = list(self._iter_docs(yaml_content))
        resources = list(self._flatten_resources(docs))

        # Pass 1: register all nodes (ServiceAccounts, Roles, ClusterRoles)
        roles_by_id: Dict[str, List[dict]] = {}
        for res in resources:
            kind = res.get("kind", "")
            if kind in ("Role", "ClusterRole"):
                node_id = self._role_node_id(res)
                roles_by_id[node_id] = res.get("rules") or []
                self._add_role_node(graph, res)
            elif kind == "ServiceAccount":
                self._add_sa_node(graph, res)

        # Pass 2: process bindings and derive resource edges
        for res in resources:
            kind = res.get("kind", "")
            if kind in ("RoleBinding", "ClusterRoleBinding"):
                self._process_binding(graph, res)

        # Pass 3: infer resource access edges from role rules
        if self._infer_resource_edges:
            for role_id, rules in roles_by_id.items():
                self._infer_edges_from_rules(graph, role_id, rules)

        return graph

    # ------------------------------------------------------------------
    # Node builders
    # ------------------------------------------------------------------

    def _add_role_node(self, graph: TrustGraph, res: dict) -> None:
        node_id = self._role_node_id(res)
        if graph._graph.has_node(node_id):
            return
        name   = res["metadata"]["name"]
        rules  = res.get("rules") or []
        priv   = _KNOWN_PRIVILEGE.get(name, privilege_from_k8s_rules(rules))
        sens   = sensitivity_from_k8s_rules(rules)
        ns     = res.get("metadata", {}).get("namespace", "cluster")
        graph.add_node(NodeMetadata(
            node_id=node_id,
            node_type=NodeType.ROLE,
            name=name,
            privilege_level=priv,
            sensitivity=sens,
            tags={
                "kind": res["kind"],
                "namespace": ns,
                "source": "k8s_rbac",
            },
        ))

    def _add_sa_node(self, graph: TrustGraph, res: dict) -> None:
        node_id = self._sa_node_id(res)
        if graph._graph.has_node(node_id):
            return
        name = res["metadata"]["name"]
        ns   = res["metadata"].get("namespace", "default")
        graph.add_node(NodeMetadata(
            node_id=node_id,
            node_type=NodeType.USER,
            name=f"{ns}/{name}",
            privilege_level=0.3,
            sensitivity=0.4,
            tags={"kind": "ServiceAccount", "namespace": ns, "source": "k8s_rbac"},
        ))

    def _ensure_subject_node(
        self, graph: TrustGraph, kind: str, name: str, namespace: str = "cluster"
    ) -> str:
        """Return node_id, creating the node if absent."""
        if kind == "ServiceAccount":
            node_id = f"sa:{namespace}:{name}"
            ntype = NodeType.USER
            label = f"{namespace}/{name}"
        elif kind == "User":
            node_id = f"k8s:user:{name}"
            ntype = NodeType.USER
            label = name
        else:  # Group
            node_id = f"k8s:group:{name}"
            ntype = NodeType.WORKLOAD
            label = name

        if not graph._graph.has_node(node_id):
            priv = 0.85 if name in ("system:masters", "cluster-admin") else 0.3
            graph.add_node(NodeMetadata(
                node_id=node_id,
                node_type=ntype,
                name=label,
                privilege_level=priv,
                sensitivity=0.5 if priv > 0.5 else 0.3,
                tags={"kind": kind, "source": "k8s_rbac"},
            ))
        return node_id

    def _ensure_resource_node(
        self, graph: TrustGraph, node_id: str, label: str, ntype: NodeType,
        priv: float, sens: float,
    ) -> None:
        if not graph._graph.has_node(node_id):
            graph.add_node(NodeMetadata(
                node_id=node_id,
                node_type=ntype,
                name=label,
                privilege_level=priv,
                sensitivity=sens,
                tags={"source": "k8s_rbac_derived"},
            ))

    # ------------------------------------------------------------------
    # Binding processing
    # ------------------------------------------------------------------

    def _process_binding(self, graph: TrustGraph, res: dict) -> None:
        """Create subject → role edges from a (Cluster)RoleBinding."""
        role_ref = res.get("roleRef", {})
        role_kind = role_ref.get("kind", "ClusterRole")
        role_name = role_ref.get("name", "")
        role_ns   = res.get("metadata", {}).get("namespace", "cluster")

        # Build role node_id
        if role_kind == "ClusterRole":
            role_id = f"clusterrole:{role_name}"
        else:
            role_id = f"role:{role_ns}:{role_name}"

        # Ensure the role node exists even if we didn't see a Role resource
        if not graph._graph.has_node(role_id):
            priv = _KNOWN_PRIVILEGE.get(role_name, 0.5)
            graph.add_node(NodeMetadata(
                node_id=role_id,
                node_type=NodeType.ROLE,
                name=role_name,
                privilege_level=priv,
                sensitivity=0.5,
                tags={"kind": role_kind, "source": "k8s_rbac_binding"},
            ))

        # Compute edge weight from role privilege
        role_priv = graph._graph.nodes[role_id]["metadata"].privilege_level
        weight = round(min(1.0, role_priv + 0.05), 4)
        is_cluster = res["kind"] == "ClusterRoleBinding"
        depth = 5 if is_cluster else 3

        for subj in res.get("subjects") or []:
            s_kind = subj.get("kind", "User")
            s_name = subj.get("name", "")
            s_ns   = subj.get("namespace", role_ns)
            subj_id = self._ensure_subject_node(graph, s_kind, s_name, s_ns)
            self._add_edge(graph, subj_id, role_id,
                           EdgeType.ASSUME_ROLE, weight, depth)

    # ------------------------------------------------------------------
    # Derived resource edges from role rules
    # ------------------------------------------------------------------

    def _infer_edges_from_rules(
        self, graph: TrustGraph, role_id: str, rules: List[dict]
    ) -> None:
        """Add SECRET_READ / TOKEN_MINT / ASSUME_ROLE edges based on rules."""
        all_resources: set = set()
        all_verbs: set     = set()
        for rule in (rules or []):
            all_resources.update(rule.get("resources", []))
            all_verbs.update(rule.get("verbs", []))

        # Wildcard resource with write access → role can escalate to anything
        if "*" in all_resources and ("*" in all_verbs or "create" in all_verbs):
            target_id = "k8s:rbac:*"
            self._ensure_resource_node(graph, target_id, "k8s-cluster-wildcard",
                                       NodeType.ROLE, 1.0, 1.0)
            self._add_edge(graph, role_id, target_id, EdgeType.ASSUME_ROLE, 0.95, 6)
            return

        for resource, (etype, target_id, weight) in _RESOURCE_EDGE_MAP.items():
            if resource not in all_resources:
                continue
            # Only create the edge if relevant verbs are present
            read_edge = etype in (EdgeType.SECRET_READ,)
            if read_edge and not (all_verbs & {"get", "list", "watch", "*"}):
                continue
            if not read_edge and not (
                all_verbs & {"create", "get", "*", "update", "patch"}
            ):
                continue

            ntype = NodeType.SECRET if etype == EdgeType.SECRET_READ else NodeType.WORKLOAD
            sens  = 0.9 if etype == EdgeType.SECRET_READ else 0.7
            self._ensure_resource_node(graph, target_id, target_id, ntype, 0.5, sens)
            self._add_edge(graph, role_id, target_id, etype, weight, depth=2)

    # ------------------------------------------------------------------
    # Edge helper
    # ------------------------------------------------------------------

    def _add_edge(
        self,
        graph: TrustGraph,
        src: str,
        tgt: str,
        edge_type: EdgeType,
        weight: float,
        depth: int = 3,
    ) -> None:
        if src == tgt:
            return
        if graph._graph.has_edge(src, tgt):
            existing = graph._graph[src][tgt].get("weight", 0.0)
            if weight <= existing:
                return
        self._edge_counter += 1
        graph.add_edge(src, tgt, EdgeMetadata(
            edge_id=f"k8s-e{self._edge_counter:04d}",
            edge_type=edge_type,
            weight=weight,
            delegation_depth_limit=depth,
            tags={"source": "k8s_rbac"},
        ))

    # ------------------------------------------------------------------
    # Node ID helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _role_node_id(res: dict) -> str:
        name = res["metadata"]["name"]
        ns   = res.get("metadata", {}).get("namespace")
        if res["kind"] == "ClusterRole" or not ns:
            return f"clusterrole:{name}"
        return f"role:{ns}:{name}"

    @staticmethod
    def _sa_node_id(res: dict) -> str:
        name = res["metadata"]["name"]
        ns   = res.get("metadata", {}).get("namespace", "default")
        return f"sa:{ns}:{name}"

    # ------------------------------------------------------------------
    # YAML parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_docs(yaml_content: str) -> Iterator[dict]:
        """Yield each non-empty YAML document from a multi-doc string."""
        for doc in yaml.safe_load_all(yaml_content):
            if doc and isinstance(doc, dict):
                yield doc

    @staticmethod
    def _flatten_resources(docs: List[dict]) -> Iterator[dict]:
        """Unwrap Kubernetes List wrappers and yield individual resources."""
        for doc in docs:
            if doc.get("kind") == "List":
                for item in doc.get("items", []):
                    if item:
                        yield item
            else:
                yield doc
