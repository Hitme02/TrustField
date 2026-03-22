"""AWS IAM policy loader — parses IAM JSON documents into TrustGraph.

Supported input formats
-----------------------
1. **Bare policy document**
   ``{"Version": "...", "Statement": [...]}``

2. **MAMIP / AWS Console export wrapper**
   ``{"PolicyVersion": {"Document": {...}}}``

3. **Role configuration bundle** (TrustField extended format)
   ``{"RoleName": "...", "RoleArn": "...", "TrustPolicy": {...},
      "PermissionPolicies": [{"PolicyName": "...", "Document": {...}}]}``

Graph construction rules
------------------------
Trust policy statement (has ``Principal`` field):
  → Creates an ASSUME_ROLE edge: principal → subject_node

Permission policy statement (no ``Principal`` field):
  → Classifies the action set into an EdgeType
  → Creates an edge: subject_node → resource_node
  → Edge weight is reduced by conditions; MFA conditions reduce further

Node privilege and sensitivity are derived from the actions/resources each
node is exposed to across all statements.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph

from ._common import (
    action_to_edge_type,
    arn_to_node_id,
    dominant_edge_type,
    edge_weight_from_statement,
    node_type_from_arn,
    privilege_from_aws_actions,
    sensitivity_from_arn,
)

# Sentinel node ID used when a resource wildcard "*" appears
_WILDCARD_RESOURCE_ID = "aws:resource:wildcard"


class IAMPolicyLoader:
    """Parses AWS IAM JSON policy documents into a TrustField ``TrustGraph``.

    Args:
        default_depth_limit: Default ``delegation_depth_limit`` for edges
            whose action type does not imply a specific depth.

    Example::

        loader = IAMPolicyLoader()

        # From a file
        graph = loader.load_file(
            "tests/fixtures/aws/lambda_execution_role.json"
        )

        # From a dict (bare policy document)
        graph = loader.load_dict(
            policy_doc,
            subject_id="iam:role:my-role",
            subject_arn="arn:aws:iam::123:role/my-role",
        )
    """

    # Edge depth limits by type
    _DEPTH_BY_EDGE_TYPE: Dict[EdgeType, int] = {
        EdgeType.ASSUME_ROLE:     6,
        EdgeType.TOKEN_MINT:      3,
        EdgeType.SECRET_READ:     1,
        EdgeType.DEPLOY_TO:       2,
        EdgeType.AUTHENTICATE_AS: 2,
    }

    def __init__(self, default_depth_limit: int = 3) -> None:
        self._default_depth = default_depth_limit
        self._edge_counter = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_file(
        self,
        path: Union[str, Path],
        subject_id: Optional[str] = None,
        subject_arn: Optional[str] = None,
    ) -> TrustGraph:
        """Load a TrustGraph from a JSON file.

        Args:
            path: Path to the JSON file.
            subject_id: Node ID of the entity this policy is attached to.
                If None, inferred from the file content or set to a default.
            subject_arn: Full ARN of the subject (used to determine NodeType
                and privilege level when subject_id is not given).

        Returns:
            A populated ``TrustGraph``.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.load_dict(data, subject_id=subject_id, subject_arn=subject_arn)

    def load_dict(
        self,
        data: dict,
        subject_id: Optional[str] = None,
        subject_arn: Optional[str] = None,
    ) -> TrustGraph:
        """Load a TrustGraph from a parsed JSON dict.

        Auto-detects format (bare policy document, MAMIP wrapper, or role
        configuration bundle).

        Args:
            data: Parsed JSON dict in any supported format.
            subject_id: Node ID of the principal this policy is attached to.
            subject_arn: Full ARN of the principal.

        Returns:
            A populated ``TrustGraph``.
        """
        self._edge_counter = 0
        graph = TrustGraph()

        # --- Detect format ---
        if "RoleName" in data or "TrustPolicy" in data:
            return self._load_role_config(data, graph)

        doc = self._unwrap_document(data)
        if not doc:
            return graph

        # Resolve subject node
        sid, sarn = self._resolve_subject(
            doc, subject_id, subject_arn, data.get("_source_policy_name", "")
        )
        self._ensure_node(graph, sid, sarn or sid)

        self._process_document(graph, doc, sid, sarn or sid)
        return graph

    # ------------------------------------------------------------------
    # Role config format
    # ------------------------------------------------------------------

    def _load_role_config(self, data: dict, graph: TrustGraph) -> TrustGraph:
        role_arn  = data.get("RoleArn", "")
        role_name = data.get("RoleName", "unknown-role")
        role_id   = arn_to_node_id(role_arn) if role_arn else f"iam:role:{role_name}"

        priv = 0.5  # will be raised by permission policy analysis
        graph.add_node(NodeMetadata(
            node_id=role_id,
            node_type=NodeType.ROLE,
            name=role_name,
            privilege_level=priv,
            sensitivity=0.6,
            tags={"arn": role_arn, "source": "aws_iam_role_config"},
        ))

        # --- Trust policy: who can assume this role ---
        trust_doc = data.get("TrustPolicy", {})
        if trust_doc:
            self._process_document(graph, trust_doc, role_id, role_id,
                                   is_trust_policy=True)

        # --- Permission policies: what this role can do ---
        for policy in data.get("PermissionPolicies", []):
            doc = self._unwrap_document(policy.get("Document", {}))
            if doc:
                self._process_document(graph, doc, role_id, role_id)

        # Recompute role privilege from all outgoing edges
        self._refresh_node_privilege(graph, role_id)
        return graph

    # ------------------------------------------------------------------
    # Document processing
    # ------------------------------------------------------------------

    def _process_document(
        self,
        graph: TrustGraph,
        doc: dict,
        subject_id: str,
        subject_arn: str,
        is_trust_policy: bool = False,
    ) -> None:
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            if "Principal" in stmt:
                # Trust statement: someone can access/assume this subject
                self._process_trust_statement(graph, stmt, subject_id, subject_arn)
            else:
                # Permission statement: subject can act on resources
                self._process_permission_statement(graph, stmt, subject_id)

    def _process_trust_statement(
        self,
        graph: TrustGraph,
        stmt: dict,
        subject_id: str,
        subject_arn: str,
    ) -> None:
        """Process a resource-based (trust) policy statement.

        Creates edges: principal → subject (ASSUME_ROLE or appropriate type).
        """
        actions = self._normalise_actions(stmt.get("Action", "sts:AssumeRole"))
        edge_type = dominant_edge_type(actions)
        weight = edge_weight_from_statement(stmt, actions)
        principals = self._extract_principals(stmt["Principal"])

        for principal_arn in principals:
            pid = arn_to_node_id(principal_arn)
            self._ensure_node(graph, pid, principal_arn)
            self._add_edge(graph, pid, subject_id, edge_type, weight,
                           is_conditional=bool(stmt.get("Condition")),
                           conditions=stmt.get("Condition", {}))

    def _process_permission_statement(
        self,
        graph: TrustGraph,
        stmt: dict,
        subject_id: str,
    ) -> None:
        """Process an identity-based permission statement.

        Creates edges: subject → resource (typed by action).
        """
        actions = self._normalise_actions(stmt.get("Action", "*"))
        resources = self._normalise_resources(stmt.get("Resource", "*"))
        edge_type = dominant_edge_type(actions)
        weight = edge_weight_from_statement(stmt, actions)

        for resource_arn in resources:
            rid = arn_to_node_id(resource_arn) if resource_arn != "*" else _WILDCARD_RESOURCE_ID
            self._ensure_node(graph, rid, resource_arn)
            self._add_edge(graph, subject_id, rid, edge_type, weight,
                           is_conditional=bool(stmt.get("Condition")),
                           conditions=stmt.get("Condition", {}))

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def _ensure_node(self, graph: TrustGraph, node_id: str, arn_or_name: str) -> None:
        """Add a node to the graph if it does not already exist."""
        if graph._graph.has_node(node_id):
            return
        ntype = node_type_from_arn(arn_or_name)
        priv  = 0.5 if ntype == NodeType.ROLE else 0.3
        sens  = sensitivity_from_arn(arn_or_name)
        name  = arn_or_name.split("/")[-1].split(":")[-1] or node_id
        graph.add_node(NodeMetadata(
            node_id=node_id,
            node_type=ntype,
            name=name,
            privilege_level=priv,
            sensitivity=sens,
            tags={"arn": arn_or_name, "source": "aws_iam"},
        ))

    def _refresh_node_privilege(self, graph: TrustGraph, node_id: str) -> None:
        """Recalculate a node's privilege from its outgoing edge weights."""
        if not graph._graph.has_node(node_id):
            return
        out_weights = [
            graph._graph[node_id][tgt].get("weight", 0.0)
            for tgt in graph._graph.successors(node_id)
        ]
        if out_weights:
            new_priv = round(max(out_weights), 4)
            graph._graph.nodes[node_id]["metadata"].privilege_level = new_priv

    # ------------------------------------------------------------------
    # Edge management
    # ------------------------------------------------------------------

    def _add_edge(
        self,
        graph: TrustGraph,
        src: str,
        tgt: str,
        edge_type: EdgeType,
        weight: float,
        is_conditional: bool = False,
        conditions: Optional[dict] = None,
    ) -> None:
        if src == tgt:
            return
        if graph._graph.has_edge(src, tgt):
            # Keep the highest-weight edge
            existing = graph._graph[src][tgt].get("weight", 0.0)
            if weight <= existing:
                return
        self._edge_counter += 1
        depth = self._DEPTH_BY_EDGE_TYPE.get(edge_type, self._default_depth)
        requires_mfa = conditions is not None and any(
            "mfa" in k.lower() or "multifactor" in k.lower()
            for k in (conditions or {})
        )
        meta = EdgeMetadata(
            edge_id=f"e{self._edge_counter:04d}",
            edge_type=edge_type,
            weight=weight,
            delegation_depth_limit=depth,
            requires_mfa=requires_mfa,
            is_conditional=is_conditional,
            conditions=conditions or {},
            tags={"source": "aws_iam"},
        )
        graph.add_edge(src, tgt, meta)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unwrap_document(data: dict) -> Optional[dict]:
        """Strip MAMIP / Console-export wrappers to get the bare policy doc."""
        if "Statement" in data:
            return data
        if "PolicyVersion" in data:
            return data["PolicyVersion"].get("Document")
        if "Document" in data:
            return data["Document"]
        return None

    @staticmethod
    def _resolve_subject(
        doc: dict,
        subject_id: Optional[str],
        subject_arn: Optional[str],
        policy_name: str,
    ) -> tuple:
        if subject_id:
            return subject_id, subject_arn or subject_id
        if subject_arn:
            return arn_to_node_id(subject_arn), subject_arn
        name = policy_name or "policy-subject"
        return f"iam:policy:{name}", name

    @staticmethod
    def _normalise_actions(actions) -> List[str]:
        if isinstance(actions, str):
            return [actions]
        return list(actions)

    @staticmethod
    def _normalise_resources(resources) -> List[str]:
        if isinstance(resources, str):
            return [resources]
        return list(resources)

    @staticmethod
    def _extract_principals(principal) -> List[str]:
        """Flatten a Principal value to a list of ARN / service strings."""
        if principal == "*":
            return ["*"]
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, list):
            return principal
        # Dict: {"AWS": [...], "Service": [...], "Federated": [...]}
        out = []
        for key in ("AWS", "Service", "Federated"):
            val = principal.get(key, [])
            if isinstance(val, str):
                out.append(val)
            else:
                out.extend(val)
        return out if out else ["*"]
