"""AWS Account Authorization Details loader.

Parses the output of ``aws iam get-account-authorization-details`` into a
TrustField ``TrustGraph``.

Input format (keys are optional but at least one must be present):
    {
        "UserDetailList":  [...],
        "GroupDetailList": [...],
        "RoleDetailList":  [...],
        "Policies":        [...]
    }

Graph construction:
    - Each IAM user   → USER node
    - Each IAM group  → ROLE node (groups act as permission bundles)
    - Each IAM role   → ROLE node
    - User ∈ Group    → AUTHENTICATE_AS edge (user → group)
    - Role trust doc  → ASSUME_ROLE edges (principal → role)
    - Permission docs → AUTHENTICATE_AS / SECRET_READ / DEPLOY_TO / TOKEN_MINT edges
                        (subject → resource)
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph

from ._common import (
    arn_to_node_id,
    dominant_edge_type,
    edge_weight_from_statement,
    node_type_from_arn,
    privilege_from_aws_actions,
    sensitivity_from_arn,
)


def detect_iam_format(data: dict) -> str:
    """Auto-detect the format of an IAM JSON document.

    Returns one of:
        ``"account_auth_dump"``  — ``aws iam get-account-authorization-details``
        ``"policy_doc"``         — bare IAM policy ``{Version, Statement}``
        ``"mamip_policy"``       — MAMIP / Console export wrapper ``{PolicyVersion: {Document}}``
        ``"role_bundle"``        — TrustField role bundle ``{RoleName, TrustPolicy}``
        ``"k8s_rbac"``           — Kubernetes RBAC ``{apiVersion, kind}``
        ``"terraform_plan"``     — Terraform plan ``{resource_changes}`` or ``{planned_values}``
        ``"unknown"``            — unrecognised
    """
    if not isinstance(data, dict):
        return "unknown"

    keys = set(data.keys())

    # Full account dump (most specific — check first)
    if keys & {"UserDetailList", "RoleDetailList", "GroupDetailList", "Policies"}:
        return "account_auth_dump"

    # Kubernetes RBAC
    if "apiVersion" in data and "kind" in data:
        return "k8s_rbac"

    # Terraform plan
    if "resource_changes" in data or "planned_values" in data:
        return "terraform_plan"

    # TrustField role bundle
    if "RoleName" in data or "TrustPolicy" in data:
        return "role_bundle"

    # MAMIP / Console export wrapper
    if "PolicyVersion" in data and "Document" in data.get("PolicyVersion", {}):
        return "mamip_policy"

    # Bare policy document
    if "Statement" in data:
        return "policy_doc"

    return "unknown"


class AccountAuthorizationLoader:
    """Loads an AWS account authorization details dump into a TrustGraph.

    Usage::

        loader = AccountAuthorizationLoader()
        graph  = loader.load_file("account_dump.json")
        # or
        graph  = loader.load_dict(parsed_json)
    """

    def __init__(self, default_depth_limit: int = 3) -> None:
        self._default_depth = default_depth_limit
        self._edge_counter  = 0
        # ARN → bare policy document (populated from Policies list)
        self._policy_index: Dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_file(self, path: Union[str, Path]) -> TrustGraph:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.load_dict(data)

    def load_dict(self, data: dict) -> TrustGraph:
        self._edge_counter = 0
        self._policy_index = {}
        graph = TrustGraph()

        # Build managed-policy document index first
        for policy in data.get("Policies", []):
            arn = policy.get("Arn", "")
            if not arn:
                continue
            for version in policy.get("PolicyVersionList", []):
                if version.get("IsDefaultVersion"):
                    doc = version.get("Document", {})
                    # AWS URL-encodes the Document when returned from the API
                    if isinstance(doc, str):
                        doc = json.loads(urllib.parse.unquote(doc))
                    self._policy_index[arn] = doc
                    break

        # Process principals
        self._process_users(graph,  data.get("UserDetailList",  []))
        self._process_groups(graph, data.get("GroupDetailList", []))
        self._process_roles(graph,  data.get("RoleDetailList",  []))

        return graph

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def _process_users(self, graph: TrustGraph, users: list) -> None:
        for user in users:
            arn  = user.get("Arn", "")
            name = user.get("UserName", arn_to_node_id(arn) if arn else "unknown-user")
            uid  = arn_to_node_id(arn) if arn else f"iam:user:{name}"

            priv = self._priv_from_policy_list(
                user.get("UserPolicyList", []),
                user.get("AttachedManagedPolicies", []),
            )
            self._ensure_node(graph, uid, arn or uid, NodeType.USER, priv)

            # User → group membership (AUTHENTICATE_AS edge)
            for group_name in user.get("GroupList", []):
                gid = f"iam:group:{group_name}"
                self._ensure_node(graph, gid, gid, NodeType.ROLE, 0.4)
                self._add_edge(graph, uid, gid, EdgeType.AUTHENTICATE_AS, 0.5)

            # Inline user policies
            for inline in user.get("UserPolicyList", []):
                self._apply_policy_doc(graph, inline.get("PolicyDocument", {}), uid, arn or uid)

            # Attached managed policies
            for attached in user.get("AttachedManagedPolicies", []):
                doc = self._policy_index.get(attached.get("PolicyArn", ""), {})
                if doc:
                    self._apply_policy_doc(graph, doc, uid, arn or uid)

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def _process_groups(self, graph: TrustGraph, groups: list) -> None:
        for group in groups:
            arn   = group.get("Arn", "")
            name  = group.get("GroupName", "unknown-group")
            gid   = f"iam:group:{name}"

            priv = self._priv_from_policy_list(
                group.get("GroupPolicyList", []),
                group.get("AttachedManagedPolicies", []),
            )
            # Ensure node (may already exist from user membership edges above)
            if not graph._graph.has_node(gid):
                self._ensure_node(graph, gid, arn or gid, NodeType.ROLE, priv)
            else:
                # Update privilege if we have better info now
                graph._graph.nodes[gid]["metadata"].privilege_level = priv

            for inline in group.get("GroupPolicyList", []):
                self._apply_policy_doc(graph, inline.get("PolicyDocument", {}), gid, arn or gid)
            for attached in group.get("AttachedManagedPolicies", []):
                doc = self._policy_index.get(attached.get("PolicyArn", ""), {})
                if doc:
                    self._apply_policy_doc(graph, doc, gid, arn or gid)

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def _process_roles(self, graph: TrustGraph, roles: list) -> None:
        for role in roles:
            arn  = role.get("Arn", "")
            name = role.get("RoleName", "unknown-role")
            rid  = arn_to_node_id(arn) if arn else f"iam:role:{name}"

            priv = self._priv_from_policy_list(
                role.get("RolePolicyList", []),
                role.get("AttachedManagedPolicies", []),
            )
            self._ensure_node(graph, rid, arn or rid, NodeType.ROLE, priv)

            # Trust policy: who can assume this role
            trust_doc = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust_doc, str):
                trust_doc = json.loads(urllib.parse.unquote(trust_doc))
            if trust_doc:
                self._apply_trust_policy(graph, trust_doc, rid)

            # Inline role policies
            for inline in role.get("RolePolicyList", []):
                self._apply_policy_doc(graph, inline.get("PolicyDocument", {}), rid, arn or rid)

            # Attached managed policies
            for attached in role.get("AttachedManagedPolicies", []):
                doc = self._policy_index.get(attached.get("PolicyArn", ""), {})
                if doc:
                    self._apply_policy_doc(graph, doc, rid, arn or rid)

    # ------------------------------------------------------------------
    # Policy processing
    # ------------------------------------------------------------------

    def _apply_trust_policy(self, graph: TrustGraph, doc: dict, subject_id: str) -> None:
        """Process a role trust policy — creates principal → role edges."""
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            principal_field = stmt.get("Principal")
            if not principal_field:
                continue

            actions = self._norm_list(stmt.get("Action", "sts:AssumeRole"))
            edge_type = dominant_edge_type(actions)
            weight    = edge_weight_from_statement(stmt, actions)

            for principal_arn in self._extract_principals(principal_field):
                pid = arn_to_node_id(principal_arn)
                if pid == subject_id:
                    continue
                self._ensure_node(graph, pid, principal_arn)
                self._add_edge(graph, pid, subject_id, edge_type, weight,
                               conditions=stmt.get("Condition", {}))

    def _apply_policy_doc(self, graph: TrustGraph, doc: dict,
                           subject_id: str, subject_arn: str) -> None:
        """Process an identity-based policy — creates subject → resource edges."""
        if isinstance(doc, str):
            try:
                doc = json.loads(urllib.parse.unquote(doc))
            except Exception:
                return

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            if "Principal" in stmt:
                # This is a trust-style statement embedded in a permission policy — skip
                continue

            actions   = self._norm_list(stmt.get("Action", "*"))
            resources = self._norm_list(stmt.get("Resource", "*"))
            edge_type = dominant_edge_type(actions)
            weight    = edge_weight_from_statement(stmt, actions)

            for res_arn in resources:
                if res_arn == "*":
                    rid = "aws:resource:wildcard"
                    if not graph._graph.has_node(rid):
                        graph.add_node(NodeMetadata(
                            node_id=rid,
                            node_type=NodeType.SECRET,
                            name="* (wildcard)",
                            privilege_level=1.0,
                            sensitivity=1.0,
                            tags={"source": "aws_iam_wildcard"},
                        ))
                else:
                    rid = arn_to_node_id(res_arn)
                    self._ensure_node(graph, rid, res_arn)
                self._add_edge(graph, subject_id, rid, edge_type, weight,
                               conditions=stmt.get("Condition", {}))

    # ------------------------------------------------------------------
    # Privilege estimation
    # ------------------------------------------------------------------

    def _priv_from_policy_list(self, inline_list: list, attached_list: list) -> float:
        """Estimate privilege from policy names/counts without parsing full docs."""
        from ._common import privilege_from_aws_actions
        high_priv_keywords = ("admin", "poweruser", "fullaccess", "administrator",
                               "iam", "root", "sudo", "owner")
        all_names = (
            [p.get("PolicyName", "") for p in inline_list]
            + [p.get("PolicyName", "") for p in attached_list]
        )
        for name in all_names:
            if any(kw in name.lower() for kw in high_priv_keywords):
                return 0.9
        if all_names:
            return 0.5
        return 0.2

    # ------------------------------------------------------------------
    # Node / edge helpers
    # ------------------------------------------------------------------

    def _ensure_node(self, graph: TrustGraph, node_id: str,
                     arn_or_name: str,
                     ntype: Optional[NodeType] = None,
                     priv: Optional[float] = None) -> None:
        if graph._graph.has_node(node_id):
            return
        if ntype is None:
            ntype = node_type_from_arn(arn_or_name)
        if priv is None:
            priv = 0.5 if ntype == NodeType.ROLE else 0.3
        sens  = sensitivity_from_arn(arn_or_name)
        name  = arn_or_name.split("/")[-1].split(":")[-1] or node_id
        graph.add_node(NodeMetadata(
            node_id=node_id,
            node_type=ntype,
            name=name,
            privilege_level=round(min(1.0, max(0.0, priv)), 4),
            sensitivity=round(min(1.0, max(0.0, sens)), 4),
            tags={"arn": arn_or_name, "source": "aws_iam_account_dump"},
        ))

    def _add_edge(self, graph: TrustGraph, src: str, tgt: str,
                  edge_type: EdgeType, weight: float,
                  conditions: Optional[dict] = None) -> None:
        if src == tgt:
            return
        if graph._graph.has_edge(src, tgt):
            existing = graph._graph[src][tgt].get("weight", 0.0)
            if weight <= existing:
                return
        self._edge_counter += 1
        depth_map = {
            EdgeType.ASSUME_ROLE:     6,
            EdgeType.TOKEN_MINT:      3,
            EdgeType.SECRET_READ:     1,
            EdgeType.DEPLOY_TO:       2,
            EdgeType.AUTHENTICATE_AS: 2,
        }
        requires_mfa = conditions is not None and any(
            "mfa" in k.lower() or "multifactor" in k.lower()
            for k in (conditions or {})
        )
        meta = EdgeMetadata(
            edge_id=f"e{self._edge_counter:04d}",
            edge_type=edge_type,
            weight=weight,
            delegation_depth_limit=depth_map.get(edge_type, self._default_depth),
            requires_mfa=requires_mfa,
            is_conditional=bool(conditions),
            conditions=conditions or {},
            tags={"source": "aws_iam_account_dump"},
        )
        graph.add_edge(src, tgt, meta)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _norm_list(val) -> List[str]:
        if isinstance(val, str):
            return [val]
        return list(val) if val else []

    @staticmethod
    def _extract_principals(principal) -> List[str]:
        if principal == "*":
            return ["*"]
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, list):
            return principal
        out = []
        for key in ("AWS", "Service", "Federated"):
            val = principal.get(key, [])
            if isinstance(val, str):
                out.append(val)
            else:
                out.extend(val)
        return out or ["*"]
