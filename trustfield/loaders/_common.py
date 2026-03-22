"""Shared utilities for real-world config loaders.

Provides ARN parsing, action-to-EdgeType mapping, and privilege/sensitivity
scoring used by both the AWS IAM and Kubernetes RBAC loaders.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from trustfield.graph.edge_types import EdgeType
from trustfield.graph.node_types import NodeType

# ---------------------------------------------------------------------------
# AWS action → EdgeType mapping
# ---------------------------------------------------------------------------

# Actions whose primary effect is trust delegation / role assumption
_ASSUME_ROLE_PREFIXES = (
    "sts:assumerole",
    "sts:assumerolewithwebidentity",
    "sts:assumerolewithsaml",
    "sts:tagSession",
)

# Actions whose primary effect is spawning / minting a new token / invocation
_TOKEN_MINT_PREFIXES = (
    "lambda:invoke",
    "lambda:invokeasync",
    "lambda:invokeurl",
    "apigateway:invoke",
    "states:startexecution",
    "states:startsynccexecution",
    "events:put",
    "sqs:sendmessage",
    "sns:publish",
)

# Actions whose primary effect is reading a secret / credential
_SECRET_READ_PREFIXES = (
    "secretsmanager:getsecretvalue",
    "secretsmanager:getrandompassword",
    "ssm:getparameter",
    "ssm:getparameters",
    "ssm:getparametersbypath",
    "ssm:getsecretvalue",
    "kms:decrypt",
    "kms:generatedata",
)

# Actions that deploy workloads
_DEPLOY_PREFIXES = (
    "codedeploy:",
    "codepipeline:",
    "codebuild:",
    "ecr:initiatelayerupload",
    "ecs:updateservice",
    "ecs:registercontainerinstance",
    "eks:",
    "lambda:updatefunctioncode",
    "lambda:createfunction",
    "lambda:publishversion",
    "elasticbeanstalk:updateenvironment",
    "cloudformation:create",
    "cloudformation:update",
    "cloudformation:execute",
)


def action_to_edge_type(action: str) -> EdgeType:
    """Map a single IAM action string to the most appropriate EdgeType.

    Matching is case-insensitive.  Wildcard actions (``"*"``) are treated
    as ASSUME_ROLE since they imply the highest trust delegation level.

    Args:
        action: An IAM action string, e.g. ``"sts:AssumeRole"`` or ``"s3:GetObject"``.

    Returns:
        The most semantically appropriate ``EdgeType``.
    """
    a = action.lower().strip()
    if a == "*":
        return EdgeType.ASSUME_ROLE
    for prefix in _ASSUME_ROLE_PREFIXES:
        if a.startswith(prefix) or a == prefix:
            return EdgeType.ASSUME_ROLE
    for prefix in _TOKEN_MINT_PREFIXES:
        if a.startswith(prefix):
            return EdgeType.TOKEN_MINT
    for prefix in _SECRET_READ_PREFIXES:
        if a.startswith(prefix):
            return EdgeType.SECRET_READ
    for prefix in _DEPLOY_PREFIXES:
        if a.startswith(prefix):
            return EdgeType.DEPLOY_TO
    return EdgeType.AUTHENTICATE_AS


def dominant_edge_type(actions: List[str]) -> EdgeType:
    """Return the highest-risk EdgeType across a list of actions.

    Priority order: ASSUME_ROLE > SECRET_READ > DEPLOY_TO > TOKEN_MINT > AUTHENTICATE_AS
    """
    priority = {
        EdgeType.ASSUME_ROLE:      5,
        EdgeType.SECRET_READ:      4,
        EdgeType.DEPLOY_TO:        3,
        EdgeType.TOKEN_MINT:       2,
        EdgeType.AUTHENTICATE_AS:  1,
    }
    best = EdgeType.AUTHENTICATE_AS
    for action in actions:
        et = action_to_edge_type(action)
        if priority[et] > priority[best]:
            best = et
    return best


# ---------------------------------------------------------------------------
# AWS ARN parsing
# ---------------------------------------------------------------------------

_ARN_RE = re.compile(
    r"arn:(?P<partition>[^:]+):(?P<service>[^:]*):(?P<region>[^:]*)"
    r":(?P<account>[^:]*):(?P<resource>.+)"
)


def parse_arn(arn: str) -> dict:
    """Parse an AWS ARN into its components.

    Returns a dict with keys: partition, service, region, account, resource_type,
    resource_name.  Returns an empty dict if ``arn`` is not a valid ARN.
    """
    m = _ARN_RE.match(arn)
    if not m:
        return {}
    resource = m.group("resource")
    # resource can be "role/MyRole", "user/Alice", "assumed-role/X/Y", etc.
    parts = resource.split("/", 1)
    resource_type = parts[0]
    resource_name = parts[1] if len(parts) > 1 else parts[0]
    return {
        "partition": m.group("partition"),
        "service": m.group("service"),
        "region": m.group("region"),
        "account": m.group("account"),
        "resource_type": resource_type,
        "resource_name": resource_name,
    }


def arn_to_node_id(arn: str) -> str:
    """Convert an ARN to a compact, stable TrustField node ID.

    Examples::

        arn:aws:iam::123:role/MyRole       → iam:role:MyRole
        arn:aws:iam::123:user/alice        → iam:user:alice
        arn:aws:s3:::my-bucket             → s3:bucket:my-bucket
        arn:aws:lambda:us-east-1:123:function:fn  → lambda:function:fn
        arn:aws:iam::123:root              → iam:root:123
    """
    parsed = parse_arn(arn)
    if not parsed:
        # Not an ARN — return as-is (service principal or literal)
        return arn
    svc = parsed["service"]
    rtype = parsed["resource_type"]
    rname = parsed["resource_name"]
    account = parsed["account"]
    if rtype == "root":
        return f"iam:root:{account}"
    return f"{svc}:{rtype}:{rname}"


def node_type_from_arn(arn: str) -> NodeType:
    """Infer TrustField NodeType from an AWS ARN or service principal."""
    a = arn.lower()
    if ":role/" in a or a.endswith(":role"):
        return NodeType.ROLE
    if ":user/" in a:
        return NodeType.USER
    if "lambda" in a or "apigateway" in a or "states" in a:
        return NodeType.SERVICE
    if "secretsmanager" in a or "/secret:" in a or "ssm" in a or "kms" in a:
        return NodeType.SECRET
    if "ec2" in a or "ecs" in a or "eks" in a or "pod" in a:
        return NodeType.WORKLOAD
    if "codepipeline" in a or "codebuild" in a or "codedeploy" in a:
        return NodeType.DEPLOYMENT
    if "s3" in a:
        return NodeType.SECRET  # treat storage buckets as high-sensitivity
    if ".amazonaws.com" in a:
        return NodeType.SERVICE
    return NodeType.USER


# ---------------------------------------------------------------------------
# Privilege + sensitivity scoring
# ---------------------------------------------------------------------------

# High-privilege action prefixes — any match bumps the score significantly
_HIGH_PRIV_PREFIXES = (
    "iam:", "sts:", "organizations:", "kms:create", "kms:delete",
    "kms:schedule", "ec2:*", "eks:", "ecs:register", "lambda:create",
    "lambda:delete", "lambda:update", "cloudformation:",
)


def privilege_from_aws_actions(actions: List[str]) -> float:
    """Compute a privilege score [0.0, 1.0] from a list of IAM actions.

    Higher = more dangerous / escalation risk.
    """
    normalized = [a.lower() for a in actions]
    if "*" in normalized:
        return 1.0
    if any(a.startswith("iam:") for a in normalized):
        return 0.9
    if any(a.startswith("sts:") for a in normalized):
        return 0.85
    if any(a.startswith(p) for a in normalized for p in _HIGH_PRIV_PREFIXES):
        return 0.75
    if any(a.startswith("secretsmanager:") or a.startswith("ssm:getparam")
           or a.startswith("kms:decrypt") for a in normalized):
        return 0.70
    if any(a.endswith(":*") for a in normalized):
        return 0.65
    write_verbs = ("create", "delete", "update", "put", "write", "invoke",
                   "attach", "detach", "modify", "start", "stop", "reboot")
    if any(v in a for a in normalized for v in write_verbs):
        return 0.5
    return 0.25


def sensitivity_from_arn(arn: str) -> float:
    """Estimate sensitivity of a resource from its ARN."""
    a = arn.lower()
    if "secretsmanager" in a or "ssm" in a or "kms" in a:
        return 0.9
    if ":role/" in a or "iam:" in a:
        return 0.8
    if "lambda" in a or "ec2" in a or "eks" in a or "ecs" in a:
        return 0.6
    if "s3" in a:
        return 0.5
    if "logs" in a or "cloudwatch" in a or "cloudtrail" in a:
        return 0.3
    return 0.4


def edge_weight_from_statement(statement: dict, actions: List[str]) -> float:
    """Compute edge weight from an IAM statement.

    Conditions reduce weight (harder to exploit), MFA required reduces further.
    """
    base = privilege_from_aws_actions(actions)
    conditions = statement.get("Condition", {})
    if conditions:
        base *= 0.8
    # MFA condition: aws:MultiFactorAuthPresent
    if any("multifactorauthpresent" in str(k).lower() or "mfa" in str(k).lower()
           for k in conditions):
        base *= 0.7
    return round(min(1.0, max(0.05, base)), 4)


# ---------------------------------------------------------------------------
# Kubernetes privilege scoring
# ---------------------------------------------------------------------------

_K8S_SENSITIVE_RESOURCES = {
    "secrets", "serviceaccounts/token",
    "clusterrolebindings", "rolebindings",
    "clusterroles", "roles",
}

_K8S_EXEC_RESOURCES = {"pods/exec", "pods/attach", "pods/portforward"}

_K8S_WRITE_VERBS = {"create", "delete", "deletecollection", "update", "patch", "*"}
_K8S_READ_VERBS  = {"get", "list", "watch"}


def privilege_from_k8s_rules(rules: Optional[List[dict]]) -> float:
    """Compute privilege score [0.0, 1.0] from Kubernetes RBAC rules."""
    if not rules:
        return 0.1
    all_verbs: set = set()
    all_resources: set = set()
    for rule in rules:
        all_verbs.update(rule.get("verbs", []))
        all_resources.update(rule.get("resources", []))
        # nonResourceURLs are lower privilege
    if "*" in all_verbs and "*" in all_resources:
        return 1.0
    if "*" in all_verbs:
        return 0.9
    if all_resources & _K8S_SENSITIVE_RESOURCES and all_verbs & _K8S_WRITE_VERBS:
        return 0.85
    if all_resources & _K8S_EXEC_RESOURCES:
        return 0.80
    if all_resources & _K8S_SENSITIVE_RESOURCES:
        return 0.70
    if all_verbs & _K8S_WRITE_VERBS:
        return 0.55
    return 0.25


def sensitivity_from_k8s_rules(rules: Optional[List[dict]]) -> float:
    """Estimate sensitivity from what resources a K8s role can access."""
    if not rules:
        return 0.1
    all_resources: set = set()
    for rule in rules:
        all_resources.update(rule.get("resources", []))
    if "*" in all_resources:
        return 0.9
    if all_resources & _K8S_SENSITIVE_RESOURCES:
        return 0.8
    if all_resources & _K8S_EXEC_RESOURCES:
        return 0.75
    if any(r in all_resources for r in ("nodes", "persistentvolumes")):
        return 0.6
    return 0.4
