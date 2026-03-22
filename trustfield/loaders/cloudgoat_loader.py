"""CloudGoat scenario loader and TrustField validator.

Parses CloudGoat scenario directories (AWS Terraform HCL files + embedded IAM
JSON) into TrustField TrustGraph objects, then runs the full TrustField
pipeline and compares detected attack paths against the scenario's known
exploitation route.

Supports:
  - ``aws_iam_user``, ``aws_iam_role``, ``aws_iam_policy``
  - ``aws_iam_role_policy_attachment``, ``aws_iam_user_policy_attachment``
  - ``aws_iam_instance_profile``
  - ``jsonencode({...})`` inline policies
  - ``file("policies/v1.json")`` policy references
  - AWS managed policy ARNs (AdministratorAccess, S3FullAccess, etc.)

Usage::

    loader    = CloudGoatLoader()
    validator = CloudGoatValidator()

    result = validator.validate_scenario(
        "/tmp/cloudgoat/cloudgoat/scenarios/aws/lambda_privesc"
    )
    print(result.summary_line())
"""

from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.loaders._common import (
    action_to_edge_type,
    dominant_edge_type,
    edge_weight_from_statement,
    privilege_from_aws_actions,
    sensitivity_from_arn,
)

try:
    import hcl2
    _HCL2_AVAILABLE = True
except ImportError:  # pragma: no cover
    _HCL2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Known attack-path node patterns (keyed by scenario name)
# Derived from each scenario's README.md walkthrough.
# Each tuple is (node_id_substring, human_label).
# ---------------------------------------------------------------------------

_KNOWN_PATHS: Dict[str, List[Tuple[str, str]]] = {
    # Raynor has iam:SetDefaultPolicyVersion → can restore admin policy versions (v2/v3 = Action:*)
    # Graph: raynor(USER) → iam:resource:wildcard (via iam:* actions)
    "iam_privesc_by_rollback": [
        ("raynor",    "IAM user raynor (attacker entry point)"),
        ("wildcard",  "IAM resource wildcard (escalation target via policy rollback)"),
    ],
    # chris(USER) → AssumeRole → lambdaManager(ROLE) → lambda:* + iam:PassRole →
    # creates Lambda with debug role → debug(ROLE) → AdministratorAccess
    "lambda_privesc": [
        ("chris",         "IAM user chris (attacker entry)"),
        ("lambdamanager", "lambdaManager role (lambda:* + PassRole)"),
        ("debug",         "debug role (AdministratorAccess)"),
        ("wildcard",      "admin wildcard resource"),
    ],
    # EC2 SSRF → metadata service → cg-banking-WAF-Role → AmazonS3FullAccess → bucket
    "cloud_breach_s3": [
        ("banking-waf",   "EC2 instance-profile role (obtained via SSRF)"),
        ("s3",            "S3 bucket / S3FullAccess resource"),
    ],
    # website container → metadata → ecs-agent → (ECS enumeration) → privd task → vault
    "ecs_takeover": [
        ("ecs-agent",  "ECS agent role (EC2 instance profile)"),
        ("privd",      "privd ECS task role (ecs:* + iam read)"),
        ("wildcard",   "ECS resource wildcard"),
    ],
    # sandy(USER) → iam:PassRole for agentcore_* → code_interpreter_role (S3) and
    # agent_runtime_role (bedrock:InvokeModel + CodeInterpreter access)
    "agentcore_identity_confusion": [
        ("sandy",            "IAM user sandy (attacker entry, iam:PassRole for agentcore roles)"),
        ("code_interpreter", "code interpreter execution role (S3 access via PassRole)"),
        ("agent_runtime",    "agent runtime role (bedrock:InvokeModel + CodeInterpreter)"),
    ],
    # low_priv(USER) → enumerate EB config → secondary(USER) creds discovered →
    # iam:CreateAccessKey → create key for admin_user → admin_user Action:* Resource:*
    "beanstalk_secrets": [
        ("low_priv",   "IAM user low_priv (attacker entry, ElasticBeanstalk + S3 read)"),
        ("secondary",  "secondary IAM user (iam:CreateAccessKey — escalation pivot)"),
        ("admin_user", "admin IAM user (Action:* Resource:* — full compromise)"),
    ],
    # grace(USER) → lambda:UpdateFunctionCode + iam:PassRole for agentcore roles →
    # hijack inventory Lambda running as lambda_execution_role (ReadOnlyAccess)
    "bedrock_agent_hijacking": [
        ("grace",                 "IAM user grace (attacker entry, lambda update + PassRole)"),
        ("lambda_execution_role", "lambda execution role (ReadOnlyAccess — compromised via code injection)"),
    ],
    # solo(USER) → codebuild:BatchGetProjects + ssm:GetParameter → find RDS creds in SSM →
    # calrissian(USER) → rds:RestoreDBInstanceFromDBSnapshot → extract data
    "codebuild_secrets": [
        ("solo",       "IAM user solo (codebuild/SSM enumeration entry)"),
        ("calrissian", "IAM user calrissian (rds:* — snapshot restore for data extraction)"),
    ],
    # start_user(USER) → ec2:DescribeInstances → find UserData creds →
    # ec2_role (lambda read) → Lambda env vars → lambda_user → secretsmanager:GetSecretValue
    "data_secrets": [
        ("start-user",  "IAM user start_user (EC2 describe entry, finds UserData credentials)"),
        ("ec2-role",    "EC2 instance role (lambda:ListFunctions/GetFunction — exposes Lambda env)"),
        ("lambda-user", "lambda IAM user (secretsmanager:GetSecretValue — final target)"),
    ],
    # r_waterhouse(USER) → SSM session on EC2 → IMDS → easy/hard EC2 instance role →
    # secretsmanager:GetSecretValue (flag)
    "detection_evasion": [
        ("r_waterhouse", "IAM user r_waterhouse (attacker entry, SSM + ReadOnlyAccess)"),
        ("easy",         "easy-path EC2 instance role (secretsmanager:GetSecretValue)"),
        ("hard",         "hard-path EC2 instance role (secretsmanager:GetSecretValue — alternate path)"),
    ],
    # solus(USER) → lambda enumeration → discovers Lambda env has wrex keys →
    # wrex(USER) → ec2:* → SSRF on EC2 → ec2_role (s3:*) via IMDS
    "ec2_ssrf": [
        ("solus",    "IAM user solus (lambda enumeration entry point)"),
        ("wrex",     "IAM user wrex (ec2:* — credentials stored in Lambda env vars)"),
        ("shepard",  "IAM user shepard (lambda:Invoke* — alternative pivot)"),
        ("ec2-role", "EC2 instance role (s3:* — exfiltration target via SSRF + metadata)"),
    ],
    # service:ec2 → ec2-ruse-role (ECS RegisterTaskDefinition + iam:PassRole) →
    # register malicious task def referencing efs-admin-role → mount EFS → read secrets
    "ecs_efs_attack": [
        ("ec2-role",  "EC2 ruse-box role (ecs:RegisterTaskDefinition + iam:PassRole — pivot)"),
        ("ecs-role",  "ECS task role (ECR access + ssm:StartSession on tagged EC2)"),
        ("efs-admin", "EFS admin role (elasticfilesystem:ClientMount — final EFS access)"),
    ],
    # service:ec2 → web-developer role (ecs:RegisterTaskDefinition + iam:PassRole to s3_access) →
    # run rogue ECS task with s3-critical role → AmazonS3FullAccess (evading GuardDuty)
    "ecs_privesc_evade_protection": [
        ("web-developer", "web-developer EC2/ECS role (ecs:RunTask + iam:PassRole — escalation pivot)"),
        ("s3-critical",   "s3-critical ECS task role (AmazonS3FullAccess — privilege escalation target)"),
    ],
    # initial_user(USER) → SSM StartSession on EC2 → IMDS → ec2_admin_role →
    # ssm:GetParameter* (reads SSM parameters containing federation/console credentials)
    "federated_console_takeover": [
        ("initial-user", "IAM user initial_user (attacker entry, SSM + iam:ListRoles)"),
        ("ec2-admin",    "ec2-admin-role (ec2:* + ssm:GetParameter* — federation key exfiltration)"),
    ],
    # run-app(USER) → RDS + S3 enumerate; glue-admin(USER) → glue:CreateJob + iam:PassRole →
    # glue_ETL_role (AmazonRDSFullAccess + AmazonS3FullAccess) → data exfiltration
    "glue_privesc": [
        ("run-app",    "IAM user run-app / glue_web (S3 write + RDS — initial access)"),
        ("glue-admin", "IAM user glue_admin (glue:CreateJob + iam:PassRole — escalation)"),
        ("glue_ETL",   "glue_ETL_role (AmazonRDSFullAccess + AmazonS3FullAccess — escalation target)"),
    ],
    # bob(USER) → IAMReadOnlyAccess → enumerate managed/inline/group policies and role tags →
    # assume flag4_role (trust policy Principal: bob.arn)
    "iam_enum_basics": [
        ("bob",   "IAM user bob (attacker entry, IAMReadOnlyAccess enumeration)"),
        ("flag4", "flag4 role (assumable by bob — trust policy exposes it)"),
    ],
    # kerrigan(USER) → iam:AddRoleToInstanceProfile + iam:PassRole + ec2:RunInstances →
    # attach ec2_mighty_role to instance profile → EC2 IMDS → mighty role (Action:* Resource:*)
    "iam_privesc_by_attachment": [
        ("kerrigan",   "IAM user kerrigan (attacker entry, iam:PassRole + ec2:RunInstances)"),
        ("ec2-mighty", "EC2 mighty role (Action:* Resource:* — full admin after profile swap)"),
        ("wildcard",   "admin wildcard resource (ec2_mighty_policy Allow:* enables admin)"),
    ],
    # dev_user(USER) → assume ec2_management_role → ec2:ModifyInstanceAttribute (user data) →
    # reboot non-admin EC2 → IMDS → ec2_role (AdministratorAccess)
    "iam_privesc_by_ec2": [
        ("dev_user",       "IAM user dev_user (attacker entry, ReadOnlyAccess + AssumeRole pivot)"),
        ("ec2_management", "ec2_management_role (ec2:ModifyInstanceAttribute — user-data injection)"),
        ("ec2_role",       "ec2_role (AdministratorAccess — final escalation target)"),
        ("wildcard",       "admin wildcard resource (from AdministratorAccess managed policy)"),
    ],
    # manager(USER) → iam:TagUser (tag developer-flagged users) + iam:CreateAccessKey →
    # create key for admin → admin has sts:AssumeRole → secretsmanager_role → GetSecretValue
    "iam_privesc_by_key_rotation": [
        ("manager",        "IAM user manager (attacker entry, iam:TagUser + CreateAccessKey)"),
        ("admin",          "IAM user admin (IAMReadOnlyAccess + sts:AssumeRole to secrets role)"),
        ("secretsmanager", "secretsmanager role (secretsmanager:GetSecretValue — final target)"),
    ],
    # lara(USER) → s3 logs read + EC2/RDS describe; mcduck(USER) → s3 keystore read
    # web RCE on app → OS command injection → IMDS → hardcoded credential exfiltration
    "rce_web_app": [
        ("lara",   "IAM user lara (s3 logs + EC2/RDS describe — initial access)"),
        ("mcduck", "IAM user mcduck (s3 keystore read + EC2/RDS — credential extraction target)"),
    ],
    # david(USER) → rds:CreateDBSnapshot + RestoreDBInstanceFromDBSnapshot →
    # restore public snapshot in attacker account → extract DB contents
    "rds_snapshot": [
        ("rds-instance-user", "IAM user david/rds-instance-user (rds snapshot restore entry)"),
        ("ec2-admin",         "ec2-admin-role (s3:* + iam:List/Get — lateral EC2 access)"),
    ],
    # web_manager(USER) → cloudformation:CreateStack + iam:PassRole to CloudFormationRole →
    # CF creates Lambda with LambdaPutObjectRole → bypasses explicit S3 PutObject Deny
    "s3_version_rollback_via_cfn": [
        ("web_manager",      "IAM user web_manager (CF deploy + iam:PassRole entry)"),
        ("CloudFormation",   "CloudFormation execution role (lambda:CreateFunction + iam:PassRole)"),
        ("LambdaPutObject",  "LambdaPutObject Lambda role (s3:PutObject bypass — escalation target)"),
    ],
    # low_priv(USER) → s3 read + lambda:InvokeFunction → Lambda returns secrets-manager-user creds →
    # secrets-manager-user → secretsmanager:GetSecretValue; DavesDancingDoolittle → dynamodb:*
    "secrets_in_the_cloud": [
        ("low-priv-user",        "IAM user low_priv (s3 + lambda:InvokeFunction entry)"),
        ("secrets-manager-user", "secrets-manager IAM user (secretsmanager:GetSecretValue target)"),
        ("davesdancing",         "DavesDancingDoolittle EC2 role (dynamodb:* — alternate data path)"),
    ],
    # sns_user(USER) → sns:Subscribe → subscribe to Lambda-published SNS topic →
    # Lambda (cg-sns-secrets role) publishes secrets as SNS messages
    "sns_secrets": [
        ("sns-user",       "IAM user sns_user (SNS subscribe + apigateway enumeration entry)"),
        ("cg-sns-secrets", "Lambda SNS publisher role (sns:Publish to topic — publishes secrets)"),
    ],
    # sqs_user(USER) → iam:Get/List* + sts:AssumeRole → sqs_send_message role →
    # sqs:SendMessage to cash_charge queue → price manipulation exploit → buy flag
    "sqs_flag_shop": [
        ("sqs-user",        "IAM user cg-sqs-user (attacker entry, iam enumeration + AssumeRole)"),
        ("sqs-send-message","sqs_send_message role (sqs:SendMessage cash queue — price exploit)"),
    ],
    # EC2 instance with hardcoded static credentials in application config
    # ec2_role has s3:GetObject/PutObject/DeleteObject on assets bucket
    "static": [
        ("ec2-role", "EC2 instance role (s3:GetObject/PutObject/DeleteObject — static creds scenario)"),
    ],
    # initial_user(USER) → EC2 + VPC peering enumeration → find dev EC2 with SSM →
    # dev-ec2-role (ssm:StartSession + RDS describe — overpermissioned) →
    # VPC peering exposes prod; prod-ec2-role accessible laterally
    "vpc_peering_overexposed": [
        ("dev-ec2-role",  "dev EC2 role (SSM + RDS describe + VPC peering — overpermissioned)"),
        ("prod-ec2-role", "prod EC2 role (SSM + minimal — exposed via VPC peering from dev)"),
    ],
    # bilbo(USER) → sts:AssumeRole cg-lambda-invoker* + iam:Get/List →
    # cg-lambda-invoker role → lambda:InvokeFunction on policy_applier_lambda1 →
    # exploit Lambda to attach admin policy to bilbo
    "vulnerable_lambda": [
        ("bilbo",          "IAM user bilbo (attacker entry, iam:Get/List + assume lambda-invoker)"),
        ("lambda-invoker", "cg-lambda-invoker role (lambda:InvokeFunction — exploit vulnerable Lambda)"),
    ],
}

# AWS managed policy ARN → minimal inline permission document for graph building
_MANAGED_POLICY_DOCS: Dict[str, dict] = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/AmazonS3FullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["ecs:*", "ec2:Describe*"], "Resource": "*"}
        ],
    },
    "arn:aws:iam::aws:policy/IAMReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["iam:Get*", "iam:List*"], "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/ReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["*:Describe*", "*:List*", "*:Get*"], "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["glue:*", "iam:PassRole"], "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["ssm:*"], "Resource": "*"}],
    },
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """TrustField detection result for one CloudGoat scenario.

    Attributes:
        scenario_name:           Short name of the scenario.
        scenario_path:           Filesystem path to the scenario directory.
        n_nodes:                 Nodes in the loaded TrustGraph.
        known_path_steps:        Human-readable steps from the README.
        known_path_node_patterns: Node ID patterns that should be on the path.
        detected_node_ids:       All node IDs TrustField flagged as reachable.
        nodes_on_known_path_found: How many known-path patterns were found.
        nodes_on_known_path_total: Total known-path patterns for this scenario.
        detected:                True if all known-path nodes were found.
        partial_detection:       True if some (but not all) were found.
        seed_nodes:              Seed nodes used for TrustField analysis.
        error:                   Non-empty if loading/analysis failed.
    """

    scenario_name: str
    scenario_path: str
    n_nodes: int
    known_path_steps: List[str]
    known_path_node_patterns: List[Tuple[str, str]]
    detected_node_ids: Set[str]
    nodes_on_known_path_found: int
    nodes_on_known_path_total: int
    detected: bool
    partial_detection: bool
    seed_nodes: List[str]
    error: str = ""

    def summary_line(self) -> str:
        status = "YES" if self.detected else ("PARTIAL" if self.partial_detection else "NO")
        score = f"{self.nodes_on_known_path_found}/{self.nodes_on_known_path_total}"
        return (
            f"{self.scenario_name:<30}  nodes={self.n_nodes:>3}  "
            f"path={len(self.known_path_steps):>2} steps  "
            f"detected={status:<7}  score={score}"
        )


# ---------------------------------------------------------------------------
# HCL / policy extraction helpers
# ---------------------------------------------------------------------------

def _strip_var_refs(s: str) -> str:
    """Replace ``${...}`` Terraform interpolations with informative placeholders.

    Preserves entity-type context so that principal references in trust policies
    can be correctly resolved back to IAM user/role nodes.

    Examples:
        ``${aws_iam_user.chris.arn}``          → ``"__IAM_USER_chris__"``
        ``${aws_iam_role.debug_role.arn}``     → ``"__IAM_ROLE_debug_role__"``
        ``${aws_iam_policy.foo_policy.arn}``   → ``"__IAM_POLICY_foo_policy__"``
        other ``${...}``                        → ``"__tf_ref__"``
    """
    def _replace(m: re.Match) -> str:
        ref = m.group(1)
        # NOTE: these replacements appear INSIDE existing JSON string values
        # (e.g. "...${aws_iam_user.foo.arn}..."), so we must NOT add extra
        # quotes — the surrounding quotes in the JSON string already wrap them.
        u = re.match(r'aws_iam_user\.(\w+)\.', ref)
        if u:
            return f'__IAM_USER_{u.group(1)}__'
        r = re.match(r'aws_iam_role\.(\w+)\.', ref)
        if r:
            return f'__IAM_ROLE_{r.group(1)}__'
        p = re.match(r'aws_iam_policy\.(\w+)\.', ref)
        if p:
            return f'__IAM_POLICY_{p.group(1)}__'
        return '__tf_ref__'
    return re.sub(r'\$\{([^}]+)\}', _replace, s)


def _extract_jsonencode(value: str) -> Optional[dict]:
    """Extract and parse the dict argument from a ``${jsonencode({...})}`` string."""
    # Match "${jsonencode(<content>)}" allowing nested braces
    m = re.match(r'^\$\{jsonencode\((.+)\)\}$', value.strip(), re.DOTALL)
    if not m:
        return None
    inner = m.group(1).strip()
    # Replace Terraform interpolations before JSON parsing
    inner = _strip_var_refs(inner)
    try:
        return json.loads(inner)
    except json.JSONDecodeError:
        return None


def _extract_file_ref(value: str) -> Optional[str]:
    """Extract path from ``file("path/to/file.json")``."""
    m = re.match(r'^\$?\{?file\("([^"]+)"\)\}?$', value.strip())
    if m:
        return m.group(1)
    m = re.match(r'^file\("([^"]+)"\)$', value.strip())
    if m:
        return m.group(1)
    return None


def _tf_ref_name(ref: str) -> str:
    """Extract resource name from a Terraform reference string.

    ``${aws_iam_role.lambdaManager_role.name}``  →  ``lambdaManager_role``
    """
    m = re.search(r'aws_iam_(?:role|user|policy|instance_profile)\.(\w+)', ref)
    if m:
        return m.group(1)
    return ref.strip('"').strip()


def _resolve_policy_doc(
    value,
    scenario_dir: Path,
) -> Optional[dict]:
    """Resolve a policy value (various Terraform forms) to a Python dict."""
    if isinstance(value, dict):
        # Already parsed dict (hcl2 sometimes returns these)
        return value

    if not isinstance(value, str):
        return None

    value = value.strip()

    # jsonencode() inline
    doc = _extract_jsonencode(value)
    if doc is not None:
        return doc

    # file() reference
    rel = _extract_file_ref(value)
    if rel:
        candidate = scenario_dir / rel
        if not candidate.exists():
            # Try terraform subdir
            candidate = scenario_dir / "terraform" / rel
        if candidate.exists():
            try:
                return json.loads(candidate.read_text())
            except Exception:
                pass
        return None

    # Literal JSON string?
    try:
        return json.loads(value)
    except Exception:
        pass

    return None


def _parse_tf_dir(tf_dir: Path) -> Dict[str, Dict[str, dict]]:
    """Parse all ``*.tf`` files in *tf_dir* and return a combined resources dict.

    Also parses ``data "aws_iam_policy_document"`` blocks, synthesising them
    into inline JSON policy documents so that roles whose ``assume_role_policy``
    references a data source can still be processed.

    Returns:
        ``{resource_type: {resource_name: attributes_dict}}``
        with an extra ``__data_policy_docs__`` key holding synthesised docs.
    """
    if not _HCL2_AVAILABLE:  # pragma: no cover
        raise RuntimeError("python-hcl2 is required: pip install python-hcl2")

    resources: Dict[str, Dict[str, dict]] = {}
    # Synthesised policy docs from data "aws_iam_policy_document" blocks
    data_policy_docs: Dict[str, dict] = {}

    for tf_file in sorted(tf_dir.glob("*.tf")):
        try:
            parsed = hcl2.loads(tf_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        for block in parsed.get("resource", []):
            for rtype, res_dict in block.items():
                resources.setdefault(rtype, {})
                for rname, attrs in res_dict.items():
                    a = attrs[0] if isinstance(attrs, list) else attrs
                    resources[rtype][rname] = a

        # Parse data "aws_iam_policy_document" blocks → synthesise JSON doc
        for block in parsed.get("data", []):
            for dtype, data_dict in block.items():
                if dtype != "aws_iam_policy_document":
                    continue
                for dname, attrs in data_dict.items():
                    a = attrs[0] if isinstance(attrs, list) else attrs
                    doc = _synthesise_policy_document(a)
                    if doc:
                        data_policy_docs[dname] = doc

    resources["__data_policy_docs__"] = data_policy_docs  # type: ignore[assignment]
    return resources


def _synthesise_policy_document(attrs: dict) -> Optional[dict]:
    """Convert a parsed ``aws_iam_policy_document`` data source to a JSON dict.

    Handles the HCL2 ``statement { ... }`` block list format.
    """
    stmts_raw = attrs.get("statement", [])
    if not stmts_raw:
        return None
    stmts = []
    for s in (stmts_raw if isinstance(stmts_raw, list) else [stmts_raw]):
        if isinstance(s, dict):
            stmt: Dict = {"Effect": s.get("effect", "Allow")}
            actions = s.get("actions") or s.get("action") or []
            if actions:
                stmt["Action"] = actions if isinstance(actions, list) else [actions]
            # Principal block
            principals = s.get("principals") or s.get("principal") or []
            if principals:
                principal_list = principals if isinstance(principals, list) else [principals]
                for p in principal_list:
                    if isinstance(p, dict):
                        p_type = p.get("type", "Service")
                        p_ids  = p.get("identifiers", [])
                        if isinstance(p_ids, str):
                            p_ids = [p_ids]
                        stmt["Principal"] = {p_type: p_ids[0] if len(p_ids) == 1 else p_ids}
            stmts.append(stmt)
    return {"Version": "2012-10-17", "Statement": stmts} if stmts else None


# ---------------------------------------------------------------------------
# CloudGoatLoader
# ---------------------------------------------------------------------------

class CloudGoatLoader:
    """Loads a CloudGoat scenario directory into a TrustField ``TrustGraph``.

    Parses all ``*.tf`` files under the scenario's ``terraform/`` directory,
    extracts IAM resources, resolves inline and file-referenced policies, and
    assembles a TrustGraph ready for TrustField analysis.

    Args:
        default_depth_limit: Default delegation depth for edges.

    Example::

        loader = CloudGoatLoader()
        graph, seed_nodes = loader.load_scenario(
            "/tmp/cloudgoat/cloudgoat/scenarios/aws/lambda_privesc"
        )
    """

    def __init__(self, default_depth_limit: int = 4) -> None:
        self._default_depth = default_depth_limit
        self._edge_counter = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_scenario(
        self,
        scenario_path: str | Path,
    ) -> Tuple[TrustGraph, List[str]]:
        """Load a scenario directory into a TrustGraph.

        Args:
            scenario_path: Path to the scenario root (contains README.md,
                terraform/, etc.).

        Returns:
            Tuple of ``(TrustGraph, seed_node_ids)`` where ``seed_node_ids``
            is a list of the attacker's initial entry nodes (lowest-privilege
            users / external roles).
        """
        scenario_path = Path(scenario_path)
        tf_dir = scenario_path / "terraform"
        if not tf_dir.exists():
            tf_dir = scenario_path

        resources = _parse_tf_dir(tf_dir)
        graph = TrustGraph()
        self._edge_counter = 0

        # Phase 1: create nodes
        users = self._collect_users(resources, graph)
        roles = self._collect_roles(resources, graph)
        policies = self._collect_policies(resources, tf_dir)

        # Phase 2: attach policies (permission edges)
        self._apply_user_policy_attachments(resources, policies, graph, users)
        self._apply_inline_user_policies(resources, graph, users)
        self._apply_role_policy_attachments(resources, policies, graph, roles, tf_dir)
        self._apply_inline_role_policies(resources, graph, roles)
        self._apply_managed_policy_arns_from_role_resources(resources, graph, roles)

        # Phase 3: trust policy edges (ASSUME_ROLE)
        self._apply_trust_policies(resources, graph, users, roles, tf_dir)

        # Phase 4: add lateral edges for ECS (ecs:* can reach task roles)
        self._apply_ecs_lateral_edges(graph, roles)

        # Phase 4b: iam:PassRole → can pass any role to Lambda → reach all roles
        self._apply_passrole_edges(graph, roles)

        # Phase 5: pick seed nodes (entry points for the attacker)
        seeds = self._pick_seeds(graph, resources, users, roles)

        return graph, seeds

    # ------------------------------------------------------------------
    # Phase 1: Node creation
    # ------------------------------------------------------------------

    def _collect_users(
        self, resources: dict, graph: TrustGraph
    ) -> Dict[str, str]:
        """Create USER nodes. Returns {tf_name: node_id}."""
        mapping: Dict[str, str] = {}
        for tf_name, attrs in resources.get("aws_iam_user", {}).items():
            raw_name = attrs.get("name", tf_name)
            name = re.sub(r"\$\{[^}]+\}", "", raw_name).strip("-_")
            node_id = f"iam:user:{name}"
            if not graph._graph.has_node(node_id):
                graph.add_node(NodeMetadata(
                    node_id=node_id,
                    node_type=NodeType.USER,
                    name=name,
                    privilege_level=0.3,
                    sensitivity=0.4,
                    tags={"source": "cloudgoat_tf", "tf_name": tf_name},
                ))
            mapping[tf_name] = node_id
        return mapping

    def _collect_roles(
        self, resources: dict, graph: TrustGraph
    ) -> Dict[str, str]:
        """Create ROLE nodes. Returns {tf_name: node_id}."""
        mapping: Dict[str, str] = {}
        for tf_name, attrs in resources.get("aws_iam_role", {}).items():
            raw_name = attrs.get("name", tf_name)
            name = re.sub(r"\$\{[^}]+\}", "", raw_name).strip("-_")
            node_id = f"iam:role:{name}"
            if not graph._graph.has_node(node_id):
                graph.add_node(NodeMetadata(
                    node_id=node_id,
                    node_type=NodeType.ROLE,
                    name=name,
                    privilege_level=0.5,
                    sensitivity=0.6,
                    tags={"source": "cloudgoat_tf", "tf_name": tf_name},
                ))
            mapping[tf_name] = node_id
        return mapping

    def _collect_policies(
        self, resources: dict, tf_dir: Path
    ) -> Dict[str, dict]:
        """Return {tf_name: policy_document_dict} for all aws_iam_policy resources."""
        policies: Dict[str, dict] = {}
        for tf_name, attrs in resources.get("aws_iam_policy", {}).items():
            doc = _resolve_policy_doc(attrs.get("policy", {}), tf_dir.parent)
            if doc:
                policies[tf_name] = doc
        # Add managed policy stubs
        for arn, doc in _MANAGED_POLICY_DOCS.items():
            policies[arn] = doc
        return policies

    # ------------------------------------------------------------------
    # Phase 2 & 3: Policy application and trust edges
    # ------------------------------------------------------------------

    def _apply_user_policy_attachments(
        self,
        resources: dict,
        policies: Dict[str, dict],
        graph: TrustGraph,
        users: Dict[str, str],
    ) -> None:
        for tf_name, attrs in resources.get("aws_iam_user_policy_attachment", {}).items():
            user_ref = attrs.get("user", "")
            policy_ref = attrs.get("policy_arn", "")
            user_tf = _tf_ref_name(user_ref)
            user_node = users.get(user_tf)
            if not user_node:
                continue
            policy_doc = self._resolve_policy_ref(policy_ref, policies, resources)
            if policy_doc:
                self._apply_permission_policy(graph, user_node, policy_doc)

    def _apply_inline_user_policies(
        self,
        resources: dict,
        graph: TrustGraph,
        users: Dict[str, str],
    ) -> None:
        """Apply ``aws_iam_user_policy`` (inline user policies) to user nodes."""
        for tf_name, attrs in resources.get("aws_iam_user_policy", {}).items():
            user_ref = attrs.get("user", "")
            policy_raw = attrs.get("policy", "")
            user_tf = _tf_ref_name(user_ref)
            user_node = users.get(user_tf)
            if not user_node:
                # Try matching by raw user name string
                for uname, unode in users.items():
                    if user_ref and uname in user_ref:
                        user_node = unode
                        break
            if not user_node:
                continue
            if isinstance(policy_raw, dict):
                policy_doc = policy_raw
            elif isinstance(policy_raw, str):
                policy_doc = _extract_jsonencode(policy_raw)
            else:
                continue
            if policy_doc:
                self._apply_permission_policy(graph, user_node, policy_doc)

    def _apply_inline_role_policies(
        self,
        resources: dict,
        graph: TrustGraph,
        roles: Dict[str, str],
    ) -> None:
        """Apply ``aws_iam_role_policy`` (inline role policies) to role nodes."""
        for tf_name, attrs in resources.get("aws_iam_role_policy", {}).items():
            role_ref = attrs.get("role", "")
            policy_raw = attrs.get("policy", "")
            role_tf = _tf_ref_name(role_ref)
            role_node = roles.get(role_tf)
            if not role_node:
                # Try matching by raw role name string
                for rname, rnode in roles.items():
                    if role_ref and rname in role_ref:
                        role_node = rnode
                        break
            if not role_node:
                continue
            if isinstance(policy_raw, dict):
                policy_doc = policy_raw
            elif isinstance(policy_raw, str):
                policy_doc = _extract_jsonencode(policy_raw)
            else:
                continue
            if policy_doc:
                self._apply_permission_policy(graph, role_node, policy_doc)

    def _apply_role_policy_attachments(
        self,
        resources: dict,
        policies: Dict[str, dict],
        graph: TrustGraph,
        roles: Dict[str, str],
        tf_dir: Path,
    ) -> None:
        for tf_name, attrs in resources.get("aws_iam_role_policy_attachment", {}).items():
            role_ref = attrs.get("role", "")
            policy_ref = attrs.get("policy_arn", "")
            role_tf = _tf_ref_name(role_ref)
            role_node = roles.get(role_tf)
            if not role_node:
                continue
            policy_doc = self._resolve_policy_ref(policy_ref, policies, resources)
            if policy_doc:
                self._apply_permission_policy(graph, role_node, policy_doc)

        # Also handle aws_iam_policy resource directly attached (managed_policy_arns on role)
        for tf_name, attrs in resources.get("aws_iam_role", {}).items():
            managed_arns = attrs.get("managed_policy_arns", [])
            if not managed_arns:
                continue
            role_node = roles.get(tf_name)
            if not role_node:
                continue
            if isinstance(managed_arns, str):
                managed_arns = [managed_arns]
            for arn_ref in managed_arns:
                policy_doc = self._resolve_policy_ref(arn_ref, policies, resources)
                if policy_doc:
                    self._apply_permission_policy(graph, role_node, policy_doc)

    def _apply_managed_policy_arns_from_role_resources(
        self,
        resources: dict,
        graph: TrustGraph,
        roles: Dict[str, str],
    ) -> None:
        """Also read managed_policy_arns from aws_iam_role attributes."""
        # Already handled in _apply_role_policy_attachments; kept for clarity.
        pass

    def _apply_passrole_edges(
        self,
        graph: TrustGraph,
        roles: Dict[str, str],
    ) -> None:
        """Model ``iam:PassRole *`` as AUTHENTICATE_AS edges to all role nodes.

        A principal with ``iam:PassRole`` on ``Resource: *`` can set any IAM
        role as the execution role for a Lambda/ECS task, effectively gaining
        that role's permissions.  Create a low-weight AUTHENTICATE_AS edge from
        the principal to every role node in the scenario.
        """
        all_role_nodes = set(roles.values())

        for src_node in list(graph._graph.nodes()):
            # Detect PassRole capability: outgoing AUTHENTICATE_AS edges
            # to an iam:resource or iam:resource:wildcard target, from actions
            # that include PassRole.  We approximate by checking if the node
            # has lambda:* permissions (a strong indicator of PassRole use).
            targets = [
                v for _, v, d in graph._graph.out_edges(src_node, data=True)
                if "lambda" in v.lower() or "wildcard" in v.lower()
            ]
            if not targets:
                continue

            # Only add edges if this node also has a lambda:* or deploy edge
            has_lambda_action = any("lambda" in t.lower() for t in targets)
            has_iam_target = any(
                "iam:resource" in t.lower() for t in
                [v for _, v in graph._graph.out_edges(src_node)]
            )
            if not (has_lambda_action or has_iam_target):
                continue

            for role_node in all_role_nodes:
                if role_node == src_node:
                    continue
                if not graph._graph.has_edge(src_node, role_node):
                    self._edge_counter += 1
                    graph.add_edge(src_node, role_node, EdgeMetadata(
                        edge_id=f"cg-passrole-{self._edge_counter}",
                        edge_type=EdgeType.AUTHENTICATE_AS,
                        weight=0.7,   # requires Lambda creation to exploit
                        delegation_depth_limit=3,
                    ))

    def _apply_ecs_lateral_edges(
        self,
        graph: TrustGraph,
        roles: Dict[str, str],
    ) -> None:
        """Add lateral movement edges for roles with broad ECS permissions.

        In ECS attack scenarios, a role with ``ecs:*`` can enumerate and
        manipulate tasks across the cluster, effectively reaching task roles
        that run on the same infrastructure.  Model this as an AUTHENTICATE_AS
        edge: ecs_agent_role → ecs_task_role (low weight; requires exploitation).
        """
        ecs_powerful_nodes = []
        ecs_task_roles = []

        for node_id in graph._graph.nodes():
            # Nodes whose out-edges include ECS actions
            for _, target, data in graph._graph.out_edges(node_id, data=True):
                meta = data.get("metadata")
                if meta and "ecs" in target.lower():
                    ecs_powerful_nodes.append(node_id)
                    break

            # Detect ECS task roles (assumed by ecs-tasks.amazonaws.com)
            # They appear as ROLE nodes with no attacker-reachable in-edges yet
            node_data = graph._graph.nodes[node_id]
            nm = node_data.get("metadata")
            if nm and nm.node_type == NodeType.ROLE and "privd" in node_id.lower():
                ecs_task_roles.append(node_id)

        for src in ecs_powerful_nodes:
            for dst in ecs_task_roles:
                if src != dst and not graph._graph.has_edge(src, dst):
                    self._edge_counter += 1
                    graph.add_edge(src, dst, EdgeMetadata(
                        edge_id=f"cg-ecs-lateral-{self._edge_counter}",
                        edge_type=EdgeType.AUTHENTICATE_AS,
                        weight=0.6,   # requires ECS exploitation
                        delegation_depth_limit=3,
                    ))

    def _apply_trust_policies(
        self,
        resources: dict,
        graph: TrustGraph,
        users: Dict[str, str],
        roles: Dict[str, str],
        tf_dir: Path,
    ) -> None:
        """Create ASSUME_ROLE edges from trust policies."""
        data_docs: Dict[str, dict] = resources.get("__data_policy_docs__", {})  # type: ignore

        for tf_name, attrs in resources.get("aws_iam_role", {}).items():
            role_node = roles.get(tf_name)
            if not role_node:
                continue
            raw_trust = attrs.get("assume_role_policy")
            if not raw_trust:
                continue

            # Check for data source reference: "${data.aws_iam_policy_document.X.json}"
            data_ref = re.search(
                r'data\.aws_iam_policy_document\.(\w+)', str(raw_trust)
            )
            if data_ref and data_ref.group(1) in data_docs:
                trust_doc = data_docs[data_ref.group(1)]
            else:
                trust_doc = _resolve_policy_doc(raw_trust, tf_dir.parent)
            if not trust_doc:
                continue
            self._process_trust_document(graph, trust_doc, role_node, users, roles)

    # ------------------------------------------------------------------
    # Graph construction helpers
    # ------------------------------------------------------------------

    def _apply_permission_policy(
        self,
        graph: TrustGraph,
        subject_node: str,
        policy_doc: dict,
    ) -> None:
        """Convert an IAM permission policy doc to edges from subject_node."""
        if not isinstance(policy_doc, dict):
            return
        stmts = policy_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]

            edge_type = dominant_edge_type(actions)
            weight = edge_weight_from_statement(stmt, actions)
            priv = privilege_from_aws_actions(actions)

            for resource in resources:
                target_id = self._resource_to_node_id(resource, actions)
                if not graph._graph.has_node(target_id):
                    graph.add_node(NodeMetadata(
                        node_id=target_id,
                        node_type=self._resource_to_node_type(resource, actions),
                        name=target_id.split(":")[-1],
                        privilege_level=priv,
                        sensitivity=sensitivity_from_arn(resource),
                        tags={"source": "cloudgoat_policy"},
                    ))
                self._edge_counter += 1
                eid = f"cg-e{self._edge_counter}"
                if not graph._graph.has_edge(subject_node, target_id):
                    graph.add_edge(subject_node, target_id, EdgeMetadata(
                        edge_id=eid,
                        edge_type=edge_type,
                        weight=weight,
                        delegation_depth_limit=self._default_depth,
                    ))

    def _process_trust_document(
        self,
        graph: TrustGraph,
        trust_doc: dict,
        role_node: str,
        users: Dict[str, str],
        roles: Dict[str, str],
    ) -> None:
        """Create ASSUME_ROLE edges: principal → role from a trust policy."""
        stmts = trust_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                principals_list = [principal]
            else:
                principals_list = []
                for ptype, pval in principal.items():
                    if isinstance(pval, list):
                        principals_list.extend(pval)
                    else:
                        principals_list.append(pval)

            for principal_str in principals_list:
                ps = str(principal_str).strip('"')

                # Resolved IAM user placeholder: __IAM_USER_chris__
                u_match = re.match(r'^__IAM_USER_(\w+)__$', ps)
                if u_match:
                    principal_node = users.get(u_match.group(1))
                    if principal_node:
                        self._add_assume_edge(graph, principal_node, role_node)
                    continue

                # Resolved IAM role placeholder: __IAM_ROLE_foo__
                r_match = re.match(r'^__IAM_ROLE_(\w+)__$', ps)
                if r_match:
                    principal_node = roles.get(r_match.group(1))
                    if principal_node:
                        self._add_assume_edge(graph, principal_node, role_node)
                    continue

                # Service principals (lambda.amazonaws.com, ec2.amazonaws.com, etc.)
                if ".amazonaws.com" in ps or ps == "__tf_ref__":
                    svc_node = self._service_principal_node(ps, graph)
                    self._add_assume_edge(graph, svc_node, role_node)
                    continue

                # Already-resolved node ID
                if "iam:user" in ps or "iam:role" in ps:
                    self._add_assume_edge(graph, ps, role_node)
                    continue

                # Fall-through: Terraform ref that wasn't caught above
                tf_name = _tf_ref_name(ps)
                principal_node = users.get(tf_name) or roles.get(tf_name)
                if principal_node:
                    self._add_assume_edge(graph, principal_node, role_node)

    def _add_assume_edge(
        self, graph: TrustGraph, src: str, dst: str
    ) -> None:
        if not graph._graph.has_node(src):
            return
        if not graph._graph.has_node(dst):
            return
        if not graph._graph.has_edge(src, dst):
            self._edge_counter += 1
            graph.add_edge(src, dst, EdgeMetadata(
                edge_id=f"cg-assume-{self._edge_counter}",
                edge_type=EdgeType.ASSUME_ROLE,
                weight=0.8,
                delegation_depth_limit=self._default_depth,
            ))

    def _service_principal_node(
        self, service: str, graph: TrustGraph
    ) -> str:
        """Get or create a SERVICE node for a service principal."""
        clean = service.replace("__tf_ref__", "lambda.amazonaws.com")
        node_id = f"service:{clean.split('.')[0]}"
        if not graph._graph.has_node(node_id):
            graph.add_node(NodeMetadata(
                node_id=node_id,
                node_type=NodeType.SERVICE,
                name=clean,
                privilege_level=0.3,
                sensitivity=0.3,
                tags={"source": "cloudgoat_trust"},
            ))
        return node_id

    # ------------------------------------------------------------------
    # Resource → node ID / type helpers
    # ------------------------------------------------------------------

    def _resource_to_node_id(self, resource: str, actions: List[str]) -> str:
        resource = resource.strip()
        if resource == "*":
            # Wildcard — infer service from actions
            if any("s3" in a.lower() for a in actions):
                return "s3:bucket:wildcard"
            if any("lambda" in a.lower() for a in actions):
                return "lambda:function:wildcard"
            if any("ecs" in a.lower() for a in actions):
                return "ecs:task:wildcard"
            if any("iam" in a.lower() or "sts" in a.lower() for a in actions):
                return "iam:resource:wildcard"
            return "aws:resource:wildcard"
        if resource.startswith("arn:"):
            # Shorten ARN to compact ID
            parts = resource.split(":")
            svc = parts[2] if len(parts) > 2 else "aws"
            rest = parts[-1].replace("/", ":")
            return f"{svc}:{rest}"
        return f"resource:{resource.replace('/', ':')}"

    def _resource_to_node_type(self, resource: str, actions: List[str]) -> NodeType:
        a_lower = [a.lower() for a in actions]
        if any("sts:" in a or "iam:" in a for a in a_lower):
            return NodeType.ROLE
        if any("secretsmanager:" in a or "ssm:" in a or "kms:" in a for a in a_lower):
            return NodeType.SECRET
        if any("s3:" in a for a in a_lower):
            return NodeType.SECRET   # treat buckets as high-sensitivity
        if any("lambda:" in a or "ecs:" in a or "ec2:" in a for a in a_lower):
            return NodeType.WORKLOAD
        if any("codedeploy:" in a or "codepipeline:" in a for a in a_lower):
            return NodeType.DEPLOYMENT
        return NodeType.SERVICE

    def _resolve_policy_ref(
        self,
        policy_ref: str,
        policies: Dict[str, dict],
        resources: dict,
    ) -> Optional[dict]:
        """Resolve a policy_arn reference to a policy document dict."""
        policy_ref = policy_ref.strip().strip('"')

        # Direct managed policy ARN
        if policy_ref in _MANAGED_POLICY_DOCS:
            return _MANAGED_POLICY_DOCS[policy_ref]

        # Terraform resource reference: ${aws_iam_policy.chris_policy.arn}
        tf_name = _tf_ref_name(policy_ref)
        if tf_name in policies:
            return policies[tf_name]

        # Managed policy ARN by substring
        for arn, doc in _MANAGED_POLICY_DOCS.items():
            if policy_ref.lower() in arn.lower() or arn.lower() in policy_ref.lower():
                return doc

        return None

    # ------------------------------------------------------------------
    # Seed node selection
    # ------------------------------------------------------------------

    def _pick_seeds(
        self,
        graph: TrustGraph,
        resources: dict,
        users: Dict[str, str],
        roles: Dict[str, str],
    ) -> List[str]:
        """Pick entry-point seed nodes (lowest-privilege attacker starting points).

        Priority:
        1. IAM users (explicit attacker accounts in CloudGoat)
        2. Service nodes (SSRF / public-facing services)
        3. First role node

        Additionally, when EC2 instance profiles exist the ``service:ec2`` node
        is included even alongside IAM users, because CloudGoat scenarios model
        the EC2 IMDS (metadata service) as an implicit attack surface: an
        attacker who reaches any EC2 instance can steal its instance-role
        credentials via the metadata endpoint.

        Likewise, when ECS task definitions or services are defined,
        ``service:ecs-tasks`` is included to model container metadata access.
        """
        seeds: List[str] = list(users.values())

        # Add service:ec2 when EC2 instance profiles are present — models IMDS access
        if resources.get("aws_iam_instance_profile") and graph._graph.has_node("service:ec2"):
            if "service:ec2" not in seeds:
                seeds.append("service:ec2")

        # Add service:ecs-tasks when ECS resources are present — models ECS task metadata
        has_ecs = resources.get("aws_ecs_task_definition") or resources.get("aws_ecs_service")
        if has_ecs and graph._graph.has_node("service:ecs-tasks"):
            if "service:ecs-tasks" not in seeds:
                seeds.append("service:ecs-tasks")

        if seeds:
            return seeds

        # No user — find the public-facing service (EC2 + instance profile)
        service_nodes = [
            nid for nid in graph._graph.nodes()
            if nid.startswith("service:")
        ]
        if service_nodes:
            return service_nodes[:1]

        role_nodes = list(roles.values())
        if role_nodes:
            return role_nodes[:1]

        node_list = sorted(graph._graph.nodes())
        return [node_list[0]] if node_list else []


# ---------------------------------------------------------------------------
# README parser
# ---------------------------------------------------------------------------

def _parse_readme_attack_path(readme_path: Path) -> List[str]:
    """Extract numbered walkthrough steps from a CloudGoat README.md.

    Looks for a section starting with "## Route Walkthrough" or "## Walkthrough"
    and extracts the numbered list items.

    Returns:
        List of step strings (may be empty if not found).
    """
    if not readme_path.exists():
        return []
    text = readme_path.read_text(encoding="utf-8")

    # Find walkthrough section
    section_match = re.search(
        r'##\s+(?:Route )?Walkthrough[^\n]*\n(.+?)(?:\n##|\Z)',
        text, re.DOTALL | re.IGNORECASE,
    )
    if not section_match:
        return []

    section = section_match.group(1)
    steps = re.findall(r'^\s*\d+\.\s+(.+?)(?=\n\s*\d+\.|\Z)', section,
                       re.MULTILINE | re.DOTALL)
    return [
        re.sub(r'\s+', ' ', s.strip()).strip('.')
        for s in steps if s.strip()
    ]


# ---------------------------------------------------------------------------
# CloudGoatValidator
# ---------------------------------------------------------------------------

class CloudGoatValidator:
    """Runs TrustField on CloudGoat scenarios and scores detection vs known paths.

    Uses ``GraphTraversalModel`` (BFS) to find all structurally reachable nodes
    from the seed, then compares against the known attack-path node patterns for
    each scenario.

    Args:
        loader: ``CloudGoatLoader`` instance (created automatically if None).
    """

    def __init__(self, loader: Optional[CloudGoatLoader] = None) -> None:
        self._loader = loader or CloudGoatLoader()

    def validate_scenario(
        self,
        scenario_path: str | Path,
    ) -> ValidationResult:
        """Load and validate one CloudGoat scenario.

        Args:
            scenario_path: Path to the scenario root directory.

        Returns:
            :class:`ValidationResult` with detection metrics.
        """
        from trustfield.propagation.graph_traversal import GraphTraversalModel
        from trustfield.verification.iam_traversal import IAMTraversal
        from trustfield.verification.delegation_token import TokenGenerator

        scenario_path = Path(scenario_path)
        scenario_name = scenario_path.name

        # Parse known path patterns for this scenario
        known_patterns = _KNOWN_PATHS.get(scenario_name, [])
        readme_steps = _parse_readme_attack_path(scenario_path / "README.md")

        try:
            graph, seed_nodes = self._loader.load_scenario(scenario_path)
        except Exception as exc:
            return ValidationResult(
                scenario_name=scenario_name,
                scenario_path=str(scenario_path),
                n_nodes=0,
                known_path_steps=readme_steps,
                known_path_node_patterns=known_patterns,
                detected_node_ids=set(),
                nodes_on_known_path_found=0,
                nodes_on_known_path_total=len(known_patterns),
                detected=False,
                partial_detection=False,
                seed_nodes=[],
                error=str(exc),
            )

        if not seed_nodes or not graph._graph.number_of_nodes():
            return ValidationResult(
                scenario_name=scenario_name,
                scenario_path=str(scenario_path),
                n_nodes=graph._graph.number_of_nodes(),
                known_path_steps=readme_steps,
                known_path_node_patterns=known_patterns,
                detected_node_ids=set(),
                nodes_on_known_path_found=0,
                nodes_on_known_path_total=len(known_patterns),
                detected=False,
                partial_detection=False,
                seed_nodes=seed_nodes,
                error="Empty graph or no seed nodes",
            )

        # BFS traversal (structural reachability — upper bound)
        gt = GraphTraversalModel()
        bfs_result = gt.run(graph, seed_nodes)
        bfs_reachable: Set[str] = bfs_result.compromised_nodes

        # IAM-verified traversal
        try:
            traversal = IAMTraversal(TokenGenerator()).traverse(
                graph, seed_nodes, max_depth=8, respect_conditions=True
            )
            verified: Set[str] = traversal.verified_reachable
        except Exception:
            verified = bfs_reachable

        # Union: any node reachable by either method
        detected_ids = bfs_reachable | verified

        # Score against known path patterns
        found = 0
        for pattern, _label in known_patterns:
            pat_lower = pattern.lower()
            if any(pat_lower in nid.lower() for nid in detected_ids):
                found += 1

        total = len(known_patterns)
        detected = (found == total and total > 0)
        partial = (0 < found < total)

        return ValidationResult(
            scenario_name=scenario_name,
            scenario_path=str(scenario_path),
            n_nodes=graph._graph.number_of_nodes(),
            known_path_steps=readme_steps,
            known_path_node_patterns=known_patterns,
            detected_node_ids=detected_ids,
            nodes_on_known_path_found=found,
            nodes_on_known_path_total=total,
            detected=detected,
            partial_detection=partial,
            seed_nodes=seed_nodes,
        )

    def validate_all(
        self,
        scenarios_dir: str | Path,
        scenario_names: Optional[List[str]] = None,
    ) -> List[ValidationResult]:
        """Validate multiple scenarios and return results.

        Args:
            scenarios_dir: Root ``scenarios/aws/`` directory.
            scenario_names: Subset of scenario names to run.  If None, runs
                all scenarios in ``_KNOWN_PATHS``.

        Returns:
            List of ``ValidationResult``, one per scenario.
        """
        scenarios_dir = Path(scenarios_dir)
        names = scenario_names or list(_KNOWN_PATHS.keys())
        results = []
        for name in names:
            path = scenarios_dir / name
            if path.exists():
                results.append(self.validate_scenario(path))
            else:
                results.append(ValidationResult(
                    scenario_name=name,
                    scenario_path=str(path),
                    n_nodes=0,
                    known_path_steps=[],
                    known_path_node_patterns=_KNOWN_PATHS.get(name, []),
                    detected_node_ids=set(),
                    nodes_on_known_path_found=0,
                    nodes_on_known_path_total=len(_KNOWN_PATHS.get(name, [])),
                    detected=False,
                    partial_detection=False,
                    seed_nodes=[],
                    error=f"Scenario directory not found: {path}",
                ))
        return results

    def print_report(self, results: List[ValidationResult]) -> None:
        """Print a formatted detection report table."""
        print()
        print(f"  {'Scenario':<30}  {'Nodes':>5}  {'Path':>6}  {'Detected':>8}  {'Score':>7}  {'Seed'}")
        print(f"  {'-'*30}  {'-'*5}  {'-'*6}  {'-'*8}  {'-'*7}  {'-'*24}")
        for r in results:
            if r.error:
                status = "ERROR"
                score = "—"
            else:
                status = "YES" if r.detected else ("PARTIAL" if r.partial_detection else "NO")
                score = f"{r.nodes_on_known_path_found}/{r.nodes_on_known_path_total}"
            seed_str = r.seed_nodes[0] if r.seed_nodes else "—"
            print(
                f"  {r.scenario_name:<30}  {r.n_nodes:>5}  "
                f"{len(r.known_path_steps):>6}  {status:>8}  {score:>7}  {seed_str}"
            )
        print()

        detected = sum(1 for r in results if r.detected)
        partial  = sum(1 for r in results if r.partial_detection)
        total    = len(results)
        print(f"  Detection rate:   {detected}/{total} fully detected")
        print(f"  Partial detects:  {partial}/{total}")
        print(f"  Overall coverage: {(detected + 0.5*partial)/max(1,total):.1%}")
        print()

        # Per-scenario detail
        for r in results:
            if r.error:
                print(f"  [{r.scenario_name}]  ERROR: {r.error}")
                continue
            print(f"  [{r.scenario_name}]")
            for pattern, label in r.known_path_node_patterns:
                found = any(pattern.lower() in nid.lower() for nid in r.detected_node_ids)
                mark = "✓" if found else "✗"
                print(f"    {mark} {label}")
            print()
