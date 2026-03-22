"""TrustField real-world config loaders.

Parse AWS IAM JSON policies and Kubernetes RBAC YAML files directly into
``TrustGraph`` objects, ready for the full analysis pipeline.

    from trustfield.loaders import IAMPolicyLoader, K8sRBACLoader

    # AWS IAM
    aws_graph = IAMPolicyLoader().load_file("lambda_execution_role.json")

    # Kubernetes RBAC
    k8s_graph = K8sRBACLoader().load_file("cluster_role_bindings.yaml")
"""

from .aws_iam_loader import IAMPolicyLoader
from .cloudgoat_loader import CloudGoatLoader, CloudGoatValidator, ValidationResult
from .k8s_rbac_loader import K8sRBACLoader

__all__ = [
    "IAMPolicyLoader",
    "K8sRBACLoader",
    "CloudGoatLoader",
    "CloudGoatValidator",
    "ValidationResult",
]
