"""Demo: TrustField real-world extended fixture case study (Improvement 6).

Runs all 9 fixtures (3 original AWS + 2 new AWS + 2 original K8s + 2 new K8s)
through the full TrustField pipeline and prints a case-study table:

  Config              | Nodes | PBR | VBR | EGD  | Class        | Key Finding
  ------------------- | ----- | --- | --- | ---- | ------------ | -----------
  aws/s3_read_only    |     3 |   1 |   0 | 1.00 | UNDER_PRED   | no attack path
  aws/lambda_exec     |   ... | ... | ... | ...  | ...          | cross-account path
  ...

EGD = exploitability_gap_score (0 = perfect, 1 = disjoint)

Run:
    PYTHONPATH=. python demos/demo_real_world_extended.py
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from trustfield.ensemble.ensemble_predictor import EnsemblePredictor, FusionMode
from trustfield.ensemble.topology_selector import TopologyAwareSelector
from trustfield.graph.fingerprinter import TopologyFingerprinter
from trustfield.graph.trust_graph import TrustGraph
from trustfield.loaders.aws_iam_loader import IAMPolicyLoader
from trustfield.loaders.k8s_rbac_loader import K8sRBACLoader
from trustfield.propagation.runner import PropagationRunner
from trustfield.verification.blast_radius import BlastRadiusCalculator, GapClassification
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal

_runner = PropagationRunner()
_fingerprinter = TopologyFingerprinter()
_selector = TopologyAwareSelector()
_predictor = EnsemblePredictor()

_FIXTURES = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures")
_AWS = os.path.join(_FIXTURES, "aws")
_K8S = os.path.join(_FIXTURES, "k8s")

# (display_name, path, loader_class, key_finding)
_CONFIGS = [
    ("aws/s3_read_only",        os.path.join(_AWS, "s3_read_only.json"),           IAMPolicyLoader, "read-only S3, minimal risk"),
    ("aws/lambda_execution",    os.path.join(_AWS, "lambda_execution_role.json"),   IAMPolicyLoader, "cross-account sts path"),
    ("aws/admin_access",        os.path.join(_AWS, "admin_access.json"),            IAMPolicyLoader, "AdministratorAccess wildcard"),
    ("aws/ecs_task_role",       os.path.join(_AWS, "ecs_task_role.json"),           IAMPolicyLoader, "ECR→secret lateral move"),
    ("aws/codepipeline_role",   os.path.join(_AWS, "codepipeline_role.json"),       IAMPolicyLoader, "iam:PassRole + cross-acct"),
    ("k8s/cluster_role_bindings", os.path.join(_K8S, "cluster_role_bindings.yaml"), K8sRBACLoader,  "cluster-admin binding"),
    ("k8s/app_rbac",            os.path.join(_K8S, "app_rbac.yaml"),               K8sRBACLoader,  "namespace-scoped app RBAC"),
    ("k8s/istio_rbac",          os.path.join(_K8S, "istio_rbac.yaml"),             K8sRBACLoader,  "ingressgateway→TLS secrets"),
    ("k8s/argo_workflows",      os.path.join(_K8S, "argo_workflows.yaml"),         K8sRBACLoader,  "cluster-admin misconfiguration"),
]


@dataclass
class CaseStudyRow:
    config: str
    n_nodes: int
    pbr: int
    vbr: int
    egd: float
    classification: str
    key_finding: str


def _run_pipeline(graph: TrustGraph) -> tuple[int, int, float, str]:
    """Returns (pbr_size, vbr_size, egd, classification_name)."""
    node_list = sorted(graph.nx_graph.nodes())
    seed_nodes = [node_list[0]] if node_list else []

    fingerprint = _fingerprinter.fingerprint(graph)

    prop_results = _runner.run_all(graph, seed_nodes)

    weight_vector = _selector.get_initial_weights(fingerprint)
    ensemble_pred = _predictor.predict(prop_results, weight_vector, FusionMode.WEIGHTED)

    tgen = TokenGenerator()
    traversal_result = IAMTraversal(tgen).traverse(
        graph, seed_nodes, max_depth=6, respect_conditions=False
    )

    analysis = BlastRadiusCalculator().compute(ensemble_pred, traversal_result, graph)

    return (
        analysis.pbr_size,
        analysis.vbr_size,
        round(analysis.exploitability_gap_score, 3),
        analysis.gap_classification.value,
    )


def _load_graph(path: str, loader_cls) -> Optional[TrustGraph]:
    try:
        loader = loader_cls()
        return loader.load_file(path)
    except Exception as exc:
        print(f"  WARNING: could not load {os.path.basename(path)}: {exc}")
        return None


def _short_class(cls: str) -> str:
    mapping = {
        "CRITICAL_MISS":  "CRITICAL_MISS",
        "CALIBRATED":     "CALIBRATED   ",
        "OVER_PREDICTED": "OVER_PRED    ",
        "UNDER_PREDICTED":"UNDER_PRED   ",
    }
    return mapping.get(cls, cls[:13])


def main() -> None:
    print("=" * 90)
    print("TrustField Real-World Extended Case Study")
    print("9 fixtures  |  full pipeline  |  PBR / VBR / EGD / GapClassification")
    print("=" * 90)

    rows: List[CaseStudyRow] = []

    for display_name, path, loader_cls, key_finding in _CONFIGS:
        graph = _load_graph(path, loader_cls)
        if graph is None:
            rows.append(CaseStudyRow(display_name, 0, 0, 0, 0.0, "LOAD_ERROR", key_finding))
            continue

        n = graph.nx_graph.number_of_nodes()
        try:
            pbr, vbr, egd, cls = _run_pipeline(graph)
        except Exception as exc:
            print(f"  WARNING: pipeline failed for {display_name}: {exc}")
            rows.append(CaseStudyRow(display_name, n, 0, 0, 0.0, "PIPELINE_ERROR", key_finding))
            continue

        rows.append(CaseStudyRow(display_name, n, pbr, vbr, egd, cls, key_finding))

    # ------------------------------------------------------------------
    # Print table
    # ------------------------------------------------------------------
    print()
    hdr = (
        f"{'Config':<28}  {'Nodes':>5}  {'PBR':>4}  {'VBR':>4}  "
        f"{'EGD':>5}  {'Classification':<14}  Key Finding"
    )
    print(hdr)
    print("-" * 90)

    critical_miss_count = 0
    for r in rows:
        cls_label = _short_class(r.classification)
        # Highlight CRITICAL_MISS rows
        marker = " <-- CRITICAL" if r.classification == "CRITICAL_MISS" else ""
        if r.classification == "CRITICAL_MISS":
            critical_miss_count += 1
        print(
            f"{r.config:<28}  {r.n_nodes:>5}  {r.pbr:>4}  {r.vbr:>4}  "
            f"{r.egd:>5.3f}  {cls_label}  {r.key_finding}{marker}"
        )

    # ------------------------------------------------------------------
    # Summary stats
    # ------------------------------------------------------------------
    print()
    print("=" * 90)
    total = len([r for r in rows if r.classification not in ("LOAD_ERROR", "PIPELINE_ERROR")])
    calibrated = sum(1 for r in rows if r.classification == "CALIBRATED")
    over_pred = sum(1 for r in rows if r.classification == "OVER_PREDICTED")
    under_pred = sum(1 for r in rows if r.classification == "UNDER_PREDICTED")

    print(f"Fixtures analysed : {total} / {len(_CONFIGS)}")
    print(f"CRITICAL_MISS     : {critical_miss_count}  (ensemble missed verified attack paths)")
    print(f"CALIBRATED        : {calibrated}  (EGD < 10%)")
    print(f"OVER_PREDICTED    : {over_pred}  (ensemble moderately over-estimates)")
    print(f"UNDER_PREDICTED   : {under_pred}  (traversal found far fewer than predicted)")

    if total > 0:
        avg_egd = sum(r.egd for r in rows if r.classification not in ("LOAD_ERROR", "PIPELINE_ERROR")) / total
        print(f"Mean EGD          : {avg_egd:.3f}")

    print()
    print("Columns:")
    print("  PBR = Predicted Blast Radius (ensemble node count)")
    print("  VBR = Verified Blast Radius  (IAM traversal node count)")
    print("  EGD = Exploitability Gap Score = 1 - Jaccard(PBR, VBR)")


if __name__ == "__main__":
    main()
