"""Demo: Real-World Config Loaders — AWS IAM + Kubernetes RBAC.

Loads real-world configuration files, converts them to TrustGraphs,
runs the full TrustField analysis pipeline, and prints results.

Real configs used
-----------------
  AWS : tests/fixtures/aws/lambda_execution_role.json
        (trust + permission policies for a Lambda execution role)
  K8s : tests/fixtures/k8s/cluster_role_bindings.yaml
        Source: kubernetes/kubernetes bootstrap policy testdata
        https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/auth/
          authorizer/rbac/bootstrappolicy/testdata/cluster-role-bindings.yaml
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.loaders import IAMPolicyLoader, K8sRBACLoader
from trustfield.pipeline import TrustFieldPipeline

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures"
OUT_DIR  = Path(__file__).parent.parent / "out"

print("=" * 70)
print("TrustField — Real-World Config Loader Demo")
print("=" * 70)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run_analysis(graph, label: str, out_dir: str) -> None:
    node_list = sorted(graph._graph.nodes())
    seed = next(
        (n for n in node_list if graph._graph.out_degree(n) > 0), node_list[0]
    )
    pipeline = TrustFieldPipeline(
        output_dir=out_dir,
        n_feedback_cycles=3,
    )
    result = pipeline.run(graph, [seed], topology_label=label, export=True)
    m = result.metrics
    cr = result.containment_result

    print(f"\n  Seed node   : {seed}")
    print(f"  Nodes       : {m['total_nodes']}  |  Edges: {graph._graph.number_of_edges()}")
    print(f"  PBR={m['pbr_size']}  VBR={m['vbr_size']}  Gap={m['gap_size']}  "
          f"({m['gap_classification']})")
    print(f"  EGD score   : {m['exploitability_gap_score']:.4f}")
    print(f"  Containment : {m['containment_success_rate']:.1%}  "
          f"(contained={m['nodes_contained']}, missed={m['missed_containments']})")
    print(f"  Strictness  : {m['final_strictness']}")
    if result.output_files:
        print(f"  Web viewer  : {result.output_files.get('json', '—')}")


# ---------------------------------------------------------------------------
# Section 1: AWS IAM — Lambda Execution Role
# ---------------------------------------------------------------------------

print("\n[1] AWS IAM — Lambda Execution Role")
print("-" * 70)

aws_graph = IAMPolicyLoader().load_file(
    FIXTURES / "aws" / "lambda_execution_role.json"
)

print(f"  Loaded graph: {aws_graph._graph.number_of_nodes()} nodes, "
      f"{aws_graph._graph.number_of_edges()} edges")

# Show node breakdown
node_types = {}
for nid in aws_graph._graph.nodes():
    ntype = aws_graph.get_node(nid).node_type.value
    node_types[ntype] = node_types.get(ntype, 0) + 1
for ntype, count in sorted(node_types.items()):
    print(f"    {ntype:<15}: {count}")

# Show edges with their types
print("\n  Trust graph edges:")
for src, tgt, data in aws_graph._graph.edges(data=True):
    meta = data["metadata"]
    print(f"    {src:<40} --[{meta.edge_type.value}]--> {tgt}")
    print(f"      weight={meta.weight:.3f}  depth={meta.delegation_depth_limit}"
          f"  conditional={meta.is_conditional}")

run_analysis(aws_graph, "aws_iam_lambda", str(OUT_DIR))

# ---------------------------------------------------------------------------
# Section 2: AWS IAM — S3 Read-Only Policy
# ---------------------------------------------------------------------------

print("\n[2] AWS IAM — AmazonS3ReadOnlyAccess (from z0ph/MAMIP)")
print("-" * 70)
print("  Source: https://github.com/z0ph/MAMIP/blob/master/policies/AmazonS3ReadOnlyAccess")

s3_graph = IAMPolicyLoader().load_file(
    FIXTURES / "aws" / "s3_read_only.json",
    subject_id="iam:role:s3-reader",
)

print(f"  Loaded: {s3_graph._graph.number_of_nodes()} nodes, "
      f"{s3_graph._graph.number_of_edges()} edges")
for src, tgt, data in s3_graph._graph.edges(data=True):
    meta = data["metadata"]
    print(f"    {src} --[{meta.edge_type.value}]--> {tgt}  (weight={meta.weight:.3f})")

# ---------------------------------------------------------------------------
# Section 3: Kubernetes RBAC — Kubernetes Bootstrap Bindings (real repo)
# ---------------------------------------------------------------------------

print("\n[3] Kubernetes RBAC — Bootstrap ClusterRoleBindings")
print("-" * 70)
print("  Source: kubernetes/kubernetes/plugin/pkg/auth/authorizer/rbac/")
print("          bootstrappolicy/testdata/cluster-role-bindings.yaml")

k8s_graph = K8sRBACLoader().load_file(
    FIXTURES / "k8s" / "cluster_role_bindings.yaml"
)

print(f"\n  Loaded graph: {k8s_graph._graph.number_of_nodes()} nodes, "
      f"{k8s_graph._graph.number_of_edges()} edges")

# Show high-privilege nodes
print("\n  High-privilege nodes (privilege ≥ 0.7):")
high_priv = [
    (nid, k8s_graph.get_node(nid))
    for nid in k8s_graph._graph.nodes()
    if k8s_graph.get_node(nid).privilege_level >= 0.7
]
high_priv.sort(key=lambda x: -x[1].privilege_level)
for nid, meta in high_priv:
    print(f"    {nid:<45} priv={meta.privilege_level:.2f}  type={meta.node_type.value}")

# Show critical path: who can reach cluster-admin
print("\n  Paths to clusterrole:cluster-admin:")
for src, tgt, data in k8s_graph._graph.in_edges("clusterrole:cluster-admin", data=True):
    meta = data["metadata"]
    print(f"    {src:<45} --[{meta.edge_type.value}]--> cluster-admin  "
          f"(weight={meta.weight:.3f})")

run_analysis(k8s_graph, "k8s_bootstrap_rbac", str(OUT_DIR))

# ---------------------------------------------------------------------------
# Section 4: Kubernetes RBAC — Application RBAC (multi-document)
# ---------------------------------------------------------------------------

print("\n[4] Kubernetes RBAC — Application RBAC (ServiceAccount + Roles + Bindings)")
print("-" * 70)

app_graph = K8sRBACLoader().load_file(
    FIXTURES / "k8s" / "app_rbac.yaml"
)

print(f"  Loaded: {app_graph._graph.number_of_nodes()} nodes, "
      f"{app_graph._graph.number_of_edges()} edges")

# Show derived resource edges
print("\n  Derived resource-access edges:")
for src, tgt, data in app_graph._graph.edges(data=True):
    meta = data["metadata"]
    if meta.tags.get("source") == "k8s_rbac_derived":
        continue  # skip — these are resource nodes not binding edges
    if "k8s:" in tgt or "k8s:" in src:
        print(f"    {src:<40} --[{meta.edge_type.value:<16}]--> {tgt}")

run_analysis(app_graph, "k8s_app_rbac", str(OUT_DIR))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n" + "=" * 70)
print("Loader Demo complete.")
print("=" * 70)
print(f"\nWeb visualizations written to: {OUT_DIR}/")
print("Open any out/<label>/index.html in a browser.")
