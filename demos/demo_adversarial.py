"""Demo: TrustField adversarial robustness evaluation.

Demonstrates all three mutation strategies against a representative
privilege-escalation graph and produces a full RobustnessReport with
LaTeX table and conclusion paragraph.

Run:
    PYTHONPATH=. python demos/demo_adversarial.py
"""

from __future__ import annotations

from trustfield.adversarial import (
    AdversarialGraphMutator,
    EvasionEvaluator,
    MutationStrategy,
    build_robustness_report,
)
from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph


# ---------------------------------------------------------------------------
# Build a representative cloud-privilege-escalation graph
# ---------------------------------------------------------------------------

def build_demo_graph() -> TrustGraph:
    """Multi-hop privilege escalation: user → workload → service chain → admin role."""
    g = TrustGraph()

    # Nodes
    g.add_node(NodeMetadata("attacker",    NodeType.USER,     "Attacker",       0.2, 0.1))
    g.add_node(NodeMetadata("svc_a",       NodeType.SERVICE,  "Service-A",      0.5, 0.5))
    g.add_node(NodeMetadata("svc_b",       NodeType.SERVICE,  "Service-B",      0.7, 0.6))
    g.add_node(NodeMetadata("svc_c",       NodeType.SERVICE,  "Service-C",      0.8, 0.7))
    g.add_node(NodeMetadata("wl_proxy",    NodeType.WORKLOAD, "Proxy-Workload", 0.4, 0.3))
    g.add_node(NodeMetadata("admin_role",  NodeType.ROLE,     "Admin-Role",     0.9, 0.9))
    g.add_node(NodeMetadata("secret_data", NodeType.SECRET,   "Secret-Data",    0.1, 1.0))

    # Edges (high weight = high exploitability)
    g.add_edge("attacker",   "svc_a",      EdgeMetadata("e1", EdgeType.AUTHENTICATE_AS, 0.85, 6))
    g.add_edge("svc_a",      "wl_proxy",   EdgeMetadata("e2", EdgeType.AUTHENTICATE_AS, 0.80, 6))
    g.add_edge("wl_proxy",   "svc_b",      EdgeMetadata("e3", EdgeType.AUTHENTICATE_AS, 0.75, 6))
    g.add_edge("svc_b",      "svc_c",      EdgeMetadata("e4", EdgeType.AUTHENTICATE_AS, 0.90, 6))
    g.add_edge("svc_c",      "admin_role", EdgeMetadata("e5", EdgeType.ASSUME_ROLE,     0.95, 6))
    g.add_edge("admin_role", "secret_data",EdgeMetadata("e6", EdgeType.TOKEN_MINT,      0.95, 4))

    return g


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print("TrustField Adversarial Robustness Demo")
    print("=" * 70)

    graph = build_demo_graph()
    seed_nodes = ["attacker"]
    orchestrator = TrustFieldOrchestrator(db_path=":memory:")
    mutator = AdversarialGraphMutator(exploitability_threshold=0.6)

    print(f"\nOriginal graph: {graph.nx_graph.number_of_nodes()} nodes, "
          f"{graph.nx_graph.number_of_edges()} edges")

    # -----------------------------------------------------------------------
    # Demonstrate each mutation strategy
    # -----------------------------------------------------------------------
    strategies_demo = [
        (MutationStrategy.EDGE_SPLITTING,    0.6),
        (MutationStrategy.PRIVILEGE_DILUTION, 0.6),
        (MutationStrategy.CHAIN_OBFUSCATION, 0.8),
    ]

    print("\n--- Mutation Strategy Preview ---")
    for strategy, intensity in strategies_demo:
        mutated = mutator.mutate(graph, strategy, intensity=intensity, seed=42)
        delta_nodes = mutated.nx_graph.number_of_nodes() - graph.nx_graph.number_of_nodes()
        delta_edges = mutated.nx_graph.number_of_edges() - graph.nx_graph.number_of_edges()
        print(f"  {strategy.value:<24} intensity={intensity:.1f}  "
              f"Δnodes={delta_nodes:+d}  Δedges={delta_edges:+d}")

    # -----------------------------------------------------------------------
    # Full evasion evaluation sweep
    # -----------------------------------------------------------------------
    print("\n--- Running Evasion Evaluation (3 strategies × 3 intensities) ---")
    evaluator = EvasionEvaluator(
        mutator=mutator,
        traversal_max_depth=8,
        percolation_n_trials=20,
        mutation_seed=42,
    )
    results = evaluator.evaluate(
        graph,
        seed_nodes=seed_nodes,
        orchestrator=orchestrator,
        strategies=list(MutationStrategy),
        intensities=[0.2, 0.4, 0.6],
    )

    print(f"\n{'Strategy':<24} {'Int':>4}  {'VBR₀':>5}  {'VBRₘ':>5}  "
          f"{'EGD₀':>6}  {'EGDₘ':>6}  {'ΔEGD':>7}  {'Robust':>7}  {'Evasion'}")
    print("-" * 82)
    for r in results:
        evasion = "YES" if r.evasion_success else "no"
        print(
            f"  {r.strategy:<22} {r.intensity:>4.1f}  {r.original_vbr_size:>5}  "
            f"{r.mutated_vbr_size:>5}  {r.original_egd_score:>6.3f}  "
            f"{r.mutated_egd_score:>6.3f}  {r.evasion_improvement:>+7.3f}  "
            f"{r.trustfield_robustness:>7.3f}  {evasion}"
        )

    # -----------------------------------------------------------------------
    # Build and display the robustness report
    # -----------------------------------------------------------------------
    report = build_robustness_report(results)

    print("\n" + "=" * 70)
    print("ROBUSTNESS REPORT SUMMARY")
    print("=" * 70)
    print(f"  Overall robustness score : {report.overall_robustness_score:.4f}")
    print(f"  Most effective strategy  : {report.most_effective_strategy}")
    print(f"  Most vulnerable topology : {report.most_vulnerable_topology}")

    evasion_count = sum(1 for r in results if r.evasion_success)
    print(f"  Evasion successes        : {evasion_count} / {len(results)}")

    print("\n--- Auto-generated Conclusion ---")
    print(report.conclusion)

    print("\n--- Markdown Table (first 3 rows) ---")
    md_lines = report.markdown_table.splitlines()
    for line in md_lines[:5]:
        print(line)
    if len(md_lines) > 5:
        print(f"  ... ({len(md_lines) - 5} more rows)")

    print("\n--- LaTeX Table (excerpt) ---")
    latex_lines = report.latex_table.splitlines()
    for line in latex_lines[:6]:
        print(line)
    print("  ...")

    print("\nDemo complete.")


if __name__ == "__main__":
    main()
