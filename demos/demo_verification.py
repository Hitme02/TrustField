"""Demo: Module 4 — Verification Engine (ExploitabilityGap analysis).

Full pipeline end-to-end for hub, chain, and dense_cluster topologies:
  Modules 1–3:  graph generation → fingerprint → ensemble prediction
  Module 4:     IAM traversal → blast radius → gap analysis

Outputs:
  - Executive summary per topology
  - Markdown results table  (paper Table 1)
  - LaTeX results table     (copy-paste for paper)
  - verification_results.csv (supplementary material)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.verification import (
    BlastRadiusCalculator,
    ExploitabilityGapAnalyzer,
    IAMTraversal,
    TokenGenerator,
    VerificationReport,
)

RANDOM_SEED = 42   # for reproducible condition checks in IAM traversal
NUM_NODES = 40
TOPOLOGIES = ["hub", "chain", "dense_cluster"]

# ---------------------------------------------------------------------------
# Run pipeline for each topology
# ---------------------------------------------------------------------------

print("=" * 70)
print("TrustField Module 4 — Verification Engine Demo")
print("=" * 70)

sim = IAMSimulator()
orch = TrustFieldOrchestrator(db_path=":memory:")
calc = BlastRadiusCalculator()
analyzer = ExploitabilityGapAnalyzer()

analyses = {}       # topology → BlastRadiusAnalysis
reports = {}        # topology → VerificationReport

for topo in TOPOLOGIES:
    print(f"\n[{topo.upper()}] Running Modules 1–3 + verification...")

    # --- Modules 1–3 ---
    graph = sim.generate(topo, num_nodes=NUM_NODES, seed=42)
    # Prefer a node that has outgoing edges (inbound spokes / services make
    # realistic attacker entry points rather than dead-end leaf nodes).
    node_list = sorted(graph._graph.nodes())
    seed_node = next(
        (n for n in node_list if graph._graph.out_degree(n) > 0),
        node_list[0],
    )
    analysis = orch.analyze(graph, seed_nodes=[seed_node])

    # --- Module 4: IAM traversal (VBR) ---
    gen = TokenGenerator()
    traversal = IAMTraversal(gen).traverse(
        graph,
        seed_nodes=[seed_node],
        max_depth=6,
        respect_conditions=True,
        random_seed=RANDOM_SEED,
    )

    # --- Blast radius comparison ---
    bra = calc.compute(analysis.ensemble_prediction, traversal, graph)

    report = VerificationReport(
        graph=graph,
        analysis_result=analysis,
        traversal_result=traversal,
        blast_radius_analysis=bra,
    )
    analyses[topo] = bra
    reports[topo] = report

    print(f"  {report.get_executive_summary()}")

    topo_type = analysis.topology_fingerprint.topology_type.value
    print(f"  Topology detected : {topo_type}")
    print(f"  Weight source     : {analysis.weight_source}")
    print(f"  Decision threshold: {analysis.ensemble_prediction.decision_threshold}")
    print(
        f"  Tokens issued / validated / rejected: "
        f"{traversal.total_tokens_generated} / "
        f"{traversal.total_tokens_validated} / "
        f"{traversal.total_tokens_rejected}"
    )
    if bra.critical_paths:
        print(f"  Critical paths to high-privilege nodes: {len(bra.critical_paths)}")
        for path in bra.critical_paths[:3]:
            print(f"    {' → '.join(path)}")

    if bra.missed_nodes:
        print(
            f"  *** CRITICAL MISS: ensemble missed {len(bra.missed_nodes)} "
            f"verified-reachable node(s): {sorted(bra.missed_nodes)}"
        )

# ---------------------------------------------------------------------------
# Cross-topology gap analysis
# ---------------------------------------------------------------------------

gap_report = analyzer.analyze_across_topologies(analyses)

for topo, report in reports.items():
    report.gap_analysis_report = gap_report

print("\n" + "=" * 70)
print("PAPER TABLE 1 — ExploitabilityGap Analysis (Markdown)")
print("=" * 70)
print(analyzer.to_markdown_table(gap_report))

print(f"\nAggregate gap score : {gap_report.aggregate_gap_score:.4f}")
print(f"Best calibration    : {gap_report.best_topology}")
print(f"Worst calibration   : {gap_report.worst_topology}")
print(f"Critical misses     : {gap_report.critical_miss_count}")

print("\n" + "=" * 70)
print("PAPER TABLE 1 — LaTeX (copy-paste ready)")
print("=" * 70)
print(analyzer.to_latex_table(gap_report))

# ---------------------------------------------------------------------------
# CSV export (supplementary material)
# ---------------------------------------------------------------------------

csv_path = Path(__file__).parent.parent / "verification_results.csv"
# Use last topology's report for the CSV export
last_topo = TOPOLOGIES[-1]
reports[last_topo].export_csv(str(csv_path))
print(f"\nPer-node CSV exported to: {csv_path}")
print("  Columns: node_id, type, privilege, in_pbr, in_vbr, exploitability_score, gap_classification")

print("\n" + "=" * 70)
print("Module 4 Demo complete.")
print("=" * 70)
