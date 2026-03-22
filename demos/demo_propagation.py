"""TrustField Module 2 — Multi-Model Propagation Engine demo.

Demonstrates all five propagation models on hub, chain, and dense_cluster
topologies. Shows a side-by-side comparison table, the ComparisonReport,
and how results differ across topology types.

Run from the project root:
    python demos/demo_propagation.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.graph import IAMSimulator, TopologyFingerprinter
from trustfield.graph.node_types import NodeType
from trustfield.propagation import PropagationRunner


def pick_entry_seed(graph, preferred_type=NodeType.SERVICE):
    """Return the lowest-privilege node of the given type."""
    nodes = graph.get_nodes_by_type(preferred_type)
    if nodes:
        return min(nodes, key=lambda n: n.privilege_level).node_id
    return next(iter(graph._graph.nodes()))


def print_separator(char="=", width=100):
    print(char * width)


def print_model_table(results):
    """Print a side-by-side comparison table of all model results."""
    headers = ["Model", "Compromised", "Depth", "Cascade Prob", "Confidence", "Conv?", "Time (ms)"]
    col_w   = [18,       12,           7,       13,             11,           6,       10]

    sep = "+-" + "-+-".join("-" * w for w in col_w) + "-+"
    row_fmt = "| " + " | ".join("{:<" + str(w) + "}" for w in col_w) + " |"

    print(sep)
    print(row_fmt.format(*headers))
    print(sep)

    order = ["graph_traversal", "epidemic", "spectral_cascade",
             "percolation", "control_system"]
    for name in order:
        if name not in results:
            continue
        r = results[name]
        print(row_fmt.format(
            name,
            len(r.compromised_nodes),
            r.propagation_depth,
            f"{r.cascade_probability:.3f}",
            f"{r.model_confidence:.2f}",
            "Y" if r.convergence_achieved else "N",
            f"{r.computation_time_ms:.1f}",
        ))
    print(sep)


def print_comparison_report(report):
    print(f"  Union compromised  : {len(report.union_compromised)} nodes")
    print(f"  Intersection       : {len(report.intersection_compromised)} nodes")
    print(f"  Agreement (Jaccard): {report.agreement_score:.4f}")
    print(f"  Avg cascade prob   : {report.avg_cascade_probability:.3f}  "
          f"(spread ±{report.cascade_probability_spread:.3f})")
    print(f"  Top-5 most dangerous nodes:")
    for i, nid in enumerate(report.most_dangerous_nodes, 1):
        count = report.per_node_consensus.get(nid, 0)
        print(f"    {i}. {nid}  (flagged by {count}/5 models)")


def main():
    sim     = IAMSimulator()
    runner  = PropagationRunner()
    fp_eng  = TopologyFingerprinter()

    print_separator()
    print("  TrustField — Module 2: Multi-Model Propagation Engine")
    print_separator()

    # -------------------------------------------------------------------------
    # Section 1: Full analysis on hub topology
    # -------------------------------------------------------------------------
    print("\n[1] Hub topology — full 5-model run\n")

    hub_g    = sim.generate("hub",   num_nodes=40, seed=42)
    hub_seed = [pick_entry_seed(hub_g)]
    hub_fp   = fp_eng.fingerprint(hub_g)

    print(f"  Graph  : {hub_g._graph.number_of_nodes()} nodes, "
          f"{hub_g._graph.number_of_edges()} edges  |  "
          f"Classification: {hub_fp.topology_type.value}")
    print(f"  Attack entry point: {hub_seed[0]}  "
          f"(privilege={hub_g.get_node(hub_seed[0]).privilege_level:.2f})\n")

    t0 = time.perf_counter()
    hub_results = runner.run_all(
        hub_g, hub_seed,
        percolation={"n_trials": 100, "random_seed": 42},
    )
    total_ms = (time.perf_counter() - t0) * 1000

    print_model_table(hub_results)
    print(f"\n  Total wall time for all 5 models: {total_ms:.1f} ms\n")

    hub_report = runner.compare_results(hub_results)
    print("  ComparisonReport:")
    print_comparison_report(hub_report)

    # -------------------------------------------------------------------------
    # Section 2: Spectral cascade details
    # -------------------------------------------------------------------------
    print("\n[2] Spectral cascade details (hub)\n")
    sc = hub_results["spectral_cascade"]
    print(f"  lambda_max            : {sc.raw_output['lambda_max']:.4f}")
    print(f"  spectral_gap          : {sc.raw_output['spectral_gap']:.4f}")
    print(f"  cascade_condition_met : {sc.raw_output['cascade_condition_met']}")
    print(f"  cascade_probability   : {sc.cascade_probability:.4f}")
    top_eigen = sorted(
        sc.raw_output["eigenvector_centrality"].items(),
        key=lambda kv: kv[1], reverse=True
    )[:3]
    print("  Top-3 nodes by eigenvector centrality:")
    for nid, val in top_eigen:
        meta = hub_g.get_node(nid)
        print(f"    {nid}  ({meta.name}, priv={meta.privilege_level:.2f})  ec={val:.4f}")

    # -------------------------------------------------------------------------
    # Section 3: Control system details
    # -------------------------------------------------------------------------
    print("\n[3] Control system details (hub)\n")
    cs = hub_results["control_system"]
    print(f"  spectral_radius (norm): {cs.raw_output['spectral_radius']:.4f}")
    print(f"  stability_margin      : {cs.raw_output['stability_margin']:.4f}")
    print(f"  system_stable         : {cs.raw_output['system_stable']}")
    print(f"  trajectory length     : {len(cs.raw_output['state_trajectory'])} steps")

    # -------------------------------------------------------------------------
    # Section 4: Cross-topology comparison
    # -------------------------------------------------------------------------
    print("\n[4] Cross-topology comparison\n")

    topologies = {
        "hub":          sim.generate("hub",           num_nodes=40, seed=42),
        "chain":        sim.generate("chain",         num_nodes=30, seed=42),
        "dense_cluster":sim.generate("dense_cluster", num_nodes=40, seed=42),
    }

    col_w2 = [15, 7, 7, 12, 16, 13, 12, 12]
    headers2 = ["Topology", "Nodes", "Edges", "Seed entry",
                "Union comp.", "Intersect.", "Agreement", "Avg cascade"]
    sep2 = "+-" + "-+-".join("-" * w for w in col_w2) + "-+"
    row_fmt2 = "| " + " | ".join("{:<" + str(w) + "}" for w in col_w2) + " |"

    print(sep2)
    print(row_fmt2.format(*headers2))
    print(sep2)

    for topo_name, g in topologies.items():
        seed = [pick_entry_seed(g)]
        results = runner.run_all(
            g, seed,
            percolation={"n_trials": 50, "random_seed": 42},
        )
        report = runner.compare_results(results)
        print(row_fmt2.format(
            topo_name,
            g._graph.number_of_nodes(),
            g._graph.number_of_edges(),
            seed[0][:12],
            len(report.union_compromised),
            len(report.intersection_compromised),
            f"{report.agreement_score:.3f}",
            f"{report.avg_cascade_probability:.3f}",
        ))

    print(sep2)
    print("\n=== Module 2 demo complete ===\n")


if __name__ == "__main__":
    main()
