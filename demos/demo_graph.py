"""TrustField Module 1 — demonstration script.

Generates hub, chain, and dense_cluster trust graphs (seed=42), prints a
summary table with key structural metrics and topology classification,
shows the top-3 privilege escalation paths for each graph, exports all three
to JSON in the output/ directory, and reports fingerprinting timing.

Run from the project root:
    python demos/demo_graph.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure the project root is on sys.path when run directly (python demos/demo_graph.py)
sys.path.insert(0, str(Path(__file__).parent.parent))


def main() -> None:
    from trustfield.graph import IAMSimulator, TopologyFingerprinter

    sim = IAMSimulator()
    fp_engine = TopologyFingerprinter()

    output_dir = Path(__file__).parent.parent / "output"
    output_dir.mkdir(exist_ok=True)

    topologies = ["hub", "chain", "dense_cluster"]
    graphs = {}
    fingerprints = {}
    timings = {}

    print("\n=== TrustField — Module 1: Trust Graph Construction ===\n")

    # -------------------------------------------------------------------------
    # Generate graphs
    # -------------------------------------------------------------------------
    for topo in topologies:
        g = sim.generate(topo, num_nodes=40, seed=42)
        graphs[topo] = g

    # -------------------------------------------------------------------------
    # Fingerprint with timing
    # -------------------------------------------------------------------------
    for topo, g in graphs.items():
        t0 = time.perf_counter()
        fp = fp_engine.fingerprint(g)
        elapsed = time.perf_counter() - t0
        fingerprints[topo] = fp
        timings[topo] = elapsed

    # -------------------------------------------------------------------------
    # Summary table
    # -------------------------------------------------------------------------
    col_w = [14, 7, 7, 12, 16, 13, 16]
    headers = [
        "Topology", "Nodes", "Edges", "Clustering",
        "Centrality Var", "Spectral Gap", "Classification",
    ]

    def fmt_row(cells):
        return "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, col_w)) + " |"

    separator = "+-" + "-+-".join("-" * w for w in col_w) + "-+"

    print(separator)
    print(fmt_row(headers))
    print(separator)

    for topo in topologies:
        fp = fingerprints[topo]
        g = graphs[topo]
        s = g.summary()
        row = [
            topo,
            s["node_count"],
            s["edge_count"],
            f"{fp.clustering_coefficient:.4f}",
            f"{fp.centrality_variance:.4f}",
            f"{fp.spectral_gap:.4f}",
            fp.topology_type.value,
        ]
        print(fmt_row(row))

    print(separator)

    # -------------------------------------------------------------------------
    # Model weight hints
    # -------------------------------------------------------------------------
    print("\n--- Ensemble Model Weight Hints ---\n")
    model_keys = ["graph_traversal", "epidemic", "spectral", "percolation", "control_system"]
    hint_col_w = [14] + [14] * len(model_keys)
    hint_headers = ["Topology"] + model_keys
    hint_sep = "+-" + "-+-".join("-" * w for w in hint_col_w) + "-+"

    print(hint_sep)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(hint_headers, hint_col_w)) + " |")
    print(hint_sep)

    for topo in topologies:
        fp = fingerprints[topo]
        row = [topo] + [f"{fp.model_weight_hints[k]:.2f}" for k in model_keys]
        print("| " + " | ".join(str(c).ljust(w) for c, w in zip(row, hint_col_w)) + " |")

    print(hint_sep)

    # -------------------------------------------------------------------------
    # Privilege escalation paths (top-3 per topology)
    # -------------------------------------------------------------------------
    print("\n--- Top-3 Privilege Escalation Paths (target privilege >= 0.8) ---\n")

    for topo, g in graphs.items():
        print(f"  [{topo.upper()}]")
        # Start from the first low-privilege USER node we find
        users = g.get_nodes_by_type(__import__("trustfield.graph", fromlist=["NodeType"]).NodeType.USER)
        low_priv_users = sorted(users, key=lambda u: u.privilege_level)
        source_candidates = low_priv_users if low_priv_users else list(g._graph.nodes())[:3]

        all_paths = []
        for candidate in source_candidates[:5]:
            src_id = candidate.node_id if hasattr(candidate, "node_id") else candidate
            try:
                paths = g.get_privilege_escalation_paths(src_id, target_privilege=0.8)
                all_paths.extend(paths)
            except Exception:
                continue

        if not all_paths:
            # Fallback: try from all nodes
            for nid in list(g._graph.nodes())[:10]:
                try:
                    paths = g.get_privilege_escalation_paths(nid, target_privilege=0.8)
                    all_paths.extend(paths)
                except Exception:
                    continue

        # Sort by length (shorter paths = more direct escalation risk)
        all_paths_sorted = sorted(all_paths, key=len)
        top3 = all_paths_sorted[:3]

        if top3:
            for i, path in enumerate(top3, 1):
                # Build human-readable path with node names
                labels = []
                for nid in path:
                    try:
                        meta = g.get_node(nid)
                        labels.append(f"{meta.name}({meta.node_type.value[0]}:{meta.privilege_level:.2f})")
                    except Exception:
                        labels.append(nid)
                path_str = " -> ".join(labels)
                print(f"    Path {i} ({len(path)} hops): {path_str}")
        else:
            print("    No escalation paths found from entry-point nodes.")
        print()

    # -------------------------------------------------------------------------
    # JSON export
    # -------------------------------------------------------------------------
    print("--- Exporting graphs to JSON ---\n")
    for topo, g in graphs.items():
        out_path = output_dir / f"graph_{topo}.json"
        graph_dict = g.to_dict()
        # Attach fingerprint metadata to the export
        fp = fingerprints[topo]
        graph_dict["fingerprint"] = fp.to_dict()
        with open(out_path, "w") as f:
            json.dump(graph_dict, f, indent=2)
        size_kb = out_path.stat().st_size / 1024
        print(f"  {topo:16s} -> {out_path}  ({size_kb:.1f} KB)")

    # -------------------------------------------------------------------------
    # Fingerprinting timing
    # -------------------------------------------------------------------------
    print("\n--- Fingerprinting Timing ---\n")
    for topo in topologies:
        print(f"  {topo:16s}: {timings[topo]*1000:.2f} ms")

    print("\n=== Module 1 demo complete ===\n")


if __name__ == "__main__":
    main()
