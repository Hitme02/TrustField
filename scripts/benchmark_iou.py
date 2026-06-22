"""
Propagation model IoU accuracy benchmark at N=1000 and N=5000.

Ground truth = set of nodes reachable from the seed via directed BFS
on the actual TrustGraph (networkx descendants + seed).

Each model's "predicted" set = nodes with per_node_risk >= THRESHOLD.
Ensemble uses topology-aware weights from TopologyAwareSelector.

Usage (from project root):
    python scripts/benchmark_iou.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import networkx as nx

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.graph import IAMSimulator, TopologyFingerprinter
from trustfield.graph.node_types import NodeType
from trustfield.propagation import PropagationRunner
from trustfield.ensemble import EnsemblePredictor, FusionMode, TopologyAwareSelector

# ─── CONFIG ─────────────────────────────────────────────────────────────────

NODE_SIZES    = [1000, 5000]
TOPOLOGIES    = ["hub", "chain", "dense_cluster", "mixed"]
N_SCENARIOS   = 5          # independent seeds per (topology, N) pair
THRESHOLD     = 0.30       # risk score cutoff for "predicted compromised"
PERC_TRIALS   = {          # reduce MC trials at large N to keep runtime sane
    1000: 50,
    5000: 20,
}
SEEDS         = [42, 7, 13, 99, 123]

MODEL_ORDER   = [
    "graph_traversal",
    "spectral_cascade",
    "percolation",
    "control_system",
    "epidemic",
]
MODEL_LABELS  = {
    "graph_traversal":  "BFS",
    "spectral_cascade": "Spectral",
    "percolation":      "Percolation",
    "control_system":   "Control Sys",
    "epidemic":         "SIR Epidemic",
}

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def pick_seed(graph):
    """Pick a low-privilege SERVICE node as the breach entry point."""
    nodes = graph.get_nodes_by_type(NodeType.SERVICE)
    if nodes:
        return min(nodes, key=lambda n: n.privilege_level).node_id
    return next(iter(graph._graph.nodes()))


def ground_truth(graph, seed_id: str) -> set:
    """BFS reachability from seed on the directed graph (networkx)."""
    return nx.descendants(graph._graph, seed_id) | {seed_id}


def iou(predicted: set, true: set) -> float:
    if not predicted and not true:
        return 1.0
    inter = len(predicted & true)
    union = len(predicted | true)
    return inter / union if union else 0.0


def predicted_set(result, threshold: float) -> set:
    return {n for n, r in result.per_node_risk.items() if r >= threshold}


def ensemble_predicted(propagation_results, graph, fp):
    """Return ensemble predicted set using topology-aware weights."""
    selector  = TopologyAwareSelector()
    predictor = EnsemblePredictor()
    wv        = selector.get_weights_for_topology_type(fp.topology_type)
    pred      = predictor.predict(
        propagation_results, wv,
        fusion_mode=FusionMode.WEIGHTED,
        decision_threshold=THRESHOLD,
    )
    return pred.compromised_nodes


# ─── BENCHMARK ───────────────────────────────────────────────────────────────

sim     = IAMSimulator()
runner  = PropagationRunner()
fp_eng  = TopologyFingerprinter()

# results[N][topology][model_name] = list of IoU floats across scenarios
results: dict = {}

total_start = time.perf_counter()

for N in NODE_SIZES:
    results[N] = {}
    n_trials = PERC_TRIALS[N]

    for topo in TOPOLOGIES:
        print(f"\nN={N:,}  topology={topo}  ({N_SCENARIOS} scenarios) ...", flush=True)
        iou_per_model: dict[str, list] = {m: [] for m in MODEL_ORDER}
        iou_per_model["ensemble"] = []

        for run_idx, seed in enumerate(SEEDS[:N_SCENARIOS]):
            t0 = time.perf_counter()
            graph = sim.generate(topo, num_nodes=N, seed=seed)
            fp    = fp_eng.fingerprint(graph)
            entry = pick_seed(graph)
            gt    = ground_truth(graph, entry)

            prop_results = runner.run_all(
                graph, [entry],
                percolation={"n_trials": n_trials, "random_seed": seed},
            )
            elapsed = (time.perf_counter() - t0) * 1000

            # Per-model IoU
            for model_name in MODEL_ORDER:
                if model_name not in prop_results:
                    continue
                pred = predicted_set(prop_results[model_name], THRESHOLD)
                iou_per_model[model_name].append(iou(pred, gt))

            # Ensemble IoU
            ens_pred = ensemble_predicted(prop_results, graph, fp)
            iou_per_model["ensemble"].append(iou(ens_pred, gt))

            print(f"  scenario {run_idx+1}/{N_SCENARIOS}  seed={seed}  "
                  f"N={graph._graph.number_of_nodes()} nodes  "
                  f"|GT|={len(gt)}  time={elapsed:.0f}ms", flush=True)

        results[N][topo] = {
            m: (sum(v)/len(v) if v else 0.0)
            for m, v in iou_per_model.items()
        }

total_elapsed = time.perf_counter() - total_start

# ─── PRINT RESULTS ───────────────────────────────────────────────────────────

COL_W = 13
TOPO_W = 14

def hr(): print("─" * (TOPO_W + (COL_W + 1) * (len(MODEL_ORDER) + 2)))

print("\n")
print("=" * 80)
print("  TrustField — Propagation Model IoU Accuracy Benchmark")
print(f"  Threshold={THRESHOLD}, Monte Carlo trials: N=1000→{PERC_TRIALS[1000]}, N=5000→{PERC_TRIALS[5000]}")
print(f"  Scenarios per cell: {N_SCENARIOS}  |  Total wall time: {total_elapsed:.1f}s")
print("=" * 80)

all_labels = [MODEL_LABELS[m] for m in MODEL_ORDER] + ["Ensemble", "Mean IoU"]

for N in NODE_SIZES:
    print(f"\n{'─'*80}")
    print(f"  N = {N:,} nodes")
    print(f"{'─'*80}")

    # Header
    header = f"{'Topology':<{TOPO_W}}"
    for lbl in all_labels:
        header += f"  {lbl:>{COL_W-2}}"
    print(header)
    print("─" * len(header))

    for topo in TOPOLOGIES:
        row_data = results[N][topo]
        model_ious = [row_data.get(m, 0.0) for m in MODEL_ORDER]
        ens_iou    = row_data.get("ensemble", 0.0)
        mean_iou   = sum(model_ious) / len(model_ious)

        row = f"{topo:<{TOPO_W}}"
        for v in model_ious:
            row += f"  {v:>{COL_W-2}.3f}"
        row += f"  {ens_iou:>{COL_W-2}.3f}"
        row += f"  {mean_iou:>{COL_W-2}.3f}"
        print(row)

    # Column means
    print("─" * len(header))
    means_row = f"{'MEAN':<{TOPO_W}}"
    for m in MODEL_ORDER:
        col_vals = [results[N][t].get(m, 0.0) for t in TOPOLOGIES]
        means_row += f"  {sum(col_vals)/len(col_vals):>{COL_W-2}.3f}"
    ens_vals = [results[N][t].get("ensemble", 0.0) for t in TOPOLOGIES]
    means_row += f"  {sum(ens_vals)/len(ens_vals):>{COL_W-2}.3f}"
    all_vals = [results[N][t].get(m, 0.0) for t in TOPOLOGIES for m in MODEL_ORDER]
    means_row += f"  {sum(all_vals)/len(all_vals):>{COL_W-2}.3f}"
    print(means_row)

print(f"\n{'='*80}\n")
