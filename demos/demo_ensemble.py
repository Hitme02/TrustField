"""Demo: Module 3 — Ensemble Predictor with Topology-Aware Model Selection.

Shows:
  1. analyze_from_topology for hub, chain, and dense_cluster
  2. Per-topology comparison table
  3. Ensemble vs individual model comparison for hub
  4. Adaptive weight update demonstration
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.ensemble import (
    TrustFieldOrchestrator,
    FusionMode,
    WeightTracker,
)
from trustfield.ensemble.topology_selector import TopologyAwareSelector
from trustfield.graph.iam_simulator import IAMSimulator

# ---------------------------------------------------------------------------
# Section 1 & 2: Run all three topologies, print comparison table
# ---------------------------------------------------------------------------

print("=" * 70)
print("TrustField Module 3 — Ensemble Predictor Demo")
print("=" * 70)

orch = TrustFieldOrchestrator(db_path=":memory:")

topologies = ["hub", "chain", "dense_cluster"]
results = {}

print("\n[1] Running analyze_from_topology for hub, chain, dense_cluster ...\n")

for topo in topologies:
    result = orch.analyze_from_topology(topo, num_nodes=40, seed=42)
    results[topo] = result

# Build comparison table
print("[2] Per-Topology Comparison Table")
print("-" * 70)
header = f"{'Topology':<15} {'Weight Source':<18} {'Blast Radius':<14} {'Agreement':<12} {'Uncertainty%'}"
print(header)
print("-" * 70)

for topo, result in results.items():
    summary = result.get_metrics_summary()
    n_total = result.ensemble_prediction.total_nodes_analyzed
    blast = summary["predicted_blast_radius"] / n_total if n_total > 0 else 0.0
    agreement = summary["model_agreement_score"]
    uncertainty = summary["high_uncertainty_fraction"] * 100
    wsource = result.weight_source

    print(
        f"{topo:<15} {wsource:<18} {blast:<14.3f} {agreement:<12.3f} {uncertainty:.1f}%"
    )

print("-" * 70)

# ---------------------------------------------------------------------------
# Section 3: Ensemble vs individual models for hub
# ---------------------------------------------------------------------------

print("\n[3] Ensemble vs Individual Models — Hub Topology")
print("-" * 70)

hub_result = results["hub"]
pred = hub_result.ensemble_prediction
prop_results = hub_result.propagation_results

n_total_nodes = hub_result.graph_summary["node_count"]

print(f"Total nodes: {n_total_nodes}")
print(f"Ensemble compromised: {len(pred.compromised_nodes)} nodes  "
      f"(risk threshold {pred.decision_threshold})")
print(f"High-uncertainty nodes (within compromised): {len(pred.high_uncertainty_nodes)}")
print()

# Per-model breakdown
print(f"{'Model':<20} {'Weight':>8} {'Compromised':>12} {'Cascade Prob':>13}")
print("-" * 56)

for contrib in pred.model_contributions:
    m = contrib.model_name
    w = contrib.weight
    pr = prop_results[m]
    n_comp = len(pr.compromised_nodes)
    casc = pr.cascade_probability
    print(f"{m:<20} {w:>8.3f} {n_comp:>12} {casc:>13.3f}")

print("-" * 56)
print(f"{'ENSEMBLE':<20} {'':>8} {len(pred.compromised_nodes):>12}")

# Show weight vector
print("\nWeight vector used:")
for model, w in sorted(hub_result.weight_vector_used.weights.items(), key=lambda x: -x[1]):
    bar = "#" * int(w * 40)
    print(f"  {model:<22} {w:.3f}  {bar}")

# ---------------------------------------------------------------------------
# Section 4: Adaptive weight update demonstration
# ---------------------------------------------------------------------------

print("\n[4] Adaptive Weight Update Demonstration")
print("-" * 70)

tracker = WeightTracker(db_path=":memory:")
selector = TopologyAwareSelector()

# Simulate fresh graph
sim = IAMSimulator()
graph = sim.generate("hub", num_nodes=30, seed=10)
node_list = sorted(graph._graph.nodes())
seed_node = node_list[0]

# Get initial topology-prior weights
from trustfield.graph.fingerprinter import TopologyFingerprinter
fp = TopologyFingerprinter().fingerprint(graph)
prior_wv = selector.get_initial_weights(fp)

print(f"Topology detected: {fp.topology_type.value}")
print(f"\nBefore learning — topology prior weights (source='{prior_wv.source}'):")
for model, w in sorted(prior_wv.weights.items(), key=lambda x: -x[1]):
    print(f"  {model:<22} {w:.3f}")

# Inject 6 mock accuracy records (graph_traversal and percolation perform well on hub)
topo_str = fp.topology_type.value
mock_scores = {
    "graph_traversal":  [{"predicted": {"n1","n2","n3","n4","n5"}, "actual": {"n1","n2","n3","n4","n5"}}] * 6,
    "epidemic":         [{"predicted": {"n1","n2"},               "actual": {"n1","n2","n3","n4","n5"}}] * 6,
    "spectral_cascade": [{"predicted": {"n1"},                    "actual": {"n1","n2","n3","n4","n5"}}] * 6,
    "percolation":      [{"predicted": {"n1","n2","n3","n4","n5"}, "actual": {"n1","n2","n3","n4","n5"}}] * 6,
    "control_system":   [{"predicted": {"n1","n2"},               "actual": {"n1","n2","n3","n4","n5"}}] * 6,
}

print(f"\nRecording 6 accuracy observations per model for topology '{topo_str}' ...")

for model, records in mock_scores.items():
    for rec in records:
        tracker.record_result(model, topo_str, rec["predicted"], rec["actual"])

adaptive_wv = tracker.get_adaptive_weights(topo_str, min_history=5)

if adaptive_wv is not None:
    print(f"\nAfter learning — adaptive weights (source='{adaptive_wv.source}'):")
    for model, w in sorted(adaptive_wv.weights.items(), key=lambda x: -x[1]):
        prior = prior_wv.weights.get(model, 0.0)
        delta = w - prior
        arrow = "▲" if delta > 0.005 else ("▼" if delta < -0.005 else "~")
        print(f"  {model:<22} {w:.3f}  (prior: {prior:.3f})  {arrow} {delta:+.3f}")
    print("\nModels with high empirical F1 (graph_traversal, percolation) received")
    print("higher adaptive weights; spectral_cascade penalized for low F1 on DAG hub.")
else:
    print("Not enough history for adaptive weights (need min_history=5 per model).")

print("\n" + "=" * 70)
print("Module 3 Demo complete.")
print("=" * 70)
