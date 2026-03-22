"""Demo: TrustField GNN Propagation Model.

Trains the Graph Convolutional Network on synthetic IAM graphs, evaluates
per-topology F1, then runs the full TrustField ensemble on a chain graph
to show the GNN's contribution alongside the classical models.

Usage:
    python demos/demo_gnn.py
"""

from __future__ import annotations

import time
from pathlib import Path


def main() -> None:
    print("=" * 70)
    print("  TrustField — GNN Propagation Model Demo")
    print("=" * 70)
    print()

    # ------------------------------------------------------------------
    # Step 1: Check torch availability
    # ------------------------------------------------------------------
    try:
        import torch
        print(f"  PyTorch {torch.__version__} available — running GCN training.\n")
    except ImportError:
        print("  PyTorch not installed.  GNNModel will fall back to GraphTraversal.")
        print("  Install with: pip install torch")
        print()
        _demo_fallback()
        return

    # ------------------------------------------------------------------
    # Step 2: Train the GCN on synthetic data
    # ------------------------------------------------------------------
    from trustfield.propagation.gnn_trainer import GCNModel, GNNTrainer
    from trustfield.propagation.gnn_features import NUM_NODE_FEATURES

    print("  Generating training data (200 synthetic IAM graphs) …")
    t0 = time.time()
    trainer = GNNTrainer(n_graphs=200, seed=42, max_epochs=80, patience=10)
    data = trainer.generate_training_data()
    print(f"  Generated {len(data)} graphs in {time.time() - t0:.1f}s\n")

    print("  Training GCN …")
    t0 = time.time()
    model = GCNModel(in_features=NUM_NODE_FEATURES)
    result = trainer.train(model, data)
    print(f"  Trained {result.epochs_trained} epochs in {result.training_time_s:.1f}s")
    print(f"  Best val F1:    {result.best_val_f1:.4f}")
    print(f"  Final train loss: {result.final_train_loss:.4f}")
    print(f"  Converged:      {result.converged}\n")

    # ------------------------------------------------------------------
    # Step 3: Per-topology evaluation
    # ------------------------------------------------------------------
    from trustfield.graph import IAMSimulator

    sim = IAMSimulator()
    print("── Per-Topology Evaluation ─────────────────────────────────────")
    print(f"  {'Topology':<16}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}")
    print(f"  {'-'*16}  {'-'*10}  {'-'*8}  {'-'*8}")

    for topo in ["chain", "hub", "dense_cluster"]:
        topo_trainer = GNNTrainer(n_graphs=30, seed=99)
        topo_data = topo_trainer.generate_training_data(topologies=[topo])
        m = topo_trainer.evaluate(model, topo_data)
        print(f"  {topo:<16}  {m['precision']:>10.4f}  {m['recall']:>8.4f}  {m['f1']:>8.4f}")

    # ------------------------------------------------------------------
    # Step 4: Save weights
    # ------------------------------------------------------------------
    weights_path = Path(__file__).parent.parent / "models" / "gnn.pt"
    weights_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), str(weights_path))
    print(f"\n  Weights saved → {weights_path}\n")

    # ------------------------------------------------------------------
    # Step 5: Baseline comparison (publication strength)
    # ------------------------------------------------------------------
    print("── Baseline Comparison ─────────────────────────────────────────")
    print("  Generating test set for baseline evaluation …")
    test_trainer = GNNTrainer(n_graphs=60, seed=13)
    test_data, test_graphs, test_seeds = test_trainer.generate_training_data(return_graphs=True)
    # Build GT sets from labels in GraphData
    gt_sets = [
        {gd.node_ids[i] for i, lbl in enumerate(gd.labels) if lbl > 0.5}
        for gd in test_data
    ]
    # evaluate_with_baselines needs a trained model set on the trainer
    trainer._trained_model = model
    bc = trainer.evaluate_with_baselines(test_data, test_graphs, test_seeds, gt_sets)

    print()
    print(f"  {'Baseline':<22}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}")
    print(f"  {'-'*22}  {'-'*10}  {'-'*8}  {'-'*8}")
    print(f"  {'Predict All':<22}  {'—':>10}  {'—':>8}  {bc.naive_all_f1:>8.4f}")
    print(f"  {'Predict Seed Only':<22}  {'—':>10}  {'—':>8}  {bc.naive_seed_f1:>8.4f}")
    print(f"  {'1-hop Neighbors':<22}  {'—':>10}  {'—':>8}  {bc.naive_neighbors_f1:>8.4f}")
    print(f"  {'GNN (ours)':<22}  {bc.gnn_precision:>10.4f}  {bc.gnn_recall:>8.4f}  {bc.gnn_f1:>8.4f}")
    print()
    sign = "+" if bc.gnn_improvement_over_best_naive >= 0 else ""
    print(f"  Improvement over best naive:  {sign}{bc.gnn_improvement_over_best_naive:+.4f}")
    print(f"  Verdict:  {bc.verdict}")
    print()

    # ------------------------------------------------------------------
    # Step 6: Cross-topology generalization (publication strength)
    # ------------------------------------------------------------------
    print("── Cross-Topology Generalization ───────────────────────────────")

    for train_t, test_t in [
        (["hub", "chain"], ["dense_cluster", "mixed"]),
        (["dense_cluster", "mixed"], ["hub", "chain"]),
    ]:
        print(f"  Train on {train_t}  →  test on {test_t} …")
        gen_trainer = GNNTrainer(n_graphs=200, seed=42, max_epochs=30, patience=8)
        gr = gen_trainer.cross_topology_generalization_test(
            train_topologies=train_t,
            test_topologies=test_t,
            n_train=120,
            n_test=40,
            epochs=30,
        )
        print(f"    In-distribution F1:       {gr.in_distribution_f1:.4f}")
        print(f"    Out-of-distribution F1:   {gr.out_of_distribution_f1:.4f}")
        print(f"    Generalization gap:       {gr.generalization_gap:.4f}")
        print(f"    Generalizes well:         {gr.generalizes_well}")
        print(f"    Verdict:                  {gr.verdict}")
        print()

    # ------------------------------------------------------------------
    # Step 7: Real-world fixture evaluation (publication strength)
    # ------------------------------------------------------------------
    print("── Real-World Fixture Evaluation ───────────────────────────────")
    print("  Running GNN on all AWS / K8s fixture files …")
    rw = trainer.evaluate_on_real_world(model=model)

    print()
    print(f"  {'Fixture':<30}  {'N':>4}  {'GT':>4}  {'Pred':>5}  {'F1':>7}  {'Miss?':>6}")
    print(f"  {'-'*30}  {'-'*4}  {'-'*4}  {'-'*5}  {'-'*7}  {'-'*6}")
    for r in rw.results:
        miss = "MISS" if r.critical_miss else "ok"
        print(
            f"  {r.fixture_name:<30}  {r.n_nodes:>4}  {r.ground_truth_size:>4}"
            f"  {r.gnn_prediction_size:>5}  {r.f1:>7.4f}  {miss:>6}"
        )
    print()
    print(f"  Mean F1:        {rw.mean_f1:.4f}")
    print(f"  Mean Precision: {rw.mean_precision:.4f}")
    print(f"  Mean Recall:    {rw.mean_recall:.4f}")
    if rw.fixtures_with_critical_miss:
        print(f"  Critical misses: {', '.join(rw.fixtures_with_critical_miss)}")
    print(f"  Real-world generalization: {rw.real_world_generalization}")
    print()

    # ------------------------------------------------------------------
    # Step 8: Run full ensemble on a chain graph
    # ------------------------------------------------------------------
    print("── Full Ensemble on Chain Graph (30 nodes) ─────────────────────")
    chain_graph = sim.generate("chain", num_nodes=30, seed=42)
    seed_node = sorted(chain_graph._graph.nodes())[0]

    from trustfield.ensemble import TrustFieldOrchestrator

    orch = TrustFieldOrchestrator(db_path=":memory:")
    analysis = orch.analyze(
        chain_graph,
        seed_nodes=[seed_node],
        model_kwargs={"percolation": {"n_trials": 50}},
    )

    ep = analysis.ensemble_prediction
    print(f"  Topology detected:    {analysis.topology_fingerprint.topology_type.value}")
    print(f"  Compromised nodes:    {len(ep.compromised_nodes)} / {chain_graph._graph.number_of_nodes()}")
    avg_risk = sum(ep.ensemble_risk.values()) / max(1, len(ep.ensemble_risk))
    print(f"  Avg ensemble risk:    {avg_risk:.3f}")
    print(f"  Weight source:        {analysis.weight_source}")
    print()

    print("  Per-model compromised counts:")
    for name, result in sorted(analysis.propagation_results.items()):
        print(f"    {name:<20}  {len(result.compromised_nodes):>3} nodes  "
              f"(conf={result.model_confidence:.2f})")

    print()
    print("  Top-5 most dangerous nodes:")
    for nid in analysis.comparison_report.most_dangerous_nodes:
        risk = ep.ensemble_risk.get(nid, 0.0)
        print(f"    {nid:<20}  ensemble_risk={risk:.3f}")

    print()
    print("=" * 70)
    print("  GNN demo complete.")
    print("=" * 70)
    print()
    print("  To run full publication-quality training (slower):")
    print("    t = GNNTrainer()")
    print("    r = t.train(n_graphs=500, epochs=50, save_path='models/gnn.pt')")
    print("    print(r.baseline_comparison.verdict)")
    print("    print(r.generalization_report.verdict)")
    print("    print(r.real_world_validation.real_world_generalization)")


def _demo_fallback() -> None:
    """Show fallback behaviour when torch is not installed."""
    from trustfield.propagation.gnn_model import GNNModel
    from trustfield.graph import IAMSimulator

    sim = IAMSimulator()
    graph = sim.generate("chain", num_nodes=20, seed=42)
    seed_node = sorted(graph._graph.nodes())[0]

    model = GNNModel(auto_train=False)
    result = model.run(graph, [seed_node])
    print(f"  GNNModel (fallback) compromised: {len(result.compromised_nodes)} nodes")
    print(f"  model_confidence: {result.model_confidence}")
    print(f"  raw_output: {result.raw_output}")


if __name__ == "__main__":
    main()
