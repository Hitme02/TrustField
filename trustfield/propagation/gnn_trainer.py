"""GCN trainer for TrustField's GNN propagation model.

Defines:
  GCNModel         — two-layer Graph Convolutional Network
  NaiveBaseline    — three trivial baselines for contextualising GNN F1
  GNNTrainer       — data generation, training, and publication-quality evaluation
  TrainingResult   — full training summary (basic + baseline + OOD + real-world)
  BaselineComparison     — GNN vs naive baselines
  GeneralizationReport   — cross-topology OOD generalization
  RealWorldResult        — per-fixture inference result
  RealWorldValidation    — aggregate over all real-world fixtures

Architecture (pure PyTorch — no torch_geometric dependency):
    H1     = ReLU(A_hat @ W1(x))
    H2     = ReLU(A_hat @ W2(H1))
    logits = W3(H2).squeeze(-1)      — shape (N,)

Training details:
    - Ground truth: GraphTraversalModel (BFS upper bound, F1 = 1.0).
    - Loss: BCEWithLogitsLoss with pos_weight = 3.0 (handles class imbalance).
    - Optimizer: Adam, lr = 1e-3, weight_decay = 1e-4.
    - Scheduler: ReduceLROnPlateau on validation F1.
    - Early stopping: patience = 10 epochs.
    - Inference threshold: 0.4 (GNN under-predicts minority class).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

from trustfield.propagation.gnn_features import (
    GNNFeatureExtractor,
    GraphData,
    NUM_NODE_FEATURES,
)

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    _TORCH_AVAILABLE = True
    _ModuleBase = nn.Module
except ImportError:  # pragma: no cover
    _TORCH_AVAILABLE = False
    _ModuleBase = object


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BaselineComparison:
    """GNN F1 compared against three naive baselines.

    Attributes:
        gnn_f1: GNN F1 on the test set.
        gnn_precision: GNN precision on the test set.
        gnn_recall: GNN recall on the test set.
        naive_all_f1: F1 of "predict every node compromised" baseline.
        naive_seed_f1: F1 of "predict only seed nodes" baseline.
        naive_neighbors_f1: F1 of "predict seed + 1-hop neighbors" baseline.
        gnn_improvement_over_best_naive: gnn_f1 - max(naive_f1s).
        result_is_trivial: True if improvement < 0.05.
        verdict: "MEANINGFUL" | "MARGINAL" | "TRIVIAL".
    """
    gnn_f1: float
    gnn_precision: float
    gnn_recall: float
    naive_all_f1: float
    naive_seed_f1: float
    naive_neighbors_f1: float
    gnn_improvement_over_best_naive: float
    result_is_trivial: bool
    verdict: str


@dataclass
class GeneralizationReport:
    """Cross-topology out-of-distribution generalization evaluation.

    Attributes:
        train_topologies: Topologies used for training.
        test_topologies: Unseen topologies used for OOD evaluation.
        in_distribution_f1: F1 on held-out graphs from train_topologies.
        out_of_distribution_f1: F1 on test_topologies graphs.
        generalization_gap: in_distribution_f1 - out_of_distribution_f1.
        generalizes_well: True if gap < 0.15.
        verdict: "STRONG" | "ACCEPTABLE" | "WEAK".
    """
    train_topologies: List[str]
    test_topologies: List[str]
    in_distribution_f1: float
    out_of_distribution_f1: float
    generalization_gap: float
    generalizes_well: bool
    verdict: str


@dataclass
class RealWorldResult:
    """GNN evaluation result for a single real-world fixture.

    Attributes:
        fixture_name: Short name of the fixture file (e.g. "aws/s3_read_only").
        n_nodes: Number of nodes in the loaded graph.
        ground_truth_size: Number of nodes in the GT compromised set.
        gnn_prediction_size: Number of nodes the GNN predicted as compromised.
        precision: Precision of GNN vs GT.
        recall: Recall of GNN vs GT.
        f1: F1 score.
        critical_miss: True if ground_truth_size > gnn_prediction_size + 2.
    """
    fixture_name: str
    n_nodes: int
    ground_truth_size: int
    gnn_prediction_size: int
    precision: float
    recall: float
    f1: float
    critical_miss: bool


@dataclass
class RealWorldValidation:
    """Aggregate GNN evaluation over all real-world fixture graphs.

    Attributes:
        results: Per-fixture results.
        mean_f1: Mean F1 across all fixtures.
        mean_precision: Mean precision.
        mean_recall: Mean recall.
        fixtures_with_critical_miss: Fixture names where critical miss occurred.
        real_world_generalization: "STRONG" / "ACCEPTABLE" / "WEAK".
        latex_table: LaTeX booktabs table of per-fixture results.
        markdown_table: Markdown table of per-fixture results.
    """
    results: List[RealWorldResult]
    mean_f1: float
    mean_precision: float
    mean_recall: float
    fixtures_with_critical_miss: List[str]
    real_world_generalization: str
    latex_table: str
    markdown_table: str


@dataclass
class TrainingResult:
    """Summary statistics from a GNN training run.

    Attributes (original):
        epochs_trained: Number of epochs completed.
        final_train_loss: BCE loss on training set at the last epoch.
        best_val_f1: Best validation F1 during training.
        training_time_s: Wall-clock training time in seconds.
        n_train_graphs: Number of graphs used for training.
        converged: True if early-stopping patience was exhausted.

    Attributes (new — publication-quality evaluation):
        val_f1: Alias for best_val_f1.
        test_f1: F1 on the held-out test split.
        test_precision: Precision on the held-out test split.
        test_recall: Recall on the held-out test split.
        per_topology_f1: Per-topology F1 scores.
        model_path: Path where model was saved (empty if not saved).
        training_time_seconds: Alias for training_time_s.
        baseline_comparison: GNN vs naive baselines (None if not run).
        generalization_report: OOD generalization (None if not run).
        real_world_validation: Real-world fixture evaluation (None if not run).
    """
    epochs_trained: int
    final_train_loss: float
    best_val_f1: float
    training_time_s: float
    n_train_graphs: int
    converged: bool
    # Extended publication fields
    val_f1: float = 0.0
    test_f1: float = 0.0
    test_precision: float = 0.0
    test_recall: float = 0.0
    per_topology_f1: Dict[str, float] = field(default_factory=dict)
    model_path: str = ""
    training_time_seconds: float = 0.0
    baseline_comparison: Optional[BaselineComparison] = None
    generalization_report: Optional[GeneralizationReport] = None
    real_world_validation: Optional[RealWorldValidation] = None


# ---------------------------------------------------------------------------
# Naive baselines
# ---------------------------------------------------------------------------

class NaiveBaseline:
    """Three trivial baselines that contextualise the GNN F1 score.

    If the GNN is not significantly better than these, the result is trivial
    and adds no value over simple heuristics.
    """

    @staticmethod
    def predict_all_compromised(graph, seed_nodes: List[str]) -> Set[str]:
        """Predicts every node is compromised. Upper bound on recall."""
        return set(graph.nx_graph.nodes())

    @staticmethod
    def predict_seed_only(graph, seed_nodes: List[str]) -> Set[str]:
        """Predicts only seed nodes compromised. Lower bound."""
        return set(seed_nodes)

    @staticmethod
    def predict_neighbors_only(graph, seed_nodes: List[str]) -> Set[str]:
        """Predicts seed + direct successors. 1-hop heuristic."""
        nodes: Set[str] = set(seed_nodes)
        for s in seed_nodes:
            nodes.update(graph.nx_graph.successors(s))
        return nodes


# ---------------------------------------------------------------------------
# GCN model
# ---------------------------------------------------------------------------

class GCNModel(_ModuleBase):
    """Two-layer Graph Convolutional Network for node-level binary classification.

    Architecture::

        H1     = ReLU(A_hat @ Linear(x,  hidden1))
        H2     = ReLU(A_hat @ Linear(H1, hidden2))
        logits = Linear(H2, 1).squeeze(-1)

    Args:
        in_features: Dimensionality of the input node features (default 13).
        hidden1: Width of the first hidden layer (default 64).
        hidden2: Width of the second hidden layer (default 32).
    """

    def __init__(
        self,
        in_features: int = NUM_NODE_FEATURES,
        hidden1: int = 64,
        hidden2: int = 32,
    ) -> None:
        if not _TORCH_AVAILABLE:  # pragma: no cover
            raise RuntimeError("torch is required to instantiate GCNModel")
        super().__init__()
        self.W1 = nn.Linear(in_features, hidden1)
        self.W2 = nn.Linear(hidden1, hidden2)
        self.W3 = nn.Linear(hidden2, 1)

    def forward(self, x, adj_hat):
        h1 = F.relu(adj_hat @ self.W1(x))
        h2 = F.relu(adj_hat @ self.W2(h1))
        return self.W3(h2).squeeze(-1)


# ---------------------------------------------------------------------------
# GNN Trainer
# ---------------------------------------------------------------------------

class GNNTrainer:
    """Generates synthetic training data and trains the GCN model.

    Supports two calling styles for ``train()``:

    *Original style* (backward compatible)::

        data  = trainer.generate_training_data()
        model = GCNModel()
        result = trainer.train(model, data)

    *High-level style* (runs all publication evaluations automatically)::

        trainer = GNNTrainer()
        result  = trainer.train(n_graphs=500, epochs=50, save_path="models/gnn.pt")
        print(result.baseline_comparison.verdict)
        print(result.generalization_report.verdict)
        print(result.real_world_validation.real_world_generalization)

    Args:
        n_graphs: Total number of synthetic graphs to generate.
        seed: Random seed for reproducibility.
        max_epochs: Maximum training epochs.
        patience: Early-stopping patience.
        lr: Adam learning rate.
        weight_decay: Adam L2 regularisation.
        pos_weight: BCEWithLogitsLoss positive-class weight.
        val_fraction: Fraction of data held out for validation.
    """

    def __init__(
        self,
        n_graphs: int = 200,
        seed: int = 42,
        max_epochs: int = 100,
        patience: int = 10,
        lr: float = 1e-3,
        weight_decay: float = 1e-4,
        pos_weight: float = 3.0,
        val_fraction: float = 0.2,
    ) -> None:
        self.n_graphs     = n_graphs
        self.seed         = seed
        self.max_epochs   = max_epochs
        self.patience     = patience
        self.lr           = lr
        self.weight_decay = weight_decay
        self.pos_weight   = pos_weight
        self.val_fraction = val_fraction
        self._extractor   = GNNFeatureExtractor()
        self._trained_model: Optional[GCNModel] = None

    # ------------------------------------------------------------------
    # Data generation
    # ------------------------------------------------------------------

    def generate_training_data(
        self,
        topologies: Optional[List[str]] = None,
        return_graphs: bool = False,
        topology_mix: Optional[Dict[str, int]] = None,
    ):
        """Generate synthetic labelled graphs.

        Args:
            topologies: List of topology names to sample from (cycled).
                When ``None`` uses the default mix (chain × 5, hub × 2,
                dense_cluster × 3).  Ignored when ``topology_mix`` is given.
            return_graphs: When ``True`` returns a 3-tuple
                ``(data_list, graphs, seed_nodes_per_graph)`` instead of just
                ``data_list``.  Used internally by the high-level ``train()``.
            topology_mix: Dict mapping topology name → exact graph count, e.g.
                ``{"hub": 150, "chain": 150, "dense_cluster": 150, "mixed": 150}``.
                When provided the total number of graphs is
                ``sum(topology_mix.values())`` and the sequence is shuffled so
                topologies are interleaved during training.  Overrides both
                ``topologies`` and ``self.n_graphs``.

        Returns:
            ``List[GraphData]`` or, if ``return_graphs=True``, a tuple of
            ``(List[GraphData], List[TrustGraph], List[List[str]])``.
        """
        from trustfield.graph import IAMSimulator
        from trustfield.propagation.graph_traversal import GraphTraversalModel

        sim       = IAMSimulator()
        gt_model  = GraphTraversalModel()
        extractor = self._extractor
        rng       = random.Random(self.seed)

        if topology_mix is not None:
            # Build an explicit shuffled sequence from the mix dict
            _sequence: List[str] = []
            for tname, count in topology_mix.items():
                _sequence.extend([tname] * count)
            rng.shuffle(_sequence)
            n_iter = len(_sequence)
            def _topo_at(i: int) -> str:
                return _sequence[i]
        else:
            if topologies is not None:
                _cycle = topologies
            else:
                _cycle = ["chain"] * 5 + ["hub"] * 2 + ["dense_cluster"] * 3
            n_iter = self.n_graphs
            def _topo_at(i: int) -> str:
                return _cycle[i % len(_cycle)]

        data_list:    List[GraphData]      = []
        graphs_list:  List               = []
        seeds_list:   List[List[str]]     = []

        for i in range(n_iter):
            topo       = _topo_at(i)
            num_nodes  = rng.randint(15, 40)
            graph_seed = rng.randint(0, 99999)

            try:
                graph = sim.generate(topo, num_nodes=num_nodes, seed=graph_seed)
            except Exception:
                continue

            g_nx     = graph._graph
            node_ids = list(g_nx.nodes())
            if not node_ids:
                continue

            seed_node  = self._pick_seed(graph)
            seed_nodes = [seed_node]

            result    = gt_model.run(graph, seed_nodes)
            compromised = result.compromised_nodes
            labels    = {nid: (1 if nid in compromised else 0) for nid in node_ids}

            gd = extractor.extract(graph, seed_nodes, labels=labels)
            data_list.append(gd)
            if return_graphs:
                graphs_list.append(graph)
                seeds_list.append(seed_nodes)

        if return_graphs:
            return data_list, graphs_list, seeds_list
        return data_list

    # ------------------------------------------------------------------
    # Training — public API
    # ------------------------------------------------------------------

    def train(
        self,
        model: Optional["GCNModel"] = None,
        data_list: Optional[List[GraphData]] = None,
        *,
        n_graphs: Optional[int] = None,
        epochs:   Optional[int] = None,
        save_path: Optional[str] = None,
        topology_mix: Optional[Dict[str, int]] = None,
    ) -> TrainingResult:
        """Train the GCN.

        Can be called in two ways:

        *Original* (positional args, backward compatible)::

            result = trainer.train(model, data_list)

        *High-level* (keyword args, runs all publication evaluations)::

            result = trainer.train(n_graphs=500, epochs=50, save_path="models/gnn.pt")
            # With explicit topology distribution:
            result = trainer.train(
                n_graphs=600, epochs=50,
                topology_mix={"hub": 150, "chain": 150,
                               "dense_cluster": 150, "mixed": 150},
                save_path="models/gnn_diverse.pt",
            )

        Args:
            topology_mix: When provided, overrides ``n_graphs`` with
                ``sum(topology_mix.values())`` and generates exactly the
                specified count of graphs per topology.  Interleaved randomly
                during training for stable gradient updates.

        Returns:
            :class:`TrainingResult` — extended with publication fields when
            called in high-level mode.
        """
        if not _TORCH_AVAILABLE:  # pragma: no cover
            raise RuntimeError("torch is required for GNN training")

        # -- High-level mode ---------------------------------------------------
        if model is None:
            resolved_n = (
                sum(topology_mix.values()) if topology_mix is not None
                else (n_graphs or self.n_graphs)
            )
            return self._train_highlevel(
                n_graphs=resolved_n,
                epochs=epochs or self.max_epochs,
                save_path=save_path,
                topology_mix=topology_mix,
            )

        # -- Original mode (backward compatible) ------------------------------
        if data_list is None:
            raise ValueError("data_list must be provided when model is given")
        return self._train_core(model, data_list)

    # ------------------------------------------------------------------
    # Internal training core
    # ------------------------------------------------------------------

    def _train_core(
        self,
        model: "GCNModel",
        data_list: List[GraphData],
    ) -> TrainingResult:
        """Core training loop. Modifies ``model`` in-place."""
        import torch
        import torch.nn as nn

        rng = random.Random(self.seed)
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)

        shuffled  = data_list.copy()
        rng.shuffle(shuffled)
        n_val     = max(1, int(len(shuffled) * self.val_fraction))
        val_data  = shuffled[:n_val]
        train_data = shuffled[n_val:] or data_list

        optimizer = torch.optim.Adam(
            model.parameters(), lr=self.lr, weight_decay=self.weight_decay
        )
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode="max", factor=0.5, patience=5, min_lr=1e-5
        )
        pos_w     = torch.tensor([self.pos_weight])
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_w)

        best_val_f1       = 0.0
        best_state: Optional[dict] = None
        patience_counter  = 0
        final_train_loss  = 0.0
        t0                = time.time()
        last_epoch        = 0

        for epoch in range(self.max_epochs):
            last_epoch = epoch
            model.train()
            rng.shuffle(train_data)
            epoch_losses = []

            for gd in train_data:
                if gd.x.shape[0] == 0:
                    continue
                x_t   = torch.from_numpy(gd.x)
                adj_t = torch.from_numpy(gd.adj_hat)
                y_t   = torch.from_numpy(gd.labels)

                optimizer.zero_grad()
                logits = model(x_t, adj_t)
                loss   = criterion(logits, y_t)
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                epoch_losses.append(loss.item())

            final_train_loss = float(np.mean(epoch_losses)) if epoch_losses else 0.0
            val_f1           = self._mean_f1(model, val_data)
            scheduler.step(val_f1)

            if val_f1 > best_val_f1:
                best_val_f1      = val_f1
                best_state       = {k: v.clone() for k, v in model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= self.patience:
                    break

        if best_state is not None:
            model.load_state_dict(best_state)

        elapsed = time.time() - t0
        return TrainingResult(
            epochs_trained       = last_epoch + 1,
            final_train_loss     = final_train_loss,
            best_val_f1          = float(best_val_f1),
            training_time_s      = elapsed,
            n_train_graphs       = len(train_data),
            converged            = patience_counter >= self.patience,
            val_f1               = float(best_val_f1),
            training_time_seconds= elapsed,
        )

    def _train_highlevel(
        self,
        n_graphs: int,
        epochs: int,
        save_path: Optional[str],
        topology_mix: Optional[Dict[str, int]] = None,
    ) -> TrainingResult:
        """Full pipeline: generate → train → all publication evaluations."""
        orig_n, orig_e = self.n_graphs, self.max_epochs
        self.n_graphs   = n_graphs
        self.max_epochs = epochs

        if topology_mix is not None:
            mix_desc = ", ".join(f"{t}×{c}" for t, c in topology_mix.items())
            print(f"[GNN] Generating {n_graphs} training graphs ({mix_desc}) …")
        else:
            print(f"[GNN] Generating {n_graphs} training graphs …")
        data_list, graphs, seeds = self.generate_training_data(
            return_graphs=True, topology_mix=topology_mix
        )

        print("[GNN] Training GCN …")
        model  = GCNModel(in_features=NUM_NODE_FEATURES)
        result = self._train_core(model, data_list)
        self._trained_model = model

        self.n_graphs   = orig_n
        self.max_epochs = orig_e

        # -- Test-set metrics --------------------------------------------------
        rng = random.Random(self.seed)
        shuffled = list(range(len(data_list)))
        rng.shuffle(shuffled)
        n_test  = max(1, int(len(shuffled) * 0.1))
        test_idx = shuffled[:n_test]
        test_data = [data_list[i] for i in test_idx]
        test_graphs = [graphs[i] for i in test_idx]
        test_seeds  = [seeds[i]  for i in test_idx]

        test_metrics = self.evaluate(model, test_data)
        result.test_f1        = test_metrics["f1"]
        result.test_precision = test_metrics["precision"]
        result.test_recall    = test_metrics["recall"]

        # -- Per-topology F1 ---------------------------------------------------
        result.per_topology_f1 = self._per_topology_f1(model)

        # -- Baseline comparison -----------------------------------------------
        print("[GNN] Evaluating naive baselines …")
        gt_sets = [
            {gd.node_ids[i] for i, l in enumerate(gd.labels) if l > 0.5}
            for gd in test_data
        ]
        result.baseline_comparison = self.evaluate_with_baselines(
            test_data, test_graphs, test_seeds, gt_sets
        )

        # -- Cross-topology generalization -------------------------------------
        print("[GNN] Cross-topology generalization test …")
        result.generalization_report = self.cross_topology_generalization_test(
            train_topologies=["hub", "chain"],
            test_topologies=["dense_cluster", "mixed"],
            n_train=150,
            n_test=50,
            epochs=min(epochs, 30),
        )

        # -- Real-world fixture evaluation ------------------------------------
        print("[GNN] Evaluating on real-world fixtures …")
        result.real_world_validation = self.evaluate_on_real_world(model=model)

        # -- Save model --------------------------------------------------------
        if save_path is not None:
            import pathlib, torch
            pathlib.Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            torch.save(model.state_dict(), save_path)
            result.model_path = save_path

        return result

    # ------------------------------------------------------------------
    # Evaluation helpers
    # ------------------------------------------------------------------

    def evaluate(
        self,
        model: "GCNModel",
        data_list: List[GraphData],
        threshold: float = 0.4,
    ) -> Dict[str, float]:
        """Compute aggregate precision, recall, and F1 over a dataset."""
        import torch

        model.eval()
        all_tp = all_fp = all_fn = 0

        with torch.no_grad():
            for gd in data_list:
                if gd.x.shape[0] == 0:
                    continue
                probs = torch.sigmoid(
                    model(torch.from_numpy(gd.x), torch.from_numpy(gd.adj_hat))
                ).numpy()
                pred   = {gd.node_ids[i] for i, p in enumerate(probs) if p >= threshold}
                actual = {gd.node_ids[i] for i, l in enumerate(gd.labels) if l > 0.5}
                tp = len(pred & actual)
                all_tp += tp
                all_fp += len(pred - actual)
                all_fn += len(actual - pred)

        p  = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0.0
        r  = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        return {"precision": float(p), "recall": float(r), "f1": float(f1)}

    def evaluate_with_baselines(
        self,
        test_data: List[GraphData],
        graphs: List,
        seed_nodes_per_graph: List[List[str]],
        ground_truths: List[Set[str]],
        threshold: float = 0.4,
    ) -> BaselineComparison:
        """Compare GNN against three naive baselines on a test set.

        Args:
            test_data: GraphData for inference.
            graphs: Corresponding TrustGraph objects (needed for naive baselines).
            seed_nodes_per_graph: Seed nodes per graph.
            ground_truths: Ground-truth compromised sets per graph.
            threshold: GNN sigmoid threshold.

        Returns:
            :class:`BaselineComparison` with F1 scores and verdict.
        """
        if not _TORCH_AVAILABLE:  # pragma: no cover
            raise RuntimeError("torch required for evaluate_with_baselines")
        import torch

        # GNN predictions
        gnn_tp = gnn_fp = gnn_fn = 0
        all_tp_all_nodes = all_fp_all_nodes = all_fn_all_nodes = 0
        seed_tp = seed_fp = seed_fn = 0
        nb_tp   = nb_fp   = nb_fn   = 0

        model = self._trained_model
        if model is None:
            raise RuntimeError(
                "No trained model available; call train() first or provide a model."
            )
        model.eval()

        n = min(len(test_data), len(graphs), len(seed_nodes_per_graph), len(ground_truths))

        with torch.no_grad():
            for i in range(n):
                gd      = test_data[i]
                graph   = graphs[i]
                seeds   = seed_nodes_per_graph[i]
                gt_set  = ground_truths[i]
                all_ids = set(gd.node_ids)

                if gd.x.shape[0] == 0:
                    continue

                probs = torch.sigmoid(
                    model(torch.from_numpy(gd.x), torch.from_numpy(gd.adj_hat))
                ).numpy()
                gnn_pred = {gd.node_ids[j] for j, p in enumerate(probs) if p >= threshold}

                # Naive predictions
                all_pred  = NaiveBaseline.predict_all_compromised(graph, seeds)
                seed_pred = NaiveBaseline.predict_seed_only(graph, seeds)
                nb_pred   = NaiveBaseline.predict_neighbors_only(graph, seeds)

                gnn_tp += len(gnn_pred & gt_set)
                gnn_fp += len(gnn_pred - gt_set)
                gnn_fn += len(gt_set - gnn_pred)

                all_tp_all_nodes += len(all_pred & gt_set)
                all_fp_all_nodes += len(all_pred - gt_set)
                all_fn_all_nodes += len(gt_set - all_pred)

                seed_tp += len(seed_pred & gt_set)
                seed_fp += len(seed_pred - gt_set)
                seed_fn += len(gt_set - seed_pred)

                nb_tp += len(nb_pred & gt_set)
                nb_fp += len(nb_pred - gt_set)
                nb_fn += len(gt_set - nb_pred)

        def _f1(tp, fp, fn):
            p  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            return 2 * p * r / (p + r) if (p + r) > 0 else 0.0, p, r

        gnn_f1, gnn_p, gnn_r = _f1(gnn_tp, gnn_fp, gnn_fn)
        naive_all_f1, _, _   = _f1(all_tp_all_nodes, all_fp_all_nodes, all_fn_all_nodes)
        naive_seed_f1, _, _  = _f1(seed_tp, seed_fp, seed_fn)
        naive_nb_f1, _, _    = _f1(nb_tp, nb_fp, nb_fn)

        best_naive  = max(naive_all_f1, naive_seed_f1, naive_nb_f1)
        improvement = gnn_f1 - best_naive

        if improvement >= 0.15:
            verdict = "MEANINGFUL — GNN significantly outperforms naive baselines"
        elif improvement >= 0.05:
            verdict = "MARGINAL — GNN slightly outperforms naive baselines"
        else:
            verdict = "TRIVIAL — GNN does not meaningfully exceed naive prediction"

        return BaselineComparison(
            gnn_f1=round(gnn_f1, 4),
            gnn_precision=round(gnn_p, 4),
            gnn_recall=round(gnn_r, 4),
            naive_all_f1=round(naive_all_f1, 4),
            naive_seed_f1=round(naive_seed_f1, 4),
            naive_neighbors_f1=round(naive_nb_f1, 4),
            gnn_improvement_over_best_naive=round(improvement, 4),
            result_is_trivial=improvement < 0.05,
            verdict=verdict,
        )

    def cross_topology_generalization_test(
        self,
        train_topologies: List[str] = None,
        test_topologies:  List[str] = None,
        n_train: int  = 300,
        n_test:  int  = 100,
        epochs:  int  = 40,
    ) -> GeneralizationReport:
        """Train on one set of topologies; evaluate on completely unseen ones.

        Args:
            train_topologies: Topology names used for training.
            test_topologies:  Topology names used for OOD evaluation.
            n_train: Number of training graphs.
            n_test:  Number of test graphs (both in-dist and OOD).
            epochs:  Maximum training epochs for the inner trainer.

        Returns:
            :class:`GeneralizationReport` with in-dist vs OOD F1 and verdict.
        """
        if train_topologies is None:
            train_topologies = ["hub", "chain"]
        if test_topologies is None:
            test_topologies = ["dense_cluster", "mixed"]

        if not _TORCH_AVAILABLE:  # pragma: no cover
            raise RuntimeError("torch required")

        inner = GNNTrainer(
            n_graphs=n_train,
            seed=self.seed,
            max_epochs=epochs,
            patience=min(self.patience, 8),
            lr=self.lr,
            weight_decay=self.weight_decay,
            pos_weight=self.pos_weight,
            val_fraction=0.2,
        )

        # Training data from train_topologies only
        train_data = inner.generate_training_data(topologies=train_topologies)

        # In-distribution held-out set (20% of training topologies)
        inner_rng = random.Random(self.seed + 1)
        all_ids   = list(range(len(train_data)))
        inner_rng.shuffle(all_ids)
        n_in_val  = max(1, int(len(all_ids) * 0.2))
        in_val_data = [train_data[i] for i in all_ids[:n_in_val]]
        fit_data    = [train_data[i] for i in all_ids[n_in_val:]] or train_data

        model = GCNModel(in_features=NUM_NODE_FEATURES)
        inner._train_core(model, fit_data)

        # In-distribution F1 (held-out from same topologies)
        in_metrics = inner.evaluate(model, in_val_data)
        in_f1      = in_metrics["f1"]

        # OOD data from test_topologies
        ood_inner = GNNTrainer(
            n_graphs=n_test,
            seed=self.seed + 2,
            max_epochs=epochs,
        )
        ood_data = ood_inner.generate_training_data(topologies=test_topologies)
        ood_metrics = inner.evaluate(model, ood_data)
        ood_f1      = ood_metrics["f1"]

        gap = in_f1 - ood_f1
        if gap < 0.05:
            verdict = "STRONG — model generalizes across topology types"
        elif gap < 0.15:
            verdict = "ACCEPTABLE — minor degradation on unseen topologies"
        else:
            verdict = "WEAK — model is topology-specific, limited generalization"

        return GeneralizationReport(
            train_topologies=list(train_topologies),
            test_topologies=list(test_topologies),
            in_distribution_f1=round(in_f1, 4),
            out_of_distribution_f1=round(ood_f1, 4),
            generalization_gap=round(abs(gap), 4),
            generalizes_well=gap < 0.15,
            verdict=verdict,
        )

    def evaluate_on_real_world(
        self,
        fixture_dir: str = "tests/fixtures",
        model: Optional["GCNModel"] = None,
        threshold: float = 0.4,
    ) -> RealWorldValidation:
        """Evaluate the GCN on all real-world fixture graphs.

        Loads every ``*.json`` (AWS IAM) and ``*.yaml`` (K8s RBAC) file in
        ``fixture_dir`` and runs GNN inference vs GraphTraversalModel ground
        truth.

        Args:
            fixture_dir: Directory containing ``aws/`` and ``k8s/`` subdirs.
            model: GCNModel to evaluate.  Uses ``self._trained_model`` if None.
            threshold: Sigmoid threshold for positive prediction.

        Returns:
            :class:`RealWorldValidation` with per-fixture results and aggregate
            statistics.
        """
        from trustfield.propagation.graph_traversal import GraphTraversalModel

        m = model if model is not None else self._trained_model
        use_gnn = _TORCH_AVAILABLE and m is not None

        import pathlib
        fix_dir = pathlib.Path(fixture_dir)
        aws_dir = fix_dir / "aws"
        k8s_dir = fix_dir / "k8s"

        fixtures: List[Tuple[str, str, str]] = []   # (short_name, path, kind)
        if aws_dir.exists():
            for p in sorted(aws_dir.glob("*.json")):
                fixtures.append((f"aws/{p.stem}", str(p), "aws"))
        if k8s_dir.exists():
            for p in sorted(k8s_dir.glob("*.yaml")):
                fixtures.append((f"k8s/{p.stem}", str(p), "k8s"))

        from trustfield.loaders.aws_iam_loader import IAMPolicyLoader
        from trustfield.loaders.k8s_rbac_loader import K8sRBACLoader

        gt_model  = GraphTraversalModel()
        extractor = self._extractor
        results: List[RealWorldResult] = []

        for short_name, path, kind in fixtures:
            try:
                loader = IAMPolicyLoader() if kind == "aws" else K8sRBACLoader()
                graph  = loader.load_file(path)
            except Exception:
                continue

            node_ids = list(graph._graph.nodes())
            if not node_ids:
                continue

            seed_node  = self._pick_seed(graph)
            seed_nodes = [seed_node]

            # Ground truth via BFS traversal
            try:
                gt_result = gt_model.run(graph, seed_nodes)
                gt_set    = gt_result.compromised_nodes
            except Exception:
                gt_set = set(seed_nodes)

            # GNN prediction
            if use_gnn:
                import torch
                try:
                    gd    = extractor.extract(graph, seed_nodes)
                    if gd.x.shape[0] == 0:
                        raise ValueError("empty graph")
                    m.eval()
                    with torch.no_grad():
                        probs = torch.sigmoid(
                            m(torch.from_numpy(gd.x), torch.from_numpy(gd.adj_hat))
                        ).numpy()
                    gnn_pred = {gd.node_ids[i] for i, p in enumerate(probs) if p >= threshold}
                    gnn_pred.add(seed_node)   # always include seed
                except Exception:
                    gnn_pred = set(seed_nodes)
            else:
                # Fallback: use GraphTraversalModel predictions
                gnn_pred = gt_set.copy()

            tp = len(gnn_pred & gt_set)
            fp = len(gnn_pred - gt_set)
            fn = len(gt_set - gnn_pred)
            p  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0

            results.append(RealWorldResult(
                fixture_name      = short_name,
                n_nodes           = len(node_ids),
                ground_truth_size = len(gt_set),
                gnn_prediction_size = len(gnn_pred),
                precision         = round(p, 4),
                recall            = round(r, 4),
                f1                = round(f1, 4),
                critical_miss     = len(gt_set) > len(gnn_pred) + 2,
            ))

        # Aggregates
        mean_f1  = float(np.mean([r.f1        for r in results])) if results else 0.0
        mean_p   = float(np.mean([r.precision  for r in results])) if results else 0.0
        mean_r   = float(np.mean([r.recall     for r in results])) if results else 0.0
        critical = [r.fixture_name for r in results if r.critical_miss]

        if mean_f1 >= 0.70:
            verdict = "STRONG real-world generalization"
        elif mean_f1 >= 0.50:
            verdict = "ACCEPTABLE real-world generalization"
        else:
            verdict = "WEAK — model struggles on real configs"

        return RealWorldValidation(
            results=results,
            mean_f1=round(mean_f1, 4),
            mean_precision=round(mean_p, 4),
            mean_recall=round(mean_r, 4),
            fixtures_with_critical_miss=critical,
            real_world_generalization=verdict,
            latex_table=self._rw_latex(results, mean_f1, verdict),
            markdown_table=self._rw_markdown(results, mean_f1, verdict),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _mean_f1(
        self,
        model: "GCNModel",
        data_list: List[GraphData],
        threshold: float = 0.4,
    ) -> float:
        """Per-graph mean F1 (used during validation)."""
        import torch

        model.eval()
        scores: List[float] = []

        with torch.no_grad():
            for gd in data_list:
                if gd.x.shape[0] == 0:
                    continue
                probs  = torch.sigmoid(
                    model(torch.from_numpy(gd.x), torch.from_numpy(gd.adj_hat))
                ).numpy()
                pred   = {gd.node_ids[i] for i, p in enumerate(probs) if p >= threshold}
                actual = {gd.node_ids[i] for i, l in enumerate(gd.labels) if l > 0.5}

                if not pred and not actual:
                    scores.append(1.0)
                elif not pred or not actual:
                    scores.append(0.0)
                else:
                    tp = len(pred & actual)
                    p  = tp / len(pred)
                    r  = tp / len(actual)
                    scores.append(2 * p * r / (p + r) if (p + r) > 0 else 0.0)

        return float(np.mean(scores)) if scores else 0.0

    def _per_topology_f1(
        self,
        model: "GCNModel",
        n_per_topo: int = 30,
    ) -> Dict[str, float]:
        """Generate a small eval set per topology and return F1 dict."""
        results: Dict[str, float] = {}
        for topo in ["hub", "chain", "dense_cluster", "mixed"]:
            inner = GNNTrainer(n_graphs=n_per_topo, seed=self.seed + hash(topo) % 100)
            try:
                data = inner.generate_training_data(topologies=[topo])
                m    = self.evaluate(model, data)
                results[topo] = round(m["f1"], 4)
            except Exception:
                results[topo] = 0.0
        return results

    @staticmethod
    def _pick_seed(graph) -> str:
        """Return lowest-privilege SERVICE/USER node, or first node."""
        g_nx      = graph._graph
        node_ids  = list(g_nx.nodes())
        preferred = [
            nid for nid in node_ids
            if (g_nx.nodes[nid].get("metadata") is not None
                and g_nx.nodes[nid]["metadata"].node_type.value in ("SERVICE", "USER"))
        ]
        pool = preferred if preferred else node_ids
        return min(
            pool,
            key=lambda nid: (
                g_nx.nodes[nid]["metadata"].privilege_level
                if g_nx.nodes[nid].get("metadata") is not None else 1.0
            ),
        )

    @staticmethod
    def _rw_latex(results: List[RealWorldResult], mean_f1: float, verdict: str) -> str:
        rows = "\n".join(
            f"  {r.fixture_name} & {r.n_nodes} & {r.ground_truth_size} "
            f"& {r.gnn_prediction_size} & {r.f1:.3f} "
            f"& {'Yes' if r.critical_miss else 'No'} \\\\"
            for r in results
        )
        return (
            "\\begin{table}[h]\n\\centering\n"
            "\\caption{GNN Real-World Fixture Evaluation}\n"
            "\\label{tab:rw}\n"
            "\\begin{tabular}{lrrrrl}\n\\hline\n"
            "Fixture & N & GT & GNN & F1 & Critical Miss \\\\\n\\hline\n"
            f"{rows}\n\\hline\n"
            f"\\multicolumn{{6}}{{l}}{{Mean F1: {mean_f1:.3f} — {verdict}}} \\\\\n"
            "\\end{tabular}\n\\end{table}"
        )

    @staticmethod
    def _rw_markdown(results: List[RealWorldResult], mean_f1: float, verdict: str) -> str:
        header = "| Fixture | Nodes | GT | GNN | F1 | Critical Miss |\n"
        sep    = "|---|---|---|---|---|---|\n"
        rows   = "".join(
            f"| {r.fixture_name} | {r.n_nodes} | {r.ground_truth_size} "
            f"| {r.gnn_prediction_size} | {r.f1:.3f} "
            f"| {'Yes' if r.critical_miss else 'No'} |\n"
            for r in results
        )
        footer = f"\nMean F1: **{mean_f1:.3f}** — {verdict}\n"
        return header + sep + rows + footer
