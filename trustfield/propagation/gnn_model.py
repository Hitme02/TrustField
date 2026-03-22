"""GNN propagation model — sixth TrustField propagation model.

Uses a two-layer Graph Convolutional Network (GCN) trained on synthetic IAM
graphs to predict trust-compromise propagation.  The GNN is the primary model
for chain topologies, where classical epidemic models under-perform.

Fallback behaviour:
    - If PyTorch is not installed, returns GraphTraversalModel output with
      model_confidence = 0.5.
    - If no pre-trained weights exist and auto_train is False, also falls back
      to GraphTraversalModel.
    - If no pre-trained weights exist and auto_train is True, trains on
      synthetic data and saves the result to ``models/gnn.pt``.

Inference threshold:
    Nodes with sigmoid(logit) >= 0.4 are considered compromised.  The lower
    threshold (vs. 0.5) compensates for the GNN's tendency to under-predict
    the minority (compromised) class.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

import networkx as nx
import numpy as np

from trustfield.graph.trust_graph import TrustGraph
from trustfield.propagation.base import PropagationModel
from trustfield.propagation.gnn_features import GNNFeatureExtractor, NUM_NODE_FEATURES
from trustfield.propagation.propagation_result import PropagationResult

_MODEL_NAME = "gnn"
_MODEL_CONFIDENCE = 0.6200
_DEFAULT_THRESHOLD = 0.4
_MODELS_DIR = Path(__file__).parent.parent.parent / "models"
_DEFAULT_WEIGHTS_PATH = _MODELS_DIR / "gnn.pt"

try:
    import torch as _torch
    _TORCH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _TORCH_AVAILABLE = False


class GNNModel(PropagationModel):
    """Graph Convolutional Network propagation model.

    Learns trust-compromise propagation patterns from synthetic IAM graphs
    and generalises to unseen graphs at inference time.

    When torch is available and pre-trained weights exist at ``models/gnn.pt``,
    the model runs the GCN forward pass.  Otherwise it falls back to
    :class:`~trustfield.propagation.graph_traversal.GraphTraversalModel`.

    Example::

        model = GNNModel(auto_train=True, n_train_graphs=200)
        result = model.run(graph, seed_nodes=["svc-001"])
        print(result.compromised_nodes)

    Args:
        weights_path: Path to the ``.pt`` weights file.  Defaults to
            ``models/gnn.pt`` relative to the project root.
        auto_train: If True and no weights file exists, auto-train on synthetic
            data and save the weights.  Defaults to True.
        n_train_graphs: Number of synthetic graphs to generate for
            auto-training.  Ignored if weights exist.
        threshold: Sigmoid threshold for compromise classification.
            Default 0.4 (lower than 0.5 to reduce false negatives on chain).
    """

    def __init__(
        self,
        weights_path: Optional[Path] = None,
        auto_train: bool = True,
        n_train_graphs: int = 100,
        threshold: float = _DEFAULT_THRESHOLD,
    ) -> None:
        self._weights_path: Path = weights_path or _DEFAULT_WEIGHTS_PATH
        self._auto_train = auto_train
        self._n_train_graphs = n_train_graphs
        self._threshold = threshold
        self._extractor = GNNFeatureExtractor()
        self._torch_model = None   # Lazy-loaded on first run()
        self._torch_available = _TORCH_AVAILABLE

    @property
    def model_name(self) -> str:
        return _MODEL_NAME

    # ------------------------------------------------------------------
    # Model loading / training (lazy)
    # ------------------------------------------------------------------

    def _load_or_train(self):
        """Return a ready GCNModel, or None if torch is unavailable."""
        if not self._torch_available:
            return None

        from trustfield.propagation.gnn_trainer import GCNModel, GNNTrainer
        import torch

        model = GCNModel(in_features=NUM_NODE_FEATURES)

        # Try loading from disk first
        if self._weights_path.exists():
            try:
                state = torch.load(
                    str(self._weights_path), map_location="cpu", weights_only=True
                )
                model.load_state_dict(state)
                model.eval()
                return model
            except Exception:
                pass  # Corrupt weights — fall through to auto-train

        # Auto-train if enabled
        if self._auto_train:
            trainer = GNNTrainer(n_graphs=self._n_train_graphs)
            data = trainer.generate_training_data()
            trainer.train(model, data)
            model.eval()
            # Persist weights for future runs
            try:
                self._weights_path.parent.mkdir(parents=True, exist_ok=True)
                torch.save(model.state_dict(), str(self._weights_path))
            except Exception:
                pass  # Write failure is non-fatal
            return model

        return None  # No weights, no auto-train → will fall back

    def _get_torch_model(self):
        """Lazily load/train and cache the GCNModel."""
        if self._torch_model is None and self._torch_available:
            self._torch_model = self._load_or_train()
        return self._torch_model

    # ------------------------------------------------------------------
    # PropagationModel interface
    # ------------------------------------------------------------------

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        **kwargs,
    ) -> PropagationResult:
        """Predict compromised nodes using the GCN.

        If torch is unavailable or no weights exist (and auto_train=False),
        the method delegates to :class:`~trustfield.propagation.graph_traversal.GraphTraversalModel`
        and returns its output with ``model_confidence = 0.5``.

        Args:
            graph: TrustGraph to analyse.
            seed_nodes: Initially compromised node IDs.
            **kwargs: Unused (for interface compatibility with other models).

        Returns:
            :class:`~trustfield.propagation.propagation_result.PropagationResult`
            with GCN-predicted compromise set and per-node risk scores.
        """
        t0 = time.time()
        g_nx = graph._graph
        all_nodes = list(g_nx.nodes())

        # --- Empty graph ---
        if not all_nodes:
            return PropagationResult(
                model_name=_MODEL_NAME,
                seed_nodes=list(seed_nodes),
                compromised_nodes=set(seed_nodes),
                propagation_depth=0,
                cascade_probability=0.0,
                model_confidence=_MODEL_CONFIDENCE,
                time_steps=0,
                convergence_achieved=True,
                per_node_risk={},
                raw_output={},
                computation_time_ms=(time.time() - t0) * 1000,
            )

        torch_model = self._get_torch_model()

        # --- Fallback path ---
        if torch_model is None:
            from trustfield.propagation.graph_traversal import GraphTraversalModel

            fb = GraphTraversalModel()
            r = fb.run(graph, seed_nodes)
            return PropagationResult(
                model_name=_MODEL_NAME,
                seed_nodes=r.seed_nodes,
                compromised_nodes=r.compromised_nodes,
                propagation_depth=r.propagation_depth,
                cascade_probability=r.cascade_probability,
                model_confidence=0.5,
                time_steps=r.time_steps,
                convergence_achieved=r.convergence_achieved,
                per_node_risk=r.per_node_risk,
                raw_output={"fallback": "graph_traversal", "reason": "torch_unavailable_or_no_weights"},
                computation_time_ms=(time.time() - t0) * 1000,
            )

        # --- GCN inference ---
        import torch

        gd = self._extractor.extract(graph, seed_nodes)  # labels=None → inference mode
        torch_model.eval()

        with torch.no_grad():
            x_t = torch.from_numpy(gd.x)
            adj_t = torch.from_numpy(gd.adj_hat)
            logits = torch_model(x_t, adj_t)
            probs = torch.sigmoid(logits).numpy()

        # Build per-node risk dict
        per_node_risk: dict = {
            nid: float(probs[i]) for i, nid in enumerate(gd.node_ids)
        }

        # Compromised nodes: probability >= threshold, plus all seeds
        compromised = {
            nid for i, nid in enumerate(gd.node_ids) if probs[i] >= self._threshold
        }
        compromised |= set(s for s in seed_nodes if s in g_nx)

        # Propagation depth: max BFS distance from any seed to any compromised node
        depths: dict = {}
        for s in seed_nodes:
            if s in g_nx:
                for nid, d in nx.single_source_shortest_path_length(g_nx, s).items():
                    if nid in compromised:
                        depths[nid] = max(depths.get(nid, 0), d)
        prop_depth = max(depths.values()) if depths else 0

        cascade_prob = float(np.mean(probs)) if len(probs) > 0 else 0.0
        elapsed = (time.time() - t0) * 1000

        return PropagationResult(
            model_name=_MODEL_NAME,
            seed_nodes=list(seed_nodes),
            compromised_nodes=compromised,
            propagation_depth=prop_depth,
            cascade_probability=cascade_prob,
            model_confidence=_MODEL_CONFIDENCE,
            time_steps=1,
            convergence_achieved=True,
            per_node_risk=per_node_risk,
            raw_output={
                "probabilities": per_node_risk,
                "threshold": self._threshold,
                "model": "gcn_2layer",
                "weights_path": str(self._weights_path),
            },
            computation_time_ms=elapsed,
        )
