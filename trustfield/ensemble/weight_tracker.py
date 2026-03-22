"""WeightTracker — SQLite-backed adaptive weight learning for TrustField.

Records model prediction accuracy over time and uses historical F1 scores to
compute adaptive weight vectors that improve on the topology priors as more
ground-truth data becomes available.

The adaptive mechanism implements a simple Bayesian-inspired update:
  weight_i ∝ mean_F1_i(last 20 records for this topology)

This ensures that models which have demonstrated empirical accuracy on a given
topology type receive proportionally higher ensemble weight in future runs.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from .weight_vector import MODEL_NAMES, WeightVector


@dataclass
class ModelAccuracy:
    """Precision, recall, and F1 score for a single model prediction result.

    Attributes:
        model_name: Name of the propagation model evaluated.
        topology_type: Topology of the graph this result was computed on.
        precision: TP / (TP + FP) — fraction of predicted compromised nodes
            that were actually compromised.
        recall: TP / (TP + FN) — fraction of actually compromised nodes that
            were predicted.
        f1_score: Harmonic mean of precision and recall.
    """

    model_name: str
    topology_type: str
    precision: float
    recall: float
    f1_score: float


def _compute_metrics(
    predicted: Set[str], actual: Set[str]
) -> tuple[float, float, float]:
    """Compute precision, recall, and F1 for a set-based prediction.

    Args:
        predicted: Set of node IDs predicted as compromised.
        actual: Set of node IDs that were actually compromised.

    Returns:
        Tuple of (precision, recall, f1_score), each in [0.0, 1.0].
    """
    if not predicted and not actual:
        return 1.0, 1.0, 1.0
    if not predicted:
        return 0.0, 0.0, 0.0
    if not actual:
        return 0.0, 0.0, 0.0

    tp = len(predicted & actual)
    precision = tp / len(predicted)
    recall = tp / len(actual)
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return precision, recall, f1


class WeightTracker:
    """Persists model accuracy history and derives adaptive ensemble weights.

    Uses SQLite for lightweight, file-based persistence with no external
    dependencies.  The database stores per-run accuracy metrics and current
    weight snapshots, enabling the ensemble to improve as more labelled
    outcomes become available.

    Example::

        tracker = WeightTracker("trustfield_weights.db")
        tracker.record_result("epidemic", "CHAIN", predicted_set, actual_set)
        wv = tracker.get_adaptive_weights("CHAIN", min_history=5)
        if wv is not None:
            print(wv.weights)  # adaptively tuned weights

    Args:
        db_path: Path to the SQLite database file.  Created automatically on
            first use.  Use ``":memory:"`` for in-memory ephemeral storage
            (useful for testing).
    """

    _CREATE_HISTORY = """
        CREATE TABLE IF NOT EXISTS model_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name    TEXT    NOT NULL,
            topology_type TEXT    NOT NULL,
            predicted_nodes TEXT  NOT NULL,
            actual_nodes  TEXT    NOT NULL,
            precision     REAL    NOT NULL,
            recall        REAL    NOT NULL,
            f1_score      REAL    NOT NULL,
            timestamp     TEXT    NOT NULL
        )
    """

    _CREATE_WEIGHTS = """
        CREATE TABLE IF NOT EXISTS current_weights (
            topology_type TEXT NOT NULL,
            model_name    TEXT NOT NULL,
            weight        REAL NOT NULL,
            updated_at    TEXT NOT NULL,
            PRIMARY KEY (topology_type, model_name)
        )
    """

    def __init__(self, db_path: str = "trustfield_weights.db") -> None:
        """Initialise the WeightTracker, creating the database schema if needed.

        Args:
            db_path: Filesystem path for the SQLite database, or ``":memory:"``
                for an in-memory database (no persistence across Python sessions).
        """
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute(self._CREATE_HISTORY)
            self._conn.execute(self._CREATE_WEIGHTS)

    # ------------------------------------------------------------------
    # Recording results
    # ------------------------------------------------------------------

    def record_result(
        self,
        model_name: str,
        topology_type: str,
        predicted: Set[str],
        actual: Set[str],
    ) -> ModelAccuracy:
        """Record a model's prediction against ground-truth and compute metrics.

        Inserts a row into ``model_history`` with the precision, recall, and
        F1 score for this prediction.

        Args:
            model_name: Name of the propagation model (e.g. ``"epidemic"``).
            topology_type: Topology classification string (e.g. ``"CHAIN"``).
            predicted: Set of node IDs predicted as compromised by the model.
            actual: Set of node IDs that were actually compromised (ground truth).

        Returns:
            A ``ModelAccuracy`` dataclass with the computed metrics.
        """
        precision, recall, f1 = _compute_metrics(predicted, actual)
        ts = datetime.now(timezone.utc).isoformat()

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO model_history
                    (model_name, topology_type, predicted_nodes, actual_nodes,
                     precision, recall, f1_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    model_name,
                    topology_type,
                    ",".join(sorted(predicted)),
                    ",".join(sorted(actual)),
                    precision,
                    recall,
                    f1,
                    ts,
                ),
            )

        return ModelAccuracy(
            model_name=model_name,
            topology_type=topology_type,
            precision=precision,
            recall=recall,
            f1_score=f1,
        )

    # ------------------------------------------------------------------
    # Adaptive weight computation
    # ------------------------------------------------------------------

    def get_adaptive_weights(
        self, topology_type: str, min_history: int = 5
    ) -> Optional[WeightVector]:
        """Derive adaptive weights from historical model accuracy.

        For each model, computes the mean F1 score over the last 20 records
        for the given topology type, then normalises these means into a weight
        distribution.

        Args:
            topology_type: Topology classification string (e.g. ``"HUB"``).
            min_history: Minimum number of records required per-model before
                adaptive weights are computed.  If any model has fewer than
                ``min_history`` records the function returns ``None`` and the
                caller should fall back to the topology prior.

        Returns:
            A ``WeightVector`` with ``source="adaptive"`` if sufficient
            history exists, otherwise ``None``.
        """
        mean_f1: Dict[str, float] = {}

        for model in MODEL_NAMES:
            rows = self._conn.execute(
                """
                SELECT f1_score FROM model_history
                WHERE model_name = ? AND topology_type = ?
                ORDER BY id DESC LIMIT 20
                """,
                (model, topology_type),
            ).fetchall()

            if len(rows) < min_history:
                return None  # Not enough data for any model

            mean_f1[model] = sum(r["f1_score"] for r in rows) / len(rows)

        # Normalise F1 means into a probability distribution
        wv = WeightVector(
            weights=mean_f1,
            topology_type=topology_type,
            source="adaptive",
        ).normalize()
        wv.validate()
        return wv

    # ------------------------------------------------------------------
    # Weight persistence
    # ------------------------------------------------------------------

    def update_weights(
        self, topology_type: str, new_weights: WeightVector
    ) -> None:
        """Persist a weight vector snapshot to ``current_weights``.

        Args:
            topology_type: Topology classification string.
            new_weights: The ``WeightVector`` to persist.
        """
        ts = datetime.now(timezone.utc).isoformat()
        with self._conn:
            for model, w in new_weights.weights.items():
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO current_weights
                        (topology_type, model_name, weight, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (topology_type, model, w, ts),
                )

    def get_weight_history(
        self, topology_type: str, model_name: str
    ) -> List[dict]:
        """Retrieve the last 50 accuracy records for a model/topology pair.

        Args:
            topology_type: Topology classification string.
            model_name: Name of the propagation model.

        Returns:
            List of dicts (each with keys ``precision``, ``recall``,
            ``f1_score``, ``timestamp``), most-recent first.
        """
        rows = self._conn.execute(
            """
            SELECT precision, recall, f1_score, timestamp
            FROM model_history
            WHERE model_name = ? AND topology_type = ?
            ORDER BY id DESC LIMIT 50
            """,
            (model_name, topology_type),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __del__(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
