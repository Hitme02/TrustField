"""Empirical calibration analysis for TrustField propagation model confidence values.

The five propagation models each carry a hardcoded ``_MODEL_CONFIDENCE`` constant
(graph_traversal: 0.85, epidemic: 0.75, spectral_cascade: 0.80, percolation: 0.70,
control_system: 0.78).  These were theoretical estimates.  This module measures the
*empirical* F1 score of each model against a structural ground truth and replaces
those constants with the measured values.

Algorithm
---------
For each (model, topology) combination:

1. Generate ``n_graphs`` graphs using ``IAMSimulator`` (seeds 0 … n_graphs-1).
2. For each graph, pick the lowest-privilege SERVICE node as the attacker seed.
   Falls back to the globally lowest-privilege node if no SERVICE node exists.
3. Run the model → ``predicted = PropagationResult.compromised_nodes``.
4. Ground truth = ``GraphTraversalModel`` result (deterministic structural upper
   bound; every reachable node is in the BFS reachable set).
5. Compute per-graph precision / recall / F1.
6. Average across all graphs → ``empirical_f1``.
7. ``calibration_error = |stated_confidence − empirical_f1|``.

Side effects (called automatically from ``CalibrationAnalysis.run()``)
----------------------------------------------------------------------
* Updates ``_MODEL_CONFIDENCE`` in each of the five propagation model source files
  to the recommended empirical value.
* Updates ``_HUB_WEIGHTS``, ``_CHAIN_WEIGHTS``, ``_DENSE_CLUSTER_WEIGHTS`` in
  ``trustfield/ensemble/topology_selector.py`` to be proportional to the per-topology
  empirical F1 scores (normalised to sum to 1.0).

Usage::

    from trustfield.baselines.calibration_analysis import CalibrationAnalysis
    report = CalibrationAnalysis(n_graphs=100).run()
    print(report.markdown_table)
    print(report.latex_table)
"""

from __future__ import annotations

import re
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.graph.node_types import NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.propagation.graph_traversal import GraphTraversalModel
from trustfield.propagation.runner import PropagationRunner

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Stated (hardcoded) confidence values — the starting point before calibration.
STATED_CONFIDENCE: Dict[str, float] = {
    "graph_traversal":  0.85,
    "epidemic":         0.75,
    "spectral_cascade": 0.80,
    "percolation":      0.70,
    "control_system":   0.78,
}

#: All five model names (must match PropagationRunner registry keys).
MODEL_NAMES: List[str] = list(STATED_CONFIDENCE)

#: Paths to each model source file, relative to the project root.
_MODEL_FILE_RELPATH: Dict[str, str] = {
    "graph_traversal":  "trustfield/propagation/graph_traversal.py",
    "epidemic":         "trustfield/propagation/epidemic.py",
    "spectral_cascade": "trustfield/propagation/spectral_cascade.py",
    "percolation":      "trustfield/propagation/percolation.py",
    "control_system":   "trustfield/propagation/control_system.py",
}

#: Topology → name of the weight-dict variable in topology_selector.py.
_WEIGHT_VAR: Dict[str, str] = {
    "hub":           "_HUB_WEIGHTS",
    "chain":         "_CHAIN_WEIGHTS",
    "dense_cluster": "_DENSE_CLUSTER_WEIGHTS",
}

#: Project root (two levels above trustfield/baselines/).
_PROJECT_ROOT: Path = Path(__file__).parent.parent.parent


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ModelCalibration:
    """Calibration metrics for one (model, topology) pair.

    Attributes:
        model_name:           Propagation model identifier.
        topology_type:        Topology label (``"hub"``, ``"chain"``, etc.).
        stated_confidence:    The hardcoded ``_MODEL_CONFIDENCE`` value.
        empirical_precision:  Mean precision across all calibration graphs.
        empirical_recall:     Mean recall across all calibration graphs.
        empirical_f1:         Mean F1 score — becomes the new confidence value.
        calibration_error:    ``|stated_confidence − empirical_f1|``.
        is_calibrated:        ``True`` if ``calibration_error < 0.05``.
    """

    model_name: str
    topology_type: str
    stated_confidence: float
    empirical_precision: float
    empirical_recall: float
    empirical_f1: float
    calibration_error: float
    is_calibrated: bool


@dataclass
class CalibrationReport:
    """Full calibration results across all models and topologies.

    Attributes:
        per_model_topology:              Nested dict ``model → topology → ModelCalibration``.
        overall_calibration_errors:      ``model → mean calibration error across topologies``.
        recommended_confidence_updates:  ``model → new confidence value (mean F1)``.
        latex_table:                     Ready-to-include LaTeX table (booktabs style).
        markdown_table:                  Markdown table for quick inspection.
    """

    per_model_topology: Dict[str, Dict[str, ModelCalibration]] = field(default_factory=dict)
    overall_calibration_errors: Dict[str, float] = field(default_factory=dict)
    recommended_confidence_updates: Dict[str, float] = field(default_factory=dict)
    latex_table: str = ""
    markdown_table: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pick_seed(graph: TrustGraph) -> str:
    """Return the lowest-privilege SERVICE node; fall back to any min-privilege node."""
    all_nodes = [(nid, data["metadata"])
                 for nid, data in graph._graph.nodes(data=True)]
    service_nodes = [(nid, m) for nid, m in all_nodes
                     if m.node_type == NodeType.SERVICE]
    candidates = service_nodes if service_nodes else all_nodes
    return min(candidates, key=lambda x: x[1].privilege_level)[0]


def _f1(predicted: Set[str], ground_truth: Set[str]) -> Tuple[float, float, float]:
    """Compute (precision, recall, F1) for predicted vs ground_truth sets.

    Edge cases:
    * Both empty → (1.0, 1.0, 1.0): perfect agreement on "nothing reachable".
    * Predicted empty, ground_truth non-empty → (1.0, 0.0, 0.0): no false
      positives but zero recall.
    * Ground_truth empty, predicted non-empty → (0.0, 1.0, 0.0): all false
      positives, vacuous recall.
    """
    if not predicted and not ground_truth:
        return 1.0, 1.0, 1.0
    if not predicted:
        return 1.0, 0.0, 0.0
    if not ground_truth:
        return 0.0, 1.0, 0.0
    tp = len(predicted & ground_truth)
    precision = tp / len(predicted)
    recall = tp / len(ground_truth)
    if precision + recall == 0.0:
        return 0.0, 0.0, 0.0
    return precision, recall, 2.0 * precision * recall / (precision + recall)


def _update_model_confidence_file(model_name: str, new_value: float) -> None:
    """Overwrite ``_MODEL_CONFIDENCE`` in the model's source file."""
    rel = _MODEL_FILE_RELPATH[model_name]
    path = _PROJECT_ROOT / rel
    content = path.read_text(encoding="utf-8")
    new_content = re.sub(
        r"^(_MODEL_CONFIDENCE\s*=\s*)[\d.]+",
        lambda m: f"{m.group(1)}{new_value:.4f}",
        content,
        flags=re.MULTILINE,
    )
    path.write_text(new_content, encoding="utf-8")


def _parse_reserved_weights(content: str, var_name: str) -> Dict[str, float]:
    """Read weight values from a named dict block that are NOT in MODEL_NAMES.

    These are "reserved" slots for future models (e.g. ``gnn``).  The
    calibration must preserve their values and scale the 5-model weights to
    fill only the remaining proportion (``1.0 − reserved_total``).

    Args:
        content: Full text of topology_selector.py.
        var_name: Name of the dict variable, e.g. ``"_CHAIN_WEIGHTS"``.

    Returns:
        Dict mapping reserved key → current float value.
    """
    lines = content.split("\n")
    in_block = False
    reserved: Dict[str, float] = {}
    model_names_set = set(MODEL_NAMES)

    for line in lines:
        if not in_block:
            if re.match(rf"^{re.escape(var_name)}\s*=\s*\{{", line):
                in_block = True
        else:
            if re.match(r"^\}\s*$", line):
                break
            m = re.match(r'^\s+"(\w+)":\s*([\d.]+)\s*,\s*$', line)
            if m and m.group(1) not in model_names_set:
                reserved[m.group(1)] = float(m.group(2))

    return reserved


def _update_topology_selector_weights(
    topo_weights: Dict[str, Dict[str, float]],
) -> None:
    """Rewrite weight values in topology_selector.py for each calibrated topology.

    Reserved weight slots (keys not in MODEL_NAMES, e.g. ``"gnn"``) are
    preserved at their current values.  The five calibrated model weights are
    scaled to fill ``1.0 − sum(reserved_weights)`` so the full dict still
    sums to 1.0.

    Args:
        topo_weights: Mapping ``topology → {model_name: raw_f1_score}``.
            Only topologies present in the dict are updated; ``_MIXED_WEIGHTS``
            is left unchanged (no calibration data for mixed graphs).
    """
    selector_path = _PROJECT_ROOT / "trustfield" / "ensemble" / "topology_selector.py"
    content = selector_path.read_text(encoding="utf-8")

    for topo, raw_f1 in topo_weights.items():
        var_name = _WEIGHT_VAR.get(topo)
        if var_name is None:
            continue

        # Find any reserved (non-MODEL_NAMES) weights already in this block
        reserved = _parse_reserved_weights(content, var_name)
        reserved_total = sum(reserved.values())
        available = max(0.0, round(1.0 - reserved_total, 6))

        # Normalise the 5-model F1 scores to fill the available proportion
        total_f1 = sum(raw_f1.values())
        if total_f1 > 0 and available > 0:
            scaled = {m: round(v * available / total_f1, 4) for m, v in raw_f1.items()}
        elif available > 0:
            n = len(raw_f1)
            scaled = {m: round(available / n, 4) for m in raw_f1}
        else:
            scaled = {m: 0.0 for m in raw_f1}

        # Fix rounding so that scaled weights sum exactly to `available`
        _fix_sum_to(scaled, available)
        content = _replace_weights_in_block(content, var_name, scaled)

    selector_path.write_text(content, encoding="utf-8")


def _replace_weights_in_block(
    content: str,
    var_name: str,
    new_weights: Dict[str, float],
) -> str:
    """Replace numeric weight values for each model inside a named dict block.

    The block is identified by ``var_name = {`` and terminated by a bare ``}``
    at the start of a line (no indent).  Only assignment lines of the form
    ``    "model_name":   0.XX,`` are modified; comment lines are untouched.
    """
    lines = content.split("\n")
    result: List[str] = []
    in_block = False

    for line in lines:
        if not in_block:
            # Detect dict start: e.g. `_HUB_WEIGHTS = {`
            if re.match(rf"^{re.escape(var_name)}\s*=\s*\{{", line):
                in_block = True
            result.append(line)
        else:
            # Detect dict end: bare `}` at column 0
            if re.match(r"^\}\s*$", line):
                in_block = False
                result.append(line)
                continue
            # Try to replace a weight assignment line
            replaced = False
            for model, new_w in new_weights.items():
                m = re.match(
                    r'^(\s+"' + re.escape(model) + r'":\s*)[\d.]+(\s*,\s*)$',
                    line,
                )
                if m:
                    line = f"{m.group(1)}{new_w:.4f}{m.group(2)}"
                    replaced = True
                    break
            result.append(line)

    return "\n".join(result)


# ---------------------------------------------------------------------------
# CalibrationAnalysis
# ---------------------------------------------------------------------------

class CalibrationAnalysis:
    """Measure empirical precision/recall/F1 for all five TrustField propagation
    models and update their hardcoded confidence constants accordingly.

    Args:
        n_graphs:       Number of graphs per (model × topology) cell.
                        Higher values reduce variance; 100 is recommended for
                        publication.
        topology_types: Which topologies to calibrate on.  Defaults to the three
                        structural extremes: hub, chain, dense_cluster.
        num_nodes:      Nodes per generated graph.  20 is fast; 50 is more
                        representative of real IAM deployments.
        apply_updates:  If ``True`` (default), write empirical F1 values back to
                        model source files and update topology selector weights.

    Example::

        report = CalibrationAnalysis(n_graphs=100).run()
        print(report.markdown_table)
    """

    def __init__(
        self,
        n_graphs: int = 100,
        topology_types: Optional[List[str]] = None,
        num_nodes: int = 20,
        apply_updates: bool = True,
    ) -> None:
        self._n_graphs = n_graphs
        self._topologies = topology_types or ["hub", "chain", "dense_cluster"]
        self._num_nodes = num_nodes
        self._apply_updates = apply_updates
        self._sim = IAMSimulator()
        self._runner = PropagationRunner()
        self._gt_model = GraphTraversalModel()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> CalibrationReport:
        """Run the full calibration sweep and (optionally) update source files.

        Returns:
            :class:`CalibrationReport` with all metrics, tables, and
            recommended confidence updates.
        """
        report = CalibrationReport()

        # --- Calibrate each (model, topology) cell ---
        for model in MODEL_NAMES:
            report.per_model_topology[model] = {}
            for topo in self._topologies:
                cal = self._calibrate(model, topo)
                report.per_model_topology[model][topo] = cal

        # --- Overall calibration error per model (mean across topologies) ---
        for model in MODEL_NAMES:
            errors = [
                report.per_model_topology[model][t].calibration_error
                for t in self._topologies
            ]
            report.overall_calibration_errors[model] = round(
                statistics.mean(errors), 4
            )

        # --- Recommended confidence: mean empirical F1 across topologies ---
        for model in MODEL_NAMES:
            f1s = [
                report.per_model_topology[model][t].empirical_f1
                for t in self._topologies
            ]
            report.recommended_confidence_updates[model] = round(
                statistics.mean(f1s), 4
            )

        # --- Render tables ---
        report.markdown_table = self._to_markdown(report)
        report.latex_table = self._to_latex(report)

        # --- Apply updates to source files ---
        if self._apply_updates:
            self._apply(report)

        return report

    # ------------------------------------------------------------------
    # Internal: calibration for one (model, topology) pair
    # ------------------------------------------------------------------

    def _calibrate(self, model_name: str, topology: str) -> ModelCalibration:
        precisions: List[float] = []
        recalls: List[float] = []
        f1s: List[float] = []

        for seed in range(self._n_graphs):
            graph = self._sim.generate(
                topology, num_nodes=self._num_nodes, seed=seed
            )
            entry = _pick_seed(graph)

            # Ground truth: deterministic BFS upper bound
            gt_nodes: Set[str] = self._gt_model.run(
                graph, [entry]
            ).compromised_nodes

            # Model prediction
            pred_nodes: Set[str] = self._runner.run_single(
                model_name, graph, [entry]
            ).compromised_nodes

            p, r, f = _f1(pred_nodes, gt_nodes)
            precisions.append(p)
            recalls.append(r)
            f1s.append(f)

        emp_p = round(statistics.mean(precisions), 4)
        emp_r = round(statistics.mean(recalls), 4)
        emp_f1 = round(statistics.mean(f1s), 4)
        stated = STATED_CONFIDENCE[model_name]
        error = round(abs(stated - emp_f1), 4)

        return ModelCalibration(
            model_name=model_name,
            topology_type=topology,
            stated_confidence=stated,
            empirical_precision=emp_p,
            empirical_recall=emp_r,
            empirical_f1=emp_f1,
            calibration_error=error,
            is_calibrated=error < 0.05,
        )

    # ------------------------------------------------------------------
    # Internal: apply updates to source files
    # ------------------------------------------------------------------

    def _apply(self, report: CalibrationReport) -> None:
        """Write empirical confidence values to model files + topology selector."""
        # 1. Update _MODEL_CONFIDENCE in each model file
        for model, new_conf in report.recommended_confidence_updates.items():
            _update_model_confidence_file(model, new_conf)

        # 2. Update topology selector weight tables
        #    For each calibrated topology: weights ∝ per-topology F1 (normalised)
        topo_weights: Dict[str, Dict[str, float]] = {}
        for topo in self._topologies:
            if topo not in _WEIGHT_VAR:
                continue
            raw = {
                model: report.per_model_topology[model][topo].empirical_f1
                for model in MODEL_NAMES
            }
            total = sum(raw.values())
            if total > 0:
                normalised = {m: round(v / total, 4) for m, v in raw.items()}
                # Fix floating point rounding so weights sum to exactly 1.0
                _fix_sum(normalised)
            else:
                n = len(MODEL_NAMES)
                normalised = {m: round(1.0 / n, 4) for m in MODEL_NAMES}
            topo_weights[topo] = normalised

        _update_topology_selector_weights(topo_weights)

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------

    def _to_markdown(self, report: CalibrationReport) -> str:
        lines = [
            "## Model Calibration — Empirical vs Stated Confidence\n",
            "| Model | Topology | Stated | Precision | Recall | F1 (new) | Error | Calibrated |",
            "|-------|----------|--------|-----------|--------|----------|-------|------------|",
        ]
        for model in MODEL_NAMES:
            for topo in self._topologies:
                c = report.per_model_topology[model][topo]
                ok = "✓" if c.is_calibrated else "✗"
                lines.append(
                    f"| {model} | {topo} "
                    f"| {c.stated_confidence:.2f} "
                    f"| {c.empirical_precision:.4f} "
                    f"| {c.empirical_recall:.4f} "
                    f"| **{c.empirical_f1:.4f}** "
                    f"| {c.calibration_error:.4f} "
                    f"| {ok} |"
                )
        lines.append("\n### Recommended Updates\n")
        lines.append("| Model | Stated | → New | Error |")
        lines.append("|-------|--------|-------|-------|")
        for model in MODEL_NAMES:
            old = STATED_CONFIDENCE[model]
            new = report.recommended_confidence_updates[model]
            err = report.overall_calibration_errors[model]
            arrow = "↑" if new > old else ("↓" if new < old else "=")
            lines.append(
                f"| {model} | {old:.2f} | {arrow} {new:.4f} | {err:.4f} |"
            )
        return "\n".join(lines)

    def _to_latex(self, report: CalibrationReport) -> str:
        r"""Render a booktabs-style LaTeX table.

        Format::

            Model & Topology & Stated & Precision & Recall & F1 (new) & Error \\
        """
        rows = []
        for model in MODEL_NAMES:
            for topo in self._topologies:
                c = report.per_model_topology[model][topo]
                f1_str = (
                    r"\textbf{" + f"{c.empirical_f1:.4f}" + "}"
                    if c.is_calibrated
                    else f"{c.empirical_f1:.4f}"
                )
                rows.append(
                    f"{model.replace('_', r'-')} & "
                    f"{topo.replace('_', '-')} & "
                    f"{c.stated_confidence:.2f} & "
                    f"{c.empirical_precision:.4f} & "
                    f"{c.empirical_recall:.4f} & "
                    f"{f1_str} & "
                    f"{c.calibration_error:.4f} \\\\"
                )
        body = "\n".join(rows)

        return (
            "% === TrustField Model Calibration — Auto-Generated ===\n\n"
            r"\begin{table}[h]" + "\n"
            r"\centering" + "\n"
            r"\caption{Empirical Calibration of TrustField Propagation Model Confidence Values}" + "\n"
            r"\label{tab:calibration}" + "\n"
            r"\begin{tabular}{llrrrrr}" + "\n"
            r"\toprule" + "\n"
            r"Model & Topology & Stated & Precision & Recall & F1 (new) & Error \\" + "\n"
            r"\midrule" + "\n"
            + body + "\n"
            r"\bottomrule" + "\n"
            r"\end{tabular}" + "\n"
            r"\end{table}"
        )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _fix_sum(weights: Dict[str, float]) -> None:
    """Adjust the largest weight so the dict sums to exactly 1.0 (in-place)."""
    _fix_sum_to(weights, 1.0)


def _fix_sum_to(weights: Dict[str, float], target: float) -> None:
    """Adjust the largest weight so the dict sums to exactly ``target`` (in-place)."""
    total = sum(weights.values())
    diff = round(target - total, 6)
    if abs(diff) > 1e-9 and weights:
        largest = max(weights, key=weights.__getitem__)
        weights[largest] = round(weights[largest] + diff, 4)
