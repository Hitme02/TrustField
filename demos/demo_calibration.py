"""Demo: TrustField Propagation Model Calibration.

Measures empirical precision/recall/F1 for all five propagation models across
hub, chain, and dense_cluster topologies, then replaces the hardcoded
_MODEL_CONFIDENCE constants with the measured values.

Usage:
    python demos/demo_calibration.py
"""

from __future__ import annotations

import time

from trustfield.baselines.calibration_analysis import (
    CalibrationAnalysis,
    MODEL_NAMES,
    STATED_CONFIDENCE,
    _PROJECT_ROOT,
)


def main() -> None:
    print("=" * 70)
    print("  TrustField — Empirical Model Calibration")
    print("=" * 70)
    print()
    print("Running calibration: 5 models × 3 topologies × 100 graphs …")
    print()

    t0 = time.time()
    ca = CalibrationAnalysis(n_graphs=100, apply_updates=True)
    report = ca.run()
    elapsed = round(time.time() - t0, 1)
    print(f"Done in {elapsed}s\n")

    # --- Before / After confidence table ---
    print("── Before / After Confidence ──────────────────────────────────")
    print(f"  {'Model':<20}  {'Stated':>7}  {'Empirical F1':>13}  {'Error':>7}  Status")
    print(f"  {'-'*20}  {'-'*7}  {'-'*13}  {'-'*7}  ------")
    for model in MODEL_NAMES:
        old = STATED_CONFIDENCE[model]
        new = report.recommended_confidence_updates[model]
        err = report.overall_calibration_errors[model]
        direction = "↑" if new > old else ("↓" if new < old else "=")
        status = "OK  (error < 0.05)" if err < 0.05 else "MISCALIBRATED"
        print(f"  {model:<20}  {old:>7.4f}  {direction} {new:>10.4f}  {err:>7.4f}  {status}")

    # --- Miscalibrated models ---
    print()
    miscal = [m for m in MODEL_NAMES if report.overall_calibration_errors[m] >= 0.05]
    if miscal:
        print(f"  MISCALIBRATED models (error ≥ 0.05): {', '.join(miscal)}")
    else:
        print("  All models are within calibration tolerance (error < 0.05).")

    # --- Per-topology breakdown ---
    print()
    print("── Per-Topology F1 Scores ─────────────────────────────────────")
    header = f"  {'Model':<20}" + "".join(f"  {'hub':>8}  {'chain':>8}  {'dense':>8}")
    print(header.replace("  hub      chain      dense", "  hub      chain      dense_cl"))
    print(f"  {'-'*20}  {'---':>8}  {'---':>8}  {'---':>8}")
    for model in MODEL_NAMES:
        row = f"  {model:<20}"
        for topo in ["hub", "chain", "dense_cluster"]:
            f1 = report.per_model_topology[model][topo].empirical_f1
            row += f"  {f1:>8.4f}"
        print(row)

    # --- Updated topology selector weights ---
    print()
    print("── Updated Topology Selector Weights (after calibration) ───────")
    import importlib
    import trustfield.ensemble.topology_selector as ts
    importlib.reload(ts)

    for label, weights in [
        ("HUB",           ts._HUB_WEIGHTS),
        ("CHAIN",         ts._CHAIN_WEIGHTS),
        ("DENSE_CLUSTER", ts._DENSE_CLUSTER_WEIGHTS),
    ]:
        total = sum(weights.values())
        parts = "  ".join(f"{m[:6]}={w:.4f}" for m, w in weights.items())
        print(f"  {label:<14} [{parts}]  sum={total:.4f}")

    # --- Markdown table ---
    print()
    print("=" * 70)
    print("  MARKDOWN TABLE")
    print("=" * 70)
    print()
    print(report.markdown_table)

    # --- LaTeX table ---
    print()
    print("=" * 70)
    print("  LATEX TABLE")
    print("=" * 70)
    print()
    print(report.latex_table)


if __name__ == "__main__":
    main()
