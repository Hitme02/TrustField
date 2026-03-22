"""Demo: TrustField Baseline Comparison.

Runs all three ablation baselines (NaiveBFS, SingleBestModel, RandomGuards)
against the full TrustField pipeline on all four IAM topology archetypes and
prints Markdown + LaTeX comparison tables.

Usage:
    python demos/demo_baselines.py
"""

from __future__ import annotations

import time

from trustfield.baselines import BaselineComparison


def main() -> None:
    print("=" * 70)
    print("  TrustField — Baseline Comparison (Ablation Study)")
    print("=" * 70)
    print()
    print("Running all 4 methods × 4 topologies (num_nodes=30) ...")
    print()

    t_start = time.time()

    cmp = BaselineComparison(
        num_nodes=50,
        random_seed=42,
        top_k=15,
        n_feedback_cycles=5,
        guards_per_edge=3,
    )
    results = cmp.run_all_topologies()

    elapsed = round(time.time() - t_start, 1)
    print(f"Done in {elapsed}s\n")

    # --- Per-topology summary ---
    for topo, cr in results.items():
        print(f"── {topo.replace('_', ' ').upper()} ──")
        for label, res in cr.all_methods():
            bar_len = int(res.containment_success_rate * 20)
            bar = "#" * bar_len + "." * (20 - bar_len)
            print(
                f"  {label:<15}  [{bar}]  {res.containment_success_rate:.1%}"
                f"  guards={res.guards_deployed}  {res.final_strictness}"
                f"  ({res.elapsed_seconds}s)"
            )
        print()

    # --- Markdown table ---
    print("=" * 70)
    print("  MARKDOWN TABLE")
    print("=" * 70)
    print()
    print(cmp.to_markdown(results))

    # --- LaTeX table ---
    print()
    print("=" * 70)
    print("  LATEX TABLE (paste directly into paper)")
    print("=" * 70)
    print()
    print(cmp.to_latex(results))


if __name__ == "__main__":
    main()
