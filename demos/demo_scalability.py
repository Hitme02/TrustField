"""Demo: TrustField scalability benchmark.

Runs the full pipeline across N = 20, 50, 100, 200, 500, 1000 nodes,
prints a timing table, and exports the LaTeX table to output/scalability_table.tex.

Run:
    PYTHONPATH=. python demos/demo_scalability.py
"""

from __future__ import annotations

import os

from trustfield.baselines import ScalabilityBenchmark


def main() -> None:
    print("=" * 72)
    print("TrustField Scalability Benchmark")
    print("topology=hub  |  percolation n_trials=20  |  n_runs=3")
    print("=" * 72)

    bench = ScalabilityBenchmark(topology="hub", seed=42)

    print("\nRunning benchmark (this may take a minute at N=1000)...")
    report = bench.run(
        node_counts=[20, 50, 100, 200, 500, 1000],
        n_runs=3,
        include_gnn=True,
    )

    # ------------------------------------------------------------------
    # Print timing table
    # ------------------------------------------------------------------
    header = (
        f"\n{'N':>6}  {'|E|':>6}  {'FP':>7}  {'Prop':>8}  {'Ens':>7}  "
        f"{'Ver':>8}  {'Guard':>8}  {'Total':>9}  <100ms"
    )
    sub = (
        f"{'':>6}  {'':>6}  {'ms':>7}  {'ms':>8}  {'ms':>7}  "
        f"{'ms':>8}  {'ms':>8}  {'ms':>9}"
    )
    print(header)
    print(sub)
    print("-" * 72)

    for r in report.results:
        guard_ok = "Y" if r.meets_100ms_guard_target else "N"
        marker = " *" if r.total_ms > 1000 else "  "
        print(
            f"{r.n_nodes:>6}  {r.n_edges:>6}  "
            f"{r.fingerprint_ms:>7.1f}  {r.propagation_ms:>8.1f}  "
            f"{r.ensemble_ms:>7.1f}  {r.verification_ms:>8.1f}  "
            f"{r.guard_deployment_ms:>8.1f}  {r.total_ms:>9.1f}  "
            f"{guard_ok}{marker}"
        )

    print("\n  * row exceeds 1 second")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  System stays under 1 s up to N={report.max_n_under_1s} nodes")
    print(f"  System stays under 5 s up to N={report.max_n_under_5s} nodes")
    print(f"  Bottleneck: {report.bottleneck_stage}  |  Complexity: {report.complexity_estimate}")

    print("\nNotes:")
    for note in report.notes:
        print(f"  • {note}")

    # ------------------------------------------------------------------
    # Export LaTeX table
    # ------------------------------------------------------------------
    output_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output"
    )
    os.makedirs(output_dir, exist_ok=True)
    tex_path = os.path.join(output_dir, "scalability_table.tex")

    with open(tex_path, "w") as fh:
        fh.write(report.latex_table)
        fh.write("\n")

    print(f"\nLaTeX table exported to: {tex_path}")
    print("\nDemo complete.")


if __name__ == "__main__":
    main()
