"""Demo: Module 6 — Full Pipeline + Visualization + Publication Output.

Runs TrustFieldPipeline.run_all_topologies() across all four IAM topology
archetypes and produces:

  1. Per-topology containment summary table
  2. Cross-topology ExploitabilityGap markdown table
  3. LaTeX results section (Tables 1-3)
  4. Web export paths (JSON / JS / CSV) for the Three.js viewer
  5. Aggregate publication metrics
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.pipeline import TrustFieldPipeline
from trustfield.visualization.report_generator import ReportGenerator

NUM_NODES   = 50
RANDOM_SEED = 42
OUTPUT_DIR  = str(Path(__file__).parent.parent / "out")

print("=" * 70)
print("TrustField Module 6 — Full Pipeline + Visualization Demo")
print("=" * 70)

# ---------------------------------------------------------------------------
# Step 1: Run all four topologies
# ---------------------------------------------------------------------------

print(f"\n[1] Running full pipeline on all 4 topologies ({NUM_NODES} nodes each)...")

pipeline = TrustFieldPipeline(
    output_dir=OUTPUT_DIR,
    n_feedback_cycles=5,
    random_seed=RANDOM_SEED,
)

results = pipeline.run_all_topologies(
    num_nodes=NUM_NODES,
    random_seed=RANDOM_SEED,
    export=True,
)

print(f"  Topologies processed: {list(results.keys())}")

# ---------------------------------------------------------------------------
# Step 2: Per-topology summary
# ---------------------------------------------------------------------------

print("\n[2] Per-topology containment summary")
print("-" * 70)
print(f"  {'Topology':<16} {'Nodes':>5} {'PBR':>4} {'VBR':>4} {'Gap':>4} "
      f"{'Classification':<18} {'Contain%':>8} {'Missed':>6}")
print(f"  {'-'*16} {'-'*5} {'-'*4} {'-'*4} {'-'*4} "
      f"{'-'*18} {'-'*8} {'-'*6}")

for topo, result in results.items():
    m = result.metrics
    rate = m["containment_success_rate"]
    icon = "✓" if rate >= 0.95 else "✗"
    print(
        f"  {topo:<16} {m['total_nodes']:>5} "
        f"{m['pbr_size']:>4} {m['vbr_size']:>4} {m['gap_size']:>4} "
        f"{m['gap_classification']:<18} "
        f"{rate:>7.1%}{icon} "
        f"{m['missed_containments']:>6}"
    )

# ---------------------------------------------------------------------------
# Step 3: Cross-topology ExploitabilityGap table (Markdown)
# ---------------------------------------------------------------------------

print("\n[3] Cross-topology ExploitabilityGap table")
print("-" * 70)

analyses = {topo: r.blast_radius_analysis for topo, r in results.items()}
containments = {topo: r.containment_result for topo, r in results.items()}

reporter = ReportGenerator()
print(reporter.gap_table_markdown(analyses))

# ---------------------------------------------------------------------------
# Step 4: Containment effectiveness table (Markdown)
# ---------------------------------------------------------------------------

print("\n[4] Containment effectiveness table")
print("-" * 70)
print(reporter.containment_table_markdown(containments))

# ---------------------------------------------------------------------------
# Step 5: LaTeX results section
# ---------------------------------------------------------------------------

print("\n[5] LaTeX results section (Tables 1–2)")
print("-" * 70)

latex_out = reporter.full_latex_section(analyses, containments)
# Print first 25 lines to avoid flooding the console
latex_lines = latex_out.split("\n")
for line in latex_lines[:25]:
    print(f"  {line}")
if len(latex_lines) > 25:
    print(f"  ... ({len(latex_lines) - 25} more lines)")

# Save to file
latex_path = Path(OUTPUT_DIR) / "results_tables.tex"
latex_path.parent.mkdir(parents=True, exist_ok=True)
latex_path.write_text(latex_out, encoding="utf-8")
print(f"\n  Saved: {latex_path}")

# ---------------------------------------------------------------------------
# Step 6: Web export summary
# ---------------------------------------------------------------------------

print("\n[6] Web visualization output files")
print("-" * 70)

for topo, result in results.items():
    if result.output_files:
        print(f"  {topo}:")
        for ftype, fpath in result.output_files.items():
            print(f"    {ftype:<6} → {fpath}")
    else:
        print(f"  {topo}: (no output files)")

# ---------------------------------------------------------------------------
# Step 7: Aggregate publication metrics
# ---------------------------------------------------------------------------

print("\n[7] Aggregate publication metrics")
print("-" * 70)

rates = [r.metrics["containment_success_rate"] for r in results.values()]
gap_scores = [r.metrics["exploitability_gap_score"] for r in results.values()]
vbr_sizes = [r.metrics["vbr_size"] for r in results.values()]
pbr_sizes = [r.metrics["pbr_size"] for r in results.values()]

avg_rate       = sum(rates) / len(rates)
avg_gap_score  = sum(gap_scores) / len(gap_scores)
critical_misses = sum(
    1 for r in results.values()
    if r.metrics["gap_classification"] == "CRITICAL_MISS"
)

print(f"  Mean containment success rate : {avg_rate:.1%}")
print(f"  Mean ExploitabilityGap score  : {avg_gap_score:.4f}")
print(f"  Critical-miss topologies      : {critical_misses} / {len(results)}")
print(f"  Mean VBR size                 : {sum(vbr_sizes)/len(vbr_sizes):.1f} nodes")
print(f"  Mean PBR size                 : {sum(pbr_sizes)/len(pbr_sizes):.1f} nodes")

print("\n  To view the 3D visualization:")
print(f"  Open {Path(OUTPUT_DIR) / 'hub' / 'index.html'} in a browser")
print("  (Or open web/index.html after copying a graph_data.js into web/)")

print("\n" + "=" * 70)
print("Module 6 Demo complete.")
print("=" * 70)
