"""Demo: Module 5 — Cyber-Physical Guard Simulation.

Simulates a live attack on a hub-topology graph (50 nodes):
  1. Full pipeline: graph → ensemble → verification → guard deployment
  2. Step-by-step attacker traversal against guards
  3. Feedback loop tightening with strictness transitions
  4. Final containment metrics
  5. Missed-containment priority analysis
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.guards import (
    ContainmentEngine,
    GuardNetwork,
    HardwareSoftwareFeedback,
    PropagationSensor,
    StrictnessLevel,
)
from trustfield.verification import (
    BlastRadiusCalculator,
    IAMTraversal,
    TokenGenerator,
    VerificationReport,
)

NUM_NODES = 50
TOPOLOGY = "hub"
RANDOM_SEED = 7  # different from Module 4 demo for variety

print("=" * 70)
print("TrustField Module 5 — Cyber-Physical Guard Simulation Demo")
print("=" * 70)

# ---------------------------------------------------------------------------
# Step 1: Full Modules 1–4 pipeline
# ---------------------------------------------------------------------------

print("\n[1] Running Modules 1–4 pipeline on hub topology (50 nodes)...")

sim = IAMSimulator()
orch = TrustFieldOrchestrator(db_path=":memory:")

graph = sim.generate(TOPOLOGY, num_nodes=NUM_NODES, seed=42)
node_list = sorted(graph._graph.nodes())
seed_node = next(
    (n for n in node_list if graph._graph.out_degree(n) > 0), node_list[0]
)

analysis = orch.analyze(graph, seed_nodes=[seed_node])
topo = analysis.topology_fingerprint.topology_type.value
pred = analysis.ensemble_prediction

print(f"  Topology: {topo}  |  PBR={pred.total_nodes_analyzed} total nodes")
print(f"  Ensemble predicted {len(pred.compromised_nodes)} compromised  "
      f"(threshold={pred.decision_threshold})")

# Verification (Module 4)
gen = TokenGenerator()
traversal = IAMTraversal(gen).traverse(
    graph, [seed_node], max_depth=6, respect_conditions=True, random_seed=RANDOM_SEED
)
bra = BlastRadiusCalculator().compute(pred, traversal, graph)
report = VerificationReport(
    graph=graph,
    analysis_result=analysis,
    traversal_result=traversal,
    blast_radius_analysis=bra,
)

print(f"  VBR={len(traversal.verified_reachable)}  |  "
      f"Gap={bra.gap_size}  |  "
      f"Missed={len(bra.missed_nodes)}  |  "
      f"Classification={bra.gap_classification.value}")

# ---------------------------------------------------------------------------
# Step 2: Deploy guards, simulate attacker traversal step-by-step
# ---------------------------------------------------------------------------

print("\n[2] Deploying guards and simulating attacker traversal...")

guard_gen = TokenGenerator()
guard_net = GuardNetwork(graph, guard_gen)

blast_edges = set(guard_net.get_high_risk_edges(bra, top_k=15))
traversal_edges = {
    (s.from_node, s.to_node) for s in traversal.traversal_steps if s.succeeded
}
all_guard_edges = list(blast_edges | traversal_edges)
guard_net.deploy_guards(all_guard_edges, guards_per_edge=3)

print(f"  Guards deployed on {len(all_guard_edges)} edges "
      f"({len(blast_edges)} from blast radius + "
      f"{len(traversal_edges - blast_edges)} traversal-only)")

# Simulate attacker attempting the verified traversal steps
print()
n_allowed = 0
n_blocked = 0
for step_num, step in enumerate(traversal.traversal_steps[:12], start=1):
    edge = (step.from_node, step.to_node)
    try:
        edge_meta = graph.get_edge(*edge)
    except KeyError:
        continue
    token = guard_gen.generate(step.from_node, step.to_node, edge_meta, current_depth=step.depth)
    result = guard_net.validate_with_consensus(edge, token, required_approvals=2)
    status = result.consensus_decision
    approvals = result.approval_count
    # Find the blocking guard's reason (if blocked)
    reason = ""
    if status == "BLOCKED":
        for gid, dec in result.individual_decisions.items():
            if dec == "BLOCKED":
                reason = f" ({gid})"
                break
        n_blocked += 1
    else:
        n_allowed += 1
    print(f"  [Step {step_num:>2}] {step.from_node} → {step.to_node}: "
          f"{status}  (approvals={approvals}/3){reason}")

if len(traversal.traversal_steps) > 12:
    remaining = len(traversal.traversal_steps) - 12
    print(f"  ... {remaining} more traversal steps (omitted for brevity)")

print(f"\n  Summary: {n_allowed} ALLOWED, {n_blocked} BLOCKED out of first "
      f"{min(12, len(traversal.traversal_steps))} steps")

# ---------------------------------------------------------------------------
# Step 3: Feedback loop tightening
# ---------------------------------------------------------------------------

print("\n[3] Hardware-software feedback loop (5 cycles)...")

engine = ContainmentEngine(orch, token_generator=TokenGenerator())

# Run the full containment (includes feedback loop internally)
result = engine.execute(graph, [seed_node], report, n_feedback_cycles=5)

if result.feedback_actions:
    for i, action in enumerate(result.feedback_actions, 1):
        trigger_str = action.trigger.replace("risk_score_", "risk=")
        print(f"  Cycle {i}: {trigger_str} → "
              f"{action.old_strictness.value} → {action.new_strictness.value}")
else:
    print("  No strictness changes (risk stayed below ELEVATED threshold)")

print(f"\n  Final strictness: {result.final_strictness_level.value}")

# Sensor summary
if result.sensor_readings:
    last_reading = result.sensor_readings[-1]
    print(f"  Last sensor reading: "
          f"freq={last_reading.delegation_request_frequency:.2f}/s  "
          f"val_rate={last_reading.token_validation_rate:.2f}  "
          f"esc={last_reading.escalation_attempt_count}  "
          f"anomaly_score={last_reading.anomaly_score:.3f}  "
          f"anomaly={'YES' if last_reading.anomaly_detected else 'no'}")

# ---------------------------------------------------------------------------
# Step 4: Final containment metrics
# ---------------------------------------------------------------------------

print("\n[4] Final containment metrics")
print("-" * 50)
original_vbr_size = len(traversal.verified_reachable)
print(f"  Original VBR (pre-guards)   : {original_vbr_size} nodes")
post_vbr_size = original_vbr_size - len(result.contained_nodes)
print(f"  Post-guard VBR              : {post_vbr_size} nodes")
print(f"  Nodes contained             : {len(result.contained_nodes)}")
print(f"  Missed containments         : {len(result.missed_containments)}")
rate = result.containment_success_rate
status_icon = "✓" if rate >= 0.95 else "✗"
print(f"  Containment success rate    : {rate:.1%}  {status_icon} "
      f"(target >95%)")
print(f"  Edges blocked by guards     : {len(result.blocked_transitions)}")
print(f"  Total guard events          : {len(result.guard_events)}")
print(f"  Feedback actions taken      : {len(result.feedback_actions)}")

# ---------------------------------------------------------------------------
# Step 5: Missed containment priority analysis
# ---------------------------------------------------------------------------

if result.missed_containments:
    print("\n[5] Missed containment priority (next hardening targets)")
    print("-" * 50)
    # Score by privilege level
    scored = []
    for node_id in result.missed_containments:
        try:
            meta = graph.get_node(node_id)
            scored.append((node_id, meta.node_type.value, meta.privilege_level))
        except KeyError:
            scored.append((node_id, "UNKNOWN", 0.0))
    scored.sort(key=lambda x: -x[2])
    print(f"  {'Node':<20} {'Type':<15} {'Privilege':>10}")
    print(f"  {'-'*20} {'-'*15} {'-'*10}")
    for node_id, ntype, priv in scored[:8]:
        print(f"  {node_id:<20} {ntype:<15} {priv:>10.3f}")
    if len(scored) > 8:
        print(f"  ... {len(scored) - 8} more")
    print(f"\n  Recommendation: add explicit guards on inbound edges to "
          f"the top-{min(3, len(scored))} nodes above.")
else:
    print("\n[5] No missed containments — all verified paths successfully blocked.")

print("\n" + "=" * 70)
print("Module 5 Demo complete.")
print("=" * 70)
