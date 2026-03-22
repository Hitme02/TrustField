"""Demo: TrustField temporal attack simulator.

Runs all three move strategies (greedy, stealthy, random) on a 40-node hub
topology and shows:
  - Per-step timeline for each strategy
  - Side-by-side summary: steps to high-priv, time to detection, success
  - Post-hoc sensor analysis comparing anomaly scores

Run:
    PYTHONPATH=. python demos/demo_temporal.py
"""

from __future__ import annotations

from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.guards.guard_network import GuardNetwork
from trustfield.guards.sensor import PropagationSensor
from trustfield.propagation.temporal_model import TemporalAttackSimulator, TemporalResult
from trustfield.verification.delegation_token import TokenGenerator

_HIGH_PRIV = 0.8
_STRATEGIES = ["greedy", "stealthy", "random"]


def _steps_to_high_priv(result: TemporalResult, graph) -> str:
    for step in result.timeline:
        for nid in step.nodes_compromised_so_far:
            meta = graph.nx_graph.nodes.get(nid, {}).get("metadata")
            if meta and meta.privilege_level >= _HIGH_PRIV:
                return str(step.time_step)
    return "never"


def _print_timeline(result: TemporalResult, strategy: str, max_rows: int = 12) -> None:
    print(f"\n  Timeline — {strategy.upper()} (first {max_rows} steps)")
    print(f"  {'Step':>4}  {'Node':<20}  {'Action':<10}  "
          f"{'#Comp':>5}  {'Detect':>6}  {'Strict'}")
    print("  " + "-" * 64)
    for step in result.timeline[:max_rows]:
        det = "YES" if step.detection_triggered else "---"
        print(
            f"  {step.time_step:>4}  {step.current_node:<20}  "
            f"{step.action:<10}  {len(step.nodes_compromised_so_far):>5}  "
            f"{det:>6}  {step.strictness_level}"
        )
    if len(result.timeline) > max_rows:
        print(f"  ... ({len(result.timeline) - max_rows} more steps)")


def main() -> None:
    print("=" * 72)
    print("TrustField Temporal Attack Simulator Demo")
    print("topology=hub (40 nodes)  |  dwell_time=3  |  detection_prob=0.15")
    print("=" * 72)

    graph = IAMSimulator().generate("hub", num_nodes=40, seed=42)
    tgen = TokenGenerator()
    guard_net = GuardNetwork(graph, tgen)
    sensor = PropagationSensor(anomaly_threshold=0.6)

    # Seed: use hub node (highest out-degree) for clear strategy differences
    hub_node = max(
        graph.nx_graph.nodes(), key=lambda n: graph.nx_graph.out_degree(n)
    )
    seed_nodes = [hub_node]
    print(f"\nAttacker entry point: {hub_node}")
    print(f"Hub out-degree: {graph.nx_graph.out_degree(hub_node)} outgoing edges")

    results: dict[str, TemporalResult] = {}
    for strategy in _STRATEGIES:
        sim = TemporalAttackSimulator(
            dwell_time=3,
            detection_probability=0.15,
            move_strategy=strategy,
            seed=42,
        )
        results[strategy] = sim.simulate(
            graph, seed_nodes, guard_net, sensor, max_steps=40
        )

    # ------------------------------------------------------------------
    # Per-strategy timelines
    # ------------------------------------------------------------------
    for strategy in _STRATEGIES:
        _print_timeline(results[strategy], strategy)

    # ------------------------------------------------------------------
    # Side-by-side summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("STRATEGY COMPARISON SUMMARY")
    print("=" * 72)
    header = (
        f"  {'Strategy':<10}  {'Steps→HighPriv':>14}  "
        f"{'Time→Detection':>14}  {'Success':>7}  "
        f"{'Events/Step':>11}  {'FinalComp':>9}"
    )
    print(header)
    print("  " + "-" * 68)

    for strategy in _STRATEGIES:
        r = results[strategy]
        high_step = _steps_to_high_priv(r, graph)
        det = str(r.time_to_first_detection) if r.time_to_first_detection else "never"
        success = "YES" if r.attacker_success else "no"
        print(
            f"  {strategy:<10}  {high_step:>14}  {det:>14}  "
            f"{success:>7}  {r.mean_events_per_step:>11.2f}  "
            f"{len(r.nodes_compromised_final):>9}"
        )

    # ------------------------------------------------------------------
    # Post-hoc sensor analysis
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("SENSOR ANALYSIS (post-hoc, all accumulated events)")
    print("=" * 72)
    print(f"  {'Strategy':<10}  {'Events':>7}  {'Freq/s':>8}  "
          f"{'ValRate':>8}  {'AnomalyScore':>12}  {'Detected?'}")
    print("  " + "-" * 62)

    for strategy in _STRATEGIES:
        r = results[strategy]
        reading = sensor.analyze(r.all_events, time_window=float(r.total_time_steps))
        det = "YES" if reading.anomaly_detected else "no"
        print(
            f"  {strategy:<10}  {len(r.all_events):>7}  "
            f"{reading.delegation_request_frequency:>8.2f}  "
            f"{reading.token_validation_rate:>8.2f}  "
            f"{reading.anomaly_score:>12.4f}  {det}"
        )

    # ------------------------------------------------------------------
    # Key insights
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("KEY INSIGHTS")
    print("=" * 72)
    g_r = results["greedy"]
    s_r = results["stealthy"]
    r_r = results["random"]

    print(f"  Greedy   — events/step: {g_r.mean_events_per_step:.2f}  "
          f"(probes ALL {graph.nx_graph.out_degree(hub_node)} hub outbound edges)")
    print(f"  Stealthy — events/step: {s_r.mean_events_per_step:.2f}  "
          f"(probes only 1 edge per step — {g_r.mean_events_per_step / max(s_r.mean_events_per_step, 0.01):.1f}× quieter)")
    print(f"  Random   — events/step: {r_r.mean_events_per_step:.2f}")

    g_hp = _steps_to_high_priv(g_r, graph)
    s_hp = _steps_to_high_priv(s_r, graph)
    print(f"\n  Greedy reaches high-privilege at step {g_hp}  "
          f"(stealthy: {s_hp})")
    print("\nDemo complete.")


if __name__ == "__main__":
    main()
