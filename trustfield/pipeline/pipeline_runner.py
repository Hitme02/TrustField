"""TrustFieldPipeline — single entry point for the full six-module system.

Calling ``TrustFieldPipeline().run(graph, seed_nodes)`` executes all six
TrustField modules in order and returns a ``PipelineResult`` containing
every intermediate and final artefact, ready for visualization or paper export.

``run_all_topologies()`` iterates over all four IAM topology archetypes and
returns one ``PipelineResult`` per topology, making cross-topology comparison
trivial for the publication evaluation.

Pipeline stages
---------------
  M1  TopologyFingerprinting  (inside TrustFieldOrchestrator.analyze)
  M2  5-Model Propagation      (inside TrustFieldOrchestrator.analyze)
  M3  Ensemble Prediction      (inside TrustFieldOrchestrator.analyze)
  M4  Verification Engine      (IAMTraversal + BlastRadiusCalculator)
  M5  Cyber-Physical Guards    (ContainmentEngine)
  M6  Visualization / Export   (GraphExporter + ReportGenerator)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from trustfield.ensemble import TrustFieldOrchestrator
from trustfield.ensemble.ensemble_result import AnalysisResult
from trustfield.graph.iam_simulator import IAMSimulator
from trustfield.graph.trust_graph import TrustGraph
from trustfield.guards.containment_engine import ContainmentEngine, ContainmentResult
from trustfield.verification.blast_radius import BlastRadiusCalculator, BlastRadiusAnalysis
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.verification.iam_traversal import IAMTraversal, TraversalResult
from trustfield.verification.verification_report import VerificationReport
from trustfield.visualization.graph_exporter import GraphExporter
from trustfield.visualization.layout_engine import Layout3DEngine


@dataclass
class PipelineResult:
    """Full output of one TrustFieldPipeline.run() execution.

    Attributes:
        topology: Topology label (``"hub"``, ``"chain"``, etc.).
        graph: The TrustGraph that was analyzed.
        analysis_result: Module 1-3 ensemble output.
        traversal_result: Module 4 IAM traversal.
        blast_radius_analysis: Module 4 blast radius / gap analysis.
        verification_report: Module 4 consolidated report.
        containment_result: Module 5 guard containment output.
        metrics: Summary dict for quick comparison across topologies.
        output_files: Dict of file-type → absolute path for M6 outputs.
        elapsed_seconds: Wall-clock time for the full run.
    """

    topology: str
    graph: TrustGraph
    analysis_result: AnalysisResult
    traversal_result: TraversalResult
    blast_radius_analysis: BlastRadiusAnalysis
    verification_report: VerificationReport
    containment_result: ContainmentResult
    metrics: Dict[str, object] = field(default_factory=dict)
    output_files: Dict[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0


class TrustFieldPipeline:
    """End-to-end TrustField pipeline (Modules 1–6).

    Args:
        db_path: SQLite database path for adaptive weight learning.
            Use ``":memory:"`` for ephemeral runs (default).
        output_dir: Directory for M6 visual and export outputs.
        traversal_max_depth: BFS depth cap for IAMTraversal.
        n_feedback_cycles: Feedback loop iterations in ContainmentEngine.
        random_seed: Seed for traversal + layout reproducibility.

    Example::

        pipeline = TrustFieldPipeline(output_dir="out/")
        result = pipeline.run(graph, seed_nodes=["svc-hub-00"])
        print(f"Containment: {result.containment_result.containment_success_rate:.1%}")

        # Run all four topologies
        results = pipeline.run_all_topologies(num_nodes=30)
        for topo, r in results.items():
            print(f"{topo}: {r.metrics['containment_success_rate']:.1%}")
    """

    TOPOLOGIES = ["hub", "chain", "dense_cluster", "mixed"]

    def __init__(
        self,
        db_path: str = ":memory:",
        output_dir: str = "out",
        traversal_max_depth: int = 6,
        n_feedback_cycles: int = 5,
        random_seed: int = 42,
    ) -> None:
        self._orchestrator = TrustFieldOrchestrator(db_path=db_path)
        self._output_dir = Path(output_dir)
        self._traversal_max_depth = traversal_max_depth
        self._n_feedback_cycles = n_feedback_cycles
        self._random_seed = random_seed

    # ------------------------------------------------------------------
    # Primary single-graph run
    # ------------------------------------------------------------------

    def run(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        topology_label: str = "unknown",
        export: bool = True,
        use_gnn: bool = True,
    ) -> PipelineResult:
        """Execute the full six-module pipeline on a single graph.

        Args:
            graph: TrustGraph to analyze.
            seed_nodes: Attacker entry-point node IDs.
            topology_label: Human-readable label stored in outputs.
            export: If True, write M6 JSON/JS/CSV outputs to output_dir.

        Returns:
            Fully populated ``PipelineResult``.
        """
        t0 = time.time()

        # --- M1-M3: Ensemble analysis ---
        analysis = self._orchestrator.analyze(graph, seed_nodes=seed_nodes, use_gnn=use_gnn)
        pred = analysis.ensemble_prediction

        # --- M4: Verification ---
        token_gen = TokenGenerator()
        traversal = IAMTraversal(token_gen).traverse(
            graph,
            seed_nodes,
            max_depth=self._traversal_max_depth,
            respect_conditions=True,
            random_seed=self._random_seed,
        )
        bra = BlastRadiusCalculator().compute(pred, traversal, graph)
        report = VerificationReport(
            graph=graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
        )

        # --- M5: Containment ---
        engine = ContainmentEngine(self._orchestrator, token_generator=TokenGenerator())
        containment = engine.execute(
            graph, seed_nodes, report, n_feedback_cycles=self._n_feedback_cycles, use_gnn=use_gnn
        )

        # --- M6: Export ---
        output_files: Dict[str, str] = {}
        if export:
            topo_dir = self._output_dir / topology_label
            exporter = GraphExporter(output_dir=str(topo_dir))
            ensemble_risk = pred.ensemble_risk
            output_files = exporter.export(
                graph,
                verification_report=report,
                ensemble_risk=ensemble_risk,
                topology_label=topology_label,
                traversal_result=traversal,
                containment_result=containment,
            )

        metrics = self._build_metrics(pred, bra, containment)

        return PipelineResult(
            topology=topology_label,
            graph=graph,
            analysis_result=analysis,
            traversal_result=traversal,
            blast_radius_analysis=bra,
            verification_report=report,
            containment_result=containment,
            metrics=metrics,
            output_files=output_files,
            elapsed_seconds=round(time.time() - t0, 2),
        )

    # ------------------------------------------------------------------
    # Multi-topology evaluation
    # ------------------------------------------------------------------

    def run_all_topologies(
        self,
        num_nodes: int = 30,
        random_seed: int = 42,
        seed: int | None = None,
        export: bool = True,
    ) -> Dict[str, PipelineResult]:
        """Run the full pipeline on all four IAM topology archetypes.

        Args:
            num_nodes: Number of nodes in each generated graph.
            random_seed: Seed for IAMSimulator graph generation.
            export: If True, write M6 outputs per topology.

        Returns:
            Dictionary mapping topology name → ``PipelineResult``.
        """
        effective_seed = seed if seed is not None else random_seed
        sim = IAMSimulator()
        results: Dict[str, PipelineResult] = {}

        for topo in self.TOPOLOGIES:
            graph = sim.generate(topo, num_nodes=num_nodes, seed=effective_seed)
            node_list = sorted(graph._graph.nodes())
            # Prefer a node with outgoing edges as the attacker seed
            seed_node = next(
                (n for n in node_list if graph._graph.out_degree(n) > 0),
                node_list[0],
            )
            result = self.run(
                graph,
                seed_nodes=[seed_node],
                topology_label=topo,
                export=export,
            )
            results[topo] = result

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_metrics(pred, bra, containment) -> Dict[str, object]:
        return {
            "total_nodes": pred.total_nodes_analyzed,
            "compromised_predicted": len(pred.compromised_nodes),
            "pbr_size": bra.pbr_size,
            "predicted_blast_radius": bra.pbr_size,  # alias
            "vbr_size": bra.vbr_size,
            "gap_size": bra.gap_size,
            "gap_classification": bra.gap_classification.value,
            "exploitability_gap_score": bra.exploitability_gap_score,
            "containment_success_rate": containment.containment_success_rate,
            "nodes_contained": len(containment.contained_nodes),
            "missed_containments": len(containment.missed_containments),
            "blocked_transitions": len(containment.blocked_transitions),
            "final_strictness": containment.final_strictness_level.value,
        }
