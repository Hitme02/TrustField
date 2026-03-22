"""3D force-directed layout engine for TrustField graphs.

Computes 3D coordinates for each node using NetworkX spring_layout (2D)
and maps privilege_level to the Z axis.  The resulting positions are
normalized to a consistent bounding box and exported as a JSON-serializable
dictionary suitable for the Three.js front-end.

Layout mapping
--------------
  x, y  -- spring_layout positions, normalized to [-10, 10]
  z     -- node.privilege_level * 10.0  (0 = low trust, 10 = root)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

import networkx as nx

from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification.blast_radius import BlastRadiusAnalysis


@dataclass
class NodePosition3D:
    """3D coordinates and display metadata for a single node.

    Attributes:
        node_id: Graph node identifier.
        x: Spring-layout x coordinate normalized to [-10, 10].
        y: Spring-layout y coordinate normalized to [-10, 10].
        z: Privilege-level coordinate in [0, 10].
        node_type: NodeType enum value string (e.g. ``"SERVICE"``).
        privilege_level: Raw privilege level in [0.0, 1.0].
        risk_score: Ensemble risk value (0.0 if not provided).
        state: Visual state tag — one of ``"compromised"``, ``"critical_miss"``,
            ``"predicted_only"``, ``"contained"``, ``"safe"``.
    """

    node_id: str
    x: float
    y: float
    z: float
    node_type: str
    privilege_level: float
    risk_score: float = 0.0
    state: str = "safe"


class Layout3DEngine:
    """Computes 3D positions for all nodes in a TrustGraph.

    Args:
        spring_k: Optimal spring constant passed to NetworkX spring_layout.
            Larger values spread nodes further apart.
        seed: Random seed for layout reproducibility.

    Example::

        engine = Layout3DEngine()
        positions = engine.compute_layout(graph, blast_radius_analysis)
        data = engine.to_dict(graph, positions)
    """

    def __init__(self, spring_k: float = 2.0, seed: int = 42) -> None:
        self._spring_k = spring_k
        self._seed = seed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_layout(
        self,
        graph: TrustGraph,
        blast_radius: Optional[BlastRadiusAnalysis] = None,
        ensemble_risk: Optional[Dict[str, float]] = None,
    ) -> Dict[str, NodePosition3D]:
        """Compute 3D positions for all nodes.

        Args:
            graph: The TrustGraph to lay out.
            blast_radius: Optional BlastRadiusAnalysis used to assign node
                ``state`` values (compromised / critical_miss / predicted_only /
                contained / safe).
            ensemble_risk: Optional mapping node_id → risk_score from the
                ensemble predictor.  Used to colour nodes by risk intensity.

        Returns:
            Dictionary mapping node_id → NodePosition3D.
        """
        g = graph._graph

        # --- 2D spring layout ---
        raw_pos = nx.spring_layout(g, k=self._spring_k, seed=self._seed)

        # --- Normalize x/y to [-10, 10] ---
        if raw_pos:
            xs = [p[0] for p in raw_pos.values()]
            ys = [p[1] for p in raw_pos.values()]
            x_min, x_max = min(xs), max(xs)
            y_min, y_max = min(ys), max(ys)
            x_range = max(x_max - x_min, 1e-9)
            y_range = max(y_max - y_min, 1e-9)
        else:
            x_min = y_min = 0.0
            x_range = y_range = 1.0

        # --- Determine node states from blast radius ---
        vbr: set = set()
        pbr: set = set()
        if blast_radius is not None:
            vbr = blast_radius.vbr_nodes
            pbr = blast_radius.pbr_nodes

        positions: Dict[str, NodePosition3D] = {}
        for node_id in g.nodes():
            meta = graph.get_node(node_id)
            raw = raw_pos.get(node_id, (0.0, 0.0))

            x_norm = (raw[0] - x_min) / x_range * 20.0 - 10.0
            y_norm = (raw[1] - y_min) / y_range * 20.0 - 10.0
            z = meta.privilege_level * 10.0

            risk = (ensemble_risk or {}).get(node_id, 0.0)

            state = self._classify_state(node_id, vbr, pbr, blast_radius)

            positions[node_id] = NodePosition3D(
                node_id=node_id,
                x=round(x_norm, 4),
                y=round(y_norm, 4),
                z=round(z, 4),
                node_type=meta.node_type.value,
                privilege_level=meta.privilege_level,
                risk_score=round(risk, 4),
                state=state,
            )

        return positions

    def to_dict(
        self,
        graph: TrustGraph,
        positions: Dict[str, NodePosition3D],
    ) -> dict:
        """Serialize layout + graph topology to a JSON-compatible dict.

        The output structure is consumed by the Three.js front-end:

        .. code-block:: json

            {
              "nodes": [
                {"id": "svc-1", "x": 3.2, "y": -1.1, "z": 4.0,
                 "type": "SERVICE", "privilege": 0.4,
                 "risk": 0.72, "state": "compromised"}
              ],
              "edges": [
                {"source": "svc-1", "target": "role-1",
                 "type": "ASSUME_ROLE", "weight": 0.8}
              ]
            }

        Args:
            graph: Source TrustGraph (used for edge metadata).
            positions: Pre-computed positions from ``compute_layout``.

        Returns:
            JSON-serializable dictionary with ``"nodes"`` and ``"edges"`` lists.
        """
        nodes_out = []
        for pos in positions.values():
            nodes_out.append({
                "id": pos.node_id,
                "x": pos.x,
                "y": pos.y,
                "z": pos.z,
                "type": pos.node_type,
                "privilege": pos.privilege_level,
                "risk": pos.risk_score,
                "state": pos.state,
            })

        edges_out = []
        for src, tgt, data in graph._graph.edges(data=True):
            meta = data.get("metadata")
            edges_out.append({
                "source": src,
                "target": tgt,
                "type": meta.edge_type.value if meta else "UNKNOWN",
                "weight": round(meta.weight if meta else 1.0, 4),
            })

        return {"nodes": nodes_out, "edges": edges_out}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_state(
        node_id: str,
        vbr: set,
        pbr: set,
        blast_radius: Optional[BlastRadiusAnalysis],
    ) -> str:
        """Map a node to a visual state string.

        States (priority order):
          compromised   — in both VBR and PBR (confirmed + predicted)
          critical_miss — in VBR only (verified but not predicted)
          predicted_only — in PBR only (predicted but traversal did not reach)
          contained     — in neither set but has non-zero exploitability
          safe          — not reachable by any model
        """
        in_vbr = node_id in vbr
        in_pbr = node_id in pbr

        if in_vbr and in_pbr:
            return "compromised"
        if in_vbr and not in_pbr:
            return "critical_miss"
        if in_pbr and not in_vbr:
            return "predicted_only"

        if blast_radius is not None:
            score = blast_radius.per_node_exploitability.get(node_id, 0.0)
            if score > 0.0:
                return "contained"

        return "safe"
