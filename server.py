"""TrustField Dashboard Server.

A lightweight Flask backend that:
  - Serves the dashboard SPA at  GET /
  - Exposes read-only graph data  GET /api/graph/<topology>
  - Lists available topologies    GET /api/topologies
  - Runs the live pipeline        POST /api/run/<topology>
    (streams Server-Sent Events so the UI can show progress in real time)

Simulated Infrastructure (new):
  - Persistent graph state        GET/POST/DELETE /api/sim/*
  - Run pipeline on sim graph     POST /api/sim/run   (SSE)
  - Breach simulation             POST /api/sim/breach/<node_id>  (SSE)

Run:
    PYTHONPATH=. python server.py
    # then open  http://localhost:5000
"""

from __future__ import annotations

import copy
import json
import pathlib
import queue
import threading
import time
from typing import Iterator, Optional

from trustfield.mock_cloud import mock_cloud

from flask import Flask, Response, jsonify, request, send_from_directory

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT          = pathlib.Path(__file__).parent
DASHBOARD     = ROOT / "dashboard"
OUT_DIR       = ROOT / "out"
STATE_DIR     = ROOT / "state"
STATE_FILE    = STATE_DIR / "sim_graph.json"
ORG_STATE_FILE = STATE_DIR / "org_graph.json"

app = Flask(__name__, static_folder=str(DASHBOARD), static_url_path="/static")

# ---------------------------------------------------------------------------
# Static serving
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(str(DASHBOARD), "index.html")

@app.route("/static/<path:filename>")
def static_files(filename):
    resp = send_from_directory(str(DASHBOARD), filename)
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ---------------------------------------------------------------------------
# Simulated infrastructure — default state
# ---------------------------------------------------------------------------

# This tells the attack-path story:
#   developer → ci-cd-role → api-service → admin-role → database → master-credentials
# A 5-hop legitimate trust chain from a low-privilege entry point to crown-jewel secrets.

DEFAULT_SIM_STATE: dict = {
    # This topology is designed so all five visual states appear after analysis:
    #
    #  COMPROMISED (red)      — attack chain, high-weight edges, all verified
    #  PREDICTED_ONLY (amber) — protected branch, weight≈0.07 so traversal
    #                           almost always fails while ensemble still flags them
    #  CONTAINED (green)      — isolated cluster reachable internally but not
    #                           from the seed; ensemble gives low signal → below
    #                           threshold, per_node_exploitability > 0
    #  SAFE (blue)            — completely disconnected singleton, no signal at all
    #
    "nodes": [
        # ── Attack chain ──────────────────────────────────────────────
        {
            "node_id": "user-dev",
            "node_type": "USER",
            "name": "developer",
            "privilege_level": 0.1,
            "sensitivity": 0.1,
        },
        {
            "node_id": "role-ci",
            "node_type": "ROLE",
            "name": "ci-cd-role",
            "privilege_level": 0.45,
            "sensitivity": 0.4,
        },
        {
            "node_id": "svc-api",
            "node_type": "SERVICE",
            "name": "api-service",
            "privilege_level": 0.3,
            "sensitivity": 0.5,
        },
        {
            "node_id": "role-admin",
            "node_type": "ROLE",
            "name": "admin-role",
            "privilege_level": 0.85,
            "sensitivity": 0.7,
        },
        {
            "node_id": "secret-prod",
            "node_type": "SECRET",
            "name": "prod-credentials",
            "privilege_level": 0.95,
            "sensitivity": 1.0,
        },
        # ── Protected branch (low-weight → traversal almost always blocked)
        {
            "node_id": "svc-internal",
            "node_type": "SERVICE",
            "name": "internal-service",
            "privilege_level": 0.4,
            "sensitivity": 0.6,
        },
        {
            "node_id": "secret-internal",
            "node_type": "SECRET",
            "name": "internal-key",
            "privilege_level": 0.6,
            "sensitivity": 0.75,
        },
        # ── Isolated cluster (no path from seed → contained/safe)
        {
            "node_id": "svc-monitoring",
            "node_type": "SERVICE",
            "name": "monitoring-svc",
            "privilege_level": 0.25,
            "sensitivity": 0.3,
        },
        {
            "node_id": "svc-logging",
            "node_type": "SERVICE",
            "name": "logging-svc",
            "privilege_level": 0.2,
            "sensitivity": 0.2,
        },
        {
            "node_id": "secret-backup",
            "node_type": "SECRET",
            "name": "backup-credentials",
            "privilege_level": 0.7,
            "sensitivity": 0.8,
        },
        # ── Completely isolated singleton (safe)
        {
            "node_id": "wl-sandbox",
            "node_type": "WORKLOAD",
            "name": "sandbox-workload",
            "privilege_level": 0.15,
            "sensitivity": 0.1,
        },
    ],
    "edges": [
        # Attack chain — high weights so traversal reliably succeeds
        {"source": "user-dev",   "target": "role-ci",      "edge_type": "ASSUME_ROLE",    "weight": 0.9},
        {"source": "role-ci",    "target": "svc-api",       "edge_type": "DEPLOY_TO",      "weight": 0.85},
        {"source": "svc-api",    "target": "role-admin",    "edge_type": "ASSUME_ROLE",    "weight": 0.8},
        {"source": "role-admin", "target": "secret-prod",   "edge_type": "SECRET_READ",    "weight": 0.9},
        # Protected branch — weight 0.07 means ~93% traversal failure rate
        # Ensemble (uses full adjacency) still flags them; traversal doesn't → predicted_only
        {"source": "role-admin", "target": "svc-internal",  "edge_type": "AUTHENTICATE_AS","weight": 0.07},
        {"source": "svc-internal","target": "secret-internal","edge_type": "SECRET_READ",  "weight": 0.07},
        # Isolated cluster — internal edges only, no path from user-dev
        {"source": "svc-monitoring","target": "svc-logging",  "edge_type": "AUTHENTICATE_AS","weight": 0.5},
        {"source": "svc-monitoring","target": "secret-backup","edge_type": "SECRET_READ",   "weight": 0.6},
        # wl-sandbox has no edges → completely safe
    ],
    "breach_seed": None,
}

VALID_NODE_TYPES = {"USER", "SERVICE", "ROLE", "WORKLOAD", "SECRET", "DEPLOYMENT"}
VALID_EDGE_TYPES = {"ASSUME_ROLE", "TOKEN_MINT", "SECRET_READ", "DEPLOY_TO", "AUTHENTICATE_AS"}

_sim_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Simulated infrastructure — state management
# ---------------------------------------------------------------------------

def _load_sim_state() -> dict:
    with _sim_lock:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return copy.deepcopy(DEFAULT_SIM_STATE)


def _save_sim_state(state: dict) -> None:
    with _sim_lock:
        STATE_DIR.mkdir(exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _invalidate_sim_cache() -> None:
    """Remove the last pipeline output so the dashboard shows a preview until re-analyzed."""
    js_path = OUT_DIR / "sim" / "graph_data.js"
    try:
        if js_path.exists():
            js_path.unlink()
    except OSError:
        pass


def _state_to_trust_graph(state: dict):
    """Convert a sim state dict into a live TrustGraph object."""
    from trustfield.graph.trust_graph import TrustGraph
    from trustfield.graph.node_types import NodeMetadata, NodeType
    from trustfield.graph.edge_types import EdgeMetadata, EdgeType

    g = TrustGraph()
    for n in state["nodes"]:
        meta = NodeMetadata(
            node_id=n["node_id"],
            node_type=NodeType(n["node_type"]),
            name=n.get("name", n["node_id"]),
            privilege_level=float(n.get("privilege_level", 0.5)),
            sensitivity=float(n.get("sensitivity", 0.5)),
        )
        g.add_node(meta)

    node_ids = {n["node_id"] for n in state["nodes"]}
    for e in state["edges"]:
        if e["source"] not in node_ids or e["target"] not in node_ids:
            continue
        meta = EdgeMetadata(
            edge_id=f"{e['source']}->{e['target']}",
            edge_type=EdgeType(e.get("edge_type", "ASSUME_ROLE")),
            weight=float(e.get("weight", 0.7)),
            delegation_depth_limit=3,
        )
        try:
            g.add_edge(e["source"], e["target"], meta)
        except KeyError:
            pass

    return g


def _build_sim_preview(state: dict) -> dict:
    """Build a minimal visualization payload from state (no analysis yet).

    Used when the dashboard loads the SIM tab before any pipeline run.
    Nodes are laid out in a circle; all states are 'safe'; risk = 0.
    """
    import math

    nodes = state["nodes"]
    n = len(nodes)

    preview_nodes = []
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / max(n, 1)
        r = 6
        preview_nodes.append({
            "id": node["node_id"],
            "label": node.get("name", node["node_id"]),
            "type": node["node_type"],
            "state": "safe",
            "privilege": node.get("privilege_level", 0.5),
            "sensitivity": node.get("sensitivity", 0.5),
            "risk": 0.0,
            "exploitability": 0.0,
            "x": math.cos(angle) * r,
            "y": math.sin(angle) * r,
            "z": node.get("privilege_level", 0.5) * 4,
        })

    preview_edges = [
        {
            "source": e["source"],
            "target": e["target"],
            "weight": e.get("weight", 0.7),
            "edge_type": e.get("edge_type", "ASSUME_ROLE"),
        }
        for e in state["edges"]
    ]

    return {
        "nodes": preview_nodes,
        "edges": preview_edges,
        "metadata": {
            "topology": "sim",
            "seed_nodes": [],
            "pbr_nodes": [],
            "vbr_nodes": [],
            "blocked_transitions": [],
            "traversal_timeline": [],
            "analysis_ready": False,
        },
    }

# ---------------------------------------------------------------------------
# Simulated infrastructure — pipeline SSE stream
# ---------------------------------------------------------------------------

def _run_sim_pipeline_stream(seed_nodes: list[str]) -> Iterator[str]:
    """Run the full pipeline on the current sim graph and yield SSE events."""

    def _evt(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _evt("progress", {"step": "init", "msg": "Loading simulated infrastructure…"})

    try:
        from trustfield.pipeline import TrustFieldPipeline

        state = _load_sim_state()

        if len(state["nodes"]) < 2:
            yield _evt("error", {"msg": "Need at least 2 nodes to run analysis. Add more nodes first."})
            return

        yield _evt("progress", {
            "step": "building",
            "msg": f"Building graph — {len(state['nodes'])} nodes, {len(state['edges'])} edges…",
        })

        graph = _state_to_trust_graph(state)

        # Resolve seed nodes
        node_ids = {n["node_id"] for n in state["nodes"]}
        active_seeds = [s for s in seed_nodes if s in node_ids]
        if not active_seeds:
            # Auto-pick lowest-privilege node as default entry point
            sorted_nodes = sorted(state["nodes"], key=lambda n: n.get("privilege_level", 0.5))
            active_seeds = [sorted_nodes[0]["node_id"]]

        yield _evt("progress", {
            "step": "fingerprint",
            "msg": f"M1–M3: Analyzing from seed '{active_seeds[0]}'…",
        })

        pipeline = TrustFieldPipeline(
            output_dir=str(OUT_DIR),
            n_feedback_cycles=5,
            random_seed=42,
        )

        result = pipeline.run(
            graph,
            seed_nodes=active_seeds,
            topology_label="sim",
            export=True,
        )

        m = result.metrics
        yield _evt("progress", {
            "step": "verification",
            "msg": f"M4 — PBR={m['pbr_size']} VBR={m['vbr_size']} EGD={m['exploitability_gap_score']:.3f}",
        })
        yield _evt("progress", {
            "step": "containment",
            "msg": f"M5 — containment={m['containment_success_rate']:.1%} strictness={m['final_strictness']}",
        })
        yield _evt("progress", {"step": "export", "msg": "M6 — graph data written to out/sim/"})

        js_path = OUT_DIR / "sim" / "graph_data.js"
        data = _parse_graph_js(js_path)
        yield _evt("done", {
            "topology": "sim",
            "metrics": m,
            "data": data,
            "seed_nodes": active_seeds,
        })

    except Exception as exc:
        import traceback
        yield _evt("error", {"msg": str(exc), "trace": traceback.format_exc()})

# ---------------------------------------------------------------------------
# API — topology list
# ---------------------------------------------------------------------------

KNOWN_TOPOLOGIES = ["hub", "chain", "dense_cluster", "mixed"]

@app.route("/api/topologies")
def api_topologies():
    available = []
    for topo in KNOWN_TOPOLOGIES:
        if (OUT_DIR / topo / "graph_data.js").exists():
            available.append(topo)
    # sim is always available
    available.append("sim")
    # org tab appears whenever an org graph has been uploaded
    available.append("org")
    return jsonify({"topologies": available})

# ---------------------------------------------------------------------------
# API — graph data (reads pre-generated JS files)
# ---------------------------------------------------------------------------

def _parse_graph_js(path: pathlib.Path) -> dict:
    content = path.read_text(encoding="utf-8")
    # Strip JS wrapper: "const GRAPH_DATA = {...};"
    json_str = content.replace("const GRAPH_DATA = ", "", 1).rstrip(";\n")
    return json.loads(json_str)


@app.route("/api/graph/<topology>")
def api_graph(topology: str):
    if topology == "sim":
        return _api_sim_graph_view()
    if topology == "org":
        return _api_org_graph_view()

    js_path = OUT_DIR / topology / "graph_data.js"
    if not js_path.exists():
        return jsonify({"error": f"No data for topology '{topology}'. Run /api/run/{topology} first."}), 404
    try:
        data = _parse_graph_js(js_path)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(data)


def _api_sim_graph_view():
    """Return sim graph data: post-analysis if available, otherwise a preview."""
    js_path = OUT_DIR / "sim" / "graph_data.js"
    if js_path.exists():
        try:
            data = _parse_graph_js(js_path)
            return jsonify(data)
        except Exception:
            pass
    # No analysis yet — return preview layout
    state = _load_sim_state()
    return jsonify(_build_sim_preview(state))

# ---------------------------------------------------------------------------
# API — live pipeline run with SSE progress stream (synthetic topologies)
# ---------------------------------------------------------------------------

def _run_pipeline_stream(topology: str, num_nodes: int, seed: int) -> Iterator[str]:
    """Run the TrustField pipeline in this thread and yield SSE events."""

    def _evt(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _evt("progress", {"step": "init", "msg": f"Initialising pipeline for '{topology}' ({num_nodes} nodes)…"})

    try:
        from trustfield.pipeline import TrustFieldPipeline

        yield _evt("progress", {"step": "generating", "msg": "Generating IAM graph…"})

        pipeline = TrustFieldPipeline(
            output_dir=str(OUT_DIR),
            n_feedback_cycles=5,
            random_seed=seed,
        )

        from trustfield.graph.iam_simulator import IAMSimulator
        sim   = IAMSimulator()
        graph = sim.generate(topology, num_nodes=num_nodes, seed=seed)

        node_list = sorted(graph._graph.nodes())
        seed_node = next(
            (n for n in node_list if graph._graph.out_degree(n) > 0),
            node_list[0],
        )

        yield _evt("progress", {"step": "fingerprint", "msg": "M1–M3: Fingerprint + propagation + ensemble…"})

        result = pipeline.run(
            graph,
            seed_nodes=[seed_node],
            topology_label=topology,
            export=True,
        )

        m = result.metrics
        yield _evt("progress", {"step": "verification",
                                  "msg": f"M4 complete — PBR={m['pbr_size']} VBR={m['vbr_size']} EGD={m['exploitability_gap_score']:.3f}"})
        yield _evt("progress", {"step": "containment",
                                  "msg": f"M5 complete — containment={m['containment_success_rate']:.1%} strictness={m['final_strictness']}"})
        yield _evt("progress", {"step": "export",
                                  "msg": "M6 complete — graph data written to out/"})

        js_path = OUT_DIR / topology / "graph_data.js"
        data = _parse_graph_js(js_path)
        yield _evt("done", {"topology": topology, "metrics": m, "data": data})

    except Exception as exc:
        import traceback
        yield _evt("error", {"msg": str(exc), "trace": traceback.format_exc()})


@app.route("/api/run/<topology>", methods=["POST"])
def api_run(topology: str):
    if topology not in KNOWN_TOPOLOGIES:
        return jsonify({"error": f"Unknown topology '{topology}'"}), 400

    body      = request.get_json(silent=True) or {}
    num_nodes = int(body.get("num_nodes", 50))
    seed      = int(body.get("seed", 42))
    num_nodes = max(10, min(200, num_nodes))

    return Response(
        _run_pipeline_stream(topology, num_nodes, seed),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )

# ---------------------------------------------------------------------------
# API — simulated infrastructure CRUD
# ---------------------------------------------------------------------------

@app.route("/api/sim/state")
def api_sim_state():
    """Return the raw sim state (node/edge lists) for the admin panel."""
    return jsonify(_load_sim_state())


@app.route("/api/sim/node", methods=["POST"])
def api_sim_add_node():
    body = request.get_json(silent=True) or {}
    node_id   = str(body.get("node_id", "")).strip()
    node_type = str(body.get("node_type", "SERVICE")).strip().upper()
    name      = str(body.get("name", node_id)).strip() or node_id
    privilege = float(body.get("privilege_level", 0.5))
    sensitivity = float(body.get("sensitivity", 0.5))

    if not node_id:
        return jsonify({"error": "node_id is required"}), 400
    if node_type not in VALID_NODE_TYPES:
        return jsonify({"error": f"node_type must be one of {sorted(VALID_NODE_TYPES)}"}), 400

    state = _load_sim_state()
    if any(n["node_id"] == node_id for n in state["nodes"]):
        return jsonify({"error": f"Node '{node_id}' already exists"}), 409

    state["nodes"].append({
        "node_id": node_id,
        "node_type": node_type,
        "name": name,
        "privilege_level": round(max(0.0, min(1.0, privilege)), 2),
        "sensitivity":     round(max(0.0, min(1.0, sensitivity)), 2),
    })
    _save_sim_state(state)
    _invalidate_sim_cache()

    return jsonify({"ok": True, "state": state})


@app.route("/api/sim/node/<path:node_id>", methods=["DELETE"])
def api_sim_del_node(node_id: str):
    state = _load_sim_state()
    if not any(n["node_id"] == node_id for n in state["nodes"]):
        return jsonify({"error": f"Node '{node_id}' not found"}), 404

    state["nodes"] = [n for n in state["nodes"] if n["node_id"] != node_id]
    # Remove all edges that reference this node
    state["edges"] = [
        e for e in state["edges"]
        if e["source"] != node_id and e["target"] != node_id
    ]
    # Clear breach seed if it was this node
    if state.get("breach_seed") == node_id:
        state["breach_seed"] = None

    _save_sim_state(state)
    _invalidate_sim_cache()

    return jsonify({"ok": True, "state": state})


@app.route("/api/sim/edge", methods=["POST"])
def api_sim_add_edge():
    body      = request.get_json(silent=True) or {}
    source    = str(body.get("source", "")).strip()
    target    = str(body.get("target", "")).strip()
    edge_type = str(body.get("edge_type", "ASSUME_ROLE")).strip().upper()
    weight    = float(body.get("weight", 0.7))

    if not source or not target:
        return jsonify({"error": "source and target are required"}), 400
    if edge_type not in VALID_EDGE_TYPES:
        return jsonify({"error": f"edge_type must be one of {sorted(VALID_EDGE_TYPES)}"}), 400
    if source == target:
        return jsonify({"error": "Self-loops are not allowed"}), 400

    state    = _load_sim_state()
    node_ids = {n["node_id"] for n in state["nodes"]}

    if source not in node_ids:
        return jsonify({"error": f"Source node '{source}' not found"}), 404
    if target not in node_ids:
        return jsonify({"error": f"Target node '{target}' not found"}), 404
    if any(e["source"] == source and e["target"] == target for e in state["edges"]):
        return jsonify({"error": f"Edge {source} → {target} already exists"}), 409

    state["edges"].append({
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "weight": round(max(0.0, min(1.0, weight)), 2),
    })
    _save_sim_state(state)
    _invalidate_sim_cache()

    return jsonify({"ok": True, "state": state})


@app.route("/api/sim/edge", methods=["DELETE"])
def api_sim_del_edge():
    body   = request.get_json(silent=True) or {}
    source = str(body.get("source", "")).strip()
    target = str(body.get("target", "")).strip()

    if not source or not target:
        return jsonify({"error": "source and target are required"}), 400

    state = _load_sim_state()
    before = len(state["edges"])
    state["edges"] = [
        e for e in state["edges"]
        if not (e["source"] == source and e["target"] == target)
    ]
    if len(state["edges"]) == before:
        return jsonify({"error": f"Edge {source} → {target} not found"}), 404

    _save_sim_state(state)
    _invalidate_sim_cache()

    return jsonify({"ok": True, "state": state})


@app.route("/api/sim/reset", methods=["POST"])
def api_sim_reset():
    """Reset sim state to the default infrastructure."""
    _save_sim_state(copy.deepcopy(DEFAULT_SIM_STATE))
    _invalidate_sim_cache()
    return jsonify({"ok": True, "state": _load_sim_state()})

# ---------------------------------------------------------------------------
# API — sim pipeline run + breach simulation (SSE)
# ---------------------------------------------------------------------------

@app.route("/api/sim/run", methods=["POST"])
def api_sim_run():
    """Run the full pipeline on the current sim graph state (uses last breach seed if set)."""
    state = _load_sim_state()
    seed  = state.get("breach_seed")
    seeds = [seed] if seed else []

    return Response(
        _run_sim_pipeline_stream(seeds),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/sim/breach/<path:node_id>", methods=["POST"])
def api_sim_breach(node_id: str):
    """Mark a node as compromised and run the pipeline from it as seed."""
    state = _load_sim_state()
    node_ids = {n["node_id"] for n in state["nodes"]}
    if node_id not in node_ids:
        return jsonify({"error": f"Node '{node_id}' not found in sim graph"}), 404

    # Persist the breach seed so subsequent /api/sim/run uses it too
    state["breach_seed"] = node_id
    _save_sim_state(state)

    return Response(
        _run_sim_pipeline_stream([node_id]),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )

# ---------------------------------------------------------------------------
# CORS (allow file:// clients during development)
# ---------------------------------------------------------------------------

@app.after_request
def _add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response


@app.route("/api/sim/upload-iam", methods=["POST"])
def api_sim_upload_iam():
    """Parse an AWS IAM policy JSON and merge its nodes/edges into the sim graph.

    Body JSON:
        policy      (dict, required)  — IAM policy document or role config bundle
        subject_id  (str, optional)   — node ID of the principal this policy belongs to
        subject_arn (str, optional)   — full ARN (used to infer node type / privilege)
        replace     (bool, optional)  — if true, clear existing state first (default false)
    """
    body        = request.get_json(silent=True) or {}
    policy_data = body.get("policy")
    subject_id  = str(body.get("subject_id",  "")).strip() or None
    subject_arn = str(body.get("subject_arn", "")).strip() or None
    replace     = bool(body.get("replace", False))

    if not policy_data:
        return jsonify({"error": "'policy' field is required"}), 400

    try:
        from trustfield.loaders.aws_iam_loader import IAMPolicyLoader

        loader = IAMPolicyLoader()
        graph  = loader.load_dict(policy_data, subject_id=subject_id,
                                  subject_arn=subject_arn)

        state = copy.deepcopy(DEFAULT_SIM_STATE) if replace else _load_sim_state()

        existing_ids   = {n["node_id"] for n in state["nodes"]}
        existing_edges = {(e["source"], e["target"]) for e in state["edges"]}

        added_nodes = 0
        added_edges = 0

        for node_id, data in graph._graph.nodes(data=True):
            if node_id in existing_ids:
                continue
            meta = data["metadata"]
            sim_type = meta.node_type.value          # NodeType enum values == VALID_NODE_TYPES
            if sim_type not in VALID_NODE_TYPES:
                sim_type = "SERVICE"
            state["nodes"].append({
                "node_id":       node_id,
                "node_type":     sim_type,
                "name":          meta.name or node_id,
                "privilege_level": round(max(0.0, min(1.0, meta.privilege_level)), 2),
                "sensitivity":     round(max(0.0, min(1.0, meta.sensitivity)),     2),
            })
            existing_ids.add(node_id)
            added_nodes += 1

        for src, tgt, data in graph._graph.edges(data=True):
            if (src, tgt) in existing_edges:
                continue
            if src not in existing_ids or tgt not in existing_ids:
                continue
            meta      = data["metadata"]
            edge_type = meta.edge_type.value
            if edge_type not in VALID_EDGE_TYPES:
                edge_type = "ASSUME_ROLE"
            state["edges"].append({
                "source":    src,
                "target":    tgt,
                "edge_type": edge_type,
                "weight":    round(max(0.0, min(1.0, meta.weight)), 2),
            })
            existing_edges.add((src, tgt))
            added_edges += 1

        _save_sim_state(state)
        _invalidate_sim_cache()

        return jsonify({
            "ok":          True,
            "added_nodes": added_nodes,
            "added_edges": added_edges,
            "state":       state,
        })

    except Exception as exc:
        import traceback
        return jsonify({"error": str(exc), "trace": traceback.format_exc()}), 500


@app.route("/api/sim/node", methods=["OPTIONS"])
@app.route("/api/sim/edge", methods=["OPTIONS"])
@app.route("/api/sim/run", methods=["OPTIONS"])
@app.route("/api/sim/reset", methods=["OPTIONS"])
@app.route("/api/sim/upload-iam", methods=["OPTIONS"])
def _options_handler():
    return "", 204

# ---------------------------------------------------------------------------
# ORG topology — real IAM data upload + analysis
# ---------------------------------------------------------------------------

_org_lock = threading.Lock()


def _load_org_state() -> Optional[dict]:
    with _org_lock:
        if ORG_STATE_FILE.exists():
            return json.loads(ORG_STATE_FILE.read_text(encoding="utf-8"))
        return None


def _save_org_state(state: dict) -> None:
    with _org_lock:
        STATE_DIR.mkdir(exist_ok=True)
        ORG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _invalidate_org_cache() -> None:
    js_path = OUT_DIR / "org" / "graph_data.js"
    try:
        if js_path.exists():
            js_path.unlink()
    except OSError:
        pass


def _api_org_graph_view():
    """Return org graph: post-analysis if available, preview if not, 404 if no data."""
    js_path = OUT_DIR / "org" / "graph_data.js"
    if js_path.exists():
        try:
            data = _parse_graph_js(js_path)
            return jsonify(data)
        except Exception:
            pass
    state = _load_org_state()
    if state is None:
        return jsonify({"error": "No org data. Upload an IAM dump first.", "needs_upload": True}), 404
    return jsonify(_build_sim_preview(state))   # reuse sim preview builder (same schema)


def _org_state_to_trust_graph(state: dict):
    """Same as _state_to_trust_graph but reads from org state."""
    return _state_to_trust_graph(state)   # schema is identical


def _run_org_pipeline_stream(seed_nodes: list, use_gnn: bool = True) -> Iterator[str]:
    """Run the full pipeline on the current org graph and yield SSE events."""

    def _evt(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _evt("progress", {"step": "init", "msg": "Loading org IAM graph…"})

    try:
        from trustfield.pipeline import TrustFieldPipeline

        state = _load_org_state()
        if state is None or len(state["nodes"]) < 2:
            yield _evt("error", {"msg": "No org data loaded. Upload an IAM dump first."})
            return

        yield _evt("progress", {
            "step": "building",
            "msg": f"Building graph — {len(state['nodes'])} nodes, {len(state['edges'])} edges…",
        })

        graph = _org_state_to_trust_graph(state)

        node_ids = {n["node_id"] for n in state["nodes"]}
        active_seeds = [s for s in seed_nodes if s in node_ids]
        if not active_seeds:
            sorted_nodes = sorted(state["nodes"], key=lambda n: n.get("privilege_level", 0.5))
            active_seeds = [sorted_nodes[0]["node_id"]]

        yield _evt("progress", {
            "step": "fingerprint",
            "msg": f"M1–M3: Analyzing from seed '{active_seeds[0]}'…",
        })

        pipeline = TrustFieldPipeline(
            output_dir=str(OUT_DIR),
            n_feedback_cycles=2,
            random_seed=42,
        )

        result = pipeline.run(
            graph,
            seed_nodes=active_seeds,
            topology_label="org",
            export=True,
            use_gnn=use_gnn,
        )

        m = result.metrics
        yield _evt("progress", {
            "step": "verification",
            "msg": f"M4 — PBR={m['pbr_size']} VBR={m['vbr_size']} EGD={m['exploitability_gap_score']:.3f}",
        })
        yield _evt("progress", {
            "step": "containment",
            "msg": f"M5 — containment={m['containment_success_rate']:.1%} strictness={m['final_strictness']}",
        })
        yield _evt("progress", {"step": "export", "msg": "M6 — graph data written to out/org/"})

        js_path = OUT_DIR / "org" / "graph_data.js"
        data = _parse_graph_js(js_path)
        yield _evt("done", {
            "topology": "org",
            "metrics": m,
            "data": data,
            "seed_nodes": active_seeds,
        })

    except Exception as exc:
        import traceback
        yield _evt("error", {"msg": str(exc), "trace": traceback.format_exc()})


def _do_org_upload(raw: dict, replace: bool = True):
    """Shared helper: parse IAM data, save org state, return Flask response.

    Accepts a parsed JSON dict (any supported format) and saves it as the
    current org graph state.  Returns a Flask jsonify response directly.
    """
    if not raw or not isinstance(raw, dict):
        return jsonify({"error": "'data' field must be a JSON object"}), 400

    try:
        from trustfield.loaders.account_auth_loader import (
            AccountAuthorizationLoader, detect_iam_format,
        )
        from trustfield.loaders.aws_iam_loader import IAMPolicyLoader

        fmt = detect_iam_format(raw)

        if fmt == "account_auth_dump":
            loader = AccountAuthorizationLoader()
            graph  = loader.load_dict(raw)
        elif fmt in ("policy_doc", "mamip_policy", "role_bundle"):
            loader = IAMPolicyLoader()
            graph  = loader.load_dict(raw)
        elif fmt == "k8s_rbac":
            from trustfield.loaders.k8s_rbac_loader import K8sRBACLoader
            loader = K8sRBACLoader()
            graph  = loader.load_dict(raw)
        else:
            return jsonify({
                "error": f"Unrecognised format. Expected one of: account_auth_dump, policy_doc, role_bundle, k8s_rbac. Got: '{fmt}'"
            }), 400

        if graph._graph.number_of_nodes() == 0:
            return jsonify({"error": "No nodes found in the uploaded data. Check the format."}), 400

        # Build org state
        existing_state = {} if replace else (_load_org_state() or {})
        existing_nodes = {n["node_id"] for n in existing_state.get("nodes", [])}
        existing_edges = {(e["source"], e["target"]) for e in existing_state.get("edges", [])}

        nodes = list(existing_state.get("nodes", []))
        edges = list(existing_state.get("edges", []))
        added_nodes = added_edges = 0

        for node_id, data in graph._graph.nodes(data=True):
            if node_id in existing_nodes:
                continue
            meta     = data["metadata"]
            sim_type = meta.node_type.value
            if sim_type not in VALID_NODE_TYPES:
                sim_type = "SERVICE"
            nodes.append({
                "node_id":         node_id,
                "node_type":       sim_type,
                "name":            meta.name or node_id,
                "privilege_level": round(max(0.0, min(1.0, meta.privilege_level)), 2),
                "sensitivity":     round(max(0.0, min(1.0, meta.sensitivity)),     2),
            })
            existing_nodes.add(node_id)
            added_nodes += 1

        for src, tgt, data in graph._graph.edges(data=True):
            if (src, tgt) in existing_edges:
                continue
            if src not in existing_nodes or tgt not in existing_nodes:
                continue
            meta      = data["metadata"]
            edge_type = meta.edge_type.value
            if edge_type not in VALID_EDGE_TYPES:
                edge_type = "ASSUME_ROLE"
            edges.append({
                "source":    src,
                "target":    tgt,
                "edge_type": edge_type,
                "weight":    round(max(0.0, min(1.0, meta.weight)), 2),
            })
            existing_edges.add((src, tgt))
            added_edges += 1

        state = {"nodes": nodes, "edges": edges, "breach_seed": None}
        _save_org_state(state)
        _invalidate_org_cache()

        return jsonify({
            "ok":          True,
            "format":      fmt,
            "added_nodes": added_nodes,
            "added_edges": added_edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        })

    except Exception as exc:
        import traceback
        return jsonify({"error": str(exc), "trace": traceback.format_exc()}), 500


@app.route("/api/org/upload", methods=["POST"])
def api_org_upload():
    """Parse a real IAM dump and store it as the org graph.

    Body: { "data": <parsed-json-dict>, "replace": bool }

    Auto-detects format:
        account_auth_dump  — aws iam get-account-authorization-details
        policy_doc         — bare IAM policy {Version, Statement}
        role_bundle        — TrustField role bundle {RoleName, TrustPolicy}
        k8s_rbac           — Kubernetes RBAC
    """
    body    = request.get_json(silent=True) or {}
    raw     = body.get("data")
    replace = bool(body.get("replace", True))
    return _do_org_upload(raw, replace=replace)


@app.route("/api/org/clear", methods=["POST"])
def api_org_clear():
    """Delete the org graph state and cached analysis."""
    if ORG_STATE_FILE.exists():
        ORG_STATE_FILE.unlink()
    _invalidate_org_cache()
    return jsonify({"ok": True})


@app.route("/api/org/run", methods=["POST"])
def api_org_run():
    state = _load_org_state()
    if state is None:
        return jsonify({"error": "No org data loaded"}), 404
    seeds = [state["breach_seed"]] if state.get("breach_seed") else []
    body = request.get_json(silent=True) or {}
    use_gnn = bool(body.get("use_gnn", True))
    return Response(
        _run_org_pipeline_stream(seeds, use_gnn=use_gnn),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Access-Control-Allow-Origin": "*"},
    )


@app.route("/api/org/breach/<path:node_id>", methods=["POST"])
def api_org_breach(node_id: str):
    state = _load_org_state()
    if state is None:
        return jsonify({"error": "No org data loaded"}), 404
    node_ids = {n["node_id"] for n in state["nodes"]}
    if node_id not in node_ids:
        return jsonify({"error": f"Node '{node_id}' not found in org graph"}), 404
    state["breach_seed"] = node_id
    _save_org_state(state)
    body = request.get_json(silent=True) or {}
    use_gnn = bool(body.get("use_gnn", True))
    return Response(
        _run_org_pipeline_stream([node_id], use_gnn=use_gnn),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Access-Control-Allow-Origin": "*"},
    )


@app.route("/api/org/seed", methods=["POST"])
def api_org_set_seed():
    """Set breach seed without running the pipeline. Invalidates analysis cache."""
    body    = request.get_json(silent=True) or {}
    node_id = str(body.get("node_id", "")).strip()
    state   = _load_org_state()
    if state is None:
        return jsonify({"error": "No org data loaded"}), 404
    node_ids = {n["node_id"] for n in state["nodes"]}
    if node_id and node_id not in node_ids:
        return jsonify({"error": f"Node '{node_id}' not found"}), 404
    state["breach_seed"] = node_id or None
    _save_org_state(state)
    _invalidate_org_cache()   # force demo to re-run pipeline with this seed
    return jsonify({"ok": True})


@app.route("/api/org/upload", methods=["OPTIONS"])
@app.route("/api/org/run", methods=["OPTIONS"])
@app.route("/api/org/clear", methods=["OPTIONS"])
@app.route("/api/org/seed", methods=["OPTIONS"])
@app.route("/api/org/breach/<path:node_id>", methods=["OPTIONS"])
def _org_options_handler(**kwargs):
    return "", 204

# ---------------------------------------------------------------------------
# AWS Connect — demo-mode endpoints
# ---------------------------------------------------------------------------

_DEMO_ACCOUNT_ID    = "123456789012"
_DEMO_ACCOUNT_ALIAS = "AcmeTech Corp"
_DEMO_IDENTITY      = "arn:aws:iam::123456789012:user/demo-admin"
_SCENARIO_FILE      = DASHBOARD / "samples" / "acmetech_breach_scenario.json"

# Hard-coded CloudTrail demo sequence
_CT_EVENTS = [
    {
        "eventName":       "AssumeRole",
        "userIdentity":    "dev-alice",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/deploy-role"},
        "status":          "ALLOWED",
        "detail":          "Normal CI/CD pipeline activity",
    },
    {
        "eventName":       "AssumeRole",
        "userIdentity":    "ci-runner",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/deploy-role"},
        "status":          "ALLOWED",
        "detail":          "Automated build triggered",
    },
    {
        "eventName":       "AssumeRole",
        "userIdentity":    "deploy-role",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/lambda-exec-role"},
        "status":          "FLAGGED",
        "detail":          "Unusual role chain detected",
    },
    {
        "eventName":       "AssumeRole",
        "userIdentity":    "lambda-exec-role",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/api-gateway-role"},
        "status":          "FLAGGED",
        "detail":          "Privilege escalation path active",
    },
    {
        "eventName":       "AssumeRole",
        "userIdentity":    "api-gateway-role",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/secrets-access-role"},
        "status":          "BREACH",
        "detail":          "Critical: secrets access role reached",
    },
    {
        "eventName":       "GetSecretValue",
        "userIdentity":    "secrets-access-role",
        "requestParameters": {"secretId": "prod/db-master"},
        "status":          "BREACH",
        "detail":          "BREACH ACTIVE: production credentials accessed",
    },
]


@app.route("/api/aws/connect", methods=["POST"])
def api_aws_connect():
    """Demo-mode AWS connection — always succeeds."""
    body   = request.get_json(silent=True) or {}
    region = str(body.get("region", "us-east-1")).strip() or "us-east-1"
    return jsonify({
        "ok":             True,
        "mode":           "demo",
        "account_id":     _DEMO_ACCOUNT_ID,
        "account_alias":  _DEMO_ACCOUNT_ALIAS,
        "region":         region,
        "identity":       _DEMO_IDENTITY,
    })


@app.route("/api/aws/pull", methods=["POST"])
def api_aws_pull():
    """Load the AcmeTech breach scenario and store it as the org graph."""
    try:
        raw = json.loads(_SCENARIO_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        return jsonify({"error": f"Could not read scenario file: {exc}"}), 500

    resp = _do_org_upload(raw, replace=True)

    # Inject account metadata into the response if the upload succeeded
    try:
        data = resp.get_json()
        if data and data.get("ok"):
            data["account_alias"] = _DEMO_ACCOUNT_ALIAS
            data["account_id"]    = _DEMO_ACCOUNT_ID
            return jsonify(data)
    except Exception:
        pass

    return resp


@app.route("/api/aws/policies")
def api_aws_policies():
    """Return enforcement policies generated from blocked_transitions in the org graph."""
    js_path = OUT_DIR / "org" / "graph_data.js"
    if not js_path.exists():
        return jsonify({"ok": True, "ready": False, "policies": []})

    try:
        data = _parse_graph_js(js_path)
    except Exception:
        return jsonify({"ok": True, "ready": False, "policies": []})

    blocked = data.get("metadata", {}).get("blocked_transitions", [])
    if not blocked:
        return jsonify({"ok": True, "ready": True, "count": 0, "policies": []})

    policies = []
    for pair in blocked:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        src, tgt = str(pair[0]), str(pair[1])
        policy_name = f"TrustField-Guard-{src.replace('/', '-')}-to-{tgt.replace('/', '-')}"
        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid":      "TrustFieldGuard",
                "Effect":   "Deny",
                "Action":   "sts:AssumeRole",
                "Resource": f"arn:aws:iam::{_DEMO_ACCOUNT_ID}:role/{tgt}",
            }],
        }
        policies.append({
            "source":          src,
            "target":          tgt,
            "policy_name":     policy_name,
            "description":     f"Deny {src} from assuming {tgt}",
            "policy_document": doc,
            "apply_command":   (
                f"aws iam put-role-policy --role-name {src} "
                f"--policy-name TrustField-Guard-{tgt} "
                f"--policy-document '{json.dumps(doc)}'"
            ),
        })

    return jsonify({"ok": True, "ready": True, "count": len(policies), "policies": policies})


@app.route("/api/aws/apply", methods=["POST"])
def api_aws_apply():
    """Demo-mode: return policies that would be applied (no real boto3 call)."""
    js_path = OUT_DIR / "org" / "graph_data.js"
    if not js_path.exists():
        return jsonify({"ok": True, "applied": 0, "mode": "demo", "policies": []})

    try:
        data = _parse_graph_js(js_path)
    except Exception:
        return jsonify({"ok": True, "applied": 0, "mode": "demo", "policies": []})

    blocked = data.get("metadata", {}).get("blocked_transitions", [])
    policies = []
    for pair in blocked:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        src, tgt = str(pair[0]), str(pair[1])
        policy_name = f"TrustField-Guard-{src.replace('/', '-')}-to-{tgt.replace('/', '-')}"
        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid":      "TrustFieldGuard",
                "Effect":   "Deny",
                "Action":   "sts:AssumeRole",
                "Resource": f"arn:aws:iam::{_DEMO_ACCOUNT_ID}:role/{tgt}",
            }],
        }
        policies.append({
            "source":          src,
            "target":          tgt,
            "policy_name":     policy_name,
            "description":     f"Deny {src} from assuming {tgt}",
            "policy_document": doc,
            "apply_command":   (
                f"aws iam put-role-policy --role-name {src} "
                f"--policy-name TrustField-Guard-{tgt} "
                f"--policy-document '{json.dumps(doc)}'"
            ),
        })

    return jsonify({"ok": True, "applied": len(policies), "mode": "demo", "policies": policies})


@app.route("/api/aws/cloudtrail")
def api_aws_cloudtrail():
    """SSE stream of simulated CloudTrail events for the AcmeTech breach scenario."""

    def _stream():
        import datetime
        time.sleep(1)
        for evt in _CT_EVENTS:
            now = datetime.datetime.now().strftime("%H:%M:%S")
            payload = dict(evt)
            payload["type"] = "cloudtrail_event"
            payload["time"] = now
            yield f"event: cloudtrail_event\ndata: {json.dumps(payload)}\n\n"
            time.sleep(1.8)

        # Final breach trigger
        breach_payload = {"type": "cloudtrail_breach", "node": "dev-alice"}
        yield f"event: cloudtrail_breach\ndata: {json.dumps(breach_payload)}\n\n"

    return Response(
        _stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/aws/connect",    methods=["OPTIONS"])
@app.route("/api/aws/pull",       methods=["OPTIONS"])
@app.route("/api/aws/policies",   methods=["OPTIONS"])
@app.route("/api/aws/apply",      methods=["OPTIONS"])
@app.route("/api/aws/cloudtrail", methods=["OPTIONS"])
def _aws_options_handler(**kwargs):
    return "", 204

# ---------------------------------------------------------------------------
# System console page
# ---------------------------------------------------------------------------

@app.route("/system")
def system_console():
    resp = send_from_directory(str(DASHBOARD), "system.html")
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ---------------------------------------------------------------------------
# Mock cloud API
# ---------------------------------------------------------------------------

@app.route("/api/mock/start", methods=["POST"])
def api_mock_start():
    state = _load_org_state() or _load_sim_state()
    mock_cloud.load(state)
    mock_cloud.start()
    return jsonify({"ok": True, "status": mock_cloud.status()})


@app.route("/api/mock/stop", methods=["POST"])
def api_mock_stop():
    mock_cloud.stop()
    return jsonify({"ok": True})


@app.route("/api/mock/attack", methods=["POST"])
def api_mock_attack():
    body    = request.get_json(silent=True) or {}
    node_id = str(body.get("node_id", "")).strip()
    if not node_id:
        return jsonify({"error": "node_id required"}), 400
    if not mock_cloud.trigger_attack(node_id):
        return jsonify({"error": f"Node '{node_id}' not found. Running: {mock_cloud._running}, nodes: {list(mock_cloud.nodes.keys())}"}), 404
    return jsonify({"ok": True})


@app.route("/api/mock/ping", methods=["POST"])
def api_mock_ping():
    body   = request.get_json(silent=True) or {}
    source = str(body.get("from", "")).strip()
    target = str(body.get("to",   "")).strip()
    if not source or not target:
        return jsonify({"error": "from and to are required"}), 400
    result = mock_cloud.manual_ping(source, target)
    return jsonify(result)


@app.route("/api/mock/guards", methods=["POST"])
def api_mock_guards():
    body    = request.get_json(silent=True) or {}
    blocked = body.get("blocked_transitions", [])
    mock_cloud.deploy_guards(blocked)
    return jsonify({"ok": True})


@app.route("/api/mock/reset", methods=["POST"])
def api_mock_reset():
    mock_cloud.reset()
    return jsonify({"ok": True})


@app.route("/api/mock/status")
def api_mock_status():
    return jsonify(mock_cloud.status())


@app.route("/api/mock/events")
def api_mock_events():
    q = mock_cloud.subscribe()

    def _stream():
        try:
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            mock_cloud.unsubscribe(q)

    return Response(
        _stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":              "no-cache",
            "X-Accel-Buffering":          "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/mock/start",  methods=["OPTIONS"])
@app.route("/api/mock/stop",   methods=["OPTIONS"])
@app.route("/api/mock/attack", methods=["OPTIONS"])
@app.route("/api/mock/ping",   methods=["OPTIONS"])
@app.route("/api/mock/guards", methods=["OPTIONS"])
@app.route("/api/mock/reset",  methods=["OPTIONS"])
def _mock_options(**kwargs):
    return "", 204

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    host = "127.0.0.1"
    port = 5000

    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a in ("--port", "-p") and i + 1 < len(args):
            port = int(args[i + 1])
        if a in ("--host",) and i + 1 < len(args):
            host = args[i + 1]

    print("=" * 60)
    print("  TrustField Dashboard Server")
    print(f"  http://{host}:{port}")
    print("=" * 60)
    app.run(host=host, port=port, debug=False, threaded=True)
