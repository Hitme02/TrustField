"""TrustField Dashboard Server.

A lightweight Flask backend that:
  - Serves the dashboard SPA at  GET /
  - Exposes read-only graph data  GET /api/graph/<topology>
  - Lists available topologies    GET /api/topologies
  - Runs the live pipeline        POST /api/run/<topology>
    (streams Server-Sent Events so the UI can show progress in real time)

Run:
    PYTHONPATH=. python server.py
    # then open  http://localhost:5000
"""

from __future__ import annotations

import json
import pathlib
import queue
import threading
import time
from typing import Iterator

from flask import Flask, Response, jsonify, request, send_from_directory

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT       = pathlib.Path(__file__).parent
DASHBOARD  = ROOT / "dashboard"
OUT_DIR    = ROOT / "out"

app = Flask(__name__, static_folder=str(DASHBOARD), static_url_path="/static")

# ---------------------------------------------------------------------------
# Static serving
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(str(DASHBOARD), "index.html")

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(str(DASHBOARD), filename)

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
    js_path = OUT_DIR / topology / "graph_data.js"
    if not js_path.exists():
        return jsonify({"error": f"No data for topology '{topology}'. Run /api/run/{topology} first."}), 404
    try:
        data = _parse_graph_js(js_path)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(data)

# ---------------------------------------------------------------------------
# API — live pipeline run with SSE progress stream
# ---------------------------------------------------------------------------

def _run_pipeline_stream(topology: str, num_nodes: int, seed: int) -> Iterator[str]:
    """Run the TrustField pipeline in this thread and yield SSE events."""

    def _evt(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _evt("progress", {"step": "init", "msg": f"Initialising pipeline for '{topology}' ({num_nodes} nodes)…"})

    try:
        # Imports here so the module loads lazily (keeps first-request fast)
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

        # Re-parse the freshly written file and stream the full payload
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

    # Clamp to sane range
    num_nodes = max(10, min(200, num_nodes))

    return Response(
        _run_pipeline_stream(topology, num_nodes, seed),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",     # disable nginx buffering if behind proxy
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
    return response

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    host = "127.0.0.1"
    port = 5000

    # Parse optional  --port NNNN  flag
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
