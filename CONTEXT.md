# TrustField — Project Context File

> Auto-generated comprehensive context for LLM assistants, contributors, and reviewers.  
> Last updated: 2026-04-02 (rev 3 — visual contrast fix: safe color, sim state redesign, in-canvas legend)

---

## 1. What Is TrustField?

TrustField is a research-grade Python system that analyzes **trust delegation relationships** in cloud infrastructure (AWS IAM, Kubernetes RBAC). It models an organization's identity graph, then predicts which nodes are reachable from a compromised seed using six propagation models, verifies those predictions against real IAM semantics, and deploys simulated cyber-physical guards to contain blast radius.

- **Team**: PS-11, RV College of Engineering, Bangalore — IDP course (CS367P), under Dr. Anand Jatti
- **Version**: 0.1.0 (see `trustfield/__init__.py`)
- **License**: MIT

---

## 2. Repository Layout

```
TrustField/
├── trustfield/                  # Main Python package
│   ├── __init__.py              # Version 0.1.0, author/team info
│   ├── graph/                   # Module 1 — Trust Graph Construction
│   │   ├── trust_graph.py       # TrustGraph (wraps networkx.DiGraph) + NodeMetadata/EdgeMetadata
│   │   ├── node_types.py        # NodeType enum: USER, SERVICE, ROLE, WORKLOAD, SECRET, DEPLOYMENT
│   │   ├── edge_types.py        # EdgeType enum: ASSUME_ROLE, TOKEN_MINT, SECRET_READ, DEPLOY_TO, AUTHENTICATE_AS
│   │   ├── iam_simulator.py     # IAMSimulator — generates 4 synthetic topologies (hub, chain, dense_cluster, mixed)
│   │   └── fingerprinter.py     # TopologyFingerprinter — 8 structural features → TopologyType classification
│   ├── propagation/             # Module 2 — Multi-Model Propagation Engine
│   │   ├── propagation_result.py  # PropagationResult container
│   │   ├── base.py              # Abstract PropagationModel base class
│   │   ├── graph_traversal.py   # BFS reachability (max_depth=6)
│   │   ├── epidemic.py          # SIR stochastic model (beta=0.3, gamma=0.1)
│   │   ├── spectral_cascade.py  # Laplacian eigendecomposition cascade
│   │   ├── percolation.py       # Monte Carlo edge-failure percolation (n_trials=100)
│   │   ├── control_system.py    # Discrete-time linear dynamical system x[t+1]=Ax[t]
│   │   ├── gnn_model.py         # 2-layer GCN (PyTorch), dropout=0.5
│   │   ├── gnn_trainer.py       # GNN training pipeline
│   │   ├── gnn_features.py      # Node feature extraction (centrality, clustering, degree, trust_depth)
│   │   ├── temporal_model.py    # Multi-step attack campaign simulator
│   │   └── runner.py            # PropagationRunner — orchestrates all 6 models → ComparisonReport
│   ├── ensemble/                # Module 3 — Topology-Aware Ensemble Predictor
│   │   ├── ensemble_result.py   # EnsemblePrediction, AnalysisResult dataclasses
│   │   ├── topology_selector.py # TopologyAwareSelector — assigns model weight priors per topology
│   │   ├── weight_tracker.py    # SQLite-backed adaptive weight learning (F1 history)
│   │   ├── weight_vector.py     # Immutable normalized WeightVector snapshots
│   │   ├── ensemble_predictor.py# Weighted (Σwᵢ·rᵢ) and voting fusion + thresholding
│   │   └── orchestrator.py      # TrustFieldOrchestrator — main API (Modules 1–3)
│   ├── verification/            # Module 4 — Verification Engine
│   │   ├── delegation_token.py  # HMAC-SHA256 signed DelegationToken + TokenGenerator
│   │   ├── iam_traversal.py     # IAMTraversal — BFS with real IAM semantics, token validation
│   │   ├── blast_radius.py      # BlastRadiusCalculator — PBR vs VBR + gap classification
│   │   ├── gap_analyzer.py      # GapAnalyzer — CALIBRATED, OVER_PREDICTED, UNDER_PREDICTED, CRITICAL_MISS
│   │   └── verification_report.py # VerificationReport — JSON/CSV export, executive summary
│   ├── guards/                  # Module 5 — Cyber-Physical Guard System
│   │   ├── guard_module.py      # CyberPhysicalGuard — 3 strictness levels: NOMINAL, ELEVATED, LOCKDOWN
│   │   ├── guard_network.py     # GuardNetwork — 2-of-3 consensus triad topology
│   │   ├── containment_engine.py# ContainmentEngine — edge selection and guard deployment
│   │   ├── feedback_loop.py     # FeedbackLoop — risk↔strictness feedback control
│   │   └── sensor.py            # Graph state polling sensor
│   ├── adversarial/             # Adversarial robustness testing
│   │   ├── graph_mutator.py     # 5 mutation strategies: ADD_EDGE, REMOVE_EDGE, SPLIT_NODE, ADD_DECOY, REWIRE
│   │   └── evasion_evaluator.py # Re-runs pipeline post-mutation, measures detection drop
│   ├── baselines/               # Empirical baseline comparisons
│   │   ├── baseline_comparison.py
│   │   ├── scalability_benchmark.py
│   │   ├── calibration.py       # ECE (Expected Calibration Error) metrics
│   │   └── sensitivity_analysis.py
│   ├── loaders/                 # Real-world config parsers
│   │   ├── _common.py           # parse_arn(), action_to_edge_type(), privilege_from_aws_actions(), etc.
│   │   ├── aws_iam_loader.py    # AWS IAM JSON → TrustGraph
│   │   ├── k8s_rbac_loader.py   # Kubernetes RBAC YAML → TrustGraph
│   │   └── cloudgoat_loader.py  # Terraform HCL2 (CloudGoat) → TrustGraph + 28-scenario validator
│   ├── visualization/           # Module 6 — Export & Layout Engines
│   │   ├── graph_exporter.py    # GraphExporter → JSON, JS (Three.js), CSV
│   │   ├── layout_engine.py     # Layout3DEngine — 3D spring-force layout stratified by trust depth
│   │   └── report_generator.py  # ReportGenerator → LaTeX tables, Markdown tables
│   └── pipeline/
│       └── pipeline_runner.py   # TrustFieldPipeline — end-to-end orchestration of all 6 modules
├── tests/                       # 381 tests across 15 test modules (1 skipped, all passing)
│   ├── fixtures/                # Test data: AWS IAM JSON files, K8s RBAC YAML files
│   ├── test_graph.py            # 84 tests — graph construction, fingerprinting, topology generation
│   ├── test_propagation.py      # 93 tests — all 6 models + comparison
│   ├── test_ensemble.py         # 62 tests — ensemble prediction, weights, topology selection
│   ├── test_verification.py     # 12 tests — traversal, blast radius, gap analysis
│   ├── test_guards.py           # 10 tests — guard network, containment, feedback loop
│   ├── test_visualization.py    # 12 tests — graph export, layout, report generation
│   ├── test_loaders.py          # 18 tests — IAM, K8s, CloudGoat loaders
│   ├── test_gnn.py              # 15 tests — GNN model, training, feature extraction
│   ├── test_baselines.py        # 10 tests — baseline comparison, scalability
│   ├── test_scalability.py      # 6 tests — timing benchmarks
│   ├── test_calibration.py      # 8 tests — ECE, calibration curves
│   ├── test_sensitivity.py      # 8 tests — parameter sensitivity
│   ├── test_adversarial.py      # 12 tests — graph mutations, evasion
│   ├── test_temporal.py         # 10 tests — temporal attack simulation
│   └── test_real_world_extended.py  # 21 tests — CloudGoat 28-scenario validation (100%)
├── demos/                       # 14 runnable demonstration scripts
│   ├── demo_full_pipeline.py    # End-to-end pipeline + publication output
│   ├── demo_graph.py            # Module 1: graph construction and fingerprinting
│   ├── demo_propagation.py      # Module 2: all models side-by-side
│   ├── demo_ensemble.py         # Module 3: ensemble with topology-aware weights
│   ├── demo_verification.py     # Module 4: verification + ExploitabilityGap
│   ├── demo_guards.py           # Module 5: guard simulation with feedback
│   ├── demo_loaders.py          # Real-world loaders (IAM/K8s/CloudGoat)
│   ├── demo_baselines.py        # TrustField vs. naive baselines
│   ├── demo_scalability.py      # N=10 to 500 timing benchmark
│   ├── demo_calibration.py      # Calibration analysis
│   ├── demo_adversarial.py      # Adversarial robustness testing
│   ├── demo_temporal.py         # Temporal attack simulator
│   ├── demo_gnn.py              # GNN training and evaluation
│   └── demo_real_world_extended.py  # Extended CloudGoat scenarios
├── dashboard/                   # Browser-based interactive dashboard
│   ├── index.html               # Main UI (topbar, graph canvas, sidebar, timeline, terminal)
│   ├── app.js                   # State management, topology switching, SSE pipeline runner
│   ├── style.css                # All styles including admin panel + breach button
│   └── components/
│       ├── graph3d.js           # Three.js 3D visualization
│       ├── inspector.js         # Node inspector + BREACH button (SIM mode only)
│       ├── metrics.js           # PBR/VBR/Gap/EGD metrics panel
│       ├── timeline.js          # Attack path timeline
│       ├── terminal.js          # Guard event log
│       └── admin.js             # [NEW] Infrastructure editor panel (nodes + policies)
├── web/                         # Three.js 3D viewer (static assets, works from file://)
│   ├── trustfield.js            # Three.js 3D graph visualization
│   └── style.css
├── state/                       # [NEW] Persistent simulated infrastructure state
│   └── sim_graph.json           # Current sim node/edge definitions (auto-created on first run)
├── out/                         # Generated pipeline outputs (per topology)
│   ├── hub/                     # Hub topology results
│   ├── chain/                   # Chain topology results
│   ├── dense_cluster/           # Dense cluster topology results
│   ├── mixed/                   # Mixed topology results
│   └── results_tables.tex       # LaTeX tables for publication
├── models/                      # Pre-trained GNN model weights
│   ├── gnn.pt                   # Main GNN model
│   └── gnn_diverse.pt           # Diverse-training variant
├── server.py                    # Flask server for dashboard (port 5000)
├── requirements.txt             # Python package dependencies
├── README.md                    # 720-line comprehensive documentation
└── LICENSE                      # MIT License
```

---

## 3. Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Graph engine | NetworkX 3.2+ |
| Numerics | NumPy 1.26+, SciPy 1.11+ |
| Machine learning | PyTorch 2.0+ (GCN) |
| Config parsing | PyYAML 6.0+ (K8s), python-hcl2 4.3+ (Terraform) |
| Web server | Flask 3.0+ |
| 3D visualization | Three.js (CDN or local) |
| Testing | pytest 7.4+ |
| Persistent storage | SQLite (adaptive weight history) |

---

## 4. Six-Module Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Module 1: Trust Graph Construction                          │
│  IAMSimulator / Loaders → TrustGraph (typed NetworkX DiGraph)│
└───────────────┬─────────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────────────────────────┐
│  Module 2: Multi-Model Propagation Engine                    │
│  6 models: BFS | SIR Epidemic | Spectral | Percolation |     │
│            Control System | GNN                              │
└───────────────┬─────────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────────────────────────┐
│  Module 3: Topology-Aware Ensemble Predictor                 │
│  Fingerprint → WeightVector → Weighted fusion → risk scores  │
└───────────────┬─────────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────────────────────────┐
│  Module 4: Verification Engine                               │
│  IAMTraversal (BFS + token validation) → PBR vs VBR gap      │
└───────────────┬─────────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────────────────────────┐
│  Module 5: Cyber-Physical Guard System                       │
│  ContainmentEngine → GuardNetwork (2-of-3 consensus) →       │
│  FeedbackLoop (risk ↔ strictness)                            │
└───────────────┬─────────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────────────────────────┐
│  Module 6: Visualization & Export                            │
│  3D layout → JSON/JS/CSV → LaTeX/Markdown reports            │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Core Data Structures

### TrustGraph (`trustfield/graph/trust_graph.py`)
Wraps `networkx.DiGraph`. All nodes carry `NodeMetadata`; all edges carry `EdgeMetadata`.

```python
@dataclass
class NodeMetadata:
    node_id: str
    node_type: NodeType          # USER | SERVICE | ROLE | WORKLOAD | SECRET | DEPLOYMENT
    name: str
    privilege_level: float       # [0, 1]
    sensitivity: float           # [0, 1]
    compromise_status: bool
    cascade_risk: float
    tags: dict

@dataclass
class EdgeMetadata:
    edge_id: str
    edge_type: EdgeType          # ASSUME_ROLE | TOKEN_MINT | SECRET_READ | DEPLOY_TO | AUTHENTICATE_AS
    weight: float                # [0, 1]
    delegation_depth_limit: int
    requires_mfa: bool
    is_conditional: bool
    conditions: dict
```

### TopologyFingerprint (`trustfield/graph/fingerprinter.py`)
8 structural features: `clustering_coefficient`, `centrality_variance`, `spectral_gap`, `degree_distribution_entropy`, `avg_path_length`, `density`, plus derived `TopologyType` (HUB | CHAIN | DENSE_CLUSTER | MIXED).

### PropagationResult (`trustfield/propagation/propagation_result.py`)
Uniform output from every propagation model: per-node risk scores `{node_id: float}`, metadata (model name, seed nodes, runtime).

### ComparisonReport (`trustfield/propagation/runner.py`)
Cross-model summary: `union_compromised`, `intersection_compromised`, `agreement_score`, `per_node_consensus`.

### WeightVector (`trustfield/ensemble/weight_vector.py`)
Immutable, normalized dict of `{model_name: weight}`. Sources: `topology_prior` | `adaptive` | `uniform`.

### EnsemblePrediction / AnalysisResult (`trustfield/ensemble/ensemble_result.py`)
Final per-node risk scores after fusion, plus metadata (topology type, weights used, threshold).

### BlastRadiusAnalysis (`trustfield/verification/blast_radius.py`)
`PBR` (Predicted Blast Radius) vs `VBR` (Verified Blast Radius), `gap`, `gap_classification` (CALIBRATED | OVER_PREDICTED | UNDER_PREDICTED | CRITICAL_MISS).

### DelegationToken (`trustfield/verification/delegation_token.py`)
HMAC-SHA256 signed token: `source_node`, `target_node`, `action`, `timestamp`, `max_depth`, `nonce`, `signature`.

---

## 6. Propagation Models Reference

| Model | File | Key Params | Algorithm |
|-------|------|-----------|-----------|
| BFS Traversal | `graph_traversal.py` | `max_depth=6` | BFS reachability |
| SIR Epidemic | `epidemic.py` | `beta=0.3`, `gamma=0.1`, `max_time_steps=100` | Stochastic SIR |
| Spectral Cascade | `spectral_cascade.py` | `n_eigenvectors=3` | Laplacian eigenvectors |
| Percolation | `percolation.py` | `n_trials=100`, `edge_failure_probability=0.2` | Monte Carlo |
| Control System | `control_system.py` | — | x[t+1] = A·x[t] |
| GNN | `gnn_model.py` | dropout=0.5 | 2-layer GCN (PyTorch) |

---

## 7. Topology-Aware Weight Priors

| Topology | Emphasized Model(s) |
|----------|-------------------|
| HUB | Spectral Cascade |
| CHAIN | SIR Epidemic |
| DENSE_CLUSTER | Percolation + Spectral |
| MIXED | Uniform across all |

Weights are further tuned adaptively via SQLite-backed F1 history in `WeightTracker`.

---

## 8. Loaders (Real-World Input)

| Loader | Source Format | Parses |
|--------|-------------|--------|
| `aws_iam_loader.py` | AWS IAM JSON | Inline/managed policies, trust policies |
| `k8s_rbac_loader.py` | K8s YAML | ClusterRole, Role, ClusterRoleBinding, RoleBinding |
| `cloudgoat_loader.py` | Terraform HCL2 | aws_iam_user/role/policy, instance profiles, ECS task definitions |

Common utilities (`loaders/_common.py`): `parse_arn()`, `action_to_edge_type()`, `privilege_from_aws_actions()`, `sensitivity_from_arn()`, `edge_weight_from_statement()`.

---

## 9. Flask Dashboard API (`server.py`)

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Serve `dashboard/index.html` |
| GET | `/api/topologies` | List available topology names as JSON array |
| GET | `/api/graph/<topology>` | Return pre-computed graph data (nodes, edges, metadata) |
| POST | `/api/run/<topology>` | Run pipeline; streams SSE progress events then `done` event |

SSE events from `POST /api/run/<topology>`:
- `event: progress` → `{"step": "init|generating|fingerprint|...", "msg": "..."}`
- `event: done` → `{"topology": "...", "metrics": {...}, "data": {...}}`
- `event: error` → `{"msg": "...", "trace": "..."}`

Default: `http://127.0.0.1:5000`

---

## 10. SQLite Schema (`trustfield_weights.db`)

```sql
CREATE TABLE model_accuracy (
    topology_type TEXT,   -- "hub" | "chain" | "dense_cluster" | "mixed"
    model_name    TEXT,   -- propagation model identifier
    f1_score      REAL,   -- observed F1 on this topology
    timestamp     INTEGER -- unix timestamp
);
```

Managed by `WeightTracker` (`trustfield/ensemble/weight_tracker.py`). Path configurable via `db_path` argument.

---

## 11. Output Artifacts (`out/`)

For each topology (hub, chain, dense_cluster, mixed):
- `out/<topology>/graph_data.json` — serialized graph + risk scores
- `out/<topology>/graph_data.js` — Three.js-ready JS module
- `out/<topology>/analysis.csv` — per-node metrics table (for supplementary material)
- `out/results_tables.tex` — LaTeX tables for conference submission
- `output/scalability_table.tex` — scalability benchmark LaTeX table

---

## 12. Pre-Trained Models (`models/`)

- `models/gnn.pt` — 2-layer GCN trained on synthetic IAM graphs
- `models/gnn_diverse.pt` — variant trained on diverse topology mix

---

## 13. Test Suite Overview

**381 tests, 1 skipped, all passing** (run with `pytest`)

| File | Tests | Covers |
|------|-------|--------|
| `test_graph.py` | 84 | TrustGraph, fingerprinting, IAMSimulator |
| `test_propagation.py` | 93 | All 6 propagation models + ComparisonReport |
| `test_ensemble.py` | 62 | WeightVector, TopologyAwareSelector, EnsemblePredictor |
| `test_verification.py` | 12 | IAMTraversal, BlastRadius, GapAnalyzer |
| `test_guards.py` | 10 | GuardNetwork, ContainmentEngine, FeedbackLoop |
| `test_visualization.py` | 12 | GraphExporter, Layout3DEngine, ReportGenerator |
| `test_loaders.py` | 18 | IAM/K8s/CloudGoat loaders |
| `test_gnn.py` | 15 | GNN model, training, features |
| `test_baselines.py` | 10 | Baseline comparison |
| `test_scalability.py` | 6 | Timing benchmarks |
| `test_calibration.py` | 8 | ECE metrics |
| `test_sensitivity.py` | 8 | Parameter sensitivity |
| `test_adversarial.py` | 12 | Graph mutations, evasion |
| `test_temporal.py` | 10 | Temporal attack simulation |
| `test_real_world_extended.py` | 21 | CloudGoat 28 scenarios (100% detection) |

---

## 14. Performance Characteristics

**End-to-end < 100 ms for 100-node graphs**

| Stage | N=10 | N=50 | N=100 | Complexity |
|-------|------|------|-------|-----------|
| Fingerprinting | ~0.5 ms | ~3 ms | ~8 ms | O(N log N) |
| Propagation (all 6) | ~1 ms | ~6 ms | ~18 ms | O(N log N) |
| Ensemble | ~0.2 ms | ~1 ms | ~3 ms | O(N) |
| Verification | ~1 ms | ~10 ms | ~40 ms | O(N²) |
| Guard Deployment | ~0.3 ms | ~2 ms | <100 ms | O(N) |

---

## 15. Key Research Metrics

- **Detection rate**: 100% on all 28 CloudGoat attack paths
- **Adversarial robustness**: >80% detection retained under 5 mutation strategies
- **Ensemble vs. single-model**: ensemble consistently outperforms any single model
- **Calibration**: ECE metrics tracked in `baselines/calibration.py`
- **Scalability**: O(N log N) for hub/chain topologies; tested up to 500 nodes

---

## 16. Dependencies (`requirements.txt`)

```
networkx>=3.2
numpy>=1.26
scipy>=1.11
pytest>=7.4
pyyaml>=6.0
torch>=2.0
python-hcl2>=4.3
flask>=3.0
```

No environment variables are required. Optional external resources:
- CloudGoat scenarios (Rhino Security Labs) for real-world testing
- Three.js CDN for visualization (fallback: local copy)

---

## 17. Entry Points

| Task | Command / Class |
|------|----------------|
| Run all topologies end-to-end | `TrustFieldPipeline.run_all_topologies()` in `trustfield/pipeline/pipeline_runner.py` |
| Analyze a single graph | `TrustFieldOrchestrator.analyze(graph, seed_nodes)` in `trustfield/ensemble/orchestrator.py` |
| Start the dashboard | `python server.py` → `http://127.0.0.1:5000` |
| Run all tests | `pytest tests/` |
| Full demo | `python demos/demo_full_pipeline.py` |
| Load AWS IAM JSON | `IAMPolicyLoader().load(json_path)` in `trustfield/loaders/aws_iam_loader.py` |
| Load K8s RBAC YAML | `K8sRBACLoader().load(yaml_path)` in `trustfield/loaders/k8s_rbac_loader.py` |
| Load CloudGoat HCL2 | `CloudGoatLoader().load(hcl_dir)` in `trustfield/loaders/cloudgoat_loader.py` |

---

## 18. Guard System Details

**CyberPhysicalGuard** (`trustfield/guards/guard_module.py`)
- Strictness levels: `NOMINAL` (monitor only) → `ELEVATED` (rate-limit) → `LOCKDOWN` (block)
- Decision outcomes: `ALLOWED`, `BLOCKED`, `FLAGGED`
- Guard state changes require 2-of-3 consensus in the GuardNetwork

**ContainmentEngine** invariant: guards deployed proportional to top-20 predicted high-risk edges + all verified high-risk edges.

**FeedbackLoop control law**: ensemble_risk ↑ → strictness tightens → risk falls → strictness relaxes.

---

## 19. Adversarial Robustness (`trustfield/adversarial/`)

5 mutation strategies available in `GraphMutator`:
1. `ADD_EDGE` — adds random edges to confuse propagation
2. `REMOVE_EDGE` — removes edges to hide attack paths
3. `SPLIT_NODE` — splits a high-value node to reduce its centrality
4. `ADD_DECOY` — inserts decoy nodes to inflate predicted blast radius
5. `REWIRE` — rewires edges while preserving degree distribution

`EvasionEvaluator` re-runs the full pipeline after mutation and reports detection drop.

---

## 20. Visualization System

**Three.js 3D Viewer** (`web/trustfield.js`): Opens from `file://` or hosted. Nodes colored by `NodeType`, sized by risk score. Z-axis = trust delegation depth.

**Dashboard** (`dashboard/`): Flask-served interactive UI with components for graph3d view, inspector panel, metrics panel, timeline, and terminal log.

**Layout3DEngine** (`trustfield/visualization/layout_engine.py`): Spring-force layout, Z-axis stratified by BFS depth from seed nodes.

**ReportGenerator** (`trustfield/visualization/report_generator.py`): Produces `results_tables.tex` (LaTeX) and Markdown summary tables for publication.

---

## 21. Simulated Infrastructure System [NEW — 2026-04-02]

This feature replaces static file loaders and IAMSimulator for demo purposes with a **live, editable simulated infrastructure** that behaves like a real cloud environment.

### Architecture

```
Browser (dashboard)                      Flask server (server.py)
────────────────────                     ─────────────────────────
Admin panel (admin.js)  ──POST/DELETE──▶ /api/sim/node, /api/sim/edge
                                              │
                                         state/sim_graph.json
                                              │
INFRA button (topbar)                    _state_to_trust_graph()
                                              │
RUN button              ──POST──────────▶ /api/sim/run  ──▶ TrustFieldPipeline
                                                               │
BREACH button           ──POST──────────▶ /api/sim/breach/<id>──▶ same, with seed
(in node inspector,                            │
 SIM tab only)                           SSE events stream back
                                              │
Dashboard                ◀── SSE ────────────┘
graph updates live
```

### Persistent State (`state/sim_graph.json`)

Created automatically on first run. Format:
```json
{
  "nodes": [
    { "node_id": "...", "node_type": "USER|SERVICE|ROLE|WORKLOAD|SECRET|DEPLOYMENT",
      "name": "...", "privilege_level": 0.0–1.0, "sensitivity": 0.0–1.0 }
  ],
  "edges": [
    { "source": "...", "target": "...",
      "edge_type": "ASSUME_ROLE|TOKEN_MINT|SECRET_READ|DEPLOY_TO|AUTHENTICATE_AS",
      "weight": 0.0–1.0 }
  ],
  "breach_seed": "node-id or null"
}
```

### Default Infrastructure (demo story)

A 6-node, 5-hop attack chain:
```
user-dev (USER, priv=0.1)
    └─ ASSUME_ROLE ──▶ role-ci (ROLE, priv=0.45)
                          └─ DEPLOY_TO ──▶ svc-api (SERVICE, priv=0.3)
                                               └─ ASSUME_ROLE ──▶ role-admin (ROLE, priv=0.85)
                                                                       └─ AUTHENTICATE_AS ──▶ svc-database (SERVICE, priv=0.6)
                                                                                                  └─ SECRET_READ ──▶ secret-master (SECRET, sensitivity=1.0)
```
Story: developer account hacked → attacker walks 5 legitimate trust hops to master credentials.

### New API Routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/sim/state` | Raw state JSON (for admin panel) |
| GET | `/api/graph/sim` | Post-analysis data if available, else preview layout |
| POST | `/api/sim/node` | Add a node `{node_id, node_type, name, privilege_level, sensitivity}` |
| DELETE | `/api/sim/node/<id>` | Remove node + all its edges |
| POST | `/api/sim/edge` | Add a trust relationship `{source, target, edge_type, weight}` |
| DELETE | `/api/sim/edge` | Remove a trust relationship `{source, target}` |
| POST | `/api/sim/reset` | Reset to default demo infrastructure |
| POST | `/api/sim/run` | Run full pipeline on current state (SSE stream) |
| POST | `/api/sim/breach/<id>` | Mark node as seed, run pipeline (SSE stream) |

All mutation routes (`node`/`edge` POST/DELETE) automatically invalidate the cached `out/sim/graph_data.js` so the dashboard shows a preview until re-analyzed.

### Admin Panel (`dashboard/components/admin.js`)

Slide-in drawer (340px wide, overlaps graph area, opens with INFRA button):
- **NODES tab**: table of current nodes (type, id, name, priv/sens bars) + delete buttons + "Add Node" form
- **POLICIES tab**: table of current edges + delete buttons + "Add Policy" form
- **Policy-changed banner**: appears after any structural edit, prompts ANALYZE
- **RESET button**: restores default demo state with confirmation

### Breach Simulation Flow

1. User clicks a node in the 3D graph on the SIM tab
2. Node inspector shows `⚡ SIMULATE BREACH FROM THIS NODE` button
3. Click → `POST /api/sim/breach/<node_id>` → server saves `breach_seed` to state, runs pipeline from that seed
4. SSE events stream into the terminal log in real time
5. On `done` event: graph reloads with attack paths lit up, blast radius shown, guards deployed
6. Subsequent `RUN` clicks re-run from the same seed until breach_seed is cleared

### Trigger Logic Summary

| Trigger | How | Seed |
|---------|-----|------|
| Policy change (add/remove node or edge) | Shows "ANALYZE" banner; user clicks it or RUN | Auto: lowest-privilege node |
| Manual RUN button on SIM tab | Button click | Last breach_seed, or auto |
| Breach simulation | Click node → BREACH button | That specific node |
