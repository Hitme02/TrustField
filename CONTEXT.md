# TrustField — Project Context File

> Auto-generated comprehensive context for LLM assistants, contributors, and reviewers.  
> Last updated: 2026-04-20 (rev 5 — AWS Connect demo, CloudTrail monitor, AcmeTech scenario, policy generator, graph edge fixes)

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
│   │   ├── aws_iam_loader.py    # AWS IAM JSON → TrustGraph (policy doc / MAMIP / role bundle)
│   │   ├── account_auth_loader.py  # [NEW] aws iam get-account-authorization-details → TrustGraph
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
│   ├── index.html               # Main UI (topbar, graph canvas, sidebar, timeline, terminal, org overlay)
│   ├── app.js                   # State management, topology switching, SSE pipeline runner
│   ├── style.css                # All styles (admin, demo overlay, org upload panel)
│   ├── samples/                 # [NEW] Bundled sample IAM JSON files (served as static assets)
│   │   ├── account_dump.json    # Full aws iam get-account-authorization-details format
│   │   ├── role_bundle.json     # TrustField role bundle {RoleName, TrustPolicy, PermissionPolicies}
│   │   └── policy_doc.json      # Bare IAM policy document {Version, Statement}
│   └── components/
│       ├── graph3d.js           # Three.js 3D visualization + setNodeState/setEdgeColor/pulseNode
│       ├── inspector.js         # Node inspector + BREACH button (SIM/ORG tabs only)
│       ├── metrics.js           # PBR/VBR/Gap/EGD metrics panel
│       ├── timeline.js          # Attack path timeline
│       ├── terminal.js          # Guard event log
│       ├── admin.js             # Infrastructure editor (nodes + trust relationships + IAM upload)
│       ├── demo.js              # [NEW] Step-by-step 6-phase demo controller (PREV/NEXT)
│       └── org.js               # [NEW] ORG tab upload panel (drag/drop, format detect, samples)
├── web/                         # Three.js 3D viewer (static assets, works from file://)
│   ├── trustfield.js            # Three.js 3D graph visualization
│   └── style.css
├── state/                       # Persistent infrastructure state
│   ├── sim_graph.json           # Simulated infrastructure (auto-created on first run)
│   └── org_graph.json           # [NEW] Uploaded real IAM data (created after first ORG upload)
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
| `aws_iam_loader.py` | AWS IAM JSON | Bare policy doc, MAMIP wrapper, TrustField role bundle |
| `account_auth_loader.py` | `aws iam get-account-authorization-details` | UserDetailList, GroupDetailList, RoleDetailList, Policies |
| `k8s_rbac_loader.py` | K8s YAML | ClusterRole, Role, ClusterRoleBinding, RoleBinding |
| `cloudgoat_loader.py` | Terraform HCL2 | aws_iam_user/role/policy, instance profiles, ECS task definitions |

Common utilities (`loaders/_common.py`): `parse_arn()`, `action_to_edge_type()`, `privilege_from_aws_actions()`, `sensitivity_from_arn()`, `edge_weight_from_statement()`.

### `account_auth_loader.py` — AccountAuthorizationLoader [NEW]

Parses the full output of `aws iam get-account-authorization-details`. Input format:
```json
{
  "UserDetailList":  [{ "UserName", "Arn", "GroupList", "UserPolicyList", "AttachedManagedPolicies" }],
  "GroupDetailList": [{ "GroupName", "Arn", "GroupPolicyList", "AttachedManagedPolicies" }],
  "RoleDetailList":  [{ "RoleName", "Arn", "AssumeRolePolicyDocument", "RolePolicyList", "AttachedManagedPolicies" }],
  "Policies":        [{ "PolicyArn", "PolicyVersionList": [{ "Document", "IsDefaultVersion" }] }]
}
```

Graph construction:
- Each user → `USER` node; each group → `ROLE` node; each role → `ROLE` node
- User ∈ Group → `AUTHENTICATE_AS` edge
- Role trust doc → `ASSUME_ROLE` edges (principal → role)
- Permission docs → typed edges (subject → resource)
- Managed policy documents resolved from the `Policies` index by ARN

### `detect_iam_format(data: dict) -> str` [NEW]

Auto-detects which format a JSON dict is in. Returns one of:
- `"account_auth_dump"` — has `UserDetailList` or `RoleDetailList`
- `"policy_doc"` — has `Statement`
- `"mamip_policy"` — has `PolicyVersion.Document`
- `"role_bundle"` — has `RoleName` or `TrustPolicy`
- `"k8s_rbac"` — has `apiVersion` + `kind`
- `"terraform_plan"` — has `resource_changes` or `planned_values`
- `"unknown"` — unrecognised

---

## 9. Flask Dashboard API (`server.py`)

### Core routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Serve `dashboard/index.html` |
| GET | `/api/topologies` | List available topology names (always includes `sim` and `org`) |
| GET | `/api/graph/<topology>` | Return graph data (post-analysis if available, else preview) |
| POST | `/api/run/<topology>` | Run pipeline on synthetic topology; streams SSE |

### Simulated infrastructure routes (`/api/sim/*`)

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/sim/state` | Raw sim state JSON (node/edge lists) |
| POST | `/api/sim/node` | Add node `{node_id, node_type, name, privilege_level, sensitivity}` |
| DELETE | `/api/sim/node/<id>` | Remove node and all its edges |
| POST | `/api/sim/edge` | Add edge `{source, target, edge_type, weight}` |
| DELETE | `/api/sim/edge` | Remove edge `{source, target}` |
| POST | `/api/sim/reset` | Reset to default demo infrastructure |
| POST | `/api/sim/run` | Run full pipeline on sim state (SSE) |
| POST | `/api/sim/breach/<id>` | Set breach seed + run pipeline (SSE) |
| POST | `/api/sim/upload-iam` | Merge IAM policy JSON into sim graph `{policy, subject_id, subject_arn, replace}` |

### ORG topology routes (`/api/org/*`)

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/org/upload` | Parse real IAM dump, store as org graph `{data, replace}` |
| GET | `/api/graph/org` | Return org graph data; 404 with `{needs_upload: true}` if no data |
| POST | `/api/org/run` | Run full pipeline on org graph (SSE) |
| POST | `/api/org/breach/<id>` | Set breach seed + run pipeline on org graph (SSE) |
| POST | `/api/org/clear` | Delete org graph state and cached analysis |

`POST /api/org/upload` auto-detects format using `detect_iam_format()` and routes to the appropriate loader (`AccountAuthorizationLoader`, `IAMPolicyLoader`, or `K8sRBACLoader`).

The upload body is handled by `_do_org_upload(raw, replace)` — a shared helper called by both `api_org_upload` and `api_aws_pull`.

### AWS Connect routes (`/api/aws/*`) [NEW — 2026-04-20]

Simulate a real AWS integration. All endpoints work in demo mode without real credentials.

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/aws/connect` | Test connection (demo: always succeeds). Returns account info. |
| POST | `/api/aws/pull` | Pull IAM data (demo: loads `acmetech_breach_scenario.json`). Stores as org graph. |
| GET | `/api/aws/policies` | Return generated IAM deny policies from last analysis. |
| POST | `/api/aws/apply` | Apply policies (demo: returns policy JSON + apply commands). |
| GET | `/api/aws/cloudtrail` | SSE stream of simulated CloudTrail events walking the attack path. |

**Demo constants** (top of AWS section in `server.py`):
- `_DEMO_ACCOUNT_ID = "123456789012"`
- `_DEMO_ACCOUNT_ALIAS = "AcmeTech Corp"`
- `_SCENARIO_FILE = dashboard/samples/acmetech_breach_scenario.json`

**Policy generation** (`/api/aws/policies`): reads `out/org/graph_data.js`, extracts `blocked_transitions`, generates one IAM deny policy per blocked edge:
```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::123456789012:role/<target>"
}
```
Returns `{ok, ready, count, policies[]}`. If no analysis has run yet: `ready: false`.

**CloudTrail SSE** (`/api/aws/cloudtrail`): streams 6 hard-coded events spaced 1.8s apart representing the AcmeTech breach path. Event types: `cloudtrail_event` (status: ALLOWED/FLAGGED/BREACH) and final `cloudtrail_breach` (triggers breach simulation in dashboard).

### SSE event format (all streaming endpoints)

- `event: progress` → `{"step": "init|building|fingerprint|verification|containment|export", "msg": "..."}`
- `event: done` → `{"topology": "...", "metrics": {...}, "data": {...}, "seed_nodes": [...]}`
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

### `graph_exporter.py` — Metadata Fields Required by Dashboard

`GraphExporter._build_metadata()` must emit these fields for the dashboard to function correctly:

```python
"pbr_nodes":           sorted(blast_radius.pbr_nodes),       # inspector PBR badge
"vbr_nodes":           sorted(blast_radius.vbr_nodes),       # inspector VBR badge
"contained_nodes":     sorted(containment_result.contained_nodes),  # graph3d green
"blocked_transitions": [list(t) for t in containment_result.blocked_transitions],  # graph3d dimmed edges
"guard_events":        [...],
"traversal_timeline":  [...],   # demo controller depth-grouped animation
"seed_nodes":          [...],   # demo controller breach step
```

If `containment_result` is `None` (no guards ran), emit empty lists for all four fields.

---

## 21. Simulated Infrastructure System

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

All mutation routes (`node`/`edge` POST/DELETE) automatically invalidate the cached `out/sim/graph_data.js` so the dashboard shows a preview until re-analyzed.

### Admin Panel (`dashboard/components/admin.js`)

Slide-in drawer (340px wide, overlaps graph area, opens with INFRA button):
- **NODES tab**: table of current nodes (type, id, name, priv/sens bars) + delete buttons + "Add Node" form
  - **Trust Relationships sub-section**: while adding a node, click `+ ADD` to define edges to/from existing nodes. Each pending edge has direction (→ can access / ← accessed by), target node select, edge type, weight slider. Edges are batch-POSTed after the node is created.
- **POLICIES tab**: table of current edges + delete buttons + "Add Policy" form
- **UPLOAD IAM tab**: paste textarea + file picker; sends `POST /api/sim/upload-iam`; shows `+N nodes, +M edges` on success
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
| Policy change (add/remove node or edge) | Shows "ANALYZE" banner; user clicks it or DEMO | Auto: lowest-privilege node |
| Manual DEMO button on SIM tab | Click → 6-phase demo | Last breach_seed, or auto |
| Breach simulation | Click node → BREACH button | That specific node |

---

## 22. Demo Controller (`dashboard/components/demo.js`) [NEW — 2026-04-17]

A step-by-step presentation layer that replays pipeline results as 6 animated phases. Designed to tell the full attack story during project reviews.

### 6 Phases

| Step | Title | What Happens |
|------|-------|-------------|
| 0 | Your Cloud Infrastructure | Graph loads with all nodes safe (blue). Narration: node count, edge count. |
| 1 | Breach Detected | Seed node pulses and turns red. Narration: node name and type. |
| 2 | Attack Path Simulation | Traversal timeline replayed depth-by-depth (~700 ms/level). Compromised edges glow red. |
| 3 | Ensemble Risk Analysis | Predicted-only (amber) and critical-miss (orange) nodes revealed. Narration: PBR vs VBR sizes, gap score. |
| 4 | Deploying Cyber-Physical Guards | Contained nodes turn green. Blocked edges dimmed. Narration: block count, containment rate. |
| 5 | Infrastructure Secured | Full final state rendered. Success/warning message. |

### Key Implementation Details

- **Cancel-token pattern**: `_cancel` integer incremented on every step change; all `setTimeout` callbacks check `if (_cancel !== tok) return` before executing. Makes PREV safe.
- **PREV is always safe**: Each step's `_renderStep(i)` rebuilds from scratch (`_safeSnapshot()` + incremental mutations), so going backwards is just re-entering the same enter function.
- **Depth-grouped animation**: `traversal_timeline` steps grouped by `depth` field; entire depth wave animates at `400 + depth * 700` ms to avoid very long animations on dense graphs.
- **Background pipeline**: On `startDemo()`, pipeline runs via SSE in the background while infra step is shown. NEXT is disabled with a spinner until `done` event arrives.
- **Topology-aware**: `DemoController.setTopology(topo)` switches between `/api/sim/run` and `/api/org/run`. Called by `app.js` whenever the active tab changes.

### UI

The demo overlay is a compact panel pinned to the bottom-right (`position: fixed; bottom: 176px; right: 288px; width: 300px`). Contains:
- Step title (12px mono, cyan)
- Narration text (11px, dim) — built dynamically from real pipeline data
- PREV / NEXT buttons
- Step counter (e.g. `2 / 6`)
- Loading spinner while pipeline runs
- Error message if pipeline fails

### graph3d.js additions (required by demo)

```javascript
Graph3D.setNodeState(nodeId, state)   // change color + emissive intensity live
Graph3D.setEdgeColor(fromId, toId, colorHex, opacity)  // recolor a specific edge; opacity=0 hides it
Graph3D.pulseNode(nodeId)             // 500ms scale-pulse animation
Graph3D.getGraphData()                // read current loaded graph data
```

`_edgeMap` (module-level dict `{from:to → Mesh object}`) enables O(1) edge lookup without rebuilding the scene.

### Edge rendering [updated 2026-04-20]

Edges use `CylinderGeometry` + `MeshBasicMaterial` instead of `THREE.Line` + `LineBasicMaterial`. This gives real visible thickness (WebGL ignores `linewidth` on most platforms). Cylinder radius: `0.55` units.

- **Blocked edges** (`blocked_transitions` in metadata): `line.visible = false` — completely hidden, not just dimmed
- **`setEdgeColor(from, to, hex, opacity)`**: bidirectional lookup (`from:to` then `to:from`); sets `line.visible = opacity > 0`
- **`pulseEdge`**: skips hidden edges (guards active = no traffic animation on blocked paths)
- **`app.js` guards_deployed handler**: calls `setEdgeColor(..., 0x1e3b2e, 0)` — hides edges when guards deploy via SSE

---

## 23. ORG Tab — Real IAM Data Upload [NEW — 2026-04-17]

Allows any organization to upload their real AWS IAM data and run the full TrustField analysis on it. The ORG tab mirrors the SIM tab but is driven by uploaded data rather than a manually-built simulated graph.

### Flow

```
1. User clicks ORG tab
2. GET /api/graph/org → 404 {needs_upload: true}
   → Upload panel shown (full graph-area overlay)

3. User drops/pastes JSON or clicks a sample LOAD button
   → Client-side format detection badge appears instantly
   → IMPORT button enabled

4. POST /api/org/upload {data, replace: true}
   → Server calls AccountAuthorizationLoader (or IAMPolicyLoader / K8sRBACLoader)
   → Stores result in state/org_graph.json
   → Returns {ok, format, added_nodes, added_edges, total_nodes, total_edges}

5. Upload panel closes → GET /api/graph/org → preview layout rendered

6. User clicks DEMO → DemoController runs /api/org/run (SSE)
   OR clicks a node → BREACH → /api/org/breach/<id> (SSE)

7. Full 6-module analysis renders — same visuals as SIM tab
```

### Upload Panel (`dashboard/components/org.js` + `#org-upload-overlay`)

The panel has **3 tabs**: UPLOAD, AWS CONNECT, CLOUDTRAIL.

**UPLOAD tab** (original behavior):
- **Drag/drop zone** or **Browse** button → reads file as text → populates paste area
- **Paste textarea** — live format detection on every keystroke
- **Format badge** — green `DETECTED: AWS ACCOUNT DUMP` or red `UNKNOWN FORMAT`
- **4 sample buttons** — load bundled local samples (`/static/samples/*.json`) for immediate demo
- **IMPORT button** — posts to `/api/org/upload`, shows `+N nodes · +M edges · format: account_auth_dump`
- Automatically closes and loads the preview after ~900ms on success

**AWS CONNECT tab** [NEW — 2026-04-20]:
- Credential form (Access Key ID, Secret Key, Region) + **TEST CONNECTION** / **USE DEMO MODE** buttons
- `USE DEMO MODE` → `POST /api/aws/connect` (no credentials needed) → account banner appears
- `PULL IAM DATA FROM AWS` → `POST /api/aws/pull` → loads AcmeTech scenario, closes panel, graph appears
- After pipeline runs, **ENFORCEMENT POLICIES** section appears automatically (polled every 3s via `GET /api/aws/policies`)
- Each policy shown as: source → target path + IAM deny policy name
- **DOWNLOAD JSON** → saves `trustfield-guards.json` with all policy documents
- **APPLY TO AWS** → `POST /api/aws/apply` → demo mode returns policies + `aws iam put-role-policy` commands

**CLOUDTRAIL tab** [NEW — 2026-04-20]:
- Connect via AWS CONNECT first, then account info appears here
- **START MONITORING** → opens `GET /api/aws/cloudtrail` SSE stream
- Events stream in one-by-one: ALLOWED (green) → FLAGGED (amber) → BREACH (red)
- Final `cloudtrail_breach` event auto-triggers breach simulation on ORG graph

**Module-level state in org.js**: `_awsConnected`, `_awsAccountId`, `_awsAccountAlias`, `_policyPollInterval` (cleared on `hideUploadPanel()`).

**Public API**: `{ init, showUploadPanel, hideUploadPanel, checkPolicies }` — `checkPolicies()` can be called by `app.js` after pipeline completes to refresh the policy display.

### Bundled Sample Files (`dashboard/samples/`)

| File | Format | Contents |
|------|--------|---------|
| `account_dump.json` | `account_auth_dump` | 2 users, 1 group, 3 roles, 2 managed policies — full chain from dev user to admin role to secrets |
| `role_bundle.json` | `role_bundle` | `data-pipeline-role` with Glue trust + S3/KMS/Secrets permissions |
| `policy_doc.json` | `policy_doc` | Bare IAM policy: sts:AssumeRole + secretsmanager:GetSecretValue + lambda:InvokeFunction |
| `acmetech_breach_scenario.json` | `account_auth_dump` | AcmeTech Corp (123456789012) — 5-hop privilege escalation demo scenario used by AWS CONNECT tab |

### AcmeTech Breach Scenario (`dashboard/samples/acmetech_breach_scenario.json`) [NEW — 2026-04-20]

Represents "AcmeTech Corp" (account `123456789012`). Designed for the AWS Connect demo.

**Attack path** (5 hops):
```
dev-alice / ci-runner
    → deploy-role          (legitimate CI/CD usage)
    → lambda-exec-role     (hidden escalation — unusual)
    → api-gateway-role     (service-to-service chain)
    → secrets-access-role  (reads prod/* secrets — BREACH)
```
**Dead ends** (to make graph realistic): `data-science-role` (S3 + SageMaker, trusted by dev-alice only), `readonly-audit-role` (no further escalation).

**CloudTrail event sequence** (hard-coded in `/api/aws/cloudtrail`):
1. `dev-alice → deploy-role` — ALLOWED
2. `ci-runner → deploy-role` — ALLOWED
3. `deploy-role → lambda-exec-role` — FLAGGED
4. `lambda-exec-role → api-gateway-role` — FLAGGED
5. `api-gateway-role → secrets-access-role` — BREACH
6. `secrets-access-role GetSecretValue prod/db-master` — BREACH ACTIVE

### Topbar Controls (ORG tab)

- **CLEAR ORG** button (replaces INFRA on ORG tab): confirms then calls `POST /api/org/clear`, returns to upload panel
- **DEMO** button: always visible; routes to `/api/org/run` when on ORG tab

### State Schema (`state/org_graph.json`)

Identical schema to `state/sim_graph.json`:
```json
{
  "nodes": [{ "node_id", "node_type", "name", "privilege_level", "sensitivity" }],
  "edges": [{ "source", "target", "edge_type", "weight" }],
  "breach_seed": "node-id or null"
}
```

### `AccountAuthorizationLoader` (`trustfield/loaders/account_auth_loader.py`)

Handles the full `get-account-authorization-details` dump. Key steps:
1. Builds a policy-document index (`Arn → Document`) from `Policies[*].PolicyVersionList` (default version only; URL-decodes if needed)
2. Processes `UserDetailList` → USER nodes, AUTHENTICATE_AS edges to groups, inline + attached policy edges
3. Processes `GroupDetailList` → ROLE nodes, inline + attached policy edges
4. Processes `RoleDetailList` → ROLE nodes, trust policy ASSUME_ROLE edges, inline + attached policy edges
5. All edges use `dominant_edge_type()` + `edge_weight_from_statement()` from `_common.py`
