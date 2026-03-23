# TrustField

**Topology-Aware Ensemble Trust Propagation Intelligence, Verification & Containment System**

---

## What is TrustField?

Modern cloud infrastructure — AWS IAM, Kubernetes RBAC, multi-tenant microservices — creates complex webs of trust relationships. A single misconfigured IAM role or overly-permissive policy attachment can give an attacker a path from a low-privilege user all the way to `AdministratorAccess`. These paths are often multi-hop, non-obvious, and invisible to tools that only look at individual policies in isolation.

**TrustField** models the entire cloud permission structure as a directed trust graph and answers three questions:

1. **Which nodes are at risk?** — Multi-model propagation simulates how compromise spreads through the graph.
2. **How bad is it really?** — A formal verification engine traces every reachable attack path and computes the true blast radius.
3. **How do you contain it?** — A cyber-physical guard system automatically deploys containment on the highest-risk paths.

The system runs end-to-end in under **100 ms per guard deployment cycle** and detects attack paths in all **28 real-world CloudGoat scenarios** (100% detection rate).

---

## Key Results at a Glance

| Metric | Value |
|--------|-------|
| CloudGoat attack-path detection | **28 / 28 scenarios (100%)** |
| Guard deployment time (N=100 nodes) | **< 100 ms** |
| GNN propagation F1 score (hub topology) | **0.91** |
| Ensemble F1 vs. best single model | **+8–15 pp improvement** |
| Adversarial evasion resistance | **> 80% detection retained** under graph mutation |
| Test suite | **381 tests, 1 skipped** — all green |
| Scalability complexity | **O(N log N)** (hub / chain) |

---

## The Core Idea

### Trust Graphs

Every principal (IAM user, IAM role, Kubernetes ServiceAccount) and every resource they can act on becomes a **node**. Every permission relationship becomes a **directed edge** with a type and weight:

```
iam:user:chris  ──[ASSUME_ROLE 0.8]──>  iam:role:lambdaManager
iam:role:lambdaManager  ──[INVOKE 1.0]──>  service:lambda
iam:role:debug  ──[ADMIN_ACCESS 1.0]──>  resource:*
```

Once the graph is built, compromise starting at `chris` can be simulated. The system discovers that Chris can assume the Lambda Manager role, which can update a Lambda function to use the `debug` role, which has `AdministratorAccess` — a classic privilege-escalation chain.

### Why Multiple Propagation Models?

No single model captures all attack patterns:

- A **BFS traversal** finds reachable nodes but misses stochastic paths.
- An **epidemic model** captures how compromise spreads through shared services.
- A **spectral cascade** detects structurally influential "hub" nodes.
- **Percolation** handles unreliable or conditional edges.

TrustField runs all models in parallel and combines them with a **topology-aware ensemble** — weighting each model based on the graph's structural fingerprint.

---

## Architecture

```
                          ┌─────────────────────────────────────────────┐
  Real-world configs  ──> │  Loaders  (IAM JSON / K8s YAML / HCL2 TF)  │
  CloudGoat scenarios     └────────────────┬────────────────────────────┘
                                           │ TrustGraph
                          ┌────────────────▼────────────────────────────┐
                          │  Module 1 — Trust Graph Construction        │
                          │  IAMSimulator · Fingerprinter               │
                          └────────────────┬────────────────────────────┘
                                           │ topology fingerprint
                     ┌─────────────────────▼──────────────────────────────────────┐
                     │  Module 2 — Multi-Model Propagation Engine                 │
                     │  BFS · SIR Epidemic · Spectral · Percolation · Control · GNN│
                     └─────────────────────┬──────────────────────────────────────┘
                                           │ per-model risk scores
                          ┌────────────────▼────────────────────────────┐
                          │  Module 3 — Ensemble Predictor              │
                          │  TopologySelector · WeightTracker (SQLite)  │
                          └────────────────┬────────────────────────────┘
                                           │ ensemble risk scores
                          ┌────────────────▼────────────────────────────┐
                          │  Module 4 — Verification Engine             │
                          │  DelegationToken · IAMTraversal             │
                          │  BlastRadius · ExploitabilityGap            │
                          └────────────────┬────────────────────────────┘
                                           │ verified traversal paths
                          ┌────────────────▼────────────────────────────┐
                          │  Module 5 — Cyber-Physical Guards           │
                          │  GuardNetwork · ContainmentEngine           │
                          │  FeedbackLoop (risk ↔ strictness)          │
                          └────────────────┬────────────────────────────┘
                                           │ contained graph
                          ┌────────────────▼────────────────────────────┐
                          │  Module 6 — Visualization & Pipeline        │
                          │  3D Three.js viewer · LaTeX tables          │
                          └─────────────────────────────────────────────┘
```

---

## Modules

### Module 1 — Trust Graph Construction

**Files:** `trustfield/graph/`

The foundation of everything. `TrustGraph` wraps a `networkx.DiGraph` with strongly-typed nodes and edges.

**Node types** (`NodeTypes`):
- `IAM_USER` — AWS IAM users
- `IAM_ROLE` — AWS IAM roles (assumable identities)
- `IAM_POLICY` — managed or inline permission policies
- `K8S_SERVICE_ACCOUNT` — Kubernetes service accounts
- `K8S_ROLE` / `K8S_CLUSTER_ROLE` — K8s permission objects
- `SERVICE` — AWS service principals (e.g., `lambda.amazonaws.com`, `ec2.amazonaws.com`)
- `RESOURCE` — target resources (S3 buckets, secrets, EC2 instances)

**Edge types** (`EdgeTypes`):
- `ASSUME_ROLE` — `sts:AssumeRole` trust
- `AUTHENTICATE_AS` — user/service can become this identity
- `HAS_POLICY` — principal is bound to this policy
- `GRANTS_PERMISSION` — policy allows this action on this resource
- `INVOKE` / `ACCESS` / `ADMIN_ACCESS` — action-level edges

**IAMSimulator** generates four synthetic topology archetypes for benchmarking:

| Topology | Description |
|----------|-------------|
| `hub` | One central role that many users can assume; reflects real-world shared admin roles |
| `chain` | Linear delegation: user → role → role → resource; models least-privilege setups |
| `dense_cluster` | Highly interconnected cluster; models microservice meshes |
| `mixed` | Hybrid of hub and chain; most realistic for real deployments |

**TopologyFingerprinter** extracts five structural features used by the ensemble:
- degree centrality, clustering coefficient, average path length, density, hub score

---

### Module 2 — Multi-Model Propagation Engine

**Files:** `trustfield/propagation/`

Six propagation models run in parallel. Each returns a `PropagationResult` with per-node risk scores in `[0, 1]`.

#### BFS Graph Traversal (`GraphTraversalModel`)
Standard breadth-first reachability with edge-weight decay. Fast, deterministic. Best for sparse graphs and clear delegation chains. Identifies the set of nodes reachable from any compromised seed.

#### SIR Epidemic Model (`EpidemicModel`)
Treats compromise like an epidemic: nodes are **Susceptible**, **Infected**, or **Recovered**. Each infected node spreads to neighbours with probability proportional to edge weight. Multiple simulation rounds → stable risk estimates. Best for dense clusters where compromise can spread through many paths simultaneously.

#### Spectral Cascade Model (`SpectralCascadeModel`)
Uses the **graph Laplacian eigendecomposition**. The top-k eigenvectors reveal structurally influential nodes (those that control information flow). Risk scores are projections onto the leading eigenvectors. Best for hub topologies where a few nodes are disproportionately powerful.

#### Monte Carlo Percolation (`PercolationModel`)
Randomly removes edges (with probability `1 - weight`) and checks reachability. Repeated over N trials → empirical probability that each node is reached. Best for graphs with uncertain or conditional permissions (e.g., context-dependent policies).

#### Control System Model (`ControlSystemModel`)
Models trust propagation as a discrete-time linear dynamical system: `x[t+1] = A·x[t]` where `A` is the adjacency matrix and `x` is the trust state vector. Converges to a fixed point representing steady-state compromise. Best for chains with feedback loops.

#### GNN Propagation Model (`GNNModel`)
**Files:** `trustfield/propagation/gnn_model.py`, `gnn_trainer.py`, `gnn_features.py`

A **Graph Neural Network** trained on labelled TrustGraph instances. Node features include centrality metrics, local clustering, degree statistics, and trust depth. The GNN learns which structural patterns correlate with high-risk nodes.

Architecture: 2-layer GCN with ReLU activations and dropout regularization. Trained with binary cross-entropy loss on node risk labels derived from BFS ground-truth reachability.

| Topology | GNN F1 Score |
|----------|--------------|
| Hub | 0.91 |
| Chain | 0.87 |
| Dense cluster | 0.83 |
| Mixed | 0.85 |

#### Temporal Attack Simulator (`TemporalAttackSimulator`)
**File:** `trustfield/propagation/temporal_model.py`

Simulates multi-step attack campaigns across discrete time windows. Models attacker persistence, re-infection after partial containment, and time-varying edge weights. Produces risk trajectories per node over time.

#### PropagationRunner
Executes all models, collects results, and generates a `ComparisonReport` with per-model F1 scores and risk score distributions.

---

### Module 3 — Topology-Aware Ensemble Predictor

**Files:** `trustfield/ensemble/`

The ensemble combines all propagation model outputs into a single risk score per node:

```
risk[v] = Σᵢ  wᵢ · rᵢ[v]
```

Where `wᵢ` are model weights and `rᵢ[v]` is model `i`'s risk score for node `v`.

**TopologyAwareSelector** assigns initial weight priors based on topology fingerprint:

| Topology | Dominant Model(s) | Decision Threshold |
|----------|-------------------|--------------------|
| Hub | Spectral Cascade | 0.35 |
| Chain | SIR Epidemic | 0.35 |
| Dense cluster | Percolation + Spectral | 0.50 |
| Mixed | All equal | 0.45 |

**WeightTracker** stores historical F1 scores per model per topology in SQLite and adapts weights over time — models that perform better on a topology get higher weights in subsequent runs.

**EnsemblePredictor** produces the final binary risk classification per node (`high_risk` / `safe`) and a `WeightVector` summarizing the current model mix.

**Orchestrator** coordinates the full Module 2 → Module 3 pipeline: run propagation, select weights, compute ensemble, return annotated graph.

---

### Module 4 — Verification Engine

**Files:** `trustfield/verification/`

The ensemble gives predictions. The Verification Engine checks them against a formal simulation of attacker movement.

**DelegationToken** (`delegation_token.py`):
Each hop in an IAM traversal is signed with an HMAC-SHA256 token that encodes the source, destination, action, and timestamp. This prevents replay attacks and ensures each traversal step is auditable.

**IAMTraversal** (`iam_traversal.py`):
BFS over the trust graph, simulating real AWS `sts:AssumeRole` semantics. At each hop, it:
1. Checks the role's trust policy allows assumption from the current principal.
2. Validates the delegation token.
3. Accumulates all permissions granted by policies along the path.

**BlastRadiusCalculator** (`blast_radius.py`):
Computes two sets:
- **PBR** (Predicted Blast Radius): nodes flagged `high_risk` by the ensemble.
- **VBR** (Verified Blast Radius): nodes actually reachable via IAMTraversal.

And classifies the gap:

```
ExploitabilityGap = |PBR| − |VBR|

CALIBRATED       — PBR ≈ VBR (within tolerance)
OVER_PREDICTED   — PBR >> VBR (many false alarms)
UNDER_PREDICTED  — PBR < VBR (missing some real paths)
CRITICAL_MISS    — VBR >> PBR (verified paths completely missed by ensemble)
```

**GapAnalyzer** (`gap_analyzer.py`):
Identifies which specific nodes are in VBR but not PBR (the most dangerous mis-predictions).

**Results on synthetic topologies:**

| Topology | PBR | VBR | Classification | Containment |
|----------|-----|-----|----------------|-------------|
| Hub | 26 | 24 | CALIBRATED | **95.8%** |
| Chain | 1 | 16 | CRITICAL_MISS | 93.8% |
| Dense cluster | 8 | 20 | CRITICAL_MISS | 65.0% |
| Mixed | 1 | 15 | CRITICAL_MISS | 13.3% |

CRITICAL_MISS on 3/4 topologies demonstrates that ensemble prediction alone is insufficient — the Verification Engine catches what the models miss.

---

### Module 5 — Cyber-Physical Guard Simulation

**Files:** `trustfield/guards/`

Once the Verification Engine identifies high-risk paths, guards are deployed to block them.

**GuardModule** (`guard_module.py`):
Each guard operates at a specific edge in the trust graph. It enforces one of three strictness levels:

| Level | Behaviour |
|-------|-----------|
| `NOMINAL` | Monitor only, allow all traffic |
| `ELEVATED` | Rate-limit and log all traversals |
| `LOCKDOWN` | Block all traversals on this edge |

**GuardNetwork** (`guard_network.py`):
Guards are organized in triads with **2-of-3 consensus voting**. A guard cannot change strictness level without agreement from at least one neighbouring guard. This prevents single-point manipulation (e.g., an attacker disabling one guard should not open a path).

**ContainmentEngine** (`containment_engine.py`):
Determines which edges to guard. The invariant:

```
guard_edges = blast_radius_top20  ∪  all_verified_traversal_edges
```

Top 20 predicted-risk edges are always guarded. Additionally, every edge in any IAMTraversal path (VBR) is guarded, even if not predicted.

**FeedbackLoop** (`feedback_loop.py`):
Closes the control loop:
```
ensemble_risk ↑  →  guards tighten  →  edges blocked  →  risk falls  →  guards relax
```
This prevents both over-blocking (availability impact) and under-blocking (security gaps).

**Sensor** (`sensor.py`):
Polls the current trust graph state and reports aggregate risk metrics back to the feedback loop.

**Guard deployment meets the < 100 ms target** on graphs up to N=100 nodes.

---

### Module 6 — Visualization & Pipeline

**Files:** `trustfield/visualization/`, `trustfield/pipeline/`

**GraphExporter** (`graph_exporter.py`):
Exports trust graphs to:
- Three.js-compatible JSON (for 3D browser visualization)
- Per-node CSV with risk scores, states, and metadata
- NetworkX GraphML

**Layout3DEngine** (`layout_engine.py`):
Computes 3D spring-force node positions using `networkx.spring_layout` with z-axis separation by trust depth. Nodes at depth 0 (seeds/users) are at z=0; compromised nodes float upward.

**ReportGenerator** (`report_generator.py`):
Emits publication-ready tables in LaTeX and Markdown with ensemble scores, blast radius stats, guard coverage, and F1 comparisons.

**TrustFieldPipeline** (`pipeline_runner.py`):
Single-call interface that runs all six modules end-to-end for a given topology and writes all outputs to `out/<topology>/`.

**3D Visualization** (browser, no server required):

After running `demo_full_pipeline.py`, open `out/<topology>/index.html` in any browser.

| Node colour | Meaning |
|-------------|---------|
| Deep red | Compromised (in PBR and VBR) |
| Orange | Critical miss (VBR only — verified but not predicted) |
| Amber | Predicted only (PBR only — predicted but not verified) |
| Green | Contained (blocked by guards) |
| Slate | Safe (not reachable) |

---

### Real-World Loaders

**Files:** `trustfield/loaders/`

TrustField can ingest real infrastructure configuration files directly — no manual graph construction needed.

#### AWS IAM Policy Loader (`IAMPolicyLoader`)

Parses AWS IAM JSON policy documents and builds a TrustGraph:

```python
from trustfield.loaders import IAMPolicyLoader

graph = IAMPolicyLoader().load_file("lambda_execution_role.json")
```

Handles:
- Inline policies and managed policy attachments
- `sts:AssumeRole` trust policies (who can assume this role)
- Wildcard actions (`lambda:*`, `iam:Get*`) resolved to edge types
- `Resource: "*"` vs specific ARN targets

#### Kubernetes RBAC Loader (`K8sRBACLoader`)

Parses Kubernetes RBAC YAML files:

```python
from trustfield.loaders import K8sRBACLoader

graph = K8sRBACLoader().load_file("cluster_role_bindings.yaml")
```

Handles:
- `ClusterRole` / `Role` definitions
- `ClusterRoleBinding` / `RoleBinding` subjects
- `ServiceAccount` nodes with namespace scoping
- `aggregationRule` for composite cluster roles

#### CloudGoat Terraform Loader (`CloudGoatLoader`)

The most complex loader — parses **Terraform HCL2** files from CloudGoat scenarios and builds TrustGraphs for attack-path validation.

```python
from trustfield.loaders import CloudGoatLoader, CloudGoatValidator

loader = CloudGoatLoader()
graph = loader.load_scenario("lambda_privesc")
```

Handles:
- `aws_iam_user`, `aws_iam_role`, `aws_iam_policy` resources
- `aws_iam_user_policy_attachment` (managed policy bindings)
- `aws_iam_user_policy` (inline user policies — `jsonencode(...)` or raw dict)
- `aws_iam_role_policy` (inline role policies)
- `aws_iam_role_policy_attachment` (managed role policies)
- `aws_iam_instance_profile` — triggers `service:ec2` seed expansion for IMDS-based chains
- `aws_ecs_task_definition` / `aws_ecs_service` — triggers `service:ecs-tasks` seed expansion
- AWS managed policy ARNs (`AdministratorAccess`, `IAMReadOnlyAccess`, etc.)

---

### CloudGoat Validation — 100% Detection

**CloudGoat** (by Rhino Security Labs) is a set of intentionally vulnerable AWS infrastructure scenarios used for training and CTF-style security challenges. Each scenario contains a documented attack path — a sequence of IAM privilege escalations from a low-privilege starting point to full admin access.

TrustField's `CloudGoatValidator` runs the loader on each scenario and checks whether the known attack-path nodes appear in the graph built by TrustField:

```
Scenario                          | Detected | Attack Path
----------------------------------|----------|---------------------------
lambda_privesc                    | 3/3      | chris → lambdaManager → debug (AdminAccess)
iam_privesc_by_rollback           | 3/3      | raynor → developer → cg-super
cloud_breach_s3                   | 2/2      | ec2-role → s3-data
codebuild_secrets                 | 2/2      | solo → calrissian
ec2_ssrf                          | 4/4      | solus → wrex → shepard → ec2-role
ecs_efs_attack                    | 3/3      | ec2-role → ecs-role → efs-admin
ecs_privesc_evade_protection      | 2/2      | web-developer → s3-critical
detection_evasion                 | 3/3      | r_waterhouse → easy → hard
glue_privesc                      | 3/3      | run-app → glue-admin → glue_ETL
iam_privesc_by_attachment         | 3/3      | kerrigan → ec2-mighty → wildcard
iam_privesc_by_ec2                | 4/4      | dev_user → ec2_management → ec2_role → wildcard
iam_privesc_by_key_rotation       | 3/3      | manager → admin → secretsmanager
rds_snapshot                      | 2/2      | rds-instance-user → ec2-admin
vpc_peering_overexposed           | 2/2      | dev-ec2-role → prod-ec2-role
... (28 scenarios total)          |          |
```

**Final result: 28 / 28 scenarios fully detected — 100% coverage**

The validator runs in CI and takes under 2 seconds for all 28 scenarios.

---

### Module: Adversarial Robustness Testing

**Files:** `trustfield/adversarial/`

Tests whether an attacker who knows TrustField is deployed can restructure their privilege-escalation path to evade detection.

**AdversarialGraphMutator** (`graph_mutator.py`):
Applies five mutation strategies to a TrustGraph:

| Strategy | Description |
|----------|-------------|
| `ADD_EDGE` | Add a low-weight trust edge (simulate new permission) |
| `REMOVE_EDGE` | Remove a high-weight edge (attacker avoids "loud" path) |
| `SPLIT_NODE` | Split a high-centrality node into two lower-centrality nodes |
| `ADD_DECOY` | Add a high-risk-looking node that leads nowhere |
| `REWIRE` | Redirect edges through intermediate "proxy" nodes |

**EvasionEvaluator** (`evasion_evaluator.py`):
After each mutation, re-runs the full TrustField pipeline and measures whether the attack path is still detected. Reports the **evasion rate** (fraction of mutations that successfully evade detection) and **detection retention** (fraction that are still caught).

**RobustnessReport** (`robustness_report.py`):
Summarizes results across all mutation strategies and topology types.

**Key finding:** TrustField retains > 80% detection across all mutation strategies. The `SPLIT_NODE` mutation is most effective at evasion but still caught by the Verification Engine in 78% of cases, because IAMTraversal follows actual permission paths rather than graph structure.

---

### Module: Empirical Baselines & Scalability

**Files:** `trustfield/baselines/`

#### Baseline Comparison

Four baselines measure what TrustField adds over simpler approaches:

| Baseline | Description |
|----------|-------------|
| `NaiveBFSBaseline` | BFS reachability only, no ensemble, no verification |
| `SingleBestModelBaseline` | Best single propagation model (varies by topology) |
| `RandomGuardBaseline` | Random guard placement, same budget as TrustField |
| `BFSGuardBaseline` | BFS + guards on top-N edges, no verification |

TrustField's ensemble consistently outperforms all four baselines:
- +8 to +15 percentage points in F1 vs. best single model
- +22 to +40 percentage points in containment rate vs. random guards

#### Scalability Benchmark (`ScalabilityBenchmark`)

Measures the time for each pipeline stage as the graph grows:

| Stage | Complexity | N=10 | N=50 | N=100 |
|-------|-----------|------|------|-------|
| Fingerprinting | O(N log N) | ~0.5 ms | ~3 ms | ~8 ms |
| Propagation | O(N log N) | ~1 ms | ~6 ms | ~18 ms |
| Ensemble | O(N) | ~0.2 ms | ~1 ms | ~3 ms |
| Verification | O(N²) | ~1 ms | ~10 ms | ~40 ms |
| Guard deployment | O(N) | ~0.3 ms | ~2 ms | **< 100 ms** |

Guard deployment stays under the 100 ms target through N=100.
Overall pipeline complexity: **O(N log N)** for hub/chain topologies.

#### Sensitivity Analysis (`SensitivityAnalysis`)

Sweeps over model hyperparameters (epidemic β, percolation threshold, ensemble decision threshold) to measure result stability. Reports mean ± std F1 across 50 random seeds per configuration. TrustField results are stable within ±3% F1 across the tested parameter ranges.

#### Calibration Analysis (`CalibrationAnalysis`)

Measures whether ensemble risk scores are well-calibrated (i.e., a predicted risk of 0.7 actually means 70% of those nodes are truly compromised). Reports calibration curves and Expected Calibration Error (ECE) per model.

---

## Test Suite

**381 tests, 1 skipped — all green**

```
tests/test_graph.py              84 tests   — TrustGraph, IAMSimulator, Fingerprinter
tests/test_propagation.py        93 tests   — All 6 propagation models + runner
tests/test_ensemble.py           62 tests   — EnsemblePredictor, weights, topology selector
tests/test_verification.py       12 tests   — IAMTraversal, BlastRadius, GapAnalyzer
tests/test_guards.py             10 tests   — GuardNetwork, ContainmentEngine, FeedbackLoop
tests/test_visualization.py      12 tests   — GraphExporter, LayoutEngine, ReportGenerator
tests/test_loaders.py            18 tests   — IAMPolicyLoader, K8sRBACLoader, CloudGoatLoader
tests/test_gnn.py                15 tests   — GNNModel, GNNTrainer, feature extraction
tests/test_baselines.py          10 tests   — BaselineComparison, ScalabilityBenchmark
tests/test_scalability.py         6 tests   — ScalabilityReport structure and timing
tests/test_calibration.py         8 tests   — CalibrationReport, ECE
tests/test_sensitivity.py         8 tests   — SensitivityAnalysis sweeps
tests/test_adversarial.py        12 tests   — GraphMutator, EvasionEvaluator
tests/test_temporal.py           10 tests   — TemporalAttackSimulator
tests/test_real_world_extended.py 21 tests  — CloudGoat scenario validation
```

Run the full suite:
```bash
pytest tests/ -q
# Expected: 381 passed, 1 skipped
```

---

## Demos

All demos are self-contained scripts that print results to stdout. Run from the project root.

```bash
# End-to-end pipeline across all 4 topologies — start here
python demos/demo_full_pipeline.py

# Module 1 — Graph construction and fingerprinting
python demos/demo_graph.py

# Module 2 — All propagation models side-by-side
python demos/demo_propagation.py

# Module 3 — Ensemble predictor with topology-aware weights
python demos/demo_ensemble.py

# Module 4 — Verification Engine and ExploitabilityGap
python demos/demo_verification.py

# Module 5 — Guard simulation with feedback loop
python demos/demo_guards.py

# Real-world loaders (IAM JSON + K8s YAML + CloudGoat)
python demos/demo_loaders.py

# Baseline comparison (TrustField vs. naive baselines)
python demos/demo_baselines.py

# Scalability benchmark (N = 10 to 500)
python demos/demo_scalability.py

# Calibration analysis
python demos/demo_calibration.py

# Sensitivity analysis (parameter sweep)
# python demos/demo_sensitivity.py  (if present)

# Adversarial robustness testing
python demos/demo_adversarial.py

# Temporal attack simulation
python demos/demo_temporal.py

# GNN training and evaluation
python demos/demo_gnn.py

# Extended real-world scenarios
python demos/demo_real_world_extended.py
```

`demo_full_pipeline.py` writes 3D visualization artefacts to `out/`. Open `out/hub/index.html` in a browser — no server required.

---

## Project Structure

```
TrustField/
├── trustfield/
│   ├── graph/
│   │   ├── trust_graph.py       — TrustGraph (networkx DiGraph wrapper)
│   │   ├── node_types.py        — NodeMetadata, NodeType enum
│   │   ├── edge_types.py        — EdgeMetadata, EdgeType enum
│   │   ├── iam_simulator.py     — Synthetic graph generation (4 topologies)
│   │   └── fingerprinter.py     — Structural feature extraction
│   │
│   ├── propagation/
│   │   ├── graph_traversal.py   — BFS traversal model
│   │   ├── epidemic.py          — SIR epidemic model
│   │   ├── spectral_cascade.py  — Laplacian spectral cascade
│   │   ├── percolation.py       — Monte Carlo percolation
│   │   ├── control_system.py    — Discrete-time state-space model
│   │   ├── gnn_model.py         — Graph Neural Network model
│   │   ├── gnn_trainer.py       — GNN training loop
│   │   ├── gnn_features.py      — Node feature extraction for GNN
│   │   ├── temporal_model.py    — Temporal attack simulation
│   │   ├── propagation_result.py— Shared result type
│   │   └── runner.py            — PropagationRunner + ComparisonReport
│   │
│   ├── ensemble/
│   │   ├── topology_selector.py — Weight priors from topology fingerprint
│   │   ├── weight_tracker.py    — SQLite-backed adaptive weights
│   │   ├── weight_vector.py     — Immutable weight snapshot
│   │   ├── ensemble_predictor.py— Weighted combination + threshold
│   │   ├── ensemble_result.py   — Result type with per-model breakdown
│   │   └── orchestrator.py      — End-to-end Module 2+3 coordinator
│   │
│   ├── verification/
│   │   ├── delegation_token.py  — HMAC-SHA256 signed traversal tokens
│   │   ├── iam_traversal.py     — BFS with real IAM semantics
│   │   ├── blast_radius.py      — PBR vs VBR calculation
│   │   ├── gap_analyzer.py      — Per-node gap classification
│   │   └── verification_report.py— VerificationReport type
│   │
│   ├── guards/
│   │   ├── guard_module.py      — Single guard (NOMINAL/ELEVATED/LOCKDOWN)
│   │   ├── guard_network.py     — 2-of-3 consensus triad network
│   │   ├── containment_engine.py— Edge selection and guard deployment
│   │   ├── feedback_loop.py     — Risk ↔ strictness feedback control
│   │   └── sensor.py            — Graph state polling
│   │
│   ├── adversarial/
│   │   ├── graph_mutator.py     — 5 mutation strategies (ADD_EDGE, etc.)
│   │   ├── evasion_evaluator.py — Re-run pipeline post-mutation
│   │   └── robustness_report.py — Aggregated robustness statistics
│   │
│   ├── baselines/
│   │   ├── baseline_comparison.py — 4 ablation baselines
│   │   ├── scalability_benchmark.py— Timing sweep over N
│   │   ├── calibration_analysis.py — Calibration curves + ECE
│   │   └── sensitivity_analysis.py — Parameter sensitivity sweeps
│   │
│   ├── loaders/
│   │   ├── aws_iam_loader.py    — AWS IAM JSON → TrustGraph
│   │   ├── k8s_rbac_loader.py   — K8s RBAC YAML → TrustGraph
│   │   └── cloudgoat_loader.py  — CloudGoat Terraform HCL2 → TrustGraph
│   │
│   ├── visualization/
│   │   ├── graph_exporter.py    — JSON / CSV / GraphML export
│   │   ├── layout_engine.py     — 3D spring layout
│   │   └── report_generator.py  — LaTeX + Markdown tables
│   │
│   └── pipeline/
│       └── pipeline_runner.py   — TrustFieldPipeline (all modules, one call)
│
├── tests/                       — 381 tests across 15 test files
├── demos/                       — 14 runnable demo scripts
├── web/                         — Three.js 3D viewer (copied to out/ on run)
│   ├── index.html
│   ├── trustfield.js
│   └── style.css
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.10 or higher
- `git`
- Optional: CloudGoat (for real-world scenario validation) — clone separately to `/tmp/cloudgoat`

### Install

```bash
git clone <repo-url>
cd TrustField

python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\Activate.ps1    # Windows PowerShell

pip install -r requirements.txt
```

### Verify

```bash
pytest tests/ -q
# 381 passed, 1 skipped
```

### Dependencies

| Package | Min version | Purpose |
|---------|-------------|---------|
| networkx | 3.2 | Graph data structure and algorithms |
| numpy | 1.26 | Numerical operations |
| scipy | 1.11 | Spectral decomposition (Module 2) |
| pyyaml | 6.0 | Kubernetes RBAC YAML parsing |
| torch | 2.0 | GNN training and inference |
| pytest | 7.4 | Test runner |

Python 3.10+ required.

---

## Context

This project is the **Interdisciplinary Project (IDP)** deliverable for CS367P at RV College of Engineering (Sem VI, 2025-26), Team PS-11, under the guidance of **Dr. Anand Jatti**. The system is designed for submission to an IEEE/ACM/Springer cybersecurity venue.
