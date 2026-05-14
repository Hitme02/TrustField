/* demo.js — Step-by-step demo presentation controller for TrustField
 *
 * Replays a full pipeline result in 6 animated phases so reviewers see
 * the complete story: infra → breach → attack paths → analysis → containment → secured.
 *
 * Usage (wired by app.js):
 *   DemoController.init()          — call once at startup
 *   DemoController.startDemo()     — called by the DEMO button
 */

const DemoController = (() => {

  // ── Module state ────────────────────────────────────────────────────────
  let _data       = null;   // full pipeline result (nodes, edges, metadata)
  let _step       = -1;     // current step index  (-1 = not active)
  let _cancel     = 0;      // increment to abort in-flight animations
  let _ready      = false;  // pipeline result received
  let _attackNode = null;   // attacked node id — known immediately, before pipeline finishes
  let _useGnn     = false;  // GNN toggle — off by default for speed

  const TOTAL_STEPS = 6;

  const STEP_TITLES = [
    'Your Cloud Infrastructure',
    'Breach Detected',
    'Attack Path Simulation',
    'Ensemble Risk Analysis',
    'Deploying Cyber-Physical Guards',
    'Infrastructure Secured',
  ];

  // ── Narration (built dynamically from pipeline data) ────────────────────
  function _narration(i) {
    if (i === 0) {
      // Step 0 text is available before the pipeline result
      return 'This is a live model of your cloud environment.\n' +
             'Each node is a principal or resource — IAM users, roles, services, secrets.\n' +
             'Each edge is a trust relationship — assume-role, secret-read, deploy-to.\n\n' +
             'Click NEXT to simulate a breach.';
    }
    // Step 1 can render immediately using just the attack node — no pipeline needed
    if (!_data && i === 1) {
      const node = _attackNode || '?';
      return `"${node}" has been compromised.\n` +
             `TrustField is tracing every trust delegation the attacker can exploit.\n\n` +
             `The blue pulses are live API requests between services — even mid-breach,\n` +
             `all these connections are active and must be accounted for.\n\n` +
             `Analysis running in background — click NEXT to proceed once ready.`;
    }
    if (!_data) return 'Analysis running… please wait.';

    const meta        = _data.metadata || {};
    const seeds       = meta.seed_nodes || [];
    const seedId      = seeds[0] || '?';
    const seedNode    = (_data.nodes || []).find(n => n.id === seedId);
    const seedType    = seedNode?.type || 'NODE';
    const N           = meta.num_nodes       || (_data.nodes || []).length;
    const E           = (_data.edges || []).length;
    const pbrSize     = meta.pbr_size        || 0;
    const vbrSize     = meta.vbr_size        || 0;
    const egd         = meta.exploitability_gap_score != null
                          ? meta.exploitability_gap_score.toFixed(3) : '—';
    const timeline    = meta.traversal_timeline || [];
    const pathSteps   = timeline.filter(s => s.succeeded).length;
    const maxDepth    = Math.max(0, ...timeline.map(s => s.depth || 0));
    const guardEvents = meta.guard_events || [];
    const blockedCnt  = (meta.blocked_transitions || []).length;
    const contained   = meta.contained_nodes || [];
    const rate        = meta.containment_success_rate != null
                          ? (meta.containment_success_rate * 100).toFixed(0) : '?';
    const strictness  = meta.final_strictness || 'HIGH';
    const gapClass    = meta.gap_classification || '—';

    const lines = [
      null, // step 0 handled above
      // Step 1: BREACH
      `A ${seedType} node — "${seedId}" — has been compromised.\n` +
      `The attacker has initial foothold. TrustField is now tracing every trust delegation they can exploit.\n\n` +
      `The blue pulses are live API calls still flowing across the graph — every one of these\n` +
      `active connections is a potential lateral movement path that must be cut off.`,
      // Step 2: PATHS
      `${pathSteps} successful trust hops traced across ${maxDepth + 1} depth levels.\n` +
      `Each lit edge is an exploitable delegation — assume-role, deploy-to, secret-read.\n` +
      `${timeline.length - pathSteps} edges were blocked by weight conditions or token limits.\n\n` +
      `The attacker can reach ${vbrSize} nodes from "${seedId}".`,
      // Step 3: ANALYSIS
      (_useGnn
        ? `6 propagation models ran in parallel: BFS traversal, SIR epidemic, spectral cascade,\npercolation, control system, and GNN.\n\n`
        : `5 propagation models ran in parallel: BFS traversal, SIR epidemic, spectral cascade,\npercolation, and control system.  (GNN disabled)\n\n`) +
      `Predicted Blast Radius (PBR): ${pbrSize} nodes flagged at risk.\n` +
      `Verified Blast Radius (VBR): ${vbrSize} confirmed reachable via formal IAM traversal.\n` +
      `Exploitability Gap: ${egd}  (${gapClass})`,
      // Step 4: CONTAINMENT
      (blockedCnt > 0
        ? `The cyber-physical guard system is isolating the attack path.\n` +
          `${blockedCnt} trust edges are being revoked.\n` +
          `Adaptive feedback loop escalated strictness to ${strictness}.\n\n` +
          `Watch edges go dark as the attack path closes down.`
        : `The compromised node is a resource sink — no outward attack path.\n` +
          `TrustField is revoking all inbound trust edges to the compromised resource,\n` +
          `cutting off any further access to it.\n\n` +
          `Adaptive strictness: ${strictness}.`),
      // Step 5: SECURED
      `Containment complete.\n\n` +
      `${contained.length} nodes isolated  ·  ${rate}% containment success rate\n` +
      `The compromised path is broken. Nodes remain monitored until cleared\n` +
      `by your security team.`,
    ];

    return lines[i] || '';
  }

  // ── Graph state helpers ──────────────────────────────────────────────────

  /**
   * Edges that should be visually blocked in steps 4-5.
   *
   * We deliberately do NOT use _data.metadata.blocked_transitions here.
   * The ContainmentEngine's blocked set includes "top-20 predicted-risk edges"
   * which are structurally important hub edges that have NOTHING to do with the
   * actual attack path — hiding them makes the graph look completely disconnected
   * even when the attack could not propagate.
   *
   * Instead we use only the *verified traversal* edges (the edges the attacker
   * actually walked).  For resource-sink attacks (0 successful hops) we fall
   * back to the inbound edges of the seed node — semantically: TrustField is
   * revoking all access TO the compromised resource.
   */
  function _visualBlockEdges() {
    const meta    = _data?.metadata || {};
    const seeds   = new Set(meta.seed_nodes || []);

    const traversed = (meta.traversal_timeline || [])
      .filter(s => s.succeeded)
      .map(s => [s.from_node, s.to_node]);

    if (traversed.length > 0) return traversed;

    // Resource-sink / isolated node: block inbound edges to the seed so
    // the animation still shows TrustField doing something meaningful.
    return (_data?.edges || [])
      .filter(e => seeds.has(e.target))
      .map(e => [e.source, e.target]);
  }

  /** Return a deep copy of _data with all nodes set to 'safe' and metadata cleared. */
  function _safeSnapshot() {
    const snap = JSON.parse(JSON.stringify(_data));
    snap.nodes.forEach(n => { n.state = 'safe'; n.risk = 0; n.exploitability = 0; });
    snap.metadata = Object.assign({}, snap.metadata, {
      traversal_timeline: [], guard_events: [], blocked_transitions: [],
      seed_nodes: [], pbr_nodes: [], vbr_nodes: [], contained_nodes: [],
    });
    return snap;
  }

  // Step 0 — all nodes safe (clean infrastructure view)
  function _applyInfraStep() {
    // Use pipeline snapshot if available, otherwise clean whatever is currently loaded.
    // This ensures any node already marked compromised (from attack_started event) resets.
    const snap = _data
      ? _safeSnapshot()
      : (() => {
          const cur = Graph3D.getGraphData();
          if (!cur) return null;
          const s = JSON.parse(JSON.stringify(cur));
          s.nodes.forEach(n => { n.state = 'safe'; n.risk = 0; n.exploitability = 0; });
          s.metadata = Object.assign({}, s.metadata || {}, {
            traversal_timeline: [], guard_events: [], blocked_transitions: [],
            seed_nodes: [], pbr_nodes: [], vbr_nodes: [], contained_nodes: [],
          });
          return s;
        })();
    if (!snap) return;
    // noWave: nodes already visible from the initial org graph load — no pop-in needed.
    // noCamera: keep the reviewer's current view angle throughout the demo.
    Graph3D.loadGraph(snap, { noWave: true, noCamera: true });
  }

  // Step 1 — seed nodes turn red + pulse (works even before pipeline finishes)
  function _applyBreachStep(tok) {
    // Use pipeline seed list if available, fall back to the known attacked node
    const seeds = _data?.metadata?.seed_nodes?.length
      ? _data.metadata.seed_nodes
      : (_attackNode ? [_attackNode] : []);
    if (!seeds.length) return;

    // Reset to clean infrastructure first (removes any leftover analysis colours)
    if (_data) Graph3D.loadGraph(_safeSnapshot(), { noWave: true, noCamera: true });
    setTimeout(() => {
      if (_cancel !== tok) return;
      seeds.forEach(id => {
        Graph3D.setNodeState(id, 'compromised');
        Graph3D.pulseNode(id);
      });
    }, 250);
  }

  // Step 2 — animate traversal wave depth-by-depth
  function _applyPathsStep(tok) {
    if (!_data) return;
    Graph3D.loadGraph(_safeSnapshot(), { noWave: true, noCamera: true });
    const seeds    = _data.metadata?.seed_nodes || [];
    const timeline = _data.metadata?.traversal_timeline || [];

    // Mark seeds immediately
    setTimeout(() => {
      if (_cancel !== tok) return;
      seeds.forEach(id => {
        Graph3D.setNodeState(id, 'compromised');
        Graph3D.pulseNode(id);
      });
    }, 150);

    // Group by depth level
    const byDepth = {};
    timeline.forEach(s => {
      const d = s.depth ?? 0;
      (byDepth[d] = byDepth[d] || []).push(s);
    });

    const depths = Object.keys(byDepth).map(Number).sort((a, b) => a - b);
    depths.forEach((depth, di) => {
      setTimeout(() => {
        if (_cancel !== tok) return;
        byDepth[depth].forEach(s => {
          if (s.succeeded) {
            Graph3D.setEdgeColor(s.from_node, s.to_node, 0xff9500, 0.85);
            Graph3D.setNodeState(s.to_node, 'compromised');
            Graph3D.pulseNode(s.to_node);
          } else {
            Graph3D.setEdgeColor(s.from_node, s.to_node, 0x333355, 0.25);
          }
        });
      }, 400 + di * 700);
    });
  }

  // Step 3 — show full ensemble analysis state (before containment)
  function _applyAnalysisStep() {
    if (!_data) return;
    // Show the final graph data but un-contain contained nodes
    // so reviewer sees the pre-guard risk picture
    const snap = JSON.parse(JSON.stringify(_data));
    snap.nodes.forEach(n => {
      if (n.state === 'contained') n.state = 'compromised';
    });
    snap.metadata = Object.assign({}, snap.metadata, {
      guard_events: [], blocked_transitions: [], contained_nodes: [],
    });
    // traversal_timeline is kept — _buildGraph will colour those edges orange
    Graph3D.loadGraph(snap, { noWave: true, noCamera: true });
  }

  // Step 4 — animate guard deployment edge-by-edge, then contained nodes turn green
  function _applyContainmentStep(tok) {
    if (!_data) return;
    _applyAnalysisStep();  // start from full-risk state

    // Push the real ContainmentEngine output to mock cloud (for system-console
    // blocked-ping display) but DO NOT use it for graph visuals — it contains
    // prediction-based edges unrelated to the actual attack path.
    const realBlocked = _data.metadata?.blocked_transitions || [];
    if (realBlocked.length) {
      fetch('/api/mock/guards', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ blocked_transitions: realBlocked }),
      }).catch(() => {});
    }

    // Visually animate only the edges that are on the verified attack path
    // (or inbound edges to the seed for resource-sink scenarios).
    const blocks    = _visualBlockEdges();
    const contained = _data.metadata?.contained_nodes || [];
    const delay     = Math.max(120, Math.min(350, 1800 / Math.max(1, blocks.length)));

    // Block edges one by one
    blocks.forEach((edge, i) => {
      setTimeout(() => {
        if (_cancel !== tok) return;
        const [from, to] = Array.isArray(edge) ? edge : [edge, null];
        if (from && to) Graph3D.setEdgeColor(from, to, 0x111122, 0.95);
      }, 300 + i * delay);
    });

    // After all edges blocked: turn contained nodes green
    // Also derive contained set from blocked edges if pipeline returned empty
    const greenAt = 300 + blocks.length * delay + 500;
    const nodesToGreen = contained.length ? contained : (() => {
      // Any non-seed node whose every outgoing edge is in the blocked set
      const blockedSet = new Set(blocks.map(e => Array.isArray(e) ? e[0]+':'+e[1] : e));
      const seeds = new Set(_data.metadata?.seed_nodes || []);
      const outEdges = {};
      (_data.edges || []).forEach(e => {
        (outEdges[e.source] = outEdges[e.source] || []).push(e.source + ':' + e.target);
      });
      return Object.entries(outEdges)
        .filter(([id, outs]) => !seeds.has(id) && outs.length > 0 && outs.every(k => blockedSet.has(k)))
        .map(([id]) => id);
    })();

    nodesToGreen.forEach((id, i) => {
      setTimeout(() => {
        if (_cancel !== tok) return;
        Graph3D.setNodeState(id, 'contained');
        Graph3D.pulseNode(id);
      }, greenAt + i * 120);
    });
  }

  // Step 5 — final secured state
  function _applySecuredStep() {
    if (!_data) return;

    // Build the visual blocked set from traversal data only.
    // We MUST NOT pass _data.blocked_transitions to loadGraph directly because
    // the ContainmentEngine's predicted-risk list includes unrelated hub edges
    // that would make the whole graph look disconnected even for a zero-hop attack.
    const visualBlocked    = _visualBlockEdges();
    const visualBlockedSet = new Set(visualBlocked.map(([f, t]) => f + ':' + t));

    // Build a display snapshot that only marks verified-path edges as blocked
    const snap = JSON.parse(JSON.stringify(_data));
    snap.metadata = Object.assign({}, snap.metadata, {
      blocked_transitions: visualBlocked,
    });
    Graph3D.loadGraph(snap, { noWave: true, noCamera: true });

    // Dark-red "attack zone" tinting — only meaningful when attack actually propagated
    const hasPath = (snap.metadata.traversal_timeline || []).some(s => s.succeeded);
    if (!hasPath) return;

    const hotNodes = new Set(
      (snap.nodes || [])
        .filter(n => n.state === 'compromised' || n.state === 'critical_miss')
        .map(n => n.id)
    );

    // Tint edges touching hot nodes
    (snap.edges || []).forEach(e => {
      if (hotNodes.has(e.source) || hotNodes.has(e.target)) {
        const key = e.source + ':' + e.target;
        if (visualBlockedSet.has(key)) {
          Graph3D.setEdgeColor(e.source, e.target, 0x3b1010, 0.60);
        } else {
          Graph3D.setEdgeColor(e.source, e.target, 0x2a1a0a, 0.40);
        }
      }
    });

    // Dim any traversal edge not involving a hot node (severed by upstream containment)
    (snap.metadata.traversal_timeline || []).filter(s => s.succeeded).forEach(s => {
      if (!hotNodes.has(s.from_node) && !hotNodes.has(s.to_node)) {
        Graph3D.setEdgeColor(s.from_node, s.to_node, 0x1a1a2e, 0.20);
      }
    });
  }

  // ── Step rendering ───────────────────────────────────────────────────────

  function _renderStep(i) {
    _step = i;
    _updateUI(i);

    const tok = _cancel;
    switch (i) {
      case 0: _applyInfraStep();          break;
      case 1: _applyBreachStep(tok);      break;
      case 2: _applyPathsStep(tok);       break;
      case 3: _applyAnalysisStep();       break;
      case 4: _applyContainmentStep(tok); break;
      case 5: _applySecuredStep();        break;
    }

    // Sync sidebar state counts whenever we have pipeline data
    if (_data && typeof App !== 'undefined') {
      // For steps that mutate node states, build the display snapshot
      if (i === 3) {
        // Analysis: show compromised state (no containment applied yet)
        const snap = JSON.parse(JSON.stringify(_data));
        snap.nodes.forEach(n => { if (n.state === 'contained') n.state = 'compromised'; });
        App.updateDisplay(snap);
      } else if (i === 5) {
        App.updateDisplay(_data);
      }
    }
  }

  function _gotoStep(i) {
    if (i < 0 || i >= TOTAL_STEPS) return;
    if (i > 0 && !_ready) return;   // cannot advance until pipeline finishes
    _cancel++;
    _renderStep(i);
  }

  // ── Pipeline run ─────────────────────────────────────────────────────────

  const SYNTHETIC_TOPOS = new Set(['hub', 'chain', 'dense_cluster', 'mixed']);

  function _pipelineRequest() {
    if (SYNTHETIC_TOPOS.has(_topology)) {
      const n = parseInt(document.getElementById('node-count')?.value || '50', 10);
      return { url: `/api/run/${_topology}`, body: { num_nodes: n, seed: 42, use_gnn: _useGnn } };
    }
    return { url: `/api/${_topology}/run`, body: { use_gnn: _useGnn } };
  }

  async function _runPipeline() {
    try {
      const { url, body } = _pipelineRequest();
      const res = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();

        let event = null, dataStr = null;
        lines.forEach(line => {
          if (line.startsWith('event: '))      event   = line.slice(7).trim();
          else if (line.startsWith('data: '))  dataStr = line.slice(6).trim();
          else if (line === '' && event && dataStr) {
            try {
              const payload = JSON.parse(dataStr);
              if (event === 'done' && payload.data) {
                _data  = payload.data;
                _ready = true;
                _setLoading(false);
                // Refresh narration and unlock NEXT for whatever step we're on
                _updateUI(_step);
              } else if (event === 'error') {
                _setLoading(false);
                _setError(payload.msg || 'Pipeline error');
              }
            } catch (_) {}
            event = null; dataStr = null;
          }
        });
      }
    } catch (err) {
      _setLoading(false);
      _setError(err.message);
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────

  let _topology = 'sim';   // set by app.js via setTopology()

  function init() {
    _buildOverlay();
    // Demo starts automatically when an attack is detected from /system — no manual button
  }

  function setTopology(topo) {
    _topology = topo;
  }

  async function startDemo(attackNode) {
    _cancel++;
    _step       = 0;
    _ready      = false;
    _data       = null;
    _attackNode = attackNode || null;

    document.getElementById('demo-overlay').classList.add('active');
    _setLoading(true);
    _setError('');
    _renderStep(0);   // show infra immediately; pipeline runs in background

    _runPipeline();
  }

  function stopDemo() {
    _cancel++;
    _step  = -1;
    document.getElementById('demo-overlay').classList.remove('active');
  }

  // ── DOM ──────────────────────────────────────────────────────────────────

  function _buildOverlay() {
    const el = document.createElement('div');
    el.id = 'demo-overlay';
    el.innerHTML = `
      <div id="demo-panel">
        <div id="demo-header">
          <div id="demo-step-label">STEP <span id="demo-step-num">1</span> / ${TOTAL_STEPS}</div>
          <div id="demo-dots">${Array.from({length: TOTAL_STEPS}, (_, i) =>
            `<div class="demo-dot" data-step="${i}"></div>`).join('')}</div>
          <label id="demo-gnn-toggle" title="GNN adds graph-topology signal but takes 20-60s">
            <input type="checkbox" id="demo-gnn-check"> GNN
          </label>
          <button id="demo-close" title="Exit demo">✕</button>
        </div>
        <div id="demo-title"></div>
        <div id="demo-narration"></div>
        <div id="demo-error" style="display:none"></div>
        <div id="demo-footer">
          <div id="demo-loading" style="display:none">
            <div class="demo-spinner"></div><span>Running analysis in background…</span>
          </div>
          <div id="demo-nav">
            <button id="demo-prev">← PREV</button>
            <button id="demo-next">NEXT →</button>
          </div>
        </div>
      </div>
    `;
    document.getElementById('app').appendChild(el);

    document.getElementById('demo-close').addEventListener('click', stopDemo);
    document.getElementById('demo-prev').addEventListener('click', () => _gotoStep(_step - 1));
    document.getElementById('demo-next').addEventListener('click', () => _gotoStep(_step + 1));
    document.getElementById('demo-gnn-check').addEventListener('change', e => {
      _useGnn = e.target.checked;
    });
    document.querySelectorAll('.demo-dot').forEach(d => {
      d.addEventListener('click', () => _gotoStep(parseInt(d.dataset.step, 10)));
    });
  }

  function _updateUI(i) {
    document.getElementById('demo-step-num').textContent = i + 1;
    document.getElementById('demo-title').textContent    = STEP_TITLES[i] || '';
    document.getElementById('demo-narration').textContent = _narration(i);

    const prev = document.getElementById('demo-prev');
    const next = document.getElementById('demo-next');
    prev.disabled = (i <= 0);
    // Steps 0 and 1 don't need analysis data — only block NEXT from step 2 onwards
    next.disabled = (i >= TOTAL_STEPS - 1) || (!_ready && i >= 2);

    document.querySelectorAll('.demo-dot').forEach((d, idx) => {
      d.classList.toggle('active', idx === i);
      d.classList.toggle('done',   idx < i);
    });
  }

  function _setLoading(on) {
    const el = document.getElementById('demo-loading');
    if (el) el.style.display = on ? 'flex' : 'none';
  }

  function _setError(msg) {
    const el = document.getElementById('demo-error');
    if (!el) return;
    el.style.display = msg ? 'block' : 'none';
    el.textContent   = msg ? `Error: ${msg}` : '';
  }

  /** True while the demo overlay is active (steps 0-5). Used by app.js to
   *  suppress mock-cloud ping pulses and guards_deployed edge-hiding so they
   *  don't interfere with the demo's own animated graph transitions. */
  function isActive() { return _step >= 0; }

  return { init, startDemo, stopDemo, setTopology, isActive };
})();
