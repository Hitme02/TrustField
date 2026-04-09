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
  let _data    = null;   // full pipeline result (nodes, edges, metadata)
  let _step    = -1;     // current step index  (-1 = not active)
  let _cancel  = 0;      // increment to abort in-flight animations
  let _ready   = false;  // pipeline result received

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
      `Watch as the breach propagates through the trust graph.`,
      // Step 2: PATHS
      `${pathSteps} successful trust hops traced across ${maxDepth + 1} depth levels.\n` +
      `Each lit edge is an exploitable delegation — assume-role, deploy-to, secret-read.\n` +
      `${timeline.length - pathSteps} edges were blocked by weight conditions or token limits.\n\n` +
      `The attacker can reach ${vbrSize} nodes from "${seedId}".`,
      // Step 3: ANALYSIS
      `6 propagation models ran in parallel: BFS traversal, SIR epidemic, spectral cascade,\n` +
      `percolation, control system, and GNN.\n\n` +
      `Predicted Blast Radius (PBR): ${pbrSize} nodes flagged at risk.\n` +
      `Verified Blast Radius (VBR): ${vbrSize} confirmed reachable via formal IAM traversal.\n` +
      `Exploitability Gap: ${egd}  (${gapClass})`,
      // Step 4: CONTAINMENT
      `The cyber-physical guard system is isolating the attack path.\n` +
      `${blockedCnt} trust edges are being revoked.\n` +
      `Adaptive feedback loop escalated strictness to ${strictness}.\n\n` +
      `Watch edges go dark as the attack path closes down.`,
      // Step 5: SECURED
      `Containment complete.\n\n` +
      `${contained.length} nodes isolated  ·  ${rate}% containment success rate\n` +
      `The compromised path is broken. Nodes remain monitored until cleared\n` +
      `by your security team.`,
    ];

    return lines[i] || '';
  }

  // ── Graph state helpers ──────────────────────────────────────────────────

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

  // Step 0 — all nodes safe
  function _applyInfraStep() {
    if (!_data) return;
    Graph3D.loadGraph(_safeSnapshot());
  }

  // Step 1 — seed nodes turn red + pulse
  function _applyBreachStep(tok) {
    if (!_data) return;
    Graph3D.loadGraph(_safeSnapshot());
    const seeds = _data.metadata?.seed_nodes || [];
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
    Graph3D.loadGraph(_safeSnapshot());
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
    Graph3D.loadGraph(snap);
  }

  // Step 4 — animate guard deployment edge-by-edge, then contained nodes turn green
  function _applyContainmentStep(tok) {
    if (!_data) return;
    _applyAnalysisStep();  // start from full-risk state

    const blocks  = _data.metadata?.blocked_transitions || [];
    const contained = _data.metadata?.contained_nodes || [];
    const delay   = Math.max(120, Math.min(250, 1400 / Math.max(1, blocks.length)));

    // Block edges one by one
    blocks.forEach((edge, i) => {
      setTimeout(() => {
        if (_cancel !== tok) return;
        const [from, to] = Array.isArray(edge) ? edge : [edge, null];
        if (from && to) Graph3D.setEdgeColor(from, to, 0x111122, 0.95);
      }, 300 + i * delay);
    });

    // After all edges blocked: turn contained nodes green
    const greenAt = 300 + blocks.length * delay + 500;
    contained.forEach((id, i) => {
      setTimeout(() => {
        if (_cancel !== tok) return;
        Graph3D.setNodeState(id, 'contained');
        Graph3D.pulseNode(id);
      }, greenAt + i * 120);
    });
  }

  // Step 5 — load full final state
  function _applySecuredStep() {
    if (!_data) return;
    Graph3D.loadGraph(_data);
  }

  // ── Step rendering ───────────────────────────────────────────────────────

  function _renderStep(i) {
    _step = i;
    _updateUI(i);

    const tok = _cancel;
    switch (i) {
      case 0: _applyInfraStep();         break;
      case 1: _applyBreachStep(tok);     break;
      case 2: _applyPathsStep(tok);      break;
      case 3: _applyAnalysisStep();      break;
      case 4: _applyContainmentStep(tok);break;
      case 5: _applySecuredStep();       break;
    }
  }

  function _gotoStep(i) {
    if (i < 0 || i >= TOTAL_STEPS) return;
    if (i > 0 && !_ready) return;   // cannot advance until pipeline finishes
    _cancel++;
    _renderStep(i);
  }

  // ── Pipeline run ─────────────────────────────────────────────────────────

  async function _runPipeline() {
    try {
      const res = await fetch('/api/sim/run', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({}),
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
                // Refresh current step narration now that data is available
                if (_step === 0) _updateUI(0);
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

  function init() {
    _buildOverlay();
    const btn = document.getElementById('demo-btn');
    if (btn) btn.addEventListener('click', startDemo);
  }

  async function startDemo() {
    // Reset state
    _cancel++;
    _step   = 0;
    _ready  = false;
    _data   = null;

    document.getElementById('demo-overlay').classList.add('active');
    _setLoading(true);
    _setError('');
    _updateUI(0);

    // Fetch current preview to show infra immediately
    try {
      const res  = await fetch('/api/graph/sim');
      const prev = await res.json();
      // Reset all to safe for the infra step
      (prev.nodes || []).forEach(n => { n.state = 'safe'; n.risk = 0; });
      prev.metadata = { traversal_timeline: [], guard_events: [],
                        blocked_transitions: [], seed_nodes: [] };
      Graph3D.loadGraph(prev);
    } catch (_) {}

    // Run pipeline in background
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
    next.disabled = (i >= TOTAL_STEPS - 1) || (!_ready && i >= 0);

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

  return { init, startDemo, stopDemo };
})();
