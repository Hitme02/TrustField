/* admin.js — Infrastructure editor panel for the SIM topology.
 *
 * Provides a slide-in drawer where operators can:
 *   - View and add/remove nodes (users, roles, services, secrets, etc.)
 *   - View and add/remove trust relationships (edges / policies)
 *   - Trigger a full pipeline analysis run
 *   - Reset to the default demo infrastructure
 *
 * All mutations POST/DELETE to /api/sim/* and automatically refresh
 * the SIM graph view when done. A "policy changed" banner prompts
 * the user to re-analyze after structural edits.
 */

const Admin = (() => {

  const NODE_TYPES = ['USER', 'SERVICE', 'ROLE', 'WORKLOAD', 'SECRET', 'DEPLOYMENT'];
  const EDGE_TYPES = ['ASSUME_ROLE', 'TOKEN_MINT', 'SECRET_READ', 'DEPLOY_TO', 'AUTHENTICATE_AS'];

  const TYPE_COLORS = {
    ROLE:       '#00d4ff',
    SERVICE:    '#aa88ff',
    SECRET:     '#ff3b30',
    USER:       '#34c759',
    WORKLOAD:   '#ff9500',
    DEPLOYMENT: '#8888aa',
  };

  let _state   = null;   // last known sim state
  let _open    = false;
  let _tab     = 'nodes'; // 'nodes' | 'edges'
  let _onAnalyze = null;  // callback injected by app.js

  // ── Public API ─────────────────────────────────────────────────────────

  function init(onAnalyzeCallback) {
    _onAnalyze = onAnalyzeCallback;
    _buildPanel();
    _bindToggleBtn();
  }

  function open() {
    if (_open) return;
    _open = true;
    document.getElementById('admin-panel').classList.add('open');
    document.getElementById('admin-toggle-btn').classList.add('active');
    _refresh();
  }

  function close() {
    if (!_open) return;
    _open = false;
    document.getElementById('admin-panel').classList.remove('open');
    document.getElementById('admin-toggle-btn').classList.remove('active');
  }

  function toggle() {
    _open ? close() : open();
  }

  // Called by app.js after a breach or analysis completes to refresh state
  function refresh() {
    if (_open) _refresh();
  }

  // ── Panel DOM ──────────────────────────────────────────────────────────

  function _buildPanel() {
    const panel = document.createElement('div');
    panel.id = 'admin-panel';
    panel.innerHTML = `
      <div id="admin-header">
        <div id="admin-title">INFRASTRUCTURE EDITOR</div>
        <button id="admin-reset-btn" title="Reset to default demo infra">RESET</button>
        <button id="admin-close-btn">✕</button>
      </div>

      <div id="admin-policy-banner" style="display:none">
        <span id="admin-banner-text">Policy changed — click ANALYZE to update risk scores</span>
        <button id="admin-analyze-btn">ANALYZE</button>
      </div>

      <div id="admin-tabs">
        <button class="admin-tab active" data-tab="nodes">NODES</button>
        <button class="admin-tab" data-tab="edges">POLICIES</button>
      </div>

      <div id="admin-body">

        <!-- NODES tab -->
        <div id="admin-nodes-pane" class="admin-pane active">
          <div id="nodes-table-wrap">
            <div class="admin-loading">Loading…</div>
          </div>
          <div class="admin-form-head">ADD NODE</div>
          <div class="admin-form" id="add-node-form">
            <input  id="n-id"   type="text"   placeholder="node-id (unique)" />
            <select id="n-type">
              ${NODE_TYPES.map(t => `<option value="${t}">${t}</option>`).join('')}
            </select>
            <input  id="n-name" type="text"   placeholder="display name (optional)" />
            <div class="slider-row">
              <label>Privilege</label>
              <input id="n-priv" type="range" min="0" max="1" step="0.05" value="0.5" />
              <span  id="n-priv-val">0.50</span>
            </div>
            <div class="slider-row">
              <label>Sensitivity</label>
              <input id="n-sens" type="range" min="0" max="1" step="0.05" value="0.5" />
              <span  id="n-sens-val">0.50</span>
            </div>
            <button id="add-node-btn" class="form-submit-btn">ADD NODE</button>
            <div id="add-node-err" class="form-error"></div>
          </div>
        </div>

        <!-- EDGES tab -->
        <div id="admin-edges-pane" class="admin-pane">
          <div id="edges-table-wrap">
            <div class="admin-loading">Loading…</div>
          </div>
          <div class="admin-form-head">ADD POLICY / TRUST RELATIONSHIP</div>
          <div class="admin-form" id="add-edge-form">
            <select id="e-source"><option value="">— source node —</option></select>
            <select id="e-type">
              ${EDGE_TYPES.map(t => `<option value="${t}">${t.replace(/_/g,' ')}</option>`).join('')}
            </select>
            <select id="e-target"><option value="">— target node —</option></select>
            <div class="slider-row">
              <label>Trust weight</label>
              <input id="e-weight" type="range" min="0.1" max="1" step="0.05" value="0.7" />
              <span  id="e-weight-val">0.70</span>
            </div>
            <button id="add-edge-btn" class="form-submit-btn">ADD POLICY</button>
            <div id="add-edge-err" class="form-error"></div>
          </div>
        </div>

      </div>
    `;
    document.getElementById('app').appendChild(panel);

    // Tab switching
    panel.querySelectorAll('.admin-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        _tab = btn.dataset.tab;
        panel.querySelectorAll('.admin-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        panel.querySelectorAll('.admin-pane').forEach(p => p.classList.remove('active'));
        document.getElementById(`admin-${_tab}-pane`).classList.add('active');
      });
    });

    // Close
    document.getElementById('admin-close-btn').addEventListener('click', close);

    // Reset
    document.getElementById('admin-reset-btn').addEventListener('click', _onReset);

    // Analyze
    document.getElementById('admin-analyze-btn').addEventListener('click', () => {
      _hideBanner();
      if (_onAnalyze) _onAnalyze();
    });

    // Slider live readouts
    _bindSlider('n-priv', 'n-priv-val');
    _bindSlider('n-sens', 'n-sens-val');
    _bindSlider('e-weight', 'e-weight-val');

    // Form submissions
    document.getElementById('add-node-btn').addEventListener('click', _onAddNode);
    document.getElementById('add-edge-btn').addEventListener('click', _onAddEdge);
  }

  function _bindToggleBtn() {
    const btn = document.getElementById('admin-toggle-btn');
    if (btn) btn.addEventListener('click', toggle);
  }

  function _bindSlider(sliderId, valId) {
    const slider = document.getElementById(sliderId);
    const val    = document.getElementById(valId);
    if (!slider || !val) return;
    slider.addEventListener('input', () => {
      val.textContent = parseFloat(slider.value).toFixed(2);
    });
  }

  // ── Refresh state from server ──────────────────────────────────────────

  async function _refresh() {
    try {
      const res = await fetch('/api/sim/state');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      _state = await res.json();
      _renderNodes();
      _renderEdges();
      _populateNodeSelects();
    } catch (e) {
      console.error('Admin: failed to load state', e);
    }
  }

  // ── Nodes table ────────────────────────────────────────────────────────

  function _renderNodes() {
    const wrap = document.getElementById('nodes-table-wrap');
    if (!wrap || !_state) return;

    if (_state.nodes.length === 0) {
      wrap.innerHTML = '<div class="admin-empty">No nodes yet. Add one below.</div>';
      return;
    }

    const rows = _state.nodes.map(n => {
      const col = TYPE_COLORS[n.node_type] || '#8888aa';
      return `
        <div class="admin-row" data-id="${n.node_id}">
          <div class="ar-type" style="color:${col}">${n.node_type}</div>
          <div class="ar-id">${n.node_id}</div>
          <div class="ar-name dim">${n.name}</div>
          <div class="ar-bars">
            <div class="mini-bar" title="Privilege ${n.privilege_level}">
              <div class="mini-fill" style="width:${n.privilege_level*100}%;background:#00d4ff"></div>
            </div>
            <div class="mini-bar" title="Sensitivity ${n.sensitivity}">
              <div class="mini-fill" style="width:${n.sensitivity*100}%;background:#ff3b30"></div>
            </div>
          </div>
          <button class="del-btn" data-id="${n.node_id}" title="Remove node">✕</button>
        </div>`;
    }).join('');

    wrap.innerHTML = `<div class="admin-table">${rows}</div>`;

    wrap.querySelectorAll('.del-btn').forEach(btn => {
      btn.addEventListener('click', () => _onDeleteNode(btn.dataset.id));
    });
  }

  // ── Edges table ────────────────────────────────────────────────────────

  function _renderEdges() {
    const wrap = document.getElementById('edges-table-wrap');
    if (!wrap || !_state) return;

    if (_state.edges.length === 0) {
      wrap.innerHTML = '<div class="admin-empty">No trust policies yet. Add one below.</div>';
      return;
    }

    const rows = _state.edges.map(e => `
      <div class="admin-row">
        <div class="ar-id">${e.source}</div>
        <div class="ar-type dim" style="font-size:10px">${e.edge_type.replace(/_/g, ' ')}</div>
        <div class="ar-id">${e.target}</div>
        <div class="ar-weight dim">${e.weight.toFixed(2)}</div>
        <button class="del-btn"
          data-source="${e.source}" data-target="${e.target}"
          title="Remove policy">✕</button>
      </div>`).join('');

    wrap.innerHTML = `<div class="admin-table">${rows}</div>`;

    wrap.querySelectorAll('.del-btn').forEach(btn => {
      btn.addEventListener('click', () =>
        _onDeleteEdge(btn.dataset.source, btn.dataset.target));
    });
  }

  // ── Populate source/target selects ────────────────────────────────────

  function _populateNodeSelects() {
    if (!_state) return;
    const options = ['<option value="">— select node —</option>']
      .concat(_state.nodes.map(n => `<option value="${n.node_id}">${n.node_id} (${n.node_type})</option>`))
      .join('');

    const src = document.getElementById('e-source');
    const tgt = document.getElementById('e-target');
    if (src) src.innerHTML = options;
    if (tgt) tgt.innerHTML = options;
  }

  // ── Add node ───────────────────────────────────────────────────────────

  async function _onAddNode() {
    const nodeId    = document.getElementById('n-id').value.trim();
    const nodeType  = document.getElementById('n-type').value;
    const name      = document.getElementById('n-name').value.trim() || nodeId;
    const privilege = parseFloat(document.getElementById('n-priv').value);
    const sensitivity = parseFloat(document.getElementById('n-sens').value);
    const errEl     = document.getElementById('add-node-err');

    errEl.textContent = '';
    if (!nodeId) { errEl.textContent = 'node-id is required'; return; }

    _setBtnLoading('add-node-btn', true);
    try {
      const res = await fetch('/api/sim/node', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ node_id: nodeId, node_type: nodeType, name, privilege_level: privilege, sensitivity }),
      });
      const data = await res.json();
      if (!res.ok) { errEl.textContent = data.error || 'Error'; return; }

      // Clear form
      document.getElementById('n-id').value   = '';
      document.getElementById('n-name').value = '';
      document.getElementById('n-priv').value = '0.5';
      document.getElementById('n-priv-val').textContent = '0.50';
      document.getElementById('n-sens').value = '0.5';
      document.getElementById('n-sens-val').textContent = '0.50';

      _state = data.state;
      _renderNodes();
      _renderEdges();
      _populateNodeSelects();
      _showBanner();
    } catch (e) {
      errEl.textContent = e.message;
    } finally {
      _setBtnLoading('add-node-btn', false);
    }
  }

  // ── Delete node ────────────────────────────────────────────────────────

  async function _onDeleteNode(nodeId) {
    try {
      const res = await fetch(`/api/sim/node/${encodeURIComponent(nodeId)}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) { console.error(data.error); return; }
      _state = data.state;
      _renderNodes();
      _renderEdges();
      _populateNodeSelects();
      _showBanner();
    } catch (e) {
      console.error('Delete node error:', e);
    }
  }

  // ── Add edge ───────────────────────────────────────────────────────────

  async function _onAddEdge() {
    const source   = document.getElementById('e-source').value;
    const target   = document.getElementById('e-target').value;
    const edgeType = document.getElementById('e-type').value;
    const weight   = parseFloat(document.getElementById('e-weight').value);
    const errEl    = document.getElementById('add-edge-err');

    errEl.textContent = '';
    if (!source || !target) { errEl.textContent = 'Select source and target nodes'; return; }
    if (source === target)   { errEl.textContent = 'Self-loops are not allowed'; return; }

    _setBtnLoading('add-edge-btn', true);
    try {
      const res = await fetch('/api/sim/edge', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ source, target, edge_type: edgeType, weight }),
      });
      const data = await res.json();
      if (!res.ok) { errEl.textContent = data.error || 'Error'; return; }

      // Reset selects
      document.getElementById('e-source').value = '';
      document.getElementById('e-target').value = '';
      document.getElementById('e-weight').value = '0.7';
      document.getElementById('e-weight-val').textContent = '0.70';

      _state = data.state;
      _renderEdges();
      _showBanner();
    } catch (e) {
      errEl.textContent = e.message;
    } finally {
      _setBtnLoading('add-edge-btn', false);
    }
  }

  // ── Delete edge ────────────────────────────────────────────────────────

  async function _onDeleteEdge(source, target) {
    try {
      const res = await fetch('/api/sim/edge', {
        method:  'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ source, target }),
      });
      const data = await res.json();
      if (!res.ok) { console.error(data.error); return; }
      _state = data.state;
      _renderEdges();
      _showBanner();
    } catch (e) {
      console.error('Delete edge error:', e);
    }
  }

  // ── Reset ──────────────────────────────────────────────────────────────

  async function _onReset() {
    if (!confirm('Reset to default demo infrastructure? This will clear all custom nodes and edges.')) return;
    try {
      const res  = await fetch('/api/sim/reset', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) return;
      _state = data.state;
      _renderNodes();
      _renderEdges();
      _populateNodeSelects();
      _showBanner();
    } catch (e) {
      console.error('Reset error:', e);
    }
  }

  // ── Banner ─────────────────────────────────────────────────────────────

  function _showBanner() {
    const el = document.getElementById('admin-policy-banner');
    if (el) el.style.display = 'flex';
  }

  function _hideBanner() {
    const el = document.getElementById('admin-policy-banner');
    if (el) el.style.display = 'none';
  }

  // ── Helpers ────────────────────────────────────────────────────────────

  function _setBtnLoading(id, loading) {
    const btn = document.getElementById(id);
    if (!btn) return;
    btn.disabled      = loading;
    btn.style.opacity = loading ? '0.5' : '1';
  }

  return { init, open, close, toggle, refresh };
})();
