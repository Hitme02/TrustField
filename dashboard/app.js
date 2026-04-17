/* app.js — State management, topology switching, API communication */

const App = (() => {

  const TAB_LABELS = { org: 'ORG', register: 'REGISTER NEW ORG' };
  const API_BASE = '';

  let _currentTopo = 'org';
  let _graphData   = null;
  let _running     = false;
  let _mockFeed    = null;   // EventSource for live mock-cloud pings
  let _mockActive  = false;  // true only after START SERVICES is clicked on /system

  // ── Bootstrap ─────────────────────────────────────────────────────────
  function init() {
    _buildTabs();
    _startClock();
    Terminal.initToggle();

    const canvas = document.getElementById('graph-canvas');
    Graph3D.init(canvas);
    window._graph3d = Graph3D;

    // Wire up admin panel
    Admin.init(_runSimPipeline);

    // Wire breach callback into inspector
    Inspector.setBreachCallback(_runBreach);

    // Wire demo controller
    DemoController.init();

    // Wire ORG upload panel
    OrgUpload.init(() => {
      _currentTopo = 'org';
      _setActiveTab('org');
      _updateSimMode(false, true);
      if (_mockActive) {
        // Services already running — load the freshly registered org graph
        _loadTopology('org');
      } else {
        // Services not started yet — stay on the registration screen
        _setStatus('idle', 'Org registered · go to /system → START SERVICES to activate the graph');
      }
    });

    Inspector.setTopology('org');
    DemoController.setTopology('org');
    _updateSimMode(false, true);

    // Start blank — graph only appears once services are live on /system
    OrgUpload.showUploadPanel();
    _startMockFeed();
  }

  // ── Mock-cloud live feed ──────────────────────────────────────────────
  function _startMockFeed() {
    if (_mockFeed) return;

    // If services are already running (e.g. page reloaded after START SERVICES),
    // activate immediately instead of waiting for the missed services_started event.
    fetch('/api/mock/status').then(r => r.json()).then(s => {
      if (s.running && !_mockActive) {
        _mockActive = true;
        _loadTopology('org');
      }
    }).catch(() => {});

    _mockFeed = new EventSource('/api/mock/events');

    // START SERVICES clicked on /system — load the graph and begin showing traffic
    _mockFeed.addEventListener('services_started', () => {
      _mockActive = true;
      _loadTopology('org');
    });

    // Only pulse the graph when services are actually running
    _mockFeed.addEventListener('ping', e => {
      if (!_mockActive) return;
      const d = JSON.parse(e.data);
      if (d.status === 'blocked') {
        // Blocked by guard — edge goes silent (no pulse = containment holding)
        return;
      } else if (d.attack) {
        Graph3D.pulseEdge(d.from, d.to, 0xff9500, 500);
      } else {
        Graph3D.pulseEdge(d.from, d.to, 0x00d4ff, 350);
      }
    });

    _mockFeed.addEventListener('attack_started', async e => {
      _mockActive = true;
      const d = JSON.parse(e.data);
      Graph3D.setNodeState(d.node, 'compromised');
      Graph3D.pulseNode(d.node);
      await fetch('/api/org/seed', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ node_id: d.node }),
      }).catch(() => {});
      DemoController.startDemo(d.node);
    });

    _mockFeed.addEventListener('guards_deployed', e => {
      const d = JSON.parse(e.data);
      (d.blocked || []).forEach(([from, to]) => {
        Graph3D.setEdgeColor(from, to, 0x1e3b2e, 0.35);
      });
    });

    // Reset: services stopped — go back to blank registration screen
    _mockFeed.addEventListener('reset', () => {
      _mockActive = false;
      DemoController.stopDemo();
      Graph3D.loadGraph({ nodes: [], edges: [], metadata: {} });
      OrgUpload.showUploadPanel();
    });

    _mockFeed.onerror = () => {};
  }

  // ── Tabs ───────────────────────────────────────────────────────────────
  function _buildTabs() {
    const container = document.getElementById('topo-tabs');
    container.innerHTML = '';
    ['org', 'register'].forEach(topo => {
      const btn = document.createElement('button');
      btn.className   = 'topo-tab' + (topo === _currentTopo ? ' active' : '');
      btn.textContent = TAB_LABELS[topo];
      btn.dataset.topo = topo;
      btn.addEventListener('click', () => _switchTopology(topo));
      container.appendChild(btn);
    });
  }

  function _setActiveTab(topo) {
    document.querySelectorAll('.topo-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.topo === topo);
    });
  }

  // ── Run button + node count input ────────────────────────────────────
  function _buildRunButton() {
    const btn = document.getElementById('run-btn');
    if (!btn) return;
    btn.addEventListener('click', () => {
      if (_running) return;
      if (_currentTopo === 'sim') {
        _runSimPipeline();
      } else {
        const n = parseInt(document.getElementById('node-count')?.value || '50', 10);
        _runPipeline(_currentTopo, n);
      }
    });
  }

  function _buildNodeCount() {
    const right = document.getElementById('topbar-right');
    if (!right || document.getElementById('node-count')) return;

    const wrap = document.createElement('div');
    wrap.id = 'node-count-wrap';
    wrap.style.cssText = 'display:flex;align-items:center;gap:6px;margin-right:8px';

    const label = document.createElement('label');
    label.textContent = 'N=';
    label.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--dimmer)';

    const input = document.createElement('input');
    input.id    = 'node-count';
    input.type  = 'number';
    input.value = '50';
    input.min   = '10';
    input.max   = '200';
    input.step  = '10';
    input.style.cssText = [
      'width:52px', 'background:var(--card)', 'border:1px solid var(--border)',
      'color:var(--text)', 'font-family:var(--mono)', 'font-size:12px',
      'padding:3px 6px', 'outline:none', 'text-align:center',
    ].join(';');

    wrap.appendChild(label);
    wrap.appendChild(input);
    right.insertBefore(wrap, right.firstChild);
  }

  // ── Topology switching ─────────────────────────────────────────────────
  function _switchTopology(topo) {
    _currentTopo = topo;
    _setActiveTab(topo);

    if (topo === 'register') {
      _updateSimMode(false, false);
      OrgUpload.showUploadPanel();
      return;
    }

    // ORG tab — only show graph if services are live; otherwise keep registration screen
    Inspector.setTopology('org');
    DemoController.setTopology('org');
    _updateSimMode(false, true);

    if (!_mockActive) {
      OrgUpload.showUploadPanel();
      return;
    }

    const overlay = document.getElementById('graph-overlay');
    overlay.classList.add('fading');
    setTimeout(() => {
      _loadTopology('org');
      setTimeout(() => overlay.classList.remove('fading'), 80);
    }, 300);
  }

  function _updateSimMode(isSim, isOrg) {
    const infraBtn    = document.getElementById('admin-toggle-btn');
    const orgClearBtn = document.getElementById('org-clear-btn');
    if (infraBtn)    infraBtn.classList.remove('visible');
    if (orgClearBtn) orgClearBtn.classList.toggle('visible', !!isOrg);
    Admin.close();
    if (!isOrg) OrgUpload.hideUploadPanel();
  }

  // ── Fetch graph data from API ─────────────────────────────────────────
  async function _loadTopology(topo) {
    _currentTopo = topo;
    _setActiveTab(topo);
    Inspector.setTopology(topo);
    _setStatus('loading', `Loading ${topo}…`);

    try {
      const res = await fetch(`${API_BASE}/api/graph/${topo}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        // ORG tab: no data yet → show upload panel instead of error
        if (topo === 'org' && err.needs_upload) {
          OrgUpload.showUploadPanel();
          _setStatus('idle');
          return;
        }
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      OrgUpload.hideUploadPanel();
      const data = await res.json();
      // Always render clean — analysis state is driven by demo steps / mock-cloud events only
      _onDataLoaded(_cleanForDisplay(data));
      _setStatus('idle');
    } catch (e) {
      _setStatus('error', `Failed: ${e.message}`);
      console.error('Load error:', e);
    }
  }

  // ── Run pipeline (synthetic topologies) ───────────────────────────────
  function _runPipeline(topo, numNodes) {
    if (_running) return;
    _running = true;
    _setRunBtn(true);
    _setStatus('running', 'Starting pipeline…');

    const log = document.getElementById('terminal-log');
    if (log) log.innerHTML = '';

    _runViaFetch(`${API_BASE}/api/run/${topo}`, { num_nodes: numNodes, seed: 42 });
  }

  // ── Run pipeline (SIM / ORG topology) ────────────────────────────────
  function _runSimPipeline() {
    if (_running) return;
    _running = true;
    _setRunBtn(true);
    const endpoint = _currentTopo === 'org' ? '/api/org/run' : '/api/sim/run';
    _setStatus('running', `Running ${_currentTopo} pipeline…`);

    const log = document.getElementById('terminal-log');
    if (log) log.innerHTML = '';

    _runViaFetch(`${API_BASE}${endpoint}`, {});
  }

  // ── Breach simulation ─────────────────────────────────────────────────
  function _runBreach(nodeId) {
    if (_running) return;
    _running = true;
    _setRunBtn(true);
    _setStatus('running', `⚡ Breach from '${nodeId}'…`);

    const log = document.getElementById('terminal-log');
    if (log) log.innerHTML = '';

    _appendLog(`⚡ Simulating breach from node: ${nodeId}`, 'log-blocked');
    const endpoint = _currentTopo === 'org'
      ? `/api/org/breach/${encodeURIComponent(nodeId)}`
      : `/api/sim/breach/${encodeURIComponent(nodeId)}`;
    _runViaFetch(`${API_BASE}${endpoint}`, {});
  }

  // ── Shared fetch+SSE runner ────────────────────────────────────────────
  function _appendLog(text, cls = '') {
    const log = document.getElementById('terminal-log');
    if (!log) return;
    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = `<span class="log-ts">[pipeline]</span> <span class="${cls}">${text}</span>`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  async function _runViaFetch(url, body) {
    try {
      const res = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   buf     = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        const lines = buf.split('\n');
        buf = lines.pop();

        let event = null, dataStr = null;
        lines.forEach(line => {
          if (line.startsWith('event: ')) {
            event = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            dataStr = line.slice(6).trim();
          } else if (line === '' && event && dataStr) {
            try {
              const payload = JSON.parse(dataStr);
              _handleSSEEvent(event, payload);
            } catch {}
            event = null; dataStr = null;
          }
        });
      }
    } catch (e) {
      _appendLog(`Error: ${e.message}`, 'log-blocked');
      _setStatus('error', e.message);
    } finally {
      _running = false;
      _setRunBtn(false);
    }
  }

  function _handleSSEEvent(event, payload) {
    if (event === 'progress') {
      _appendLog(payload.msg || payload.step, 'log-sensor');
      _setStatus('running', payload.msg || '');
    } else if (event === 'done') {
      _appendLog(`Pipeline complete — ${payload.topology}`, 'log-allowed');
      _setStatus('idle');
      // Push guard state to mock cloud if it's running
      const bt = payload.data?.metadata?.blocked_transitions;
      if (bt?.length) {
        fetch('/api/mock/guards', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ blocked_transitions: bt }),
        }).catch(() => {});
      }
      if (payload.data) {
        const overlay = document.getElementById('graph-overlay');
        overlay.classList.add('fading');
        setTimeout(() => {
          _onDataLoaded(payload.data);
          setTimeout(() => overlay.classList.remove('fading'), 80);
        }, 200);
      } else {
        _loadTopology(_currentTopo);
      }
      // Refresh admin panel state after analysis (sim only)
      if (_currentTopo === 'sim') Admin.refresh();
    } else if (event === 'error') {
      _appendLog(`ERROR: ${payload.msg}`, 'log-blocked');
      _setStatus('error', payload.msg);
    }
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  /** Strip all analysis overlays so the graph renders as plain safe infrastructure. */
  function _cleanForDisplay(data) {
    const d = JSON.parse(JSON.stringify(data));
    d.nodes.forEach(n => { n.state = 'safe'; n.risk = 0; n.exploitability = 0; });
    d.metadata = Object.assign(d.metadata || {}, {
      traversal_timeline: [], guard_events: [], blocked_transitions: [],
      seed_nodes: [], pbr_nodes: [], vbr_nodes: [], contained_nodes: [],
      pbr_size: 0, vbr_size: 0, exploitability_gap_score: 0,
    });
    return d;
  }

  // ── Data display ────────────────────────────────────────────────────────
  function _onDataLoaded(data) {
    _graphData = data;

    const counts = { compromised: 0, predicted_only: 0, critical_miss: 0, contained: 0, safe: 0 };
    data.nodes.forEach(n => { if (counts[n.state] !== undefined) counts[n.state]++; });
    const total = data.nodes.length || 1;

    const states = [
      { key: 'compromised',    label: 'Compromised',    color: '#ff3b30' },
      { key: 'predicted_only', label: 'Predicted Only', color: '#ff9500' },
      { key: 'critical_miss',  label: 'Critical Miss',  color: '#ff6b35' },
      { key: 'contained',      label: 'Contained',      color: '#34c759' },
      { key: 'safe',           label: 'Safe',           color: '#2e5a88' },
    ];
    const listEl = document.getElementById('state-list');
    if (listEl) {
      listEl.innerHTML = states.map(s => {
        const cnt = counts[s.key] || 0;
        const pct = (cnt / total * 100).toFixed(1);
        return `<div class="state-row">
          <div class="state-dot" style="background:${s.color}"></div>
          <div class="state-bar-wrap">
            <div class="state-bar" style="width:${pct}%;background:${s.color}"></div>
          </div>
          <div class="state-count">${cnt}</div>
          <div class="state-name dim">${s.label}</div>
        </div>`;
      }).join('');
    }

    MetricsPanel.update(data.metadata || {});
    Graph3D.loadGraph(data);
    Timeline.render(data, id => Inspector.show(id, data));
    Terminal.render(data);
    Inspector.clear();
  }

  // ── Status bar helpers ─────────────────────────────────────────────────
  function _setStatus(state, msg = '') {
    const el = document.getElementById('status-text');
    if (!el) return;
    const icons  = { idle: '●', loading: '◌', running: '◉', error: '✕' };
    const colors = { idle: 'var(--green)', loading: 'var(--cyan)', running: 'var(--amber)', error: 'var(--red)' };
    el.textContent = `${icons[state] || '●'} ${msg || state.toUpperCase()}`;
    el.style.color = colors[state] || 'var(--dim)';
  }

  function _setRunBtn(running) {
    const btn = document.getElementById('run-btn');
    if (!btn) return;
    btn.textContent   = running ? 'RUNNING…' : 'RUN';
    btn.disabled      = running;
    btn.style.opacity = running ? '0.5' : '1';
    btn.style.cursor  = running ? 'not-allowed' : 'pointer';
  }

  // ── Clock ──────────────────────────────────────────────────────────────
  function _startClock() {
    const el = document.getElementById('clock');
    if (!el) return;
    const tick = () => { el.textContent = new Date().toTimeString().slice(0, 5); };
    tick();
    setInterval(tick, 10000);
  }

  // Called by DemoController to keep the sidebar in sync with demo step data
  function updateDisplay(data) {
    if (data) _onDataLoaded(data);
  }

  return { init, updateDisplay };
})();

window.addEventListener('DOMContentLoaded', () => App.init());
