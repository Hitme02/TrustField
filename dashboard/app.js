/* app.js — State management, topology switching, API communication */

const App = (() => {

  const TOPOLOGIES  = ['hub', 'chain', 'dense_cluster', 'mixed'];
  const TAB_LABELS  = { hub: 'HUB', chain: 'CHAIN', dense_cluster: 'DENSE', mixed: 'MIXED' };
  const API_BASE    = '';   // same origin; server.py handles routing

  let _currentTopo = 'hub';
  let _graphData   = null;
  let _running     = false;

  // ── Bootstrap ─────────────────────────────────────────────────────────
  function init() {
    _buildTabs();
    _buildRunButton();
    _buildNodeCount();
    _startClock();
    Terminal.initToggle();

    const canvas = document.getElementById('graph-canvas');
    Graph3D.init(canvas);
    window._graph3d = Graph3D;

    _loadTopology('hub');
  }

  // ── Tabs ───────────────────────────────────────────────────────────────
  function _buildTabs() {
    const container = document.getElementById('topo-tabs');
    TOPOLOGIES.forEach(topo => {
      const btn = document.createElement('button');
      btn.className = 'topo-tab' + (topo === 'hub' ? ' active' : '');
      btn.textContent = TAB_LABELS[topo] || topo.toUpperCase();
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
      const n = parseInt(document.getElementById('node-count')?.value || '50', 10);
      _runPipeline(_currentTopo, n);
    });
  }

  function _buildNodeCount() {
    // Dynamically inject node-count input next to the run button if not in HTML
    const right = document.getElementById('topbar-right');
    if (!right || document.getElementById('node-count')) return;

    const wrap = document.createElement('div');
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
    if (topo === _currentTopo && _graphData) return;
    _currentTopo = topo;
    _setActiveTab(topo);

    const overlay = document.getElementById('graph-overlay');
    overlay.classList.add('fading');
    setTimeout(() => {
      _loadTopology(topo);
      setTimeout(() => overlay.classList.remove('fading'), 80);
    }, 300);
  }

  // ── Fetch graph data from API ─────────────────────────────────────────
  async function _loadTopology(topo) {
    _currentTopo = topo;
    _setActiveTab(topo);
    _setStatus('loading', `Loading ${topo}…`);

    try {
      const res = await fetch(`${API_BASE}/api/graph/${topo}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      _onDataLoaded(data);
      _setStatus('idle');
    } catch (e) {
      _setStatus('error', `Failed: ${e.message}`);
      console.error('Load error:', e);
    }
  }

  // ── Live pipeline run via SSE ──────────────────────────────────────────
  function _runPipeline(topo, numNodes) {
    if (_running) return;
    _running = true;
    _setRunBtn(true);
    _setStatus('running', 'Starting pipeline…');

    // Clear terminal
    const log = document.getElementById('terminal-log');
    if (log) log.innerHTML = '';

    const es = new EventSource(`/api/run/${topo}?_t=${Date.now()}`);
    // We use fetch+POST for the body, but SSE needs GET or POST via EventSource workaround.
    // Use fetch for POST then parse the streaming response manually.
    es.close();

    _runViaFetch(topo, numNodes);
  }

  async function _runViaFetch(topo, numNodes) {
    const log = document.getElementById('terminal-log');

    function _appendLog(text, cls = '') {
      if (!log) return;
      const line = document.createElement('div');
      line.className = 'log-line';
      line.innerHTML = `<span class="log-ts">[pipeline]</span> <span class="${cls}">${text}</span>`;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }

    try {
      const res = await fetch(`${API_BASE}/api/run/${topo}`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ num_nodes: numNodes, seed: 42 }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   buf     = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        // Parse SSE lines
        const lines = buf.split('\n');
        buf = lines.pop();   // keep incomplete last line

        let event = null, dataStr = null;
        lines.forEach(line => {
          if (line.startsWith('event: ')) {
            event = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            dataStr = line.slice(6).trim();
          } else if (line === '' && event && dataStr) {
            try {
              const payload = JSON.parse(dataStr);
              _handleSSEEvent(event, payload, _appendLog);
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

  function _handleSSEEvent(event, payload, appendLog) {
    if (event === 'progress') {
      appendLog(payload.msg || payload.step, 'log-sensor');
      _setStatus('running', payload.msg || '');
    } else if (event === 'done') {
      appendLog(`Pipeline complete — ${payload.topology}`, 'log-allowed');
      _setStatus('idle');
      // Reload data for this topology from the fresh payload
      if (payload.data) {
        // Fade, update, fade back
        const overlay = document.getElementById('graph-overlay');
        overlay.classList.add('fading');
        setTimeout(() => {
          _onDataLoaded(payload.data);
          setTimeout(() => overlay.classList.remove('fading'), 80);
        }, 200);
      } else {
        _loadTopology(_currentTopo);
      }
    } else if (event === 'error') {
      appendLog(`ERROR: ${payload.msg}`, 'log-blocked');
      _setStatus('error', payload.msg);
    }
  }

  // ── Data display ────────────────────────────────────────────────────────
  function _onDataLoaded(data) {
    _graphData = data;

    // Compute state counts
    const counts = { compromised: 0, predicted_only: 0, critical_miss: 0, contained: 0, safe: 0 };
    data.nodes.forEach(n => { if (counts[n.state] !== undefined) counts[n.state]++; });
    const total = data.nodes.length || 1;

    // Node-states panel
    const states = [
      { key: 'compromised',    label: 'Compromised',    color: '#ff3b30' },
      { key: 'predicted_only', label: 'Predicted Only', color: '#ff9500' },
      { key: 'critical_miss',  label: 'Critical Miss',  color: '#ff6b35' },
      { key: 'contained',      label: 'Contained',      color: '#34c759' },
      { key: 'safe',           label: 'Safe',           color: '#444466' },
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
    const icons = { idle: '●', loading: '◌', running: '◉', error: '✕' };
    const colors = { idle: 'var(--green)', loading: 'var(--cyan)', running: 'var(--amber)', error: 'var(--red)' };
    el.textContent = `${icons[state] || '●'} ${msg || state.toUpperCase()}`;
    el.style.color = colors[state] || 'var(--dim)';
  }

  function _setRunBtn(running) {
    const btn = document.getElementById('run-btn');
    if (!btn) return;
    btn.textContent    = running ? 'RUNNING…' : 'RUN';
    btn.disabled       = running;
    btn.style.opacity  = running ? '0.5' : '1';
    btn.style.cursor   = running ? 'not-allowed' : 'pointer';
  }

  // ── Clock ──────────────────────────────────────────────────────────────
  function _startClock() {
    const el = document.getElementById('clock');
    if (!el) return;
    const tick = () => { el.textContent = new Date().toTimeString().slice(0, 5); };
    tick();
    setInterval(tick, 10000);
  }

  return { init };
})();

window.addEventListener('DOMContentLoaded', () => App.init());
