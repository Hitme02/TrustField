/* inspector.js — Node inspector panel */

const Inspector = (() => {

  const STATE_COLORS = {
    compromised:    '#ff3b30',
    predicted_only: '#ff9500',
    critical_miss:  '#ff6b35',
    contained:      '#34c759',
    safe:           '#2e5a88',
  };

  const TYPE_COLORS = {
    ROLE:       '#00d4ff',
    SERVICE:    '#aa88ff',
    SECRET:     '#ff3b30',
    USER:       '#34c759',
    WORKLOAD:   '#ff9500',
    DEPLOYMENT: '#8888aa',
  };

  function _bar(value, color) {
    return `<div class="bar-wrap"><div class="bar-fill" style="width:${(value*100).toFixed(1)}%;background:${color}"></div></div>`;
  }

  function _riskColor(v) {
    if (v < 0.33) return '#34c759';
    if (v < 0.66) return '#ff9500';
    return '#ff3b30';
  }

  // Injected by app.js so inspector can trigger breach without circular dep
  let _onBreach = null;
  let _currentTopology = null;

  function setBreachCallback(fn) { _onBreach = fn; }
  function setTopology(topo)     { _currentTopology = topo; }

  function show(nodeId, graphData) {
    const el = document.getElementById('inspector');
    if (!el) return;

    if (!nodeId || !graphData) {
      _showPlaceholder(el);
      return;
    }

    const node = graphData.nodes.find(n => n.id === nodeId);
    if (!node) { _showPlaceholder(el); return; }

    const meta = graphData.metadata || {};
    const inPBR = (meta.pbr_nodes || []).includes(nodeId);
    const inVBR = (meta.vbr_nodes || []).includes(nodeId);

    // Outgoing / incoming edges
    const outEdges = graphData.edges.filter(e => e.source === nodeId);
    const inEdges  = graphData.edges.filter(e => e.target === nodeId);

    const typeColor  = TYPE_COLORS[node.type]  || '#8888aa';
    const stateColor = STATE_COLORS[node.state] || '#444466';
    const priv    = node.privilege       ?? 0;
    const risk    = node.risk            ?? 0;
    const exploit = node.exploitability  ?? risk;

    let html = `<div id="insp-name">${nodeId}</div>`;

    // Type
    html += `<div class="insp-row">
      <span class="insp-key">Type</span>
      <span class="insp-val" style="color:${typeColor}">${node.type || '—'}</span>
    </div>`;

    // State
    html += `<div class="insp-row">
      <span class="insp-key">State</span>
      <span class="insp-val" style="color:${stateColor}">${(node.state || '').toUpperCase()}</span>
    </div>`;

    // Privilege bar
    html += `<div class="insp-row">
      <span class="insp-key">Privilege</span>
      ${_bar(priv, typeColor)}
      <span class="insp-val mono" style="min-width:34px;text-align:right">${priv.toFixed(2)}</span>
    </div>`;

    // Risk bar
    html += `<div class="insp-row">
      <span class="insp-key">Risk</span>
      ${_bar(risk, _riskColor(risk))}
      <span class="insp-val mono" style="min-width:34px;text-align:right">${risk.toFixed(2)}</span>
    </div>`;

    // Exploit bar
    html += `<div class="insp-row">
      <span class="insp-key">Exploit</span>
      ${_bar(exploit, _riskColor(exploit))}
      <span class="insp-val mono" style="min-width:34px;text-align:right">${exploit.toFixed(2)}</span>
    </div>`;

    // Badges
    const pbr_on  = inPBR ? 'on' : 'off';
    const vbr_on  = inVBR ? 'on' : 'off';
    const comp_on = (node.state === 'compromised' || node.state === 'critical_miss') ? 'on' : 'off';
    html += `<div style="margin-top:8px">
      <span class="badge ${pbr_on}">PBR</span>
      <span class="badge ${vbr_on}">VBR</span>
      <span class="badge ${comp_on}">COMPROMISED</span>
    </div>`;

    // Edges
    if (outEdges.length > 0 || inEdges.length > 0) {
      html += `<div class="insp-section-head">Edges</div>`;
      outEdges.slice(0, 6).forEach(e => {
        html += `<div class="edge-row" data-target="${e.target}">
          <span class="arrow">→</span>
          <span class="e-name">${e.target}</span>
          <span class="e-weight">${(e.weight||0).toFixed(2)}</span>
        </div>`;
      });
      inEdges.slice(0, 4).forEach(e => {
        html += `<div class="edge-row" data-target="${e.source}">
          <span class="arrow" style="color:#8888aa">←</span>
          <span class="e-name">${e.source}</span>
          <span class="e-weight">${(e.weight||0).toFixed(2)}</span>
        </div>`;
      });
    }

    // Breach button — only shown on the SIM topology
    if (_currentTopology === 'sim') {
      const isSeed = (meta.seed_nodes || []).includes(nodeId);
      html += `<button id="breach-btn" data-nodeid="${nodeId}">
        ⚡ SIMULATE BREACH FROM THIS NODE
      </button>`;
      if (isSeed) {
        html += `<div id="breach-seed-indicator">▲ Current breach seed</div>`;
      }
    }

    el.innerHTML = html;

    // Click edges to navigate
    el.querySelectorAll('.edge-row').forEach(row => {
      row.addEventListener('click', () => {
        const target = row.dataset.target;
        if (target && window._graph3d) window._graph3d.focusNode(target);
      });
    });

    // Breach button handler
    const breachBtn = el.querySelector('#breach-btn');
    if (breachBtn) {
      breachBtn.addEventListener('click', () => {
        const nid = breachBtn.dataset.nodeid;
        if (_onBreach) _onBreach(nid);
      });
    }
  }

  function _showPlaceholder(el) {
    el.innerHTML = `<div id="inspector-placeholder">Click a node to inspect</div>`;
  }

  function clear() {
    const el = document.getElementById('inspector');
    if (el) _showPlaceholder(el);
  }

  return { show, clear, setBreachCallback, setTopology };
})();
