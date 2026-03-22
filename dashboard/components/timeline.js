/* timeline.js — Attack path timeline scrubber */

const Timeline = (() => {

  const STATE_COLORS = {
    compromised:    '#ff3b30',
    predicted_only: '#ff9500',
    critical_miss:  '#ff6b35',
    contained:      '#34c759',
    safe:           '#444466',
  };

  function _nodeColor(nodeId, graphData) {
    const node = graphData.nodes.find(n => n.id === nodeId);
    return node ? (STATE_COLORS[node.state] || '#444466') : '#444466';
  }

  function render(graphData, onSelect) {
    const track  = document.getElementById('timeline-track');
    const empty  = document.getElementById('timeline-empty');
    const lockEl = document.getElementById('tl-lockdown');
    if (!track) return;

    const steps = (graphData.metadata || {}).traversal_timeline || [];
    const meta  = graphData.metadata || {};

    if (steps.length === 0) {
      if (empty) empty.style.display = 'block';
      track.innerHTML = '';
      if (lockEl) lockEl.style.display = 'none';
      return;
    }

    if (empty) empty.style.display = 'none';

    // Build ordered list: seed nodes first, then traversal path
    const seen = new Set();
    const ordered = [];

    (meta.seed_nodes || []).forEach(n => {
      if (!seen.has(n)) { seen.add(n); ordered.push(n); }
    });

    steps.filter(s => s.succeeded).forEach(s => {
      if (!seen.has(s.to_node)) { seen.add(s.to_node); ordered.push(s.to_node); }
    });

    // Cap display to 18 nodes to fit bar
    const display = ordered.slice(0, 18);

    let html = '';
    display.forEach((nodeId, i) => {
      const col = _nodeColor(nodeId, graphData);
      const shortName = nodeId.replace(/^(role-|svc-|secret-|deploy-|user-)/, '').substring(0, 10);
      html += `<div class="tl-node" data-id="${nodeId}" title="${nodeId}">
        <div class="tl-dot" style="background:${col}"></div>
        <div class="tl-label">${shortName}</div>
      </div>`;
      if (i < display.length - 1) {
        html += `<div class="tl-connector"></div>`;
      }
    });

    track.innerHTML = html;

    // Lockdown marker
    const strictness = meta.final_strictness || '';
    if (lockEl) {
      lockEl.style.display = strictness === 'LOCKDOWN' ? 'flex' : 'none';
    }

    // Click handlers
    track.querySelectorAll('.tl-node').forEach(el => {
      el.addEventListener('click', () => {
        const id = el.dataset.id;
        if (onSelect) onSelect(id);
        if (window._graph3d) window._graph3d.focusNode(id);
        // Highlight
        track.querySelectorAll('.tl-node .tl-dot').forEach(d => {
          d.style.boxShadow = '';
        });
        el.querySelector('.tl-dot').style.boxShadow = '0 0 0 2px #00d4ff';
      });
    });
  }

  return { render };
})();
