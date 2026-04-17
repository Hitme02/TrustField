/* system.js — TrustField System Console
 *
 * Shows a live panel per service node.
 * Auto-traffic fires along org graph edges; attack traffic blasts all targets.
 * Manual pings show BLOCKED in red once guards are deployed.
 */

const SC = (() => {

  let _nodes   = [];
  let _nodeIds = [];
  let _es      = null;
  let _pings   = 0;
  let _blocked = 0;
  let _selectedAttackTarget = null;

  const MAX_PANEL_LOG = 9;
  const MAX_FEED      = 80;

  // ── Bootstrap ──────────────────────────────────────────────────────────

  async function start() {
    const btn = document.getElementById('btn-start');
    btn.textContent = 'STARTING…';
    btn.disabled    = true;

    try {
      const r = await fetch('/api/mock/start', { method: 'POST' });
      const d = await r.json();
      if (!d.ok) { _err('Failed to start: ' + (d.error || 'unknown')); btn.disabled = false; return; }

      _nodes   = d.status.nodes;
      _nodeIds = _nodes.map(n => n.node_id);

      _buildGrid();
      _connectSSE();

      btn.style.display = 'none';
      document.getElementById('btn-attack').disabled = false;
      document.getElementById('btn-reset').disabled  = false;

      _setStatus('green', `${_nodes.length} services running · auto-traffic active`);
      _addFeed('SYS', `${_nodes.length} mock services started`, 'sys');
    } catch (e) {
      _err('Failed to start: ' + e.message);
      btn.textContent = 'START SERVICES';
      btn.disabled    = false;
    }
  }

  // ── SSE ────────────────────────────────────────────────────────────────

  function _connectSSE() {
    if (_es) _es.close();
    _es = new EventSource('/api/mock/events');
    _es.addEventListener('ping',            e => _onPing(JSON.parse(e.data)));
    _es.addEventListener('attack_started',  e => _onAttackStarted(JSON.parse(e.data)));
    _es.addEventListener('guards_deployed', e => _onGuardsDeployed(JSON.parse(e.data)));
    _es.addEventListener('reset',           () => location.reload());
    _es.onerror = () => _setStatus('red', 'connection lost — reload to reconnect');
  }

  // ── Grid ───────────────────────────────────────────────────────────────

  function _buildGrid() {
    const grid = document.getElementById('node-grid');
    grid.innerHTML = '';
    _nodes.forEach(n => {
      const id   = n.node_id;
      const type = n.node_type || 'NODE';
      const priv = (n.privilege_level ?? 0).toFixed(2);
      const opts = _nodeIds.filter(x => x !== id)
        .map(x => `<option value="${x}">${x}</option>`).join('');

      const panel = document.createElement('div');
      panel.className = 'node-panel';
      panel.id = `panel-${id}`;
      panel.innerHTML = `
        <div class="panel-head">
          <div class="panel-id">${id}</div>
          <div class="panel-badge">${type}</div>
          <div class="panel-priv">priv ${priv}</div>
        </div>
        <div class="panel-log" id="plog-${id}"></div>
        <div class="panel-ping">
          <select id="ptgt-${id}">${opts}</select>
          <button class="ping-btn" onclick="SC.ping('${id}')">PING →</button>
        </div>`;
      grid.appendChild(panel);
    });
  }

  // ── Event handlers ─────────────────────────────────────────────────────

  function _onPing(d) {
    _pings++;
    if (d.status === 'blocked') _blocked++;

    const ts  = _ts(d.ts);
    const tag = d.status === 'blocked' ? '[BLOCKED]' : (d.attack ? '[ATTACK]' : '[OK]');
    const manualMark = d.manual ? '  ◀ MANUAL' : '';

    const pCls = (d.status === 'blocked' ? 'out-block' : d.attack ? 'out-attack' : 'out-ok')
                 + (d.manual ? ' manual' : '');
    const fCls = (d.status === 'blocked' ? 'block' : d.attack ? 'attack' : 'ok')
                 + (d.manual ? ' manual' : '');

    _appendPanel(d.from, `→ ${d.to}  ${tag}${manualMark}`, pCls);
    if (d.status === 'allowed') _appendPanel(d.to, `← ${d.from}`, 'in-ok');

    const icon = d.status === 'blocked' ? '✗' : d.attack ? '⚡' : '·';
    _addFeed(ts, `${icon}  ${d.from} → ${d.to}  ${tag}${manualMark}`, fCls);

    document.getElementById('cnt-pings').textContent   = _pings;
    document.getElementById('cnt-blocked').textContent = `blocked: ${_blocked}`;
  }

  function _onAttackStarted(d) {
    const panel = document.getElementById(`panel-${d.node}`);
    if (panel) panel.classList.add('compromised');

    const btn = document.getElementById('btn-attack');
    btn.textContent = 'ATTACKING';
    btn.classList.add('attacking');

    _setStatus('amber', `ATTACK IN PROGRESS — ${d.node} compromised`);
    _addFeed('--:--:--', `⚡  ATTACK STARTED — initial foothold: ${d.node}`, 'attack');
  }

  function _onGuardsDeployed(d) {
    d.blocked.forEach(([from]) => {
      const panel = document.getElementById(`panel-${from}`);
      if (panel) panel.classList.add('guarded');
    });
    const n = d.blocked.length;
    _setStatus('green', `GUARDS ACTIVE — ${n} trust edges revoked`);
    _addFeed('--:--:--', `✓  GUARDS DEPLOYED — ${n} edges blocked`, 'sys');
    document.getElementById('guard-status').textContent = `${n} guards active`;
  }

  // ── Actions ────────────────────────────────────────────────────────────

  async function ping(fromId) {
    const sel = document.getElementById(`ptgt-${fromId}`);
    if (!sel) return;
    await fetch('/api/mock/ping', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ from: fromId, to: sel.value }),
    });
  }

  // ── Attack modal ───────────────────────────────────────────────────────

  function openAttackModal() {
    _selectedAttackTarget = null;
    _buildAttackGrid();
    document.getElementById('attack-selected-label').textContent = 'No service selected';
    document.getElementById('attack-confirm-btn').disabled = true;
    document.getElementById('attack-modal').classList.add('open');
  }

  function closeAttackModal() {
    document.getElementById('attack-modal').classList.remove('open');
    _selectedAttackTarget = null;
  }

  function _buildAttackGrid() {
    const grid = document.getElementById('attack-node-grid');
    grid.innerHTML = '';
    _nodes.forEach(n => {
      const card = document.createElement('div');
      card.className = 'attack-card';
      card.dataset.id = n.node_id;
      card.innerHTML = `
        <div class="ac-id">${n.node_id}</div>
        <div class="ac-type">${n.node_type || 'NODE'}</div>
        <div class="ac-priv">privilege  ${(n.privilege_level ?? 0).toFixed(2)}</div>`;
      card.addEventListener('click', () => _selectAttackCard(n.node_id));
      grid.appendChild(card);
    });
  }

  function _selectAttackCard(nodeId) {
    // Deselect all, select clicked
    document.querySelectorAll('.attack-card').forEach(c => {
      c.classList.toggle('selected', c.dataset.id === nodeId);
    });
    _selectedAttackTarget = nodeId;
    document.getElementById('attack-selected-label').textContent =
      `Selected: ${nodeId}`;
    document.getElementById('attack-confirm-btn').disabled = false;
  }

  async function confirmAttack() {
    if (!_selectedAttackTarget) return;
    const target = _selectedAttackTarget;  // capture before closeAttackModal resets it to null
    closeAttackModal();
    try {
      const r = await fetch('/api/mock/attack', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ node_id: target }),
      });
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        _err('Attack failed: ' + (err.error || r.status));
      }
    } catch (e) {
      _err('Attack request failed: ' + e.message);
    }
  }

  async function reset() {
    if (!confirm('Reset mock cloud? This clears all guards and attack state.')) return;
    await fetch('/api/mock/reset', { method: 'POST' });
  }

  // ── DOM helpers ────────────────────────────────────────────────────────

  function _appendPanel(nodeId, text, cls) {
    const el = document.getElementById(`plog-${nodeId}`);
    if (!el) return;
    const row = document.createElement('div');
    row.className = `plog ${cls}`;
    row.textContent = text;
    el.appendChild(row);
    while (el.children.length > MAX_PANEL_LOG) el.removeChild(el.firstChild);
    el.scrollTop = el.scrollHeight;
  }

  function _addFeed(ts, msg, cls) {
    const feed = document.getElementById('activity-feed');
    if (!feed) return;
    const row = document.createElement('div');
    row.className = `feed-row ${cls}`;
    row.innerHTML = `<span class="feed-ts">${ts}</span><span class="feed-msg">${_esc(msg)}</span>`;
    feed.appendChild(row);
    while (feed.children.length > MAX_FEED) feed.removeChild(feed.firstChild);
    feed.scrollTop = feed.scrollHeight;
  }

  function _setStatus(color, msg) {
    const dot  = document.getElementById('sys-live-dot');
    const text = document.getElementById('sys-status-text');
    const map  = { green: '#34c759', red: '#ff3b30', amber: '#ff9500', grey: '#3a3a55' };
    if (dot)  dot.style.background = map[color] || map.grey;
    if (text) text.textContent     = msg;
  }

  function _ts(ms)  { return new Date(ms).toTimeString().slice(0, 8); }
  function _esc(s)  { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function _err(m)  { alert(m); }

  return { start, ping, openAttackModal, closeAttackModal, confirmAttack, reset };
})();
