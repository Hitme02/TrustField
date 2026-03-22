/* terminal.js — Guard event log terminal */

const Terminal = (() => {

  let _collapsed = false;
  let _terminalBar = null;

  function _fmt(ts) {
    const d = new Date(ts * 1000);
    return d.toTimeString().slice(0, 8);
  }

  function _renderLine(ev) {
    const ts   = `<span class="log-ts">[${_fmt(ev.timestamp)}]</span>`;
    const gid  = `<span class="log-id">${ev.guard_id.slice(0,18)}</span>`;
    const edge = `<span class="log-edge">${ev.edge[0]}→${ev.edge[1]}</span>`;
    const decClass = ev.decision === 'ALLOWED' ? 'log-allowed' :
                     ev.decision === 'FLAGGED'  ? 'log-sensor'  : 'log-blocked';
    const dec  = `<span class="${decClass}">${ev.decision}</span>`;
    const reason = ev.reason ? `<span class="log-ts"> // ${ev.reason}</span>` : '';
    return `<div class="log-line">${ts} ${gid} ${dec} ${edge}${reason}</div>`;
  }

  function render(graphData) {
    const log   = document.getElementById('terminal-log');
    const empty = document.getElementById('terminal-empty');
    if (!log) return;

    const events = (graphData.metadata || {}).guard_events || [];

    if (events.length === 0) {
      log.innerHTML = `<div id="terminal-empty">// No guard events — run with ContainmentEngine</div>`;
      return;
    }

    if (empty) empty.style.display = 'none';

    // Render all events
    log.innerHTML = events.map(_renderLine).join('');
    // Scroll to bottom
    log.scrollTop = log.scrollHeight;
  }

  function initToggle() {
    _terminalBar = document.getElementById('terminal-bar');
    const btn    = document.getElementById('terminal-toggle');
    const logEl  = document.getElementById('terminal-log');
    if (!btn || !_terminalBar) return;

    btn.addEventListener('click', () => {
      _collapsed = !_collapsed;
      if (_collapsed) {
        logEl.style.display = 'none';
        btn.textContent = '[show]';
      } else {
        logEl.style.display = '';
        btn.textContent = '[hide]';
        logEl.scrollTop = logEl.scrollHeight;
      }
    });
  }

  return { render, initToggle };
})();
