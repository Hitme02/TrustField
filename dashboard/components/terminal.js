/* terminal.js — Guard event log terminal (software + hardware) */

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
    const isHw = ev.guard_id && ev.guard_id.startsWith('hw_');
    const tag  = isHw ? '<span class="log-hw">[HW]</span> ' : '';
    const reason = ev.reason ? `<span class="log-ts"> // ${ev.reason}</span>` : '';
    return `<div class="log-line">${ts} ${tag}${gid} ${dec} ${edge}${reason}</div>`;
  }

  function _renderHwEvent(ev, idx) {
    const decClass = ev.decision === 'ALLOWED' ? 'log-allowed' : 'log-blocked';
    const dec  = `<span class="${decClass}">${ev.decision}</span>`;
    const port = `<span class="log-hw">[${ev.source}:${ev.port}]</span>`;
    const raw  = `<span class="log-hw-raw">${ev.raw_response}</span>`;
    const ms   = `<span class="log-ts">${ev.round_trip_ms}ms</span>`;
    return `<div class="log-line log-hw-line">${port} ${dec} ${ms} ${raw}</div>`;
  }

  function render(graphData) {
    const log   = document.getElementById('terminal-log');
    const empty = document.getElementById('terminal-empty');
    if (!log) return;

    const events   = (graphData.metadata || {}).guard_events || [];
    const hwEvents = (graphData.metadata || {}).hardware_events || [];

    if (events.length === 0 && hwEvents.length === 0) {
      log.innerHTML = `<div id="terminal-empty">// No guard events — run with ContainmentEngine</div>`;
      return;
    }

    if (empty) empty.style.display = 'none';

    let html = '';

    if (hwEvents.length > 0) {
      html += '<div class="log-section-header">STM32 HARDWARE GUARD</div>';
      html += hwEvents.map(_renderHwEvent).join('');
      html += '<div class="log-section-header">SOFTWARE GUARDS</div>';
    }

    html += events.map(_renderLine).join('');

    log.innerHTML = html;
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
