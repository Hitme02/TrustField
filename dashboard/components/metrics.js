/* metrics.js — Metrics panel with count-up animations */

const MetricsPanel = (() => {

  function _countUp(el, target, duration = 600, isFloat = false) {
    const start = performance.now();
    const from  = parseFloat(el.dataset.current || '0');
    el.dataset.current = target;
    function tick(now) {
      const t = Math.min((now - start) / duration, 1);
      // ease-out cubic
      const ease = 1 - Math.pow(1 - t, 3);
      const val  = from + (target - from) * ease;
      el.textContent = isFloat ? val.toFixed(3) : Math.round(val);
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function update(meta) {
    const pbr = meta.pbr_size  ?? 0;
    const vbr = meta.vbr_size  ?? 0;
    const gap = meta.gap_size  ?? 0;
    const egd = meta.exploitability_gap_score ?? 0;

    const els = {
      pbr: document.getElementById('m-pbr'),
      vbr: document.getElementById('m-vbr'),
      gap: document.getElementById('m-gap'),
      egd: document.getElementById('m-egd'),
    };
    if (!els.pbr) return;

    _countUp(els.pbr, pbr, 600, false);
    _countUp(els.vbr, vbr, 600, false);
    _countUp(els.gap, gap, 600, false);
    _countUp(els.egd, egd, 600, true);

    // Color EGD based on severity
    const cls = meta.gap_classification || '';
    const colors = {
      CRITICAL_MISS:  '#ff3b30',
      OVER_PREDICTED: '#ff9500',
      UNDER_PREDICTED:'#ff6b35',
      CALIBRATED:     '#34c759',
    };
    els.egd.style.color = colors[cls] || '#00d4ff';
  }

  return { update };
})();
