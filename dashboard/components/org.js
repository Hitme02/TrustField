/* org.js — ORG tab upload panel and lifecycle management.
 *
 * Handles:
 *   - Showing / hiding the upload overlay on the ORG tab
 *   - File drop zone and paste textarea input
 *   - Format auto-detection badge (client-side preview, server confirms)
 *   - Sample file loader (fetches raw JSON from GitHub)
 *   - POST /api/org/upload — sends parsed JSON to the server
 *   - CLEAR ORG button — calls POST /api/org/clear
 */

const OrgUpload = (() => {

  // Sample files that ship with known IAM security tools
  const KNOWN_FORMATS = {
    account_auth_dump:  'AWS ACCOUNT DUMP',
    policy_doc:         'IAM POLICY DOC',
    mamip_policy:       'MAMIP POLICY',
    role_bundle:        'ROLE BUNDLE',
    k8s_rbac:           'K8S RBAC',
    terraform_plan:     'TERRAFORM PLAN',
  };

  let _onLoaded = null;   // callback(graphData) when import succeeds
  let _pendingJson = null;  // parsed JSON ready to import

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  function init(onLoadedCallback) {
    _onLoaded = onLoadedCallback;
    _bindDropZone();
    _bindPasteArea();
    _bindSampleBtns();
    _bindImportBtn();
    _bindClearBtn();
  }

  function showUploadPanel() {
    document.getElementById('org-upload-overlay').classList.add('active');
    _resetForm();
  }

  function hideUploadPanel() {
    document.getElementById('org-upload-overlay').classList.remove('active');
  }

  // ------------------------------------------------------------------
  // Drop zone
  // ------------------------------------------------------------------

  function _bindDropZone() {
    const zone  = document.getElementById('org-drop-zone');
    const input = document.getElementById('org-file-input');
    const link  = document.getElementById('org-browse-link');

    link.addEventListener('click', () => input.click());
    zone.addEventListener('click', (e) => {
      if (e.target !== link) input.click();
    });

    input.addEventListener('change', () => {
      const file = input.files[0];
      if (file) _readFile(file);
    });

    zone.addEventListener('dragover', (e) => {
      e.preventDefault();
      zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file) _readFile(file);
    });
  }

  function _readFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target.result;
      document.getElementById('org-paste-area').value = text;
      _detectAndPreview(text);
    };
    reader.readAsText(file);

    const label = document.getElementById('org-drop-zone-label');
    label.innerHTML = `<span style="color:var(--cyan)">${file.name}</span> &nbsp;·&nbsp; <span id="org-browse-link" style="color:var(--dim);text-decoration:underline;cursor:pointer">Change</span>`;
    document.getElementById('org-browse-link').addEventListener('click', () => {
      document.getElementById('org-file-input').click();
    });
  }

  // ------------------------------------------------------------------
  // Paste area
  // ------------------------------------------------------------------

  function _bindPasteArea() {
    const area = document.getElementById('org-paste-area');
    area.addEventListener('input', () => _detectAndPreview(area.value.trim()));
  }

  // ------------------------------------------------------------------
  // Client-side format detection (mirrors server logic for instant feedback)
  // ------------------------------------------------------------------

  function _detectFormat(data) {
    if (!data || typeof data !== 'object') return 'unknown';
    const keys = Object.keys(data);
    if (keys.some(k => ['UserDetailList','RoleDetailList','GroupDetailList','Policies'].includes(k)))
      return 'account_auth_dump';
    if ('apiVersion' in data && 'kind' in data) return 'k8s_rbac';
    if ('resource_changes' in data || 'planned_values' in data) return 'terraform_plan';
    if ('RoleName' in data || 'TrustPolicy' in data) return 'role_bundle';
    if ('PolicyVersion' in data) return 'mamip_policy';
    if ('Statement' in data) return 'policy_doc';
    return 'unknown';
  }

  function _detectAndPreview(text) {
    if (!text) {
      _hideBadge();
      _pendingJson = null;
      _setImportEnabled(false);
      return;
    }
    try {
      const parsed = JSON.parse(text);
      const fmt    = _detectFormat(parsed);
      _pendingJson = parsed;
      _showBadge(fmt);
      _setImportEnabled(true);
    } catch {
      _hideBadge();
      _pendingJson = null;
      _setImportEnabled(false);
      _setStatus('Invalid JSON', 'var(--red)');
    }
  }

  function _showBadge(fmt) {
    const badge = document.getElementById('org-format-badge');
    if (fmt === 'unknown') {
      badge.textContent = 'UNKNOWN FORMAT';
      badge.className   = 'unknown';
    } else {
      badge.textContent = `DETECTED: ${KNOWN_FORMATS[fmt] || fmt.toUpperCase()}`;
      badge.className   = 'detected';
    }
    _setStatus('');
  }

  function _hideBadge() {
    const badge = document.getElementById('org-format-badge');
    badge.className = '';
    badge.textContent = '';
  }

  // ------------------------------------------------------------------
  // Sample buttons
  // ------------------------------------------------------------------

  function _bindSampleBtns() {
    document.querySelectorAll('.org-sample-btn').forEach(btn => {
      btn.addEventListener('click', () => _loadSample(btn.dataset.url, btn));
    });
  }

  async function _loadSample(url, btn) {
    const origText = btn.textContent;
    btn.textContent = '…';
    btn.disabled    = true;
    _setStatus('Fetching sample…', 'var(--dim)');

    try {
      const res  = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      document.getElementById('org-paste-area').value = text;
      _detectAndPreview(text);
      _setStatus('Sample loaded', 'var(--green)');
    } catch (e) {
      _setStatus(`Could not fetch sample: ${e.message}`, 'var(--red)');
    } finally {
      btn.textContent = origText;
      btn.disabled    = false;
    }
  }

  // ------------------------------------------------------------------
  // Import
  // ------------------------------------------------------------------

  function _bindImportBtn() {
    document.getElementById('org-import-btn').addEventListener('click', _doImport);
  }

  async function _doImport() {
    if (!_pendingJson) {
      _setStatus('No JSON to import', 'var(--red)');
      return;
    }

    _setImportEnabled(false);
    _setStatus('Importing…', 'var(--dim)');

    try {
      const res = await fetch('/api/org/upload', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify({data: _pendingJson, replace: true}),
      });

      const json = await res.json();
      if (!res.ok) {
        _setStatus(`Error: ${json.error}`, 'var(--red)');
        _setImportEnabled(true);
        return;
      }

      _setStatus(
        `+${json.added_nodes} nodes · +${json.added_edges} edges · format: ${json.format}`,
        'var(--green)',
      );

      // Short delay then close panel and load the new graph
      setTimeout(() => {
        hideUploadPanel();
        if (_onLoaded) _onLoaded();
      }, 900);

    } catch (e) {
      _setStatus(`Network error: ${e.message}`, 'var(--red)');
      _setImportEnabled(true);
    }
  }

  // ------------------------------------------------------------------
  // Clear ORG
  // ------------------------------------------------------------------

  function _bindClearBtn() {
    const btn = document.getElementById('org-clear-btn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      if (!confirm('Remove all uploaded org IAM data?')) return;
      try {
        await fetch('/api/org/clear', {method: 'POST'});
      } catch {}
      // Show upload panel again
      showUploadPanel();
      if (_onLoaded) _onLoaded(null);
    });
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  function _setStatus(msg, color = 'var(--dim)') {
    const el = document.getElementById('org-import-status');
    if (!el) return;
    el.textContent  = msg;
    el.style.color  = color;
  }

  function _setImportEnabled(enabled) {
    const btn = document.getElementById('org-import-btn');
    if (!btn) return;
    btn.disabled = !enabled;
  }

  function _resetForm() {
    document.getElementById('org-paste-area').value = '';
    document.getElementById('org-file-input').value = '';
    document.getElementById('org-drop-zone-label').innerHTML =
      'Drop JSON file here &nbsp;·&nbsp; <span id="org-browse-link">Browse</span>';
    // Re-bind browse link after innerHTML reset
    const link  = document.getElementById('org-browse-link');
    const input = document.getElementById('org-file-input');
    if (link) link.addEventListener('click', () => input.click());
    _hideBadge();
    _setStatus('');
    _setImportEnabled(false);
    _pendingJson = null;
  }

  return { init, showUploadPanel, hideUploadPanel };
})();
