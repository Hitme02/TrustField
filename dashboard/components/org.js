/* org.js — ORG tab upload panel and lifecycle management.
 *
 * Handles:
 *   - Tab switching between UPLOAD / AWS CONNECT / CLOUDTRAIL panes
 *   - Showing / hiding the upload overlay on the ORG tab
 *   - File drop zone and paste textarea input
 *   - Format auto-detection badge (client-side preview, server confirms)
 *   - Sample file loader (fetches raw JSON from the server)
 *   - POST /api/org/upload — sends parsed JSON to the server
 *   - CLEAR ORG button — calls POST /api/org/clear
 *   - AWS Connect pane — demo-mode connection + IAM pull
 *   - Policy polling + download + apply
 *   - CloudTrail SSE stream pane
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

  let _onLoaded = null;     // callback() when import succeeds
  let _pendingJson = null;  // parsed JSON ready to import

  // AWS state
  let _awsConnected   = false;
  let _awsAccountId   = null;
  let _awsAccountAlias = null;
  let _policyPollInterval = null;
  let _lastPolicies   = [];

  // CloudTrail state
  let _ctSource = null;   // EventSource instance

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  function init(onLoadedCallback) {
    _onLoaded = onLoadedCallback;
    _bindTabs();
    _bindDropZone();
    _bindPasteArea();
    _bindSampleBtns();
    _bindImportBtn();
    _bindClearBtn();
    _bindAwsPane();
    _bindCloudTrailPane();
  }

  function showUploadPanel() {
    document.getElementById('org-upload-overlay').classList.add('active');
    _resetForm();
  }

  function hideUploadPanel() {
    document.getElementById('org-upload-overlay').classList.remove('active');
    _stopPolicyPoll();
  }

  function checkPolicies() {
    _pollPolicies();
  }

  // ------------------------------------------------------------------
  // Tab switching
  // ------------------------------------------------------------------

  function _bindTabs() {
    document.querySelectorAll('.org-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        const pane = btn.dataset.pane;
        document.querySelectorAll('.org-tab').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.org-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const paneEl = document.getElementById('org-pane-' + pane);
        if (paneEl) paneEl.classList.add('active');
      });
    });
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
      showUploadPanel();
      if (_onLoaded) _onLoaded(null);
    });
  }

  // ------------------------------------------------------------------
  // AWS Connect pane
  // ------------------------------------------------------------------

  function _bindAwsPane() {
    const testBtn   = document.getElementById('aws-test-btn');
    const demoBtn   = document.getElementById('aws-demo-btn');
    const pullBtn   = document.getElementById('aws-pull-btn');
    const dlBtn     = document.getElementById('aws-download-btn');
    const applyBtn  = document.getElementById('aws-apply-btn');

    if (testBtn)  testBtn.addEventListener('click',  _onAwsTest);
    if (demoBtn)  demoBtn.addEventListener('click',  _onAwsDemo);
    if (pullBtn)  pullBtn.addEventListener('click',  _onAwsPull);
    if (dlBtn)    dlBtn.addEventListener('click',    _onDownloadPolicies);
    if (applyBtn) applyBtn.addEventListener('click', _onApplyPolicies);
  }

  async function _onAwsTest() {
    const keyId     = (document.getElementById('aws-key-id')     || {}).value || '';
    const secretKey = (document.getElementById('aws-secret-key') || {}).value || '';
    const region    = (document.getElementById('aws-region')     || {}).value || 'us-east-1';
    await _doConnect({region, access_key_id: keyId, secret_access_key: secretKey});
  }

  async function _onAwsDemo() {
    const region = (document.getElementById('aws-region') || {}).value || 'us-east-1';
    await _doConnect({region});
  }

  async function _doConnect(body) {
    const testBtn  = document.getElementById('aws-test-btn');
    const demoBtn  = document.getElementById('aws-demo-btn');
    if (testBtn)  testBtn.disabled = true;
    if (demoBtn)  demoBtn.disabled = true;

    _setAwsPullStatus('Connecting…', 'var(--dim)');
    try {
      const res  = await fetch('/api/aws/connect', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify(body),
      });
      const json = await res.json();
      if (!res.ok || !json.ok) {
        _setAwsPullStatus(`Connection failed: ${json.error || 'unknown error'}`, 'var(--red)');
        return;
      }

      _awsConnected    = true;
      _awsAccountId    = json.account_id;
      _awsAccountAlias = json.account_alias;

      // Show account banner
      const banner = document.getElementById('aws-account-banner');
      if (banner) {
        banner.textContent = `Connected · ${json.account_alias} (${json.account_id}) · ${json.region} · ${json.mode.toUpperCase()} MODE`;
        banner.style.display = 'block';
      }

      // Show pull button
      const pullBtn = document.getElementById('aws-pull-btn');
      if (pullBtn) pullBtn.style.display = 'block';

      _setAwsPullStatus('');

      // Unlock CloudTrail tab
      _onAwsConnected();

      // Start polling for policies
      _startPolicyPoll();

    } catch (e) {
      _setAwsPullStatus(`Network error: ${e.message}`, 'var(--red)');
    } finally {
      if (testBtn)  testBtn.disabled = false;
      if (demoBtn)  demoBtn.disabled = false;
    }
  }

  async function _onAwsPull() {
    const pullBtn = document.getElementById('aws-pull-btn');
    if (pullBtn) pullBtn.disabled = true;
    _setAwsPullStatus('Pulling IAM data…', 'var(--dim)');

    try {
      const res  = await fetch('/api/aws/pull', {method: 'POST'});
      const json = await res.json();
      if (!res.ok || !json.ok) {
        _setAwsPullStatus(`Pull failed: ${json.error || 'unknown error'}`, 'var(--red)');
        if (pullBtn) pullBtn.disabled = false;
        return;
      }

      _setAwsPullStatus(
        `+${json.added_nodes} nodes · +${json.added_edges} edges · ${json.account_alias || ''}`,
        'var(--green)',
      );

      // Close panel and load graph after delay (same as _doImport)
      setTimeout(() => {
        hideUploadPanel();
        if (_onLoaded) _onLoaded();
      }, 900);

    } catch (e) {
      _setAwsPullStatus(`Network error: ${e.message}`, 'var(--red)');
      if (pullBtn) pullBtn.disabled = false;
    }
  }

  function _setAwsPullStatus(msg, color) {
    const el = document.getElementById('aws-pull-status');
    if (!el) return;
    el.textContent = msg;
    el.style.color = color || 'var(--dim)';
  }

  // ------------------------------------------------------------------
  // Policy polling
  // ------------------------------------------------------------------

  function _startPolicyPoll() {
    _stopPolicyPoll();
    _pollPolicies();
    _policyPollInterval = setInterval(_pollPolicies, 3000);
  }

  function _stopPolicyPoll() {
    if (_policyPollInterval) {
      clearInterval(_policyPollInterval);
      _policyPollInterval = null;
    }
  }

  async function _pollPolicies() {
    try {
      const res  = await fetch('/api/aws/policies');
      const json = await res.json();
      if (!json.ok || !json.ready || !json.count) return;

      _lastPolicies = json.policies || [];
      _renderPolicies(_lastPolicies);
    } catch (_) {}
  }

  function _renderPolicies(policies) {
    const section = document.getElementById('aws-policies-section');
    const list    = document.getElementById('aws-policies-list');
    if (!section || !list) return;

    section.style.display = 'block';
    list.innerHTML = policies.map(p => `
      <div class="policy-row">
        <span class="policy-badge">DENY</span>
        <div>
          <div class="policy-desc">${_esc(p.description)}</div>
          <div class="policy-name">${_esc(p.policy_name)}</div>
        </div>
      </div>
    `).join('');
  }

  async function _onDownloadPolicies() {
    if (!_lastPolicies.length) return;
    const blob = new Blob([JSON.stringify(_lastPolicies, null, 2)], {type: 'application/json'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'trustfield-guards.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  async function _onApplyPolicies() {
    const btn = document.getElementById('aws-apply-btn');
    if (btn) btn.disabled = true;
    const status = document.getElementById('aws-apply-status');
    if (status) { status.textContent = 'Applying…'; status.style.color = 'var(--dim)'; }

    try {
      const res  = await fetch('/api/aws/apply', {method: 'POST'});
      const json = await res.json();
      if (status) {
        if (json.ok) {
          status.textContent = `Applied ${json.applied} policies · ${(json.mode || 'demo').toUpperCase()} MODE`;
          status.style.color = 'var(--green)';
        } else {
          status.textContent = `Error: ${json.error || 'unknown'}`;
          status.style.color = 'var(--red)';
        }
      }
    } catch (e) {
      if (status) { status.textContent = `Network error: ${e.message}`; status.style.color = 'var(--red)'; }
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // ------------------------------------------------------------------
  // CloudTrail pane
  // ------------------------------------------------------------------

  function _bindCloudTrailPane() {
    const startBtn = document.getElementById('ct-start-btn');
    const stopBtn  = document.getElementById('ct-stop-btn');
    if (startBtn) startBtn.addEventListener('click', _onCtStart);
    if (stopBtn)  stopBtn.addEventListener('click',  _onCtStop);
  }

  function _onAwsConnected() {
    const label    = document.getElementById('ct-account-label');
    const controls = document.getElementById('ct-controls');
    const info     = document.getElementById('ct-account-info');

    if (label)    label.style.display    = 'none';
    if (controls) controls.style.display = 'block';
    if (info)     info.textContent       = `Account: ${_awsAccountAlias || ''} (${_awsAccountId || ''})`;
  }

  function _onCtStart() {
    if (_ctSource) _ctSource.close();

    const feed     = document.getElementById('ct-feed');
    const startBtn = document.getElementById('ct-start-btn');
    const stopBtn  = document.getElementById('ct-stop-btn');

    if (feed)     feed.innerHTML     = '';
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn)  stopBtn.style.display  = 'inline-block';

    _ctSource = new EventSource('/api/aws/cloudtrail');

    _ctSource.addEventListener('cloudtrail_event', (e) => {
      try {
        const data = JSON.parse(e.data);
        _appendCtEvent(data);
      } catch (_) {}
    });

    _ctSource.addEventListener('cloudtrail_breach', (e) => {
      try {
        const data = JSON.parse(e.data);
        _onCtBreach(data.node);
      } catch (_) {}
    });

    _ctSource.onerror = () => {
      _ctSource.close();
      _ctSource = null;
      if (startBtn) startBtn.style.display = 'inline-block';
      if (stopBtn)  stopBtn.style.display  = 'none';
    };
  }

  function _onCtStop() {
    if (_ctSource) {
      _ctSource.close();
      _ctSource = null;
    }
    const startBtn = document.getElementById('ct-start-btn');
    const stopBtn  = document.getElementById('ct-stop-btn');
    if (startBtn) startBtn.style.display = 'inline-block';
    if (stopBtn)  stopBtn.style.display  = 'none';
  }

  function _appendCtEvent(data) {
    const feed = document.getElementById('ct-feed');
    if (!feed) return;

    const statusClass = (data.status || 'ALLOWED').toLowerCase();
    const src    = data.userIdentity || '';
    const role   = (data.requestParameters || {}).roleArn || (data.requestParameters || {}).secretId || '';
    const target = role.split('/').pop() || role;

    const div = document.createElement('div');
    div.className = `ct-event ${statusClass}`;
    div.innerHTML = `
      <span class="ct-time">${_esc(data.time || '')}</span>
      <span class="ct-status-badge">${_esc(data.status || 'ALLOWED')}</span>
      <span class="ct-detail">
        <span class="ct-path">${_esc(src)}</span>
        ${target ? ` → <span class="ct-path">${_esc(target)}</span>` : ''}
        <br>${_esc(data.detail || '')}
      </span>
    `;
    feed.appendChild(div);
    feed.scrollTop = feed.scrollHeight;
  }

  async function _onCtBreach(node) {
    // Trigger breach in the app
    if (typeof App !== 'undefined' && typeof App.triggerBreach === 'function') {
      App.triggerBreach(node);
    } else {
      try {
        await fetch('/api/org/breach/' + encodeURIComponent(node), {method: 'POST'});
      } catch (_) {}
      // Navigate to ORG tab
      const orgTab = document.querySelector('#topo-tabs .tab-btn[data-topo="org"]');
      if (orgTab) orgTab.click();
    }
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

  function _esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return { init, showUploadPanel, hideUploadPanel, checkPolicies };
})();
