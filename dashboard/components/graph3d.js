/* graph3d.js — Enhanced Three.js 3D graph visualization */

const Graph3D = (() => {

  const NODE_COLORS = {
    compromised:    0xff3b30,   // red    — verified + predicted
    predicted_only: 0xff9500,   // amber  — predicted but not verified
    critical_miss:  0xff6b35,   // orange — verified but missed by ensemble
    contained:      0x34c759,   // green  — guarded / not in blast radius
    safe:           0x2e5a88,   // visible blue — unreachable, no risk
  };

  const EDGE_COLORS = {
    blocked:  0xff3b30,
    critical: 0xff9500,
    normal:   0x252838,
  };

  let _scene, _camera, _renderer, _animFrame;
  let _nodeMeshes  = {};
  let _edgeLines   = [];
  let _edgeMap     = {};   // 'fromId:toId' → THREE.Line, for targeted mutations
  let _starField   = null;
  let _graphData   = null;
  let _selectedId  = null;
  let _scale       = 14;     // layout coords are ±10; scale to ±140

  // Orbit state
  let _orbit = {
    theta: 0.4, phi: 1.15, radius: 340,
    targetTheta: 0.4, targetPhi: 1.15, targetRadius: 340,
    isDragging: false, lastX: 0, lastY: 0, isRight: false,
    panX: 0, panY: 0, targetPanX: 0, targetPanY: 0,
  };

  let _raycaster, _mouse, _tooltip;
  let _waveNodes = [], _waveIndex = 0, _waveActive = false;

  // ── Init ───────────────────────────────────────────────────────────────
  function init(canvas) {
    const W = canvas.clientWidth  || canvas.offsetWidth  || 800;
    const H = canvas.clientHeight || canvas.offsetHeight || 600;

    _scene    = new THREE.Scene();
    _camera   = new THREE.PerspectiveCamera(50, W / H, 0.5, 3000);
    _renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
    _renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    _renderer.setSize(W, H, false);
    _renderer.setClearColor(0x0a0a0f, 1);

    _raycaster = new THREE.Raycaster();
    _mouse     = new THREE.Vector2(-9999, -9999);
    _tooltip   = document.getElementById('node-tooltip');

    _buildStarField();
    _bindEvents(canvas);
    _updateCamera();
    _animate();

    window.addEventListener('resize', () => _onResize(canvas));
    // Fire once more after fonts/layout settle
    setTimeout(() => _onResize(canvas), 200);
  }

  // ── Starfield ──────────────────────────────────────────────────────────
  function _buildStarField() {
    if (_starField) { _scene.remove(_starField); _starField.geometry.dispose(); }
    const N   = 900;
    const pos = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) {
      pos[i*3]   = (Math.random() - 0.5) * 1600;
      pos[i*3+1] = (Math.random() - 0.5) * 1200;
      pos[i*3+2] = -400 - Math.random() * 400;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const mat = new THREE.PointsMaterial({ color: 0xffffff, size: 1.1, transparent: true, opacity: 0.3 });
    _starField = new THREE.Points(geo, mat);
    _scene.add(_starField);
  }

  // ── Compute scale from actual data range ───────────────────────────────
  function _computeScale(nodes) {
    if (!nodes.length) return 14;
    let maxR = 0;
    nodes.forEach(n => {
      const r = Math.sqrt(n.x*n.x + n.y*n.y + n.z*n.z);
      if (r > maxR) maxR = r;
    });
    // Target max radius ~160 units in Three.js space
    return maxR > 0.5 ? 160 / maxR : 14;
  }

  // ── Load graph ─────────────────────────────────────────────────────────
  function loadGraph(data) {
    _graphData = data;
    _clearGraph();
    _scale = _computeScale(data.nodes || []);
    _buildGraph(data);
    _startWave(data);

    // Reset camera to see the whole graph
    _orbit.targetRadius = Math.max(280, _scale * 22);
    _orbit.radius       = _orbit.targetRadius * 1.2;
    _orbit.panX = 0; _orbit.targetPanX = 0;
    _orbit.panY = 0; _orbit.targetPanY = 0;
  }

  function _clearGraph() {
    Object.values(_nodeMeshes).forEach(m => {
      _scene.remove(m);
      m.geometry.dispose();
      m.material.dispose();
    });
    _nodeMeshes = {};
    _edgeLines.forEach(l => {
      _scene.remove(l);
      l.geometry.dispose();
      l.material.dispose();
    });
    _edgeLines  = [];
    _edgeMap    = {};
    _selectedId = null;
  }

  function _pos(node) {
    // Center the Z axis: layout Z is always positive, shift so mean ≈ 0
    return new THREE.Vector3(
      node.x * _scale,
      node.y * _scale,
      (node.z - 5) * _scale,   // shift Z by −5 to centre around 0
    );
  }

  function _buildGraph(data) {
    const nodes = data.nodes || [];
    const edges = data.edges || [];
    const meta  = data.metadata || {};

    // Build lookup for quick position access
    const posMap = {};
    nodes.forEach(n => { posMap[n.id] = _pos(n); });

    // Build a set of VBR node pairs for colouring edges
    const vbrSet   = new Set(meta.vbr_nodes || []);
    const blockedSet = new Set(
      (meta.blocked_transitions || []).map(e => Array.isArray(e) ? e[0]+':'+e[1] : e)
    );
    // Also mark edges on traversal timeline as critical
    const timelineEdges = new Set(
      (meta.traversal_timeline || []).filter(s => s.succeeded).map(s => s.from_node+':'+s.to_node)
    );

    // ── Edges ──────────────────────────────────────────────────────────
    edges.forEach(e => {
      const sp = posMap[e.source];
      const tp = posMap[e.target];
      if (!sp || !tp) return;

      const key       = e.source + ':' + e.target;
      const isBlocked = blockedSet.has(key);
      const isCritical = timelineEdges.has(key);

      let col = EDGE_COLORS.normal;
      let opa = 0.45;
      if (isBlocked)        { col = EDGE_COLORS.blocked;  opa = 0.90; }
      else if (isCritical)  { col = EDGE_COLORS.critical; opa = 0.70; }

      const geo = new THREE.BufferGeometry().setFromPoints([sp, tp]);
      const mat = new THREE.LineBasicMaterial({ color: col, transparent: true, opacity: opa });
      const line = new THREE.Line(geo, mat);
      _scene.add(line);
      _edgeLines.push(line);
      _edgeMap[e.source + ':' + e.target] = line;
    });

    // ── Nodes ──────────────────────────────────────────────────────────
    nodes.forEach(node => {
      const col  = NODE_COLORS[node.state] || NODE_COLORS.safe;
      const priv = node.privilege ?? 0;
      const size = 2.5 + priv * 4.5;

      // Safe nodes get a slightly larger minimum so they're never invisible
      const isSafe   = node.state === 'safe';
      const emissive = isSafe ? 0.45 : 0.25;

      const geo = new THREE.SphereGeometry(size, 14, 10);
      const mat = new THREE.MeshStandardMaterial({
        color: col,
        emissive: col,
        emissiveIntensity: emissive,
        roughness: 0.55,
        metalness: 0.25,
      });
      const mesh = new THREE.Mesh(geo, mat);
      const p = posMap[node.id];
      mesh.position.copy(p);
      mesh.userData = { id: node.id, baseScale: 1.0 };
      mesh.scale.setScalar(0);   // start hidden; wave reveals
      _scene.add(mesh);
      _nodeMeshes[node.id] = mesh;
    });

    // ── Lighting ───────────────────────────────────────────────────────
    _scene.children.filter(c => c.isLight).forEach(l => _scene.remove(l));
    _scene.add(new THREE.AmbientLight(0xffffff, 0.45));
    const pt = new THREE.PointLight(0x00d4ff, 1.4, 900);
    pt.position.set(120, 200, 80);
    _scene.add(pt);
    const pt2 = new THREE.PointLight(0xff3b30, 0.5, 600);
    pt2.position.set(-100, -100, 60);
    _scene.add(pt2);
  }

  // ── Compromise wave ────────────────────────────────────────────────────
  function _startWave(data) {
    const meta  = data.metadata || {};
    const seeds = meta.seed_nodes || [];
    const steps = (meta.traversal_timeline || []).filter(s => s.succeeded);

    const seen = new Set();
    _waveNodes = [];
    seeds.forEach(n => { if (!seen.has(n)) { seen.add(n); _waveNodes.push(n); } });
    steps.forEach(s => { if (!seen.has(s.to_node)) { seen.add(s.to_node); _waveNodes.push(s.to_node); } });
    data.nodes.forEach(n => { if (!seen.has(n.id)) { seen.add(n.id); _waveNodes.push(n.id); } });

    _waveIndex = 0;
    _waveActive = true;
    _runWave();
  }

  function _runWave() {
    if (!_waveActive || _waveIndex >= _waveNodes.length) { _waveActive = false; return; }
    const id   = _waveNodes[_waveIndex++];
    const mesh = _nodeMeshes[id];
    if (mesh) _popIn(mesh);
    // Traversal path animates with delay; remaining nodes appear instantly
    const delay = _waveIndex <= (_graphData?.metadata?.traversal_timeline?.length || 0) + 5 ? 55 : 0;
    setTimeout(_runWave, delay);
  }

  function _popIn(mesh) {
    const start = performance.now();
    function tick(now) {
      const t    = Math.min((now - start) / 260, 1);
      const ease = t < 0.5 ? 2*t*t : -1+(4-2*t)*t;
      const s    = ease < 0.85 ? ease * 1.3 : 1.0 + (1 - ease);
      mesh.scale.setScalar(Math.max(0, s));
      if (t < 1) requestAnimationFrame(tick);
      else       mesh.scale.setScalar(mesh.userData.baseScale);
    }
    requestAnimationFrame(tick);
  }

  // ── Animation loop ─────────────────────────────────────────────────────
  function _animate() {
    _animFrame = requestAnimationFrame(_animate);
    const t = Date.now() * 0.003;

    // Pulse compromised/critical nodes
    Object.entries(_nodeMeshes).forEach(([id, mesh]) => {
      const state = _graphData?.nodes.find(n => n.id === id)?.state;
      if (state === 'compromised' || state === 'critical_miss') {
        const pulse = 1.0 + Math.sin(t + mesh.position.x * 0.04) * 0.1;
        if (mesh.scale.x > 0.1) mesh.scale.setScalar(mesh.userData.baseScale * pulse);
      }
    });

    // Smooth orbit
    const d = 0.08;
    _orbit.theta  += (_orbit.targetTheta  - _orbit.theta)  * d;
    _orbit.phi    += (_orbit.targetPhi    - _orbit.phi)    * d;
    _orbit.radius += (_orbit.targetRadius - _orbit.radius) * d;
    _orbit.panX   += (_orbit.targetPanX   - _orbit.panX)   * d;
    _orbit.panY   += (_orbit.targetPanY   - _orbit.panY)   * d;

    // Selected node glow
    if (_selectedId && _nodeMeshes[_selectedId]) {
      _nodeMeshes[_selectedId].material.emissiveIntensity = 0.5 + Math.sin(t * 2.5) * 0.25;
    }

    _updateCamera();
    _checkHover();
    _renderer.render(_scene, _camera);
  }

  function _updateCamera() {
    const phi = Math.max(0.1, Math.min(Math.PI - 0.1, _orbit.phi));
    const x   = _orbit.radius * Math.sin(phi) * Math.sin(_orbit.theta) + _orbit.panX;
    const y   = _orbit.radius * Math.cos(phi) + _orbit.panY;
    const z   = _orbit.radius * Math.sin(phi) * Math.cos(_orbit.theta);
    _camera.position.set(x, y, z);
    _camera.lookAt(_orbit.panX, _orbit.panY, 0);
  }

  // ── Hover tooltip ──────────────────────────────────────────────────────
  function _checkHover() {
    if (!_graphData || !_tooltip) return;
    _raycaster.setFromCamera(_mouse, _camera);
    const hits = _raycaster.intersectObjects(Object.values(_nodeMeshes));
    if (hits.length > 0) {
      const id   = hits[0].object.userData.id;
      const node = _graphData.nodes.find(n => n.id === id);
      if (node) { _showTooltip(id, node); document.body.style.cursor = 'pointer'; return; }
    }
    _hideTooltip();
    document.body.style.cursor = '';
  }

  const STATE_LABELS = {
    compromised:    'COMPROMISED',
    predicted_only: 'PREDICTED',
    critical_miss:  'CRITICAL MISS',
    contained:      'CONTAINED',
    safe:           'SAFE',
  };
  const STATE_HEX = {
    compromised:    '#ff3b30',
    predicted_only: '#ff9500',
    critical_miss:  '#ff6b35',
    contained:      '#34c759',
    safe:           '#2e5a88',
  };

  function _showTooltip(id, node) {
    if (!_tooltip) return;
    const canvas = _renderer.domElement;
    const rect   = canvas.getBoundingClientRect();
    const mesh   = _nodeMeshes[id];
    if (!mesh) return;

    const proj = mesh.position.clone().project(_camera);
    const px   = (proj.x  * 0.5 + 0.5) * rect.width  + rect.left;
    const py   = (-proj.y * 0.5 + 0.5) * rect.height + rect.top;

    const stateLabel = STATE_LABELS[node.state] || (node.state || '—').toUpperCase();
    const stateColor = STATE_HEX[node.state]    || '#8888aa';

    _tooltip.style.display = 'block';
    _tooltip.style.left    = Math.min(px + 16, rect.right  - 200) + 'px';
    _tooltip.style.top     = Math.max(py - 12, rect.top  + 4)     + 'px';
    _tooltip.innerHTML = `
      <div class="tt-name">${id}</div>
      <div class="tt-row">Type: <span>${node.type || '—'}</span></div>
      <div class="tt-row">State: <span style="color:${stateColor};font-weight:600">${stateLabel}</span></div>
      <div class="tt-row">Priv: <span>${(node.privilege||0).toFixed(2)}</span></div>
      <div class="tt-row">Risk: <span>${(node.risk||0).toFixed(2)}</span></div>
    `;
  }

  function _hideTooltip() {
    if (_tooltip) _tooltip.style.display = 'none';
  }

  // ── Node focus ─────────────────────────────────────────────────────────
  function focusNode(id) {
    if (_selectedId && _nodeMeshes[_selectedId]) {
      _nodeMeshes[_selectedId].material.emissiveIntensity = 0.25;
    }
    _selectedId = id;
    const mesh = _nodeMeshes[id];
    if (!mesh) return;

    // Fly toward node
    const p = mesh.position;
    _orbit.targetTheta = Math.atan2(p.x - _orbit.panX, p.z);
    _orbit.targetPhi   = Math.atan2(
      Math.sqrt((p.x-_orbit.panX)**2 + p.z**2),
      p.y - _orbit.panY
    );
    _orbit.targetPanX = p.x * 0.25;
    _orbit.targetPanY = p.y * 0.25;

    Inspector.show(id, _graphData);
  }

  // ── Events ─────────────────────────────────────────────────────────────
  function _bindEvents(canvas) {
    canvas.addEventListener('mousedown', e => {
      _orbit.isDragging = true;
      _orbit.lastX = e.clientX; _orbit.lastY = e.clientY;
      _orbit.isRight = (e.button === 2);
    });
    window.addEventListener('mouseup', () => { _orbit.isDragging = false; });
    window.addEventListener('mousemove', e => {
      const rect = canvas.getBoundingClientRect();
      _mouse.x =  ((e.clientX - rect.left) / rect.width)  * 2 - 1;
      _mouse.y = -((e.clientY - rect.top)  / rect.height) * 2 + 1;
      if (!_orbit.isDragging) return;
      const dx = e.clientX - _orbit.lastX;
      const dy = e.clientY - _orbit.lastY;
      _orbit.lastX = e.clientX; _orbit.lastY = e.clientY;
      if (_orbit.isRight) {
        _orbit.targetPanX -= dx * 0.35;
        _orbit.targetPanY += dy * 0.35;
      } else {
        _orbit.targetTheta -= dx * 0.007;
        _orbit.targetPhi   += dy * 0.007;
      }
    });
    canvas.addEventListener('wheel', e => {
      e.preventDefault();
      _orbit.targetRadius = Math.max(60, Math.min(800, _orbit.targetRadius + e.deltaY * 0.45));
    }, { passive: false });
    canvas.addEventListener('click', e => {
      if (!_graphData) return;
      const rect = canvas.getBoundingClientRect();
      _mouse.x =  ((e.clientX - rect.left) / rect.width)  * 2 - 1;
      _mouse.y = -((e.clientY - rect.top)  / rect.height) * 2 + 1;
      _raycaster.setFromCamera(_mouse, _camera);
      const hits = _raycaster.intersectObjects(Object.values(_nodeMeshes));
      if (hits.length > 0) focusNode(hits[0].object.userData.id);
    });
    canvas.addEventListener('contextmenu', e => e.preventDefault());
  }

  function _onResize(canvas) {
    const W = canvas.clientWidth  || canvas.offsetWidth;
    const H = canvas.clientHeight || canvas.offsetHeight;
    if (!W || !H) return;
    _camera.aspect = W / H;
    _camera.updateProjectionMatrix();
    _renderer.setSize(W, H, false);
  }

  function destroy() {
    if (_animFrame) cancelAnimationFrame(_animFrame);
    _clearGraph();
    if (_starField) { _scene.remove(_starField); _starField.geometry.dispose(); }
  }

  // ── Demo-mode mutation API ─────────────────────────────────────────────

  /** Change one node's color and state label without reloading the full graph. */
  function setNodeState(nodeId, state) {
    const mesh = _nodeMeshes[nodeId];
    if (!mesh) return;
    const col = NODE_COLORS[state] || NODE_COLORS.safe;
    mesh.material.color.setHex(col);
    mesh.material.emissive.setHex(col);
    mesh.material.emissiveIntensity = (state === 'compromised' || state === 'critical_miss') ? 0.55 : 0.25;
    if (_graphData) {
      const n = _graphData.nodes.find(n => n.id === nodeId);
      if (n) n.state = state;
    }
  }

  /** Change one edge's color and opacity. colorHex is a 0xRRGGBB number. */
  function setEdgeColor(fromId, toId, colorHex, opacity) {
    const line = _edgeMap[fromId + ':' + toId];
    if (!line) return;
    line.material.color.setHex(colorHex);
    line.material.opacity = opacity ?? 0.85;
  }

  /** Scale-burst animation on a single node — signals breach or containment. */
  function pulseNode(nodeId) {
    const mesh = _nodeMeshes[nodeId];
    if (!mesh) return;
    const base  = mesh.userData.baseScale || 1;
    const start = performance.now();
    function tick(now) {
      const t = Math.min((now - start) / 500, 1);
      mesh.scale.setScalar(base * (1 + Math.sin(t * Math.PI) * 0.65));
      if (t < 1) requestAnimationFrame(tick);
      else mesh.scale.setScalar(base);
    }
    requestAnimationFrame(tick);
  }

  /** Expose raw graph data for demo controller. */
  function getGraphData() { return _graphData; }

  return { init, loadGraph, focusNode, destroy, setNodeState, setEdgeColor, pulseNode, getGraphData };
})();
