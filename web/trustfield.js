/**
 * TrustField 3D Visualization — Three.js r128
 *
 * Renders the trust graph exported by GraphExporter as an interactive
 * 3D scene with orbit controls, node picking, and state-based colouring.
 *
 * Node state colour mapping
 * -------------------------
 *   compromised    #cc2020  deep red   (in PBR ∩ VBR)
 *   critical_miss  #e05000  orange     (VBR only — CRITICAL_MISS)
 *   predicted_only #d0a000  amber      (PBR only)
 *   contained      #20a050  green      (blocked by guards)
 *   safe           #304060  slate      (not reached)
 *
 * Controls
 * --------
 *   Left-drag   orbit
 *   Right-drag  pan
 *   Scroll      zoom
 *   Click node  show info in panel
 */

'use strict';

/* ------------------------------------------------------------------ */
/* State colours                                                        */
/* ------------------------------------------------------------------ */

const STATE_COLORS = {
  compromised:    0xcc2020,
  critical_miss:  0xe05000,
  predicted_only: 0xd0a000,
  contained:      0x20a050,
  safe:           0x304060,
};

// Edge colours by trust type — visible on dark background
const EDGE_COLORS = {
  ASSUME_ROLE:     0xe05050,   // red   — highest risk delegation
  SECRET_READ:     0xe0a020,   // amber — credential access
  TOKEN_MINT:      0x50a0e0,   // blue  — token/invocation
  DEPLOY_TO:       0xa050e0,   // purple — deployment
  AUTHENTICATE_AS: 0x408060,   // teal  — generic auth
  UNKNOWN:         0x607090,   // grey  — fallback
};
const EDGE_OPACITY      = 0.75;
const NODE_SEGMENTS     = 16;

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

let scene, camera, renderer, raycaster, mouse;
let nodeMeshes = {};      // node_id → THREE.Mesh
let edgeLines  = [];
let graphData  = null;

window.addEventListener('DOMContentLoaded', init);

function init() {
  // Three.js scene
  scene    = new THREE.Scene();
  scene.background = new THREE.Color(0x0a0a12);
  scene.fog = new THREE.FogExp2(0x0a0a12, 0.018);

  camera   = new THREE.PerspectiveCamera(55, 1, 0.1, 500);
  camera.position.set(0, 12, 32);
  camera.lookAt(0, 0, 0);

  const container = document.getElementById('canvas-container');
  renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setPixelRatio(window.devicePixelRatio);
  container.appendChild(renderer.domElement);

  // Lights
  scene.add(new THREE.AmbientLight(0x334466, 1.2));
  const dir = new THREE.DirectionalLight(0x8899cc, 0.8);
  dir.position.set(10, 20, 10);
  scene.add(dir);

  raycaster = new THREE.Raycaster();
  mouse     = new THREE.Vector2();

  // Orbit controls (manual)
  initOrbitControls(container);

  // Resize handler
  window.addEventListener('resize', onResize);
  onResize();

  // Node click
  renderer.domElement.addEventListener('click', onCanvasClick);

  // Load data
  loadGraphData();

  animate();
}

/* ------------------------------------------------------------------ */
/* Data loading                                                         */
/* ------------------------------------------------------------------ */

function loadGraphData() {
  // Prefer inline GRAPH_DATA (file:// compatible) then fall back to fetch
  if (typeof GRAPH_DATA !== 'undefined') {
    buildScene(GRAPH_DATA);
    return;
  }
  fetch('graph_data.json')
    .then(r => r.json())
    .then(buildScene)
    .catch(() => {
      document.getElementById('loading').textContent =
        'No graph_data.json found. Run the pipeline to generate data.';
    });
}

/* ------------------------------------------------------------------ */
/* Scene construction                                                   */
/* ------------------------------------------------------------------ */

function buildScene(data) {
  graphData = data;

  // --- Nodes ---
  data.nodes.forEach(node => {
    const radius = 0.18 + node.privilege * 0.22;
    const geo  = new THREE.SphereGeometry(radius, NODE_SEGMENTS, NODE_SEGMENTS);
    const col  = STATE_COLORS[node.state] ?? STATE_COLORS.safe;
    const mat  = new THREE.MeshPhongMaterial({
      color: col,
      emissive: col,
      emissiveIntensity: 0.25,
      shininess: 40,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.set(node.x, node.z, node.y);   // z = privilege height
    mesh.userData = node;
    scene.add(mesh);
    nodeMeshes[node.id] = mesh;
  });

  // --- Edges ---
  const posMap = {};
  data.nodes.forEach(n => { posMap[n.id] = new THREE.Vector3(n.x, n.z, n.y); });

  data.edges.forEach(edge => {
    const src = posMap[edge.source];
    const tgt = posMap[edge.target];
    if (!src || !tgt) return;

    const points = [src, tgt];
    const geo    = new THREE.BufferGeometry().setFromPoints(points);
    const col    = EDGE_COLORS[edge.type] ?? EDGE_COLORS.UNKNOWN;
    const mat    = new THREE.LineBasicMaterial({
      color: col,
      transparent: true,
      opacity: EDGE_OPACITY,
    });
    const line = new THREE.Line(geo, mat);
    line.userData = edge;
    scene.add(line);
    edgeLines.push(line);

    // Arrowhead: small sphere at the target end to show direction
    const dir   = new THREE.Vector3().subVectors(tgt, src).normalize();
    const ahead = tgt.clone().addScaledVector(dir, -0.25);
    const ageo  = new THREE.SphereGeometry(0.08, 6, 6);
    const amat  = new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.85 });
    const arrow = new THREE.Mesh(ageo, amat);
    arrow.position.copy(ahead);
    scene.add(arrow);
  });

  // --- UI metadata ---
  updatePanel(data);
  document.getElementById('loading').classList.add('hidden');
}

/* ------------------------------------------------------------------ */
/* Panel update                                                         */
/* ------------------------------------------------------------------ */

function updatePanel(data) {
  const meta = data.metadata || {};

  // Topology badge
  const badge = document.getElementById('topology-badge');
  if (badge) badge.textContent = data.topology || 'unknown';

  setText('val-nodes',    data.nodes.length);
  setText('val-edges',    data.edges.length);
  setText('val-pbr',      meta.pbr_size   ?? '--');
  setText('val-vbr',      meta.vbr_size   ?? '--');
  setText('val-gap',      meta.gap_size   ?? '--');
  setText('val-class',    meta.gap_classification ?? '--');
  setText('val-egd',      meta.exploitability_gap_score != null
                            ? meta.exploitability_gap_score.toFixed(4)
                            : '--');

  // Count states
  const counts = {};
  data.nodes.forEach(n => { counts[n.state] = (counts[n.state] || 0) + 1; });
  setText('cnt-compromised',    counts.compromised    || 0);
  setText('cnt-critical_miss',  counts.critical_miss  || 0);
  setText('cnt-predicted_only', counts.predicted_only || 0);
  setText('cnt-contained',      counts.contained      || 0);
  setText('cnt-safe',           counts.safe           || 0);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* ------------------------------------------------------------------ */
/* Node picking                                                         */
/* ------------------------------------------------------------------ */

function onCanvasClick(event) {
  const rect = renderer.domElement.getBoundingClientRect();
  mouse.x = ((event.clientX - rect.left) / rect.width)  * 2 - 1;
  mouse.y = -((event.clientY - rect.top)  / rect.height) * 2 + 1;

  raycaster.setFromCamera(mouse, camera);
  const meshList = Object.values(nodeMeshes);
  const hits = raycaster.intersectObjects(meshList, false);

  if (hits.length > 0) {
    showNodeInfo(hits[0].object.userData);
  } else {
    clearNodeInfo();
  }
}

function showNodeInfo(node) {
  const el = document.getElementById('node-info');
  el.classList.add('active');
  el.innerHTML = `
    <strong>${node.id}</strong><br>
    Type: ${node.type}<br>
    State: <em>${node.state}</em><br>
    Privilege: ${node.privilege.toFixed(3)}<br>
    Risk score: ${node.risk.toFixed(4)}<br>
    Position: (${node.x.toFixed(1)}, ${node.y.toFixed(1)}, ${node.z.toFixed(1)})
  `;
}

function clearNodeInfo() {
  const el = document.getElementById('node-info');
  el.classList.remove('active');
  el.textContent = 'Click a node to inspect it.';
}

/* ------------------------------------------------------------------ */
/* Manual orbit controls (spherical coordinates)                       */
/* ------------------------------------------------------------------ */

let orbit = {
  theta: 0.4,     // horizontal angle (radians)
  phi:   1.1,     // vertical angle (radians)
  radius: 32,
  panX: 0,
  panY: 0,
  dragging: false,
  panning: false,
  lastX: 0,
  lastY: 0,
};

function initOrbitControls(container) {
  container.addEventListener('mousedown', e => {
    if (e.button === 0) { orbit.dragging = true; orbit.panning = false; }
    if (e.button === 2) { orbit.panning  = true; orbit.dragging = false; }
    orbit.lastX = e.clientX;
    orbit.lastY = e.clientY;
  });

  window.addEventListener('mouseup', () => {
    orbit.dragging = false;
    orbit.panning  = false;
  });

  window.addEventListener('mousemove', e => {
    const dx = e.clientX - orbit.lastX;
    const dy = e.clientY - orbit.lastY;
    orbit.lastX = e.clientX;
    orbit.lastY = e.clientY;

    if (orbit.dragging) {
      orbit.theta -= dx * 0.008;
      orbit.phi    = Math.max(0.1, Math.min(Math.PI - 0.1, orbit.phi - dy * 0.008));
    }
    if (orbit.panning) {
      orbit.panX -= dx * 0.03;
      orbit.panY += dy * 0.03;
    }
    updateCamera();
  });

  container.addEventListener('wheel', e => {
    orbit.radius = Math.max(5, Math.min(150, orbit.radius + e.deltaY * 0.05));
    updateCamera();
    e.preventDefault();
  }, { passive: false });

  container.addEventListener('contextmenu', e => e.preventDefault());
}

function updateCamera() {
  const r  = orbit.radius;
  const ph = orbit.phi;
  const th = orbit.theta;
  camera.position.set(
    orbit.panX + r * Math.sin(ph) * Math.sin(th),
    orbit.panY + r * Math.cos(ph),
    r * Math.sin(ph) * Math.cos(th),
  );
  camera.lookAt(orbit.panX, orbit.panY, 0);
}

/* ------------------------------------------------------------------ */
/* Resize                                                               */
/* ------------------------------------------------------------------ */

function onResize() {
  const container = document.getElementById('canvas-container');
  const w = container.clientWidth;
  const h = container.clientHeight;
  renderer.setSize(w, h);
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
}

/* ------------------------------------------------------------------ */
/* Animation loop                                                       */
/* ------------------------------------------------------------------ */

function animate() {
  requestAnimationFrame(animate);
  renderer.render(scene, camera);
}
