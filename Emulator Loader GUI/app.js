'use strict';
(function () {

// ── 0. API config ─────────────────────────────────────────────────────────────
function apiBase() {
  return window.IMMORTAL_API || 'http://127.0.0.1:3000';
}
const IMMORTAL_PORTAL = window.IMMORTAL_PORTAL || '../portal/index.html';
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.portal-link').forEach((portal) => {
    portal.href = IMMORTAL_PORTAL;
    portal.addEventListener('click', (e) => {
      if (window.IMMORTAL_IS_WEBVIEW && window.chrome && window.chrome.webview) {
        e.preventDefault();
        nativeSend({ action: 'openPortal' });
      }
    });
  });
  paintApiBadge();
  probeApiHealth();
});

async function apiFetch(path, opts = {}, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(`${apiBase()}${path}`, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

function paintApiBadge(state, detail) {
  let el = document.getElementById('api-badge');
  if (!el) {
    el = document.createElement('div');
    el.id = 'api-badge';
    el.className = 'api-badge';
    document.body.appendChild(el);
  }
  el.dataset.state = state || 'pending';
  el.textContent = detail || (state === 'ok' ? 'API ONLINE' : state === 'down' ? 'API OFFLINE' : 'API …');
}

function paintHostBadge(state, detail) {
  let el = document.getElementById('host-badge');
  if (!el) {
    el = document.createElement('div');
    el.id = 'host-badge';
    el.className = 'host-badge';
    document.body.appendChild(el);
  }
  el.dataset.state = state || 'pending';
  el.textContent = detail || (state === 'ok' ? 'HOST ONLINE' : state === 'browser' ? 'BROWSER' : 'HOST …');
}

async function probeApiHealth() {
  paintApiBadge('pending', 'API …');
  try {
    const res = await apiFetch('/health', {}, 4000);
    const data = await res.json().catch(() => ({}));
    if (data.status === 'degraded' || data.db === 'down') {
      paintApiBadge('pending', data.version ? `API ${data.version} · DB?` : 'API DEGRADED');
      return false;
    }
    if (!res.ok) throw new Error('bad');
    paintApiBadge('ok', data.version ? `API ${data.version}` : 'API ONLINE');
    return true;
  } catch (_) {
    paintApiBadge('down', 'API OFFLINE');
    return false;
  }
}

// ── Device fingerprint (SHA-256 of browser hardware signals) ─────────────────
async function getDeviceFingerprint() {
  const c = document.createElement('canvas');
  const g = c.getContext('2d');
  g.textBaseline = 'top';
  g.font = '14px Segoe UI';
  g.fillStyle = '#a855f7';
  g.fillText('Immortal\u{1F52E}2024', 2, 2);
  const canvas = c.toDataURL();

  const parts = [
    navigator.userAgent,
    navigator.language,
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    String(navigator.hardwareConcurrency || 0),
    String(navigator.deviceMemory || 0),
    navigator.platform,
    canvas,
  ].join('|');

  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(parts));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Token storage (sessionStorage preferred; falls back to memory) ────────────
const Tokens = (function () {
  const mem = { access: '', refresh: '' };
  const useSession = !!(window.IMMORTAL_SECURE_STORAGE !== false && window.sessionStorage);
  return {
    save(access, refresh) {
      mem.access = access || '';
      mem.refresh = refresh || '';
      try {
        if (useSession) {
          sessionStorage.setItem('immortal_access', mem.access);
          sessionStorage.setItem('immortal_refresh', mem.refresh);
          localStorage.removeItem('immortal_access');
          localStorage.removeItem('immortal_refresh');
        }
      } catch (_) {}
    },
    access() {
      if (mem.access) return mem.access;
      try { return (useSession && sessionStorage.getItem('immortal_access')) || ''; }
      catch { return ''; }
    },
    refresh() {
      if (mem.refresh) return mem.refresh;
      try { return (useSession && sessionStorage.getItem('immortal_refresh')) || ''; }
      catch { return ''; }
    },
    clear() {
      mem.access = '';
      mem.refresh = '';
      try {
        sessionStorage.removeItem('immortal_access');
        sessionStorage.removeItem('immortal_refresh');
        localStorage.removeItem('immortal_access');
        localStorage.removeItem('immortal_refresh');
      } catch (_) {}
    },
  };
})();

async function collectBrowserHardwareInfo() {
  return {
    processorName: navigator.userAgent.slice(0, 200),
    totalMemory: (navigator.deviceMemory || 0) * 1024 * 1024 * 1024,
    screenResolution: `${screen.width}x${screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    cpuId: String(navigator.hardwareConcurrency || 0),
    motherboardSerial: '',
    diskSerial: '',
    biosSerial: '',
    macAddress: '',
    systemUuid: '',
  };
}

let _hbTimer = null;
function startClientHeartbeat() {
  stopClientHeartbeat();
  _hbTimer = setInterval(async () => {
    const tok = Tokens.access();
    if (!tok) return;
    try {
      const res = await apiFetch('/api/auth/heartbeat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tok}`,
        },
        body: JSON.stringify({ sessionCheck: true }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.status === 'REVOKED') {
        Tokens.clear();
        nativeSend({ action: 'sessionRevoked' });
        showScreen('login');
      }
    } catch (_) {}
  }, 60000);
}
function stopClientHeartbeat() {
  if (_hbTimer) clearInterval(_hbTimer);
  _hbTimer = null;
}

// ── 1. Native WebView2 bridge ─────────────────────────────────────────────────
const isNative = !!(window.chrome && window.chrome.webview);
let g_activeAction = '';
let g_hostOnline = false;
let g_loadWatch = null;
document.body.classList.remove('is-webview-pending');
document.body.classList.add(isNative ? 'is-webview' : 'is-browser');
paintHostBadge(isNative ? 'pending' : 'browser', isNative ? 'HOST …' : 'BROWSER');

function nativeSend(obj) {
  if (!isNative || !obj) return;
  try {
    window.chrome.webview.postMessage(typeof obj === 'string' ? obj : JSON.stringify(obj));
  } catch (_) {}
}

function parseHostMessage(raw) {
  if (raw == null) return null;
  if (typeof raw === 'object') return raw;
  if (typeof raw !== 'string') return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

function clearLoadWatch() {
  if (g_loadWatch) {
    clearTimeout(g_loadWatch);
    g_loadWatch = null;
  }
}

function armLoadWatch(ms) {
  clearLoadWatch();
  g_loadWatch = setTimeout(() => {
    g_loadWatch = null;
    onLoadError({ error: 'Host timed out — check WebView bridge' });
  }, ms || 12000);
}

function bindWebViewBridge() {
  if (!isNative) return;
  const wv = window.chrome.webview;
  wv.addEventListener('message', (ev) => {
    const msg = parseHostMessage(ev.data);
    if (msg && msg.action) window.handleNativeMessage(msg);
  });
  window.addEventListener('message', (ev) => {
    if (!ev || ev.source !== window) return;
    const msg = parseHostMessage(ev.data);
    if (msg && msg.action) window.handleNativeMessage(msg);
  });
  nativeSend({ action: 'uiReady', version: '2.3' });
  nativeSend({ action: 'ping' });
  setTimeout(() => {
    if (!g_hostOnline) paintHostBadge('pending', 'HOST WAIT');
  }, 2500);
}

// C++ → JS entry point (also callable from injected host scripts)
window.handleNativeMessage = function (msg) {
  if (!msg || !msg.action) return;
  switch (msg.action) {
    case 'hostReady':
      g_hostOnline = true;
      paintHostBadge('ok', msg.version ? `HOST ${msg.version}` : 'HOST ONLINE');
      break;
    case 'pong':
      g_hostOnline = true;
      paintHostBadge('ok', 'HOST ONLINE');
      break;
    case 'prefillKey':
      {
        const el = document.getElementById('key-input');
        if (el) {
          el.value = formatLicenseKey(msg.key || '');
          focusKeyField(true);
        }
      }
      break;
    case 'focusKey':
      focusKeyField(true);
      break;
    case 'setApi':
      if (msg.url) {
        window.IMMORTAL_API = String(msg.url);
        probeApiHealth();
      }
      break;
    case 'authOk':        onAuthOk(msg);        break;
    case 'authFail':      onAuthFail(msg);       break;
    case 'gameStatus':    onGameStatus(msg);     break;
    case 'loadProgress':  onLoadProgress(msg);   break;
    case 'loadDone':      onLoadDone(msg);       break;
    case 'loadError':     onLoadError(msg);      break;
    case 'spoofProgress': onLoadProgress(msg);   break;
    case 'spoofDone':     msg.success ? onLoadDone(msg) : onLoadError(msg); break;
    case 'hotkeySet':     onHotkeySet(msg);      break;
    case 'emuActive':     onEmuActive(msg);      break;
    case 'emuLog':        onEmuLog(msg);         break;
    case 'sessionRevoked':
      Tokens.clear();
      stopClientHeartbeat();
      showScreen('login');
      paintHostBadge('pending', 'SESSION LOST');
      break;
  }
};

bindWebViewBridge();

function focusKeyField(selectAll) {
  const el = document.getElementById('key-input');
  if (!el) return;
  try {
    el.focus({ preventScroll: true });
    if (selectAll) el.select();
    else {
      const n = el.value.length;
      el.setSelectionRange(n, n);
    }
  } catch (_) {
    try { el.focus(); } catch (__) {}
  }
}

// ── 2. Starfield canvas — parallax deep sky, drifting through Saturn orbit ────
// Perf contract: the sky is split into one STATIC layer (nebula + the faint
// majority of stars, painted once into an offscreen canvas that the compositor
// then reuses for free) and one ANIMATED layer of ~900 brighter stars. Sprites
// are quantised and bound to each star at build time, so the draw loop does no
// allocation, no string keys and no map lookups.
(function () {
  const canvas = document.getElementById('stars');
  if (!canvas) return;
  const ctx = canvas.getContext('2d', { alpha: true });

  // stars are soft glows — backing store above ~1.25x buys nothing visible
  const dpr = Math.min(window.devicePixelRatio || 1, 1.25);

  // static deep-sky layer lives in its own element so it never repaints
  const deep = document.createElement('canvas');
  deep.id = 'deep-sky';
  canvas.parentNode.insertBefore(deep, canvas);
  const dctx = deep.getContext('2d');

  let W = 0, H = 0;
  let layers  = [];
  let motes   = [];
  let meteors = [];
  let nextMeteor = 4000;
  let last = 0;

  /* ── Adaptive quality ──────────────────────────────────────────────────────
     This runs on whatever GPU the user happens to have, inside WebView2. If
     frames start costing too much we shed work in stages rather than just
     stuttering. Tier 1 drops the densest star layer, the dust and every
     backdrop blur; tier 2 parks the animated canvas altogether and leaves the
     static deep-sky plate on screen — which still reads as a full starfield.
     Wide hysteresis so it settles instead of flapping.                      */
  let tier = 0, budget = 0, budgetFrames = 0;

  function setTier(t) {
    if (t === tier) return;
    tier = t;
    document.body.classList.toggle('perf-lite', t >= 1);
    canvas.style.display = t >= 2 ? 'none' : '';
  }

  function assess(dt) {
    budget += dt; budgetFrames++;
    if (budget < 2000) return;
    const avg = budget / budgetFrames;
    budget = 0; budgetFrames = 0;
    if (avg > 26 && tier < 2)      setTier(tier + 1);   // worse than ~38fps
    else if (avg < 14 && tier > 0) setTier(tier - 1);   // comfortably >60fps
  }

  const mouse = { x: 0, y: 0, px: 0, py: 0 };
  const sprites = new Map();   // quantised bucket → sprite canvas

  // Stellar colours across the spectral classes (O→M), leaned toward violet so
  // the sky belongs to the purple theme while the stars stay believably white.
  const SPECTRUM = [
    [186, 168, 255], [206, 190, 255], [226, 212, 255], [244, 238, 255],
    [255, 253, 255], [252, 240, 255], [246, 222, 255], [238, 200, 252],
  ];

  const rand = (a, b) => a + Math.random() * (b - a);

  /* Glow sprite, cached per (colour index, quantised radius). Quantising to
     0.25px keeps the cache to a few dozen bitmaps instead of one per star. */
  function glowSprite(ci, radius) {
    const q = Math.max(1, Math.round(radius * 4));      // 0.25px buckets
    const key = ci * 1000 + q;
    let c = sprites.get(key);
    if (c) return c;

    const r = q / 4;
    const size = Math.max(8, Math.ceil(r * 9));
    c = document.createElement('canvas');
    c.width = c.height = size;
    const g = c.getContext('2d');
    const m = size / 2;
    const [cr, cg, cb] = SPECTRUM[ci];
    const grd = g.createRadialGradient(m, m, 0, m, m, m);
    grd.addColorStop(0,    'rgba(255,255,255,1)');
    grd.addColorStop(0.10, `rgba(${cr},${cg},${cb},.98)`);
    grd.addColorStop(0.22, `rgba(${cr},${cg},${cb},.42)`);
    grd.addColorStop(0.45, `rgba(${cr},${cg},${cb},.10)`);
    grd.addColorStop(1,    `rgba(${cr},${cg},${cb},0)`);
    g.fillStyle = grd;
    g.fillRect(0, 0, size, size);
    sprites.set(key, c);
    return c;
  }

  /* Diffraction spikes — the four-point flare a lens throws on bright stars. */
  function spikeSprite(ci) {
    const key = -1 - ci;
    let c = sprites.get(key);
    if (c) return c;

    const size = 96, m = size / 2;
    c = document.createElement('canvas');
    c.width = c.height = size;
    const g = c.getContext('2d');
    const [r, gr, b] = SPECTRUM[ci];

    for (let i = 0; i < 2; i++) {
      const len = i === 0 ? m : m * 0.55;
      const grd = g.createLinearGradient(m - len, m, m + len, m);
      grd.addColorStop(0,   `rgba(${r},${gr},${b},0)`);
      grd.addColorStop(0.5, `rgba(${r},${gr},${b},.55)`);
      grd.addColorStop(1,   `rgba(${r},${gr},${b},0)`);
      g.save();
      g.translate(m, m);
      g.rotate(i === 0 ? 0 : Math.PI / 2);
      g.translate(-m, -m);
      g.fillStyle = grd;
      g.fillRect(m - len, m - 0.7, len * 2, 1.4);
      g.restore();
    }
    sprites.set(key, c);
    return c;
  }

  /* ── Static layer: nebula veils, the galactic band, and the faint majority
     of the stars. Painted once per resize; costs nothing per frame. ───────── */
  function buildDeepSky() {
    const w = Math.max(1, Math.ceil(W / 2)), h = Math.max(1, Math.ceil(H / 2));
    deep.width = w; deep.height = h;
    deep.style.width  = W + 'px';
    deep.style.height = H + 'px';
    const g = dctx;
    g.setTransform(1, 0, 0, 1, 0, 0);
    g.clearRect(0, 0, w, h);

    // the band: a soft diagonal river of light across the whole sky
    g.save();
    g.translate(w * 0.5, h * 0.5);
    g.rotate(-0.42);
    const band = g.createLinearGradient(0, -h * 0.55, 0, h * 0.55);
    band.addColorStop(0,    'rgba(140,90,210,0)');
    band.addColorStop(0.36, 'rgba(146,96,214,.040)');
    band.addColorStop(0.5,  'rgba(196,150,246,.065)');
    band.addColorStop(0.64, 'rgba(146,96,214,.040)');
    band.addColorStop(1,    'rgba(140,90,210,0)');
    g.fillStyle = band;
    g.fillRect(-w, -h * 0.55, w * 2, h * 1.1);
    g.restore();

    // scattered emission clouds — cool cyan/violet with a warm ember or two
    const clouds = [
      ['rgba(138,66,224,',  0.055], ['rgba(176,110,255,', 0.042],
      ['rgba(96,46,178,',   0.045], ['rgba(214,150,255,', 0.030],
      ['rgba(112,72,206,',  0.040],
    ];
    for (let i = 0; i < 16; i++) {
      const [tint, peak] = clouds[i % clouds.length];
      const cx = rand(-0.1, 1.1) * w, cy = rand(-0.1, 1.1) * h;
      const radius = rand(0.16, 0.5) * Math.max(w, h);
      const grd = g.createRadialGradient(cx, cy, 0, cx, cy, radius);
      grd.addColorStop(0,   tint + (peak * rand(0.6, 1)).toFixed(3) + ')');
      grd.addColorStop(0.5, tint + (peak * 0.28).toFixed(3) + ')');
      grd.addColorStop(1,   tint + '0)');
      g.fillStyle = grd;
      g.fillRect(0, 0, w, h);
    }

    // dark dust lanes bite back into the band so it isn't a smooth smear
    g.globalCompositeOperation = 'destination-out';
    for (let i = 0; i < 22; i++) {
      const cx = rand(0, w), cy = rand(0, h), radius = rand(15, 75);
      const grd = g.createRadialGradient(cx, cy, 0, cx, cy, radius);
      grd.addColorStop(0, 'rgba(0,0,0,.5)');
      grd.addColorStop(1, 'rgba(0,0,0,0)');
      g.fillStyle = grd;
      g.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);
    }
    g.globalCompositeOperation = 'source-over';

    // the faint background multitude — these barely twinkle, so bake them in
    const faint = Math.floor(w * h / 900);
    for (let i = 0; i < faint; i++) {
      const ci = Math.floor(Math.pow(Math.random(), 1.6) * SPECTRUM.length);
      const [r, gg, b] = SPECTRUM[ci];
      const a = 0.10 + Math.pow(Math.random(), 2.2) * 0.42;
      const rad = 0.28 + Math.random() * 0.5;
      g.fillStyle = `rgba(${r},${gg},${b},${a.toFixed(3)})`;
      g.beginPath();
      g.arc(Math.random() * w, Math.random() * h, rad, 0, 6.2832);
      g.fill();
    }
  }

  function makeStar(depth) {
    const ci   = Math.floor(Math.pow(Math.random(), 1.5) * SPECTRUM.length);
    const mag  = Math.pow(Math.random(), 3.1);      // few bright, many faint
    const size = (0.45 + mag * 2.6) * (0.6 + depth * 0.7);
    const spike = mag > 0.87 && depth > 0.45;
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      ci,
      base: 0.24 + mag * 0.76,
      f1: rand(0.0006, 0.0032), p1: rand(0, 6.28),
      f2: rand(0.0021, 0.0090), p2: rand(0, 6.28),
      amp: rand(0.10, 0.42) * (1 - depth * 0.45),
      drift: (0.10 + depth * 0.30) * rand(0.55, 1),
      sprite: glowSprite(ci, size),
      flare: spike ? spikeSprite(ci) : null,
      fsize: 22 + size * 15,
    };
  }

  function build() {
    W = window.innerWidth; H = window.innerHeight;
    canvas.width  = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    buildDeepSky();

    const area = W * H;
    layers = [0.18, 0.45, 0.8, 1].map((depth, i) => {
      const density = [3200, 5000, 9000, 16000][i];
      const n = Math.max(12, Math.floor(area / density));
      const stars = [];
      for (let k = 0; k < n; k++) stars.push(makeStar(depth));
      return { depth, stars };
    });

    motes = [];
    const dustCount = Math.floor(area / 70000);
    for (let i = 0; i < dustCount; i++) {
      const rr = rand(1.6, 5.2);
      motes.push({
        x: Math.random() * W, y: Math.random() * H,
        a: rand(0.03, 0.11),
        vx: rand(-0.10, 0.10), vy: rand(0.05, 0.26),
        f: rand(0.0004, 0.0016), p: rand(0, 6.28),
        sprite: glowSprite(3, rr),
      });
    }

    meteors = [];
  }

  function spawnMeteor() {
    const fromLeft = Math.random() < 0.68;
    const ang = fromLeft ? rand(0.28, 0.62) : Math.PI - rand(0.28, 0.62);
    meteors.push({
      x: fromLeft ? rand(-0.1, 0.6) * W : rand(0.4, 1.1) * W,
      y: rand(-0.12, 0.42) * H,
      vx: Math.cos(ang) * rand(7, 14),
      vy: Math.sin(ang) * rand(7, 14),
      life: 0,
      span: rand(620, 1150),
      len: rand(90, 240),
      w: rand(0.8, 1.9),
    });
  }

  function draw(now) {
    // the loader can be hidden mid-game — don't burn frames on an unseen sky
    if (document.hidden) { last = now; requestAnimationFrame(draw); return; }
    const dt = Math.min(50, now - last || 16); last = now;
    assess(dt);
    if (tier >= 2) { requestAnimationFrame(draw); return; }

    // eased pointer parallax — the sky lags behind the head turn
    mouse.px += (mouse.x - mouse.px) * 0.045;
    mouse.py += (mouse.y - mouse.py) * 0.045;
    const offX = mouse.px - W / 2, offY = mouse.py - H / 2;

    // static layer drifts via a compositor-only transform — free
    deep.style.transform =
      'translate3d(' + (offX * -0.006).toFixed(1) + 'px,' +
                       (offY * -0.006).toFixed(1) + 'px,0)';

    ctx.clearRect(0, 0, W, H);

    const step = dt / 16;

    // tier 1 drops the densest (and least individually visible) layer
    const firstLayer = tier >= 1 ? 1 : 0;
    for (let li = firstLayer; li < layers.length; li++) {
      const layer = layers[li];
      const px = offX * -0.016 * layer.depth;
      const py = offY * -0.011 * layer.depth;
      const stars = layer.stars;

      for (let i = 0; i < stars.length; i++) {
        const s = stars[i];
        s.y += s.drift * step;
        if (s.y > H + 6) { s.y = -6; s.x = Math.random() * W; }

        const tw = 1 + (Math.sin(now * s.f1 + s.p1) * 0.66 +
                        Math.sin(now * s.f2 + s.p2) * 0.34) * s.amp;
        const a = s.base * tw;
        if (a < 0.02) continue;

        const sp = s.sprite;
        const d  = sp.width;
        ctx.globalAlpha = a > 1 ? 1 : a;
        ctx.drawImage(sp, (s.x + px - d * 0.5) | 0, (s.y + py - d * 0.5) | 0);

        if (s.flare && a > 0.45) {
          const fd = s.fsize;
          ctx.globalAlpha = (a - 0.45) * 0.85;
          ctx.drawImage(s.flare, (s.x + px - fd * 0.5) | 0,
                                 (s.y + py - fd * 0.5) | 0, fd, fd);
        }
      }
    }

    // near dust
    const dx = offX * -0.045, dy = offY * -0.035;
    for (let i = 0; tier === 0 && i < motes.length; i++) {
      const m = motes[i];
      m.x += m.vx * step; m.y += m.vy * step;
      if (m.y > H + 8) { m.y = -8; m.x = Math.random() * W; }
      if (m.x < -8) m.x = W + 8; else if (m.x > W + 8) m.x = -8;
      ctx.globalAlpha = m.a * (0.6 + 0.4 * Math.sin(now * m.f + m.p));
      const sp = m.sprite;
      ctx.drawImage(sp, (m.x + dx - sp.width * 0.5) | 0,
                        (m.y + dy - sp.height * 0.5) | 0);
    }

    // meteors
    nextMeteor -= dt;
    if (nextMeteor <= 0) { spawnMeteor(); nextMeteor = rand(5200, 15000); }
    for (let i = meteors.length - 1; i >= 0; i--) {
      const m = meteors[i];
      m.life += dt;
      m.x += m.vx * step; m.y += m.vy * step;
      const t = m.life / m.span;
      if (t >= 1) { meteors.splice(i, 1); continue; }

      const fade = Math.sin(Math.PI * t);
      const h = Math.hypot(m.vx, m.vy) || 1;
      const tx = m.x - (m.vx / h) * m.len, ty = m.y - (m.vy / h) * m.len;
      const grd = ctx.createLinearGradient(tx, ty, m.x, m.y);
      grd.addColorStop(0,   'rgba(190,140,255,0)');
      grd.addColorStop(0.7, `rgba(216,180,255,${(0.30 * fade).toFixed(3)})`);
      grd.addColorStop(1,   `rgba(255,250,255,${(0.9 * fade).toFixed(3)})`);
      ctx.globalAlpha = 1;
      ctx.strokeStyle = grd;
      ctx.lineWidth = m.w;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(m.x, m.y);
      ctx.stroke();
    }

    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }

  let resizeTimer = 0;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(build, 200);
  });
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; },
                          { passive: true });

  mouse.x = mouse.px = window.innerWidth / 2;
  mouse.y = mouse.py = window.innerHeight / 2;
  build();
  requestAnimationFrame(draw);
})();

// ── 3. Custom cursor ──────────────────────────────────────────────────────────
(function () {
  const dot  = document.getElementById('cursor-dot');
  const tail = document.getElementById('cursor-tail');
  let mx = -200, my = -200, dx = -200, dy = -200;

  window.addEventListener('mousemove', e => { mx = e.clientX; my = e.clientY; });
  document.querySelectorAll('button,.card,input').forEach(el => {
    el.addEventListener('mouseenter', () => document.body.classList.add('cursor-hover'));
    el.addEventListener('mouseleave', () => document.body.classList.remove('cursor-hover'));
  });
  document.addEventListener('mousedown', () => document.body.classList.add('cursor-down'));
  document.addEventListener('mouseup',   () => document.body.classList.remove('cursor-down'));

  (function tick() {
    dx += (mx - dx) * 0.12;
    dy += (my - dy) * 0.12;
    const vel = Math.hypot(mx - dx, my - dy);
    const sc  = 1 + Math.min(vel * 0.018, 0.3);
    dot.style.transform  = `translate(${mx}px,${my}px) translate(-50%,-50%)`;
    tail.style.transform = `translate(${dx}px,${dy}px) translate(-50%,-50%) scale(${sc})`;
    requestAnimationFrame(tick);
  })();
})();

// ── 4. Loader spinner build ───────────────────────────────────────────────────
(function () {
  [document.getElementById('loader-spinner'),
   document.getElementById('inj-spinner')].forEach(el => {
    if (!el) return;
    for (let i = 0; i < 10; i++) {
      const s = document.createElement('span');
      s.style.setProperty('--r', `${i * 36}deg`);
      s.style.animationDelay = `${-i * 0.1}s`;
      el.appendChild(s);
    }
  });
})();

// ── 5. View router ────────────────────────────────────────────────────────────
const screens = {
  login:   document.getElementById('view-login'),
  main:    document.getElementById('view-main'),
  loading: document.getElementById('view-loading'),
  result:  document.getElementById('view-result'),
};
let currentScreen = null;

function showScreen(name) {
  if (currentScreen === name) return;
  if (currentScreen && screens[currentScreen]) {
    screens[currentScreen].classList.remove('active');
  }
  currentScreen = name;
  if (screens[name]) {
    screens[name].classList.add('active');
  }
}

// ── 6. Boot sequence ──────────────────────────────────────────────────────────
let bootDone        = false;
let pendingAuthMsg  = null; // {ok, msg} set before boot done

const loader    = document.getElementById('site-loader');
const loaderSts = document.getElementById('loader-status');

function dismissLoader() {
  loader.classList.add('dismissed');
}

setTimeout(() => {
  bootDone = true;
  if (pendingAuthMsg) {
    dismissLoader();
    if (pendingAuthMsg.ok) {
      applyAuthOk(pendingAuthMsg.data);
    } else {
      applyAuthFail(pendingAuthMsg.data);
    }
  } else {
    dismissLoader();
    showScreen('login');
    setTimeout(() => focusKeyField(false), 100);
  }
}, 2800);

// Pulse loader status
const statusLabels = [
  'Opening secure channel..',
  'Handshake with control plane..',
  'Binding session keys..',
  'Integrity sweep..',
  'Ready.',
];
let sli = 0;
const statusInterval = setInterval(() => {
  sli = Math.min(sli + 1, statusLabels.length - 1);
  loaderSts.textContent = statusLabels[sli];
  if (sli === statusLabels.length - 1) clearInterval(statusInterval);
}, 700);

// ── 7. Auth handlers ──────────────────────────────────────────────────────────
function onAuthOk(msg) {
  if (!bootDone) {
    pendingAuthMsg = { ok: true, data: msg };
  } else {
    dismissLoader();
    applyAuthOk(msg);
  }
}
function onAuthFail(msg) {
  if (!bootDone) {
    pendingAuthMsg = { ok: false, data: msg };
  } else {
    dismissLoader();
    applyAuthFail(msg);
  }
}

function applyAuthOk(msg) {
  const userEl = document.getElementById('main-user');
  if (userEl) {
    const u = msg.username || '';
    const e = msg.expiry   || '';
    userEl.textContent = u + (e ? '  ·  ' + e : '');
  }
  updateCardAccess(msg.products || []);
  showScreen('main');
  setAuthBtnLoading(false);
}

function applyLock(card, hasAccess) {
  if (!card) return;
  card.classList.toggle('locked', !hasAccess);
  let chip = card.querySelector('.lock-chip');
  if (!hasAccess) {
    if (!chip) {
      chip = document.createElement('span');
      chip.className = 'lock-chip';
      chip.textContent = 'no access';
      card.appendChild(chip);
    }
  } else if (chip) {
    chip.remove();
  }
}

function updateCardAccess(products) {
  const owned = new Set((products || []).map(p => (p.id || p.name || '').toLowerCase()));
  applyLock(document.getElementById('load-card'),  owned.has('private'));
  applyLock(document.getElementById('emu-card'),   owned.has('emu'));
  applyLock(document.getElementById('spoof-card'), owned.has('spoofer'));
}

function humanAuthError(raw) {
  const e = String(raw || '').toLowerCase();
  if (e.includes('rate') || e.includes('too many')) return 'Too many tries. Wait a minute, then try again.';
  if (e.includes('license')) return 'That license key is invalid or expired.';
  if (e.includes('device')) return 'This device is not allowed for that license.';
  if (e.includes('network') || e.includes('fetch')) return 'Cannot reach Immortal API. Check your connection.';
  if (e.includes('replay') || e.includes('stale')) return 'Login expired. Try again.';
  return raw || 'Sign-in failed. Check your key and try again.';
}

function applyAuthFail(msg) {
  const err = humanAuthError(msg.error || msg.message || 'Authentication failed');
  showScreen('login');
  showAuthError(err);
  setAuthBtnLoading(false);
}

// ── 8. Login logic ────────────────────────────────────────────────────────────
const authBtn   = document.getElementById('auth-btn');
const keyInput  = document.getElementById('key-input');
const authError = document.getElementById('auth-error');

function formatLicenseKey(raw) {
  const alnum = String(raw || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
  return alnum.match(/.{1,4}/g)?.join('-') || '';
}

/** Keep caret stable while inserting dashes (critical in WebView2). */
function applyKeyFormat(el) {
  const old = el.value;
  const sel = el.selectionStart || 0;
  const rawBefore = old.slice(0, sel).toUpperCase().replace(/[^A-Z0-9]/g, '').length;
  const formatted = formatLicenseKey(old);
  if (formatted === old) return;
  el.value = formatted;
  let i = 0, seen = 0;
  while (i < formatted.length && seen < rawBefore) {
    if (/[A-Z0-9]/.test(formatted[i])) seen++;
    i++;
  }
  try { el.setSelectionRange(i, i); } catch (_) {}
}

if (keyInput) {
  keyInput.classList.add('key-masked');
  try {
    const last = localStorage.getItem('immortal_last_key') || '';
    if (last && !keyInput.value) keyInput.value = formatLicenseKey(last);
  } catch (_) {}
  keyInput.addEventListener('input', () => applyKeyFormat(keyInput));
  keyInput.addEventListener('paste', (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text');
    keyInput.value = formatLicenseKey(text);
    try {
      const n = keyInput.value.length;
      keyInput.setSelectionRange(n, n);
    } catch (_) {}
  });
  // WebView2 sometimes needs an explicit click-to-focus path
  keyInput.addEventListener('pointerdown', () => focusKeyField(false));
}

const keyReveal = document.getElementById('key-reveal');
if (keyReveal && keyInput) {
  keyReveal.addEventListener('click', () => {
    const masked = keyInput.classList.toggle('key-masked');
    keyReveal.textContent = masked ? '···' : 'ABC';
    focusKeyField(false);
  });
}

function setAuthBtnLoading(on) {
  authBtn.classList.toggle('loading', on);
  keyInput.disabled = on;
}

function showAuthError(msg) {
  authError.textContent = msg;
  authError.classList.add('visible');
  const wrap = document.getElementById('key-wrap');
  wrap.style.animation = 'none';
  wrap.offsetWidth; // reflow
  wrap.style.animation = 'shake .4s ease';
}

async function doLogin() {
  authError.classList.remove('visible');
  const key = formatLicenseKey(keyInput.value);
  keyInput.value = key;
  if (!key) { showAuthError('License key required'); return; }

  const fmt = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
  if (!fmt.test(key)) {
    showAuthError('Invalid key format');
    return;
  }

  setAuthBtnLoading(true);

  try {
    const fingerprint = await getDeviceFingerprint();
    const nonce       = crypto.randomUUID();
    const timestamp   = Math.floor(Date.now() / 1000);
    const hardwareInfo = await collectBrowserHardwareInfo();

    const online = await probeApiHealth();
    if (!online) {
      showAuthError('Cannot reach Immortal API — start the backend then retry');
      setAuthBtnLoading(false);
      return;
    }

    const res = await apiFetch('/api/auth/login/license', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: key, fingerprint, nonce, timestamp, hardwareInfo }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Authentication failed');

    Tokens.save(data.accessToken, data.refreshToken);
    try { localStorage.setItem('immortal_last_key', key); } catch (_) {}
    startClientHeartbeat();
    paintApiBadge('ok', 'API ONLINE');

    // Notify C++ host so it can persist the key and start game watch
    nativeSend({
      action:   'authOk',
      key,
      username: data.username || '',
      expiry:   data.expiry   || '',
      token:    data.accessToken,
    });

    onAuthOk({
      username: data.username || '',
      expiry:   data.expiry   || '',
      products: data.products || [],
    });

  } catch (err) {
    const msg =
      err.name === 'AbortError' ? 'Request timed out — try again'
      : err.message === 'Failed to fetch' ? 'Cannot reach Immortal servers'
      : (err.message || 'Authentication failed');
    showAuthError(msg);
    setAuthBtnLoading(false);
    paintApiBadge('down', 'API OFFLINE');
    nativeSend({ action: 'authFail', error: msg });
  }
}

authBtn.addEventListener('click', doLogin);
keyInput.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

// Shake keyframe (injected so it doesn't need a CSS file edit)
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `
@keyframes shake {
  0%,100%{ transform:translateX(0); }
  20%    { transform:translateX(-7px); }
  40%    { transform:translateX(7px); }
  60%    { transform:translateX(-5px); }
  80%    { transform:translateX(5px); }
}`;
document.head.appendChild(shakeStyle);

// ── 9. Game status ────────────────────────────────────────────────────────────
let gameReady = false;

function onGameStatus(msg) {
  gameReady = !!msg.ready;
  const dot    = document.getElementById('game-dot');
  const text   = document.getElementById('game-text');
  const badge  = document.getElementById('load-badge');
  const card   = document.getElementById('load-card');
  const detail = (msg.detail && String(msg.detail)) || '';

  if (gameReady) {
    dot && dot.classList.add('ready');
    if (text) text.textContent = detail || 'Channel ready';
    if (badge) { badge.textContent = 'READY'; badge.classList.add('ready'); }
    card && card.classList.add('game-ready');
  } else {
    dot && dot.classList.remove('ready');
    if (text) text.textContent = detail || 'Waiting for host…';
    if (badge) { badge.textContent = 'WAITING'; badge.classList.remove('ready'); }
    card && card.classList.remove('game-ready');
  }
}

// ── 10. Load private ─────────────────────────────────────────────────────────
let loadBarRaf = null;
let loadBarPct = 0;

function startLoadBar() {
  loadBarPct = 0;
  if (loadBarRaf) { cancelAnimationFrame(loadBarRaf); loadBarRaf = null; }
  const bar = document.getElementById('loading-bar');
  let lastTime = 0;
  function tick(now) {
    const dt = lastTime ? Math.min(100, now - lastTime) : 16;
    lastTime = now;
    loadBarPct += (88 - loadBarPct) * 0.025 * (dt / 60);
    bar.style.width = loadBarPct.toFixed(1) + '%';
    loadBarRaf = loadBarPct < 87.9 ? requestAnimationFrame(tick) : null;
  }
  loadBarRaf = requestAnimationFrame(tick);
}

function finishLoadBar(success) {
  if (loadBarRaf) { cancelAnimationFrame(loadBarRaf); loadBarRaf = null; }
  document.getElementById('loading-bar').style.width = '100%';
  if (!success) {
    document.getElementById('loading-bar').style.background = 'var(--red)';
    document.getElementById('loading-bar').style.boxShadow  = '0 0 8px var(--red)';
  }
}

function onLoadProgress(msg) {
  const el = document.getElementById('loading-msg');
  if (el) el.textContent = msg.msg || 'Working...';
  armLoadWatch(12000);
}
function onLoadDone(msg) {
  clearLoadWatch();
  finishLoadBar(true);
  const note = (msg && msg.msg) ? String(msg.msg) : '';
  setTimeout(() => {
    if (g_activeAction === 'loadSpoofer') {
      showResultSpooferSuccess();
    } else {
      showResultSuccess(note);
    }
  }, 500);
}
function onLoadError(msg) {
  clearLoadWatch();
  finishLoadBar(false);
  setTimeout(() => {
    showResultError(msg.error || msg.msg || 'Load failed');
  }, 400);
}

function showResultSuccess(note) {
  const mark  = document.getElementById('result-mark');
  const icon  = document.getElementById('result-icon');
  const title = document.getElementById('result-title');
  const rmsg  = document.getElementById('result-msg');
  const rmsg2 = document.getElementById('result-msg2');
  mark.className = 'result-mark success';
  icon.innerHTML = '<polyline points="8,24 20,36 40,14" stroke="#e9e9ec" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
  title.textContent = 'READY';
  rmsg.textContent  = note || 'Loader pipeline finished.';
  if (rmsg2) rmsg2.textContent = isNative ? 'WebView host acknowledged the hand-off.' : 'Browser preview mode.';
  showScreen('result');
}
function showResultSpooferSuccess() {
  const mark  = document.getElementById('result-mark');
  const icon  = document.getElementById('result-icon');
  const title = document.getElementById('result-title');
  const rmsg  = document.getElementById('result-msg');
  const rmsg2 = document.getElementById('result-msg2');
  mark.className = 'result-mark success';
  icon.innerHTML = '<polyline points="8,24 20,36 40,14" stroke="#4ade80" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
  title.textContent = 'SPOOF COMPLETE';
  rmsg.textContent  = 'Your device profile has been reset successfully.';
  if (rmsg2) rmsg2.textContent = 'Reboot your PC before launching the game.';
  showScreen('result');
}
function showResultError(errText) {
  const mark  = document.getElementById('result-mark');
  const icon  = document.getElementById('result-icon');
  const title = document.getElementById('result-title');
  const rmsg  = document.getElementById('result-msg');
  const rmsg2 = document.getElementById('result-msg2');
  mark.className = 'result-mark error';
  icon.innerHTML = '<line x1="14" y1="14" x2="34" y2="34" stroke="#c96b6b" stroke-width="2" stroke-linecap="round"/><line x1="34" y1="14" x2="14" y2="34" stroke="#c96b6b" stroke-width="2" stroke-linecap="round"/>';
  title.textContent = 'FAILED';
  rmsg.textContent  = errText;
  if (rmsg2) rmsg2.textContent = '';
  showScreen('result');
}

// ── 11. Card interactions ─────────────────────────────────────────────────────
document.querySelectorAll('.card').forEach(card => {
  let tiltPending = false, pendingX = 0, pendingY = 0, cachedRect = null;

  card.addEventListener('mouseenter', () => {
    cachedRect = card.getBoundingClientRect();
  }, { passive: true });

  card.addEventListener('mousemove', e => {
    pendingX = e.clientX; pendingY = e.clientY;
    if (tiltPending) return;
    tiltPending = true;
    requestAnimationFrame(() => {
      tiltPending = false;
      const r = cachedRect || card.getBoundingClientRect();
      const x = (pendingX - r.left) / r.width  - 0.5;
      const y = (pendingY - r.top)  / r.height - 0.5;
      card.style.transform = `perspective(700px) rotateX(${(-y * 5).toFixed(2)}deg) rotateY(${(x * 5).toFixed(2)}deg) translateY(-7px)`;
      card.style.setProperty('--mx', `${((pendingX - r.left) / r.width  * 100).toFixed(1)}%`);
      card.style.setProperty('--my', `${((pendingY - r.top)  / r.height * 100).toFixed(1)}%`);
    });
  }, { passive: true });

  card.addEventListener('mouseleave', () => {
    cachedRect = null;
    card.style.transform = '';
    card.style.removeProperty('--mx');
    card.style.removeProperty('--my');
  });
  card.addEventListener('mousedown', () => card.classList.add('is-pressed'));
  card.addEventListener('mouseup',   () => card.classList.remove('is-pressed'));
  card.addEventListener('click', e => {
    const ripple = document.createElement('span');
    ripple.className = 'click-ripple';
    const r = cachedRect || card.getBoundingClientRect();
    ripple.style.left = (e.clientX - r.left) + 'px';
    ripple.style.top  = (e.clientY - r.top)  + 'px';
    card.appendChild(ripple);
    setTimeout(() => ripple.remove(), 700);
  });
});

// EXIT card
document.getElementById('exit-card').addEventListener('click', () => {
  nativeSend({ action: 'exit' });
});

function selectedGame() {
  const sel = document.getElementById('game-select');
  return (sel && sel.value) || 'cs2';
}

function beginPrivateLoad(reason) {
  g_activeAction = 'load_private';
  document.getElementById('loading-title').textContent = 'LOADING PRIVATE';
  document.getElementById('loading-msg').textContent = 'Preparing ' + selectedGame().toUpperCase() + '…';
  document.getElementById('loading-bar').style.width = '0%';
  document.getElementById('loading-bar').style.background = '';
  document.getElementById('loading-bar').style.boxShadow = '';
  showScreen('loading');
  startLoadBar();
  armLoadWatch(14000);
  nativeSend({
    action: 'load_private',
    game: selectedGame(),
    reason: reason || 'start',
  });
  // Browser / Edge app-mode without full host: finish the UI pipeline locally.
  if (!isNative) {
    setTimeout(() => onLoadProgress({ msg: 'Binding session…' }), 200);
    setTimeout(() => onLoadProgress({ msg: 'Checking license channel…' }), 700);
    setTimeout(() => onLoadDone({ msg: 'Browser preview complete' }), 1400);
  }
}

const startBtn = document.getElementById('start-btn');
if (startBtn) {
  startBtn.addEventListener('click', () => {
    if (!Tokens.access()) {
      const hint = document.getElementById('start-hint');
      if (hint) hint.textContent = 'Authenticate with a license key first';
      showScreen('login');
      return;
    }
    beginPrivateLoad('start_btn');
  });
}

// LAUNCH PRIVATE card
document.getElementById('load-card').addEventListener('click', () => {
  beginPrivateLoad('load_card');
});

document.getElementById('spoof-card').addEventListener('click', () => {
  g_activeAction = 'loadSpoofer';
  document.getElementById('loading-title').textContent = 'SPOOFING HWID';
  document.getElementById('loading-msg').textContent = 'Preparing spoofer...';
  document.getElementById('loading-bar').style.width = '0%';
  document.getElementById('loading-bar').style.background = '';
  document.getElementById('loading-bar').style.boxShadow  = '';
  showScreen('loading');
  startLoadBar();
  armLoadWatch(14000);
  nativeSend({ action: 'loadSpoofer' });
  if (!isNative) {
    setTimeout(() => onLoadProgress({ msg: 'Refreshing identity envelope…' }), 400);
    setTimeout(() => onLoadDone({ msg: 'Browser spoof preview' }), 1200);
  }
});

// ── LAUNCH EMU card + console ───────────────────────────────────────────────
let emuActive = false;

const emuConsole = document.getElementById('emu-console');
const ecStatus   = document.getElementById('ec-status');
const ecClose    = document.getElementById('ec-close');
const ecCopy     = document.getElementById('ec-copy');
const ecLog      = document.getElementById('ec-log');

function setEmuStatusText(text, cls) {
  if (!ecStatus) return;
  ecStatus.textContent = text;
  ecStatus.classList.remove('armed', 'running');
  if (cls) ecStatus.classList.add(cls);
}

document.getElementById('emu-card').addEventListener('click', () => {
  if (emuActive) { nativeSend({ action: 'emuStop' }); return; }
  if (ecLog) ecLog.innerHTML = '';
  if (emuConsole) emuConsole.classList.add('open');
  setEmuStatusText('STARTING…', 'armed');
  nativeSend({ action: 'emuStart' });
});

const ecVerify = document.getElementById('ec-verify');
ecVerify && ecVerify.addEventListener('click', () => {
  nativeSend({ action: 'triggerVerify' });
});

ecCopy && ecCopy.addEventListener('click', () => {
  if (!ecLog) return;
  const text = Array.from(ecLog.querySelectorAll('.ec-log-line')).map(l => l.textContent).join('\n');
  navigator.clipboard.writeText(text).then(() => {
    ecCopy.textContent = '✓';
    setTimeout(() => { ecCopy.textContent = '⎘'; }, 1200);
  });
});

ecClose && ecClose.addEventListener('click', () => {
  if (emuActive) {
    nativeSend({ action: 'emuStop' });
  } else {
    if (emuConsole) emuConsole.classList.remove('open');
    setEmuStatusText('STANDBY', null);
    if (ecLog) ecLog.innerHTML = '';
  }
});

function onEmuActive(msg) {
  emuActive = !!msg.active;
  const badge = document.getElementById('emu-badge');
  const card  = document.getElementById('emu-card');
  if (badge) {
    badge.textContent = emuActive ? 'RUNNING' : 'READY';
    badge.classList.toggle('running', emuActive);
  }
  if (card) card.classList.toggle('game-ready', emuActive);

  if (emuActive) {
    if (emuConsole) emuConsole.classList.add('open', 'running');
    setEmuStatusText('RUNNING', 'running');
  } else {
    if (emuConsole) emuConsole.classList.remove('running');
    setEmuStatusText('STANDBY', null);
  }
}

// Append streamed log text (one C++ tick can carry multiple lines)
const LOG_LINE_RE = /^(\d{2}:\d{2}:\d{2})\s*\[([^\]]+)\]\s*(.*)$/;
function appendLogLine(raw) {
  if (!ecLog || !raw) return;
  const div = document.createElement('div');
  div.className = 'ec-log-line';
  const m = LOG_LINE_RE.exec(raw);
  if (m) {
    const [, ts, tag, msg] = m;
    const lower = msg.toLowerCase();
    if (/fail|error|dup failed/.test(lower)) div.classList.add('err');
    else if (/ok|active|ack|started/.test(lower)) div.classList.add('ok');
    div.innerHTML =
      '<span class="ec-ts">' + ts + '</span>' +
      '<span class="ec-tag">[' + tag + ']</span>' +
      '<span class="ec-msg"></span>';
    div.querySelector('.ec-msg').textContent = msg;
  } else {
    div.innerHTML = '<span class="ec-msg"></span>';
    div.querySelector('.ec-msg').textContent = raw;
  }
  ecLog.appendChild(div);
  // Cap the DOM at ~400 lines
  while (ecLog.childElementCount > 400) ecLog.firstChild.remove();
  ecLog.scrollTop = ecLog.scrollHeight;
}

function onEmuLog(msg) {
  if (!msg.text) return;
  const lines = msg.text.split('\n');
  for (const ln of lines) {
    if (ln.length) appendLogLine(ln);
  }
}

// ── Hotkey display + rebind ───────────────────────────────────────────────────
const VK_MAP = {
  'Insert':0x2D,'Delete':0x2E,'Home':0x24,'End':0x23,
  'PageUp':0x21,'PageDown':0x22,
  'ArrowLeft':0x25,'ArrowUp':0x26,'ArrowRight':0x27,'ArrowDown':0x28,
  'F1':0x70,'F2':0x71,'F3':0x72,'F4':0x73,'F5':0x74,'F6':0x75,
  'F7':0x76,'F8':0x77,'F9':0x78,'F10':0x79,'F11':0x7A,'F12':0x7B,
  'Pause':0x13,'ScrollLock':0x91,'NumLock':0x90,
  ' ':0x20,'Backspace':0x08,'Tab':0x09,'Escape':0x1B,
};
const KEY_LABELS = {
  'ArrowLeft':'LEFT','ArrowRight':'RIGHT','ArrowUp':'UP','ArrowDown':'DOWN',
  ' ':'SPACE','PageUp':'PGUP','PageDown':'PGDN','Escape':'ESC','Backspace':'BKSP',
};
let capturing = false;
const hkDisplay = document.getElementById('hk-display');
const hkBind    = document.getElementById('hk-bind');

function onHotkeySet(msg) {
  if (!hkDisplay || !msg.name) return;
  hkDisplay.textContent = msg.name;
  hkDisplay.classList.remove('capturing');
  capturing = false;
}

function keyToVk(e) {
  const k = e.key;
  if (VK_MAP.hasOwnProperty(k)) return VK_MAP[k];
  if (k.length === 1) {
    const c = k.toUpperCase().charCodeAt(0);
    if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A)) return c;
  }
  return 0;
}

function keyToLabel(e) {
  const k = e.key;
  if (KEY_LABELS[k]) return KEY_LABELS[k];
  if (k.length === 1) return k.toUpperCase();
  return k.toUpperCase();
}

hkBind.addEventListener('click', () => {
  if (capturing) return;
  capturing = true;
  hkDisplay.textContent = 'PRESS A KEY';
  hkDisplay.classList.add('capturing');
});

window.addEventListener('keydown', e => {
  if (!capturing) return;
  // Ignore raw modifier presses — wait for the target key
  if (e.key === 'Control' || e.key === 'Shift' || e.key === 'Alt' || e.key === 'Meta') {
    return;
  }
  e.preventDefault(); e.stopPropagation();
  const vk = keyToVk(e);
  if (!vk) return;
  let mod = 0;
  if (e.ctrlKey)  mod |= 0x0002;
  if (e.altKey)   mod |= 0x0001;
  if (e.shiftKey) mod |= 0x0004;
  nativeSend({ action: 'setHotkey', vk, mod });
  capturing = false;
  hkDisplay.classList.remove('capturing');
  hkDisplay.textContent = '...';
}, true);

// Result back button
document.getElementById('result-back').addEventListener('click', () => {
  showScreen('main');
});

// Close buttons (login + main)
document.getElementById('login-close').addEventListener('click', () => {
  nativeSend({ action: 'exit' });
});
document.getElementById('main-close').addEventListener('click', () => {
  nativeSend({ action: 'exit' });
});

// ── 12. Dev/browser fallback (no native bridge) ───────────────────────────────
if (!isNative) {
  // Show boot then login so the UI is testable in a browser
  console.log('[Immortal Phasex] running in browser mode (no native bridge)');
}

})();
