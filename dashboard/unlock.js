(function () {
  const GATE = window.IMMORTAL_GATE || {};
  const SALT = GATE.salt || 'immortal.gate.v3';
  const EXPECTED = String(GATE.hash || '').toLowerCase();
  const MAX = GATE.maxAttempts || 5;
  const LOCK_MS = GATE.lockMs || 15 * 60 * 1000;
  const SESSION_MS = GATE.sessionMs || 4 * 60 * 60 * 1000;
  const SK = 'immortal_portal_v3_session';
  const AK = 'immortal_portal_v3_attempts';

  function now() { return Date.now(); }

  function readAttempts() {
    try { return JSON.parse(sessionStorage.getItem(AK) || '{}'); }
    catch { return {}; }
  }

  function writeAttempts(data) {
    sessionStorage.setItem(AK, JSON.stringify(data));
  }

  function lockedUntil() {
    const a = readAttempts();
    return a.lockUntil && a.lockUntil > now() ? a.lockUntil : 0;
  }

  async function sha256hex(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function timingSafeEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function gateConfigured() {
    return /^[a-f0-9]{64}$/.test(EXPECTED);
  }

  function validSession() {
    try {
      const raw = sessionStorage.getItem(SK);
      if (!raw) return false;
      const s = JSON.parse(raw);
      return s.ok === true && s.exp > now() && typeof s.hash === 'string' && s.hash.length === 64;
    } catch {
      return false;
    }
  }

  function paintSessionStrip(exp) {
    let strip = document.getElementById('session-strip');
    if (!strip) {
      strip = document.createElement('div');
      strip.id = 'session-strip';
      document.body.appendChild(strip);
    }
    const tick = () => {
      const left = Math.max(0, exp - Date.now());
      const h = Math.floor(left / 3600000);
      const m = Math.floor((left % 3600000) / 60000);
      strip.textContent = left ? ('SESSION LOCKED · ' + h + 'H ' + m + 'M') : 'SESSION EXPIRED';
      if (!left) {
        sessionStorage.removeItem(SK);
        location.reload();
      }
    };
    tick();
    setInterval(tick, 30000);
  }

  async function grant(hash) {
    const exp = now() + SESSION_MS;
    sessionStorage.setItem(SK, JSON.stringify({ ok: true, exp: exp, hash: hash }));
    writeAttempts({ n: 0, lockUntil: 0 });
    document.documentElement.classList.remove('gate-locked');
    const el = document.getElementById('site-gate');
    if (el) el.remove();
    paintSessionStrip(exp);
  }

  function deny(msg) {
    const err = document.getElementById('gate-err');
    if (err) err.textContent = msg;
  }

  async function submit() {
    if (!gateConfigured()) {
      deny('Gate not configured. Run: node portal/set-gate-pass.mjs \"YourPass\"');
      return;
    }

    const until = lockedUntil();
    if (until) {
      const mins = Math.ceil((until - now()) / 60000);
      deny('Portal locked. Wait ~' + mins + ' min.');
      return;
    }

    const input = document.getElementById('gate-pass');
    const pass = (input && input.value) || '';
    if (!pass) { deny('Enter access pass'); return; }
    if (pass.length < 10) { deny('Pass too short'); return; }

    const got = await sha256hex(SALT + ':' + pass);
    if (timingSafeEqual(got, EXPECTED)) {
      await grant(got);
      return;
    }

    const a = readAttempts();
    a.n = (a.n || 0) + 1;
    if (a.n >= MAX) {
      a.lockUntil = now() + LOCK_MS;
      a.n = 0;
      writeAttempts(a);
      deny('Too many failed attempts. Locked 15 minutes.');
      return;
    }
    writeAttempts(a);
    deny('Access denied. ' + (MAX - a.n) + ' left.');
  }

  function build() {
    if (validSession() && gateConfigured()) {
      try {
        const s = JSON.parse(sessionStorage.getItem(SK) || '{}');
        if (timingSafeEqual(String(s.hash || '').toLowerCase(), EXPECTED)) {
          document.documentElement.classList.remove('gate-locked');
          if (s.exp) paintSessionStrip(s.exp);
          return;
        }
      } catch {}
      sessionStorage.removeItem(SK);
    }

    document.documentElement.classList.add('gate-locked');
    const wrap = document.createElement('div');
    wrap.id = 'site-gate';
    wrap.innerHTML = [
      '<div class="sec-scan"></div>',
      '<div class="sec-corners"></div>',
      '<div class="gate-card">',
      '<p class="login-clearance">CLASSIFIED · CLEARANCE REQUIRED</p>',
      '<img class="login-logo-img" src="logo2.png" alt="" draggable="false" onerror="this.src=\'../Emulator Loader GUI/logo2.png\'">',
      '<p class="login-brand grad-text">IMMORTAL</p>',
      '<p class="login-sub">Hardened portal</p>',
      '<div class="login-seals"><span>SHA-256</span><span>LOCKOUT</span><span>NO INDEX</span></div>',
      '<div class="login-field"><label>Access pass</label>',
      '<input id="gate-pass" type="password" autocomplete="current-password" spellcheck="false"></div>',
      '<button class="login-btn" id="gate-submit" type="button">Authenticate</button>',
      '<p class="login-err" id="gate-err"></p>',
      '<p class="gate-foot">Unauthorized access is locked out</p>',
      '</div>',
    ].join('');
    document.body.appendChild(wrap);

    document.getElementById('gate-submit').addEventListener('click', submit);
    document.getElementById('gate-pass').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submit();
    });

    if (!gateConfigured()) deny('Gate not configured.');
    else if (lockedUntil()) {
      const mins = Math.ceil((lockedUntil() - now()) / 60000);
      deny('Locked. Try again in ' + mins + ' min.');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', build);
  } else {
    build();
  }

  async function paintApiChip() {
    let el = document.getElementById('api-chip');
    if (!el) {
      el = document.createElement('div');
      el.id = 'api-chip';
      el.className = 'api-chip';
      document.body.appendChild(el);
    }
    el.textContent = 'API …';
    el.dataset.state = 'pending';
    try {
      const base = window.IMMORTAL_API || 'http://127.0.0.1:3000';
      const res = await fetch(base + '/health', { signal: AbortSignal.timeout(4000) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok && data.status !== 'degraded') throw new Error('down');
      if (data.status === 'degraded' || data.db === 'down') {
        el.dataset.state = 'pending';
        el.textContent = data.version ? ('API ' + data.version + ' · DB?') : 'API DEGRADED';
        return;
      }
      el.dataset.state = 'ok';
      el.textContent = data.version ? ('API ' + data.version) : 'API ONLINE';
    } catch (_) {
      el.dataset.state = 'down';
      el.textContent = 'API OFFLINE';
    }
  }
  paintApiChip();
  setInterval(paintApiChip, 60000);
})();
