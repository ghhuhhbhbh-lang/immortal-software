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

  async function grant(hash) {
    const exp = now() + SESSION_MS;
    sessionStorage.setItem(SK, JSON.stringify({ ok: true, exp: exp, hash: hash }));
    writeAttempts({ n: 0, lockUntil: 0 });
    document.documentElement.classList.remove('gate-locked');
    const el = document.getElementById('site-gate');
    if (el) el.remove();
    const app = document.getElementById('portal-app');
    if (app) app.hidden = false;
  }

  function deny(msg) {
    const err = document.getElementById('gate-err');
    if (err) err.textContent = msg;
  }

  async function submit() {
    if (!gateConfigured()) {
      deny('Gate not configured. Run set-gate-pass.mjs locally.');
      return;
    }

    const until = lockedUntil();
    if (until) {
      const mins = Math.ceil((until - now()) / 60000);
      deny('Locked. Wait ~' + mins + ' min.');
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
      deny('Too many tries. Locked 15 minutes.');
      return;
    }
    writeAttempts(a);
    deny('Access denied (' + (MAX - a.n) + ' left)');
  }

  async function boot() {
    if (!gateConfigured()) {
      document.documentElement.classList.add('gate-locked');
      deny('Gate not configured.');
      const btn = document.getElementById('gate-go');
      const input = document.getElementById('gate-pass');
      if (btn) btn.addEventListener('click', submit);
      if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
      return;
    }

    if (validSession()) {
      try {
        const s = JSON.parse(sessionStorage.getItem(SK));
        if (timingSafeEqual(String(s.hash).toLowerCase(), EXPECTED)) {
          document.documentElement.classList.remove('gate-locked');
          const el = document.getElementById('site-gate');
          if (el) el.remove();
          const app = document.getElementById('portal-app');
          if (app) app.hidden = false;
          return;
        }
      } catch {}
      sessionStorage.removeItem(SK);
    }

    document.documentElement.classList.add('gate-locked');
    const btn = document.getElementById('gate-go');
    const input = document.getElementById('gate-pass');
    if (btn) btn.addEventListener('click', submit);
    if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
