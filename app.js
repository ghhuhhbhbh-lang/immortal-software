(() => {
  const FAIL_KEY = 'immortal.km.fails';
  const TOKEN_KEY = 'immortal.km.token';
  const FORGED_KEY = 'immortal.km.forged';

  const el = {
    gate: document.getElementById('gate'),
    app: document.getElementById('app'),
    gUser: document.getElementById('g-user'),
    gPass: document.getElementById('g-pass'),
    gGo: document.getElementById('g-go'),
    gErr: document.getElementById('g-err'),
    gNonce: document.getElementById('g-nonce'),
    gFp: document.getElementById('g-fp'),
    gLock: document.getElementById('g-lock'),
    gApiState: document.getElementById('g-api-state'),
    gProg: document.getElementById('g-prog'),
    gBar: document.getElementById('g-bar'),
    gStep: document.getElementById('g-step'),
    product: document.getElementById('gen-product'),
    plan: document.getElementById('gen-plan'),
    count: document.getElementById('gen-count'),
    days: document.getElementById('gen-days'),
    custom: document.getElementById('gen-custom'),
    customWrap: document.getElementById('custom-wrap'),
    devices: document.getElementById('gen-devices'),
    note: document.getElementById('gen-note'),
    autobind: document.getElementById('gen-autobind'),
    gen: document.getElementById('btn-gen'),
    exp: document.getElementById('btn-export'),
    lock: document.getElementById('btn-lock'),
    refresh: document.getElementById('btn-refresh'),
    flash: document.getElementById('flash'),
    tbody: document.getElementById('tbody'),
    empty: document.getElementById('empty'),
    search: document.getElementById('search'),
    statusFilter: document.getElementById('status-filter'),
    purge: document.getElementById('btn-purge'),
    keyCount: document.getElementById('key-count'),
    apiChip: document.getElementById('api-chip'),
    presets: document.getElementById('presets'),
    forgedBox: document.getElementById('forged-box'),
    forgedList: document.getElementById('forged-list'),
    forgedTitle: document.getElementById('forged-title'),
    bindHint: document.getElementById('bind-hint'),
  };

  // Sealed — matches Loader; never shown or editable in UI
  const API = String(window.IMMORTAL_API || '').replace(/\/$/, '');
  let accessToken = '';
  let products = [];
  let licenses = [];
  let lastForged = [];

  function hexNoise(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function refreshMeta() {
    el.gNonce.textContent = hexNoise(8).toUpperCase();
    const seed = navigator.userAgent + screen.width + screen.height;
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = ((h << 5) - h + seed.charCodeAt(i)) | 0;
    el.gFp.textContent = ((h >>> 0).toString(16).padStart(8, '0') + hexNoise(4)).toUpperCase();
    const fails = Math.min(5, parseInt(sessionStorage.getItem(FAIL_KEY) || '0', 10) || 0);
    el.gLock.textContent = `${fails} / 5`;
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  async function theater() {
    el.gProg.hidden = false;
    const stages = [
      [16, 'Probing sealed channel…'],
      [34, 'Binding node fingerprint…'],
      [55, 'Challenge / nonce verify…'],
      [74, 'Argon2 clearance…'],
      [90, 'Issuing JWT seal…'],
      [100, 'Vault channel open'],
    ];
    for (const [pct, label] of stages) {
      el.gBar.style.width = pct + '%';
      el.gStep.textContent = label;
      await sleep(160 + Math.random() * 140);
    }
  }

  async function apiFetch(path, opts = {}) {
    const r = await fetch(API + path, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        'X-Immortal-Challenge': el.gNonce?.textContent || '',
        'X-Immortal-Node': el.gFp?.textContent || '',
        ...(opts.headers || {}),
      },
    });
    const text = await r.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { /* ignore */ }
    if (r.status === 401) {
      showGate('Session expired — re-authenticate');
      throw new Error('Unauthorized');
    }
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  async function pingApi() {
    try {
      const r = await fetch(API + '/health', { signal: AbortSignal.timeout(4000) });
      const data = await r.json().catch(() => ({}));
      const ok = r.ok && data.status !== 'degraded';
      if (el.gApiState) {
        el.gApiState.textContent = ok ? 'ONLINE' : 'DEGRADED';
        el.gApiState.style.color = ok ? '#5dcea0' : '#eab308';
      }
      if (el.apiChip) el.apiChip.textContent = ok ? 'CHANNEL SEALED · OK' : 'CHANNEL SEALED · ?';
      return { ok, data };
    } catch {
      if (el.gApiState) {
        el.gApiState.textContent = 'OFFLINE';
        el.gApiState.style.color = '#e8617f';
      }
      if (el.apiChip) el.apiChip.textContent = 'CHANNEL SEALED · DOWN';
      return { ok: false };
    }
  }

  function showGate(msg) {
    accessToken = '';
    sessionStorage.removeItem(TOKEN_KEY);
    el.app.hidden = true;
    el.gate.hidden = false;
    el.gProg.hidden = true;
    el.gBar.style.width = '0%';
    el.gPass.value = '';
    if (msg) el.gErr.textContent = msg;
    refreshMeta();
    pingApi();
  }

  async function openApp() {
    el.gate.hidden = true;
    el.app.hidden = false;
    if (el.apiChip) el.apiChip.textContent = 'CHANNEL SEALED · OK';
    try {
      await loadProducts();
      await loadLicenses();
      renderForged();
    } catch (e) {
      flash(e.message, true);
    }
  }

  async function tryGate() {
    const fails = parseInt(sessionStorage.getItem(FAIL_KEY) || '0', 10) || 0;
    if (fails >= 5) {
      el.gErr.textContent = 'Soft lock — clear site data or wait / new session';
      return;
    }
    const user = (el.gUser.value || '').trim();
    const pass = el.gPass.value || '';
    el.gErr.textContent = '';
    if (!user || !pass) {
      el.gErr.textContent = 'Enter USR / PASS';
      return;
    }
    if (!API) {
      el.gErr.textContent = 'Sealed channel misconfigured';
      return;
    }

    el.gGo.disabled = true;
    el.gGo.textContent = 'SEALING…';
    await theater();

    const health = await pingApi();
    if (!health.ok) {
      el.gProg.hidden = true;
      el.gErr.textContent = 'Auth channel offline — start Immortal API (same as Loader)';
      el.gGo.disabled = false;
      el.gGo.textContent = 'AUTHENTICATE';
      return;
    }

    try {
      const data = await fetch(API + '/api/auth/admin-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Immortal-Challenge': el.gNonce.textContent,
          'X-Immortal-Node': el.gFp.textContent,
        },
        body: JSON.stringify({
          username: user,
          password: pass,
          challenge: el.gNonce.textContent,
          nodeFp: el.gFp.textContent,
        }),
      }).then(async (r) => {
        const text = await r.text();
        let body = {};
        try { body = text ? JSON.parse(text) : {}; } catch { /* */ }
        if (!r.ok || !body.accessToken) throw new Error(body.error || 'Clearance denied');
        return body;
      });

      sessionStorage.setItem(FAIL_KEY, '0');
      accessToken = data.accessToken;
      sessionStorage.setItem(TOKEN_KEY, accessToken);
      el.gGo.disabled = false;
      el.gGo.textContent = 'AUTHENTICATE';
      await openApp();
    } catch (e) {
      const n = fails + 1;
      sessionStorage.setItem(FAIL_KEY, String(n));
      refreshMeta();
      el.gProg.hidden = true;
      el.gErr.textContent = n >= 5
        ? 'Clearance denied · soft lock'
        : `${e.message} · fail ${n}/5`;
      el.gGo.disabled = false;
      el.gGo.textContent = 'AUTHENTICATE';
    }
  }

  async function loadProducts() {
    const raw = await apiFetch('/api/admin/products');
    products = Array.isArray(raw) ? raw : (raw.products || []);
    el.product.innerHTML = products.length
      ? products.map((p) => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('')
      : '<option value="">No products</option>';
    fillPlans(el.product.value);
  }

  function fillPlans(pid) {
    const p = products.find((x) => x.id === pid);
    const plans = p?.plans || [];
    el.plan.disabled = !plans.length;
    el.plan.innerHTML = plans.length
      ? plans.map((pl) => {
          const d = pl.durationDays;
          const label = !d ? 'lifetime' : `${d}d`;
          return `<option value="${pl.id}">${escapeHtml(pl.name)} (${label})</option>`;
        }).join('')
      : '<option value="">No plans</option>';
  }

  async function loadLicenses() {
    const data = await apiFetch('/api/licenses?limit=200');
    licenses = data.licenses || [];
    render();
  }

  function resolveDays() {
    const v = el.days.value;
    if (v === 'plan') return undefined;
    if (v === 'custom') return Math.max(1, Number(el.custom.value) || 1);
    return Number(v);
  }

  function ago(d) {
    if (!d) return '<span class="muted">Never</span>';
    const t = new Date(d).getTime();
    if (isNaN(t)) return '—';
    const sec = Math.floor((Date.now() - t) / 1000);
    if (sec < 60) return 'Just now';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
    if (sec < 604800) return Math.floor(sec / 86400) + 'd ago';
    return new Date(t).toLocaleString();
  }

  function fmtDate(d) {
    if (!d) return '<span class="muted">—</span>';
    const dt = new Date(d);
    return isNaN(dt) ? '—' : dt.toLocaleString();
  }

  function flash(msg, bad) {
    el.flash.hidden = false;
    el.flash.textContent = msg;
    el.flash.style.color = bad ? 'var(--danger)' : 'var(--ok)';
    clearTimeout(flash._t);
    flash._t = setTimeout(() => { el.flash.hidden = true; }, 2800);
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function render() {
    const q = (el.search.value || '').trim().toLowerCase();
    const st = (el.statusFilter?.value || '').trim().toUpperCase();
    const list = licenses.filter((l) => {
      if (st && String(l.status || '').toUpperCase() !== st) return false;
      if (!q) return true;
      return String(l.keyPrefix || '').toLowerCase().includes(q)
        || String(l.status || '').toLowerCase().includes(q)
        || String(l.product || '').toLowerCase().includes(q)
        || String(l.note || '').toLowerCase().includes(q);
    });
    el.keyCount.textContent = `${licenses.length} key${licenses.length === 1 ? '' : 's'}`;
    el.tbody.innerHTML = '';
    el.empty.hidden = list.length > 0;
    for (const l of list) {
      const tr = document.createElement('tr');
      const revoked = String(l.status || '').toUpperCase() === 'REVOKED';
      tr.innerHTML = `
        <td class="key">${escapeHtml(l.keyPrefix || '????')}‑••••‑••••‑••••‑••••</td>
        <td>${escapeHtml(l.status || '—')}</td>
        <td>${escapeHtml(typeof l.product === 'string' ? l.product : (l.product?.name || '—'))}</td>
        <td>${fmtDate(l.expiresAt || l.expirationDate)}</td>
        <td title="${l.lastUsedAt ? new Date(l.lastUsedAt).toLocaleString() : ''}">${ago(l.lastUsedAt)}</td>
        <td>${fmtDate(l.activatedAt)}</td>
        <td>${l.deviceLimit ?? 1}</td>
        <td class="ops">
          <button type="button" class="btn tiny ghost" data-extend="${l.id}">+Days</button>
          ${revoked
            ? `<button type="button" class="btn tiny ghost" data-unrevoke="${l.id}">Unrevoke</button>`
            : `<button type="button" class="btn tiny danger" data-revoke="${l.id}">Revoke</button>`}
          <button type="button" class="btn tiny danger" data-delete="${l.id}">Delete</button>
        </td>`;
      el.tbody.appendChild(tr);
    }
  }

  function renderForged() {
    try {
      lastForged = JSON.parse(sessionStorage.getItem(FORGED_KEY) || '[]');
    } catch { lastForged = []; }
    if (!lastForged.length) {
      el.forgedBox.hidden = true;
      return;
    }
    el.forgedBox.hidden = false;
    el.forgedList.innerHTML = lastForged.map((k) => `
      <div class="forged-item">
        <code>${escapeHtml(k.key)}</code>
        <button type="button" class="btn tiny ghost" data-copy="${escapeHtml(k.key)}">Copy</button>
      </div>`).join('');
  }

  refreshMeta();
  setInterval(refreshMeta, 14000);
  pingApi();

  el.gGo.addEventListener('click', tryGate);
  [el.gUser, el.gPass].forEach((inp) => {
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryGate(); });
  });
  el.lock.addEventListener('click', () => showGate(''));
  el.refresh.addEventListener('click', async () => {
    try { await loadLicenses(); flash('Vault refreshed'); }
    catch (e) { flash(e.message, true); }
  });

  el.product.addEventListener('change', () => fillPlans(el.product.value));
  el.days.addEventListener('change', () => {
    el.customWrap.hidden = el.days.value !== 'custom';
  });
  el.presets.addEventListener('click', (e) => {
    const b = e.target.closest('[data-d]');
    if (!b) return;
    const d = b.dataset.d;
    if (d === '0') {
      el.days.value = '0';
      el.customWrap.hidden = true;
    } else {
      el.days.value = 'custom';
      el.customWrap.hidden = false;
      el.custom.value = d;
    }
  });

  el.gen.addEventListener('click', async () => {
    const productId = el.product.value;
    const planId = el.plan.value;
    if (!productId || !planId) {
      flash('Select product + plan', true);
      return;
    }
    const body = {
      productId,
      planId,
      quantity: Math.min(50, Math.max(1, Number(el.count.value) || 1)),
      deviceLimit: Math.min(50, Math.max(1, Number(el.devices.value) || 1)),
      autoBindHwid: el.autobind?.value !== '0',
    };
    const days = resolveDays();
    if (days !== undefined) body.durationDays = days;
    const note = (el.note.value || '').trim();
    if (note) body.note = note;

    el.gen.disabled = true;
    el.gen.textContent = 'Forging…';
    try {
      const data = await apiFetch('/api/licenses', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      const created = data?.data?.created ?? data?.created ?? 0;
      const failed = data?.data?.failed ?? 0;
      const keys = (data.keys || data?.data?.keys || []).filter(Boolean);
      lastForged = keys.map((key, i) => ({
        key,
        expiresAt: data.licenses?.[i]?.expiresAt || data?.data?.licenses?.[i]?.expiresAt || null,
        note,
        createdAt: Date.now(),
      }));
      sessionStorage.setItem(FORGED_KEY, JSON.stringify(lastForged));
      renderForged();
      if (el.forgedTitle) {
        el.forgedTitle.textContent = `Successfully generated: ${created || keys.length} · Failed: ${failed}`;
      }
      await loadLicenses();
      flash(keys.length === 1
        ? 'Key ready — paste into Loader'
        : `${keys.length} keys ready for Loader`);
      if (el.bindHint && keys.length) {
        el.bindHint.textContent = `Latest key: ${keys[0]} — Loader Auth (same API host). Prefer start-admin.bat for local forge.`;
      }
    } catch (e) {
      flash(e.message, true);
    }
    el.gen.disabled = false;
    el.gen.textContent = 'Forge for Loader';
  });

  el.exp.addEventListener('click', () => {
    if (!lastForged.length) {
      flash('Nothing forged this session', true);
      return;
    }
    const blob = new Blob([JSON.stringify(lastForged, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `immortal-mode-keys-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });

  el.search.addEventListener('input', render);
  el.statusFilter?.addEventListener('change', render);
  el.purge?.addEventListener('click', async () => {
    const n = licenses.filter((l) => String(l.status).toUpperCase() === 'REVOKED').length;
    if (!confirm(`Hard-delete all REVOKED keys? (${n} currently)`)) return;
    try {
      const r = await apiFetch('/api/licenses/purge-revoked', { method: 'POST' });
      await loadLicenses();
      flash(`Purged ${r?.data?.deleted ?? 0} keys`);
    } catch (err) { flash(err.message, true); }
  });

  el.forgedList.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      flash('Copied for Loader');
    } catch {
      flash('Copy failed', true);
    }
  });

  el.tbody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    if (btn.dataset.extend) {
      const days = parseInt(prompt('Extend by how many days?', '30') || '', 10);
      if (!days || days < 1) return;
      try {
        await apiFetch(`/api/licenses/${btn.dataset.extend}/extend`, {
          method: 'POST',
          body: JSON.stringify({ days }),
        });
        await loadLicenses();
        flash(`Extended +${days}d`);
      } catch (err) { flash(err.message, true); }
    }
    if (btn.dataset.revoke) {
      if (!confirm('Revoke this license?')) return;
      try {
        await apiFetch(`/api/licenses/${btn.dataset.revoke}/revoke`, { method: 'POST' });
        await loadLicenses();
        flash('Revoked');
      } catch (err) { flash(err.message, true); }
    }
    if (btn.dataset.unrevoke) {
      try {
        await apiFetch(`/api/licenses/${btn.dataset.unrevoke}/unrevoke`, { method: 'POST' });
        await loadLicenses();
        flash('Unrevoked — ready for Loader');
      } catch (err) { flash(err.message, true); }
    }
    if (btn.dataset.delete) {
      if (!confirm('Permanently DELETE this key from the vault?')) return;
      try {
        await apiFetch(`/api/licenses/${btn.dataset.delete}`, { method: 'DELETE' });
        await loadLicenses();
        flash('Deleted');
      } catch (err) { flash(err.message, true); }
    }
  });

  // Restore sealed session if token still valid
  const savedTok = sessionStorage.getItem(TOKEN_KEY);
  if (savedTok && API) {
    accessToken = savedTok;
    apiFetch('/api/auth/me')
      .then(() => openApp())
      .catch(() => showGate(''));
  } else {
    pingApi();
  }
})();
