(function () {
  const API = () => window.IMMORTAL_API || 'http://127.0.0.1:3000';
  let accessToken = '';
  let productsCache = [];

  const loginStatus = document.getElementById('login-status');
  const btnLogin = document.getElementById('btn-login');
  const btnGen = document.getElementById('btn-gen');
  const keysOut = document.getElementById('keys-out');
  const linkLoader = document.getElementById('link-loader');
  const linkAdmin = document.getElementById('link-admin');
  const btnOpenLoader = document.getElementById('btn-open-loader');
  const productSel = document.getElementById('product-id');
  const planSel = document.getElementById('plan-id');

  function setStatus(text, ok) {
    if (!loginStatus) return;
    loginStatus.textContent = text;
    loginStatus.classList.toggle('ok', ok === true);
    loginStatus.classList.toggle('bad', ok === false);
  }

  function resolveLoaderHref() {
    if (window.IMMORTAL_LOADER) return window.IMMORTAL_LOADER;
    try {
      return new URL('../Emulator Loader GUI/index.html', document.baseURI).href;
    } catch (_) {
      return '../Emulator Loader GUI/index.html';
    }
  }

  function wireLinks() {
    const loader = resolveLoaderHref();
    const admin = window.IMMORTAL_ADMIN || '../dashboard/index.html';
    if (linkLoader) linkLoader.href = loader;
    if (linkAdmin) linkAdmin.href = admin;
    if (btnOpenLoader) {
      btnOpenLoader.addEventListener('click', () => {
        window.open(loader, '_blank', 'noopener');
      });
    }
  }

  async function api(path, opts) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, (opts && opts.headers) || {});
    if (accessToken) headers.Authorization = 'Bearer ' + accessToken;
    const res = await fetch(API() + path, Object.assign({}, opts, { headers }));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  }

  function fillProducts(list) {
    productsCache = Array.isArray(list) ? list : [];
    if (!productSel) return;
    productSel.innerHTML = '<option value="">Select product…</option>' +
      productsCache.map((p) => '<option value="' + p.id + '">' + (p.name || p.slug || p.id) + '</option>').join('');
    productSel.disabled = productsCache.length === 0;
    if (planSel) {
      planSel.innerHTML = '<option value="">Select product…</option>';
      planSel.disabled = true;
    }
  }

  function fillPlans(productId) {
    if (!planSel) return;
    const product = productsCache.find((p) => p.id === productId);
    const plans = (product && product.plans) || [];
    planSel.innerHTML = plans.length
      ? plans.map((pl) =>
          '<option value="' + pl.id + '">' + pl.name + ' (' + pl.durationDays + 'd)</option>'
        ).join('')
      : '<option value="">No plans</option>';
    planSel.disabled = plans.length === 0;
  }

  async function loadCatalog() {
    const raw = await api('/api/admin/products');
    const list = Array.isArray(raw) ? raw : (raw.products || []);
    fillProducts(list);
    if (list.length === 1) {
      productSel.value = list[0].id;
      fillPlans(list[0].id);
    }
  }

  async function doLogin() {
    const username = (document.getElementById('admin-user').value || '').trim();
    const password = document.getElementById('admin-pass').value || '';
    if (!username || !password) {
      setStatus('Enter admin user + password', false);
      return;
    }
    setStatus('Logging in…', null);
    btnLogin.disabled = true;
    try {
      const data = await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      accessToken = data.accessToken || data.token || '';
      if (!accessToken) throw new Error('No access token');
      await loadCatalog();
      btnGen.disabled = false;
      setStatus('API online · pick product/plan · GEN KEY', true);
    } catch (e) {
      accessToken = '';
      btnGen.disabled = true;
      fillProducts([]);
      setStatus(e.message || 'Login failed — is backend on :3000?', false);
    } finally {
      btnLogin.disabled = false;
    }
  }

  async function doGen() {
    if (!accessToken) {
      setStatus('Login to API first', false);
      return;
    }
    const productId = (productSel && productSel.value) || '';
    const planId = (planSel && planSel.value) || '';
    const quantity = Math.max(1, Math.min(50, parseInt(document.getElementById('qty').value, 10) || 1));
    const daysRaw = parseInt(document.getElementById('days').value, 10) || 0;
    if (!productId || !planId) {
      setStatus('Select product and plan', false);
      return;
    }
    btnGen.disabled = true;
    setStatus('Generating…', null);
    try {
      const body = { productId, planId, quantity };
      if (daysRaw > 0) body.durationDays = daysRaw;
      const data = await api('/api/licenses', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      const list = data.licenses || [];
      const keys = (data.keys || []).length
        ? data.keys
        : list.map((lic) => (typeof lic === 'string' ? lic : (lic.key || ''))).filter(Boolean);
      keysOut.innerHTML = '';
      if (!keys.length) {
        setStatus('API returned 0 keys', false);
      } else {
        keys.forEach((key) => {
          const chip = document.createElement('div');
          chip.className = 'key-chip';
          chip.textContent = key;
          chip.title = 'Click to copy — paste into ImmortalLoader.exe';
          chip.addEventListener('click', () => {
            navigator.clipboard.writeText(String(key)).then(() => {
              chip.textContent = 'COPIED · ' + key;
              setTimeout(() => { chip.textContent = key; }, 1200);
            });
          });
          keysOut.appendChild(chip);
        });
        setStatus('Generated ' + keys.length + ' key(s) — click to copy → Loader', true);
      }
    } catch (e) {
      setStatus(e.message || 'GEN failed', false);
    } finally {
      btnGen.disabled = false;
    }
  }

  if (productSel) {
    productSel.addEventListener('change', () => fillPlans(productSel.value));
  }

  wireLinks();
  if (btnLogin) btnLogin.addEventListener('click', doLogin);
  if (btnGen) btnGen.addEventListener('click', doGen);
})();
