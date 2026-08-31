(() => {
  const STORE = 'immortal.keys.v1';
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  const el = {
    count: document.getElementById('gen-count'),
    days: document.getElementById('gen-days'),
    note: document.getElementById('gen-note'),
    gen: document.getElementById('btn-gen'),
    exp: document.getElementById('btn-export'),
    clear: document.getElementById('btn-clear'),
    flash: document.getElementById('flash'),
    tbody: document.getElementById('tbody'),
    empty: document.getElementById('empty'),
    search: document.getElementById('search'),
    keyCount: document.getElementById('key-count'),
  };

  function load() {
    try {
      const raw = localStorage.getItem(STORE);
      const list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  function save(list) {
    localStorage.setItem(STORE, JSON.stringify(list));
  }

  function chunk() {
    let s = '';
    const bytes = crypto.getRandomValues(new Uint8Array(4));
    for (let i = 0; i < 4; i++) s += alphabet[bytes[i] % alphabet.length];
    return s;
  }

  function makeKey() {
    return `${chunk()}-${chunk()}-${chunk()}-${chunk()}-${chunk()}`;
  }

  function durationLabel(days) {
    const n = Number(days);
    if (!n) return 'Lifetime';
    if (n === 1) return '1 day';
    if (n === 365) return '1 year';
    return `${n} days`;
  }

  function flash(msg) {
    el.flash.hidden = false;
    el.flash.textContent = msg;
    clearTimeout(flash._t);
    flash._t = setTimeout(() => { el.flash.hidden = true; }, 2200);
  }

  function render() {
    const q = (el.search.value || '').trim().toLowerCase();
    const list = load().filter((k) => {
      if (!q) return true;
      return k.key.toLowerCase().includes(q) || String(k.note || '').toLowerCase().includes(q);
    });

    el.keyCount.textContent = `${load().length} key${load().length === 1 ? '' : 's'}`;
    el.tbody.innerHTML = '';
    el.empty.hidden = list.length > 0;

    for (const item of list) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="key">${item.key}</td>
        <td>${durationLabel(item.days)}</td>
        <td>${escapeHtml(item.note || '—')}</td>
        <td>${new Date(item.createdAt).toLocaleString()}</td>
        <td class="ops">
          <button type="button" class="btn tiny ghost" data-copy="${item.key}">Copy</button>
          <button type="button" class="btn tiny danger" data-del="${item.id}">Delete</button>
        </td>`;
      el.tbody.appendChild(tr);
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  el.gen.addEventListener('click', () => {
    const n = Math.min(50, Math.max(1, Number(el.count.value) || 1));
    const days = Number(el.days.value);
    const note = (el.note.value || '').trim();
    const list = load();
    const created = [];

    for (let i = 0; i < n; i++) {
      const item = {
        id: crypto.randomUUID(),
        key: makeKey(),
        days,
        note,
        createdAt: Date.now(),
      };
      list.unshift(item);
      created.push(item.key);
    }

    save(list);
    render();
    flash(n === 1 ? `Created ${created[0]}` : `Created ${n} keys`);
  });

  el.exp.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(load(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `immortal-keys-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });

  el.clear.addEventListener('click', () => {
    if (!load().length) return;
    if (!confirm('Delete all keys from this browser?')) return;
    save([]);
    render();
    flash('Cleared');
  });

  el.search.addEventListener('input', render);

  el.tbody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    if (btn.dataset.copy) {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        flash('Copied');
      } catch {
        flash('Copy failed');
      }
    }
    if (btn.dataset.del) {
      save(load().filter((k) => k.id !== btn.dataset.del));
      render();
    }
  });

  render();
})();
