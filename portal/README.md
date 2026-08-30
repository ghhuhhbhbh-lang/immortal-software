# Immortal Key Portal

## Flow

1. Start API: `cd backend && npm run dev` (http://127.0.0.1:3000)
2. Seed once: `npm run seed` (creates DB admin — keep that password offline)
3. Set **web gate** pass (hash only lands in git):

```bash
node portal/set-gate-pass.mjs "YourStrongSecretPass"
```

4. Open `portal/index.html` → unlock with that pass → LOGIN API → GEN KEY
5. Run Loader → paste key → Authenticate

## Privacy

- Gate stores **SHA-256 only** — no reversible user/pass in the repo
- `noindex` + lockout after failed tries
- Do **not** commit plaintext passwords, `.env`, or GitHub tokens
- Prefer a **private** repo; static Pages URLs can still be guessed — the gate is the barrier

## Links

- Loader UI: `../Emulator Loader GUI/index.html`
- Admin: `../dashboard/index.html`
