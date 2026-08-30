# Immortal Software — Changelog

## 2.2.1 — 2026-08-30

### Loader GUI / WebView
- Real WebView2 message bridge + uiReady/focusKey handshake
- License key typing fixed (caret, reveal, last-key remember)
- API health badge + timed fetch + offline guard before login
- Local `config.js` + Edge app launcher `host/run-webview.ps1`
- Native host: virtual host `immortal.loader` + API inject

### Backend
- CORS allows file/null/localhost/`immortal.loader`
- Human error messages + metrics/health version

### Dashboard
- Clearer gate errors + API status chip

## 2.2.0 — 2026-08-30

### Menu / UI
- Shared design tokens (hover/press/borders, control heights)
- Unified button / keybind / combo hover language
- Toast notifications for config actions
- DPI + menu UI scale, reduce animations, safe mode, perf meter
- F1–F8 tab hotkeys
- Config empty states + sidebar version badge

### Loader / DRM
- Session client version 2.2
- TLS strict mode via `IMMORTAL_TLS_STRICT`
- Pin env hook `IMMORTAL_TLS_PIN_SHA256`
- Secure local store (`%LOCALAPPDATA%\ImmortalSoftware\secure`)

### Backend / Portal
- Tighter CSP + request id + version headers
- `/metrics` + richer `/health`
- Discord webhook on high-severity threats
- `APP_VERSION`, `OFFLINE_GRACE_HOURS`, webhook env

### Org
- `.editorconfig`
- Module version bump to 2.2.0

## Release QA checklist
- [ ] Login + refresh + logout
- [ ] Heartbeat revoke path
- [ ] Attest fail revokes session
- [ ] Menu open/close + DPI scale
- [ ] Config save/import/export toasts
- [ ] Health + metrics endpoints
- [ ] Webhook fires on severity ≥ 7 (if URL set)
