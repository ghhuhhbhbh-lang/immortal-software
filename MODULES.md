# Immortal module map (2.2)

| Area | Path | Role |
|------|------|------|
| License API | `backend/` | Auth, licenses, admin, heartbeat/attest/threat |
| Admin portal | `dashboard/` | Operator UI + gate |
| Native loader DRM | `loader_security/` | Anti-* + session + secure store |
| Loader GUI | `Emulator Loader GUI/` | End-user auth + launch shell |
| Cheat UI | `pablo/.../cs2/pablo/project/core/rendering/` | Menu / widgets |
| Design tokens | `.../external/xdraw/xdraw.hpp` `namespace tokens` | Shared Immortal palette |

Build channels: stable (`APP_VERSION`) vs local DEV_BUILD (softer TLS).
