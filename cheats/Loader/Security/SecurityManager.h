#pragma once
#include <string>
#include <functional>

// SecurityManager — the single integration point between the Loader and the
// full loader_security suite (from C:\loader_security\).
//
// It wraps ImmortalSecurity::Initialize() / Authenticate() / ShouldLaunchGame()
// and layers on top:
//   • Discord webhook alerts for CRITICAL / HIGH events
//   • Server-side license revocation (POST /api/security/event)
//   • Self-delete of the loader EXE
//   • PC shutdown on CRITICAL breaches
//
// Usage in WinMain:
//   SecurityManager::Initialize();                      // before UI
//   SecurityManager::Authenticate(L"XXXX-XXXX-XXXX");  // after UI login
//   if (!SecurityManager::ShouldLaunchGame()) { ... }
namespace SecurityManager {

// Must be called before any UI or network operations.
// Runs the full startup gauntlet (integrity hash, anti-debug, anti-VM, hooks).
// Returns true = environment clean.  false = threat detected (honeypot activated).
bool Initialize();

// Must be called after the user provides their license key.
// Verifies the key with the backend, starts heartbeat + attestation threads.
// Returns true = authenticated.
bool Authenticate(const std::wstring& licenseKey,
                  const std::string&  apiUrl,
                  const std::string&  accessToken);

// Returns false if honeypot is active or session was revoked.
// Wrap all injection logic inside:  if (SecurityManager::ShouldLaunchGame()) { ... }
bool ShouldLaunchGame();

// Session info (returns honeypot-safe dummy values if compromised).
const char* GetUsername();
const char* GetRole();
const char* GetExpiry();

// Called by the pipe-server heartbeat loss path — marks session suspicious.
void OnPipeLost();

// Graceful shutdown — zero memory, stop threads.
void Shutdown();

// Set the revocation callback (called when the session is revoked by the server).
// The loader uses this to post "sessionRevoked" to the JS layer and close.
void SetRevocationCallback(std::function<void()> cb);

} // namespace SecurityManager
