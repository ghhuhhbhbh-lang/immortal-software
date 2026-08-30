// ============================================================
//  Immortal Software — Security Integration Shim
//  Drop this file into your VS project and call
//  ImmortalSecurity::Initialize() at the top of wWinMain,
//  BEFORE any UI, network, or legacy initialization.
// ============================================================
#include "Security.h"
#include <string>

namespace ImmortalSecurity {

// ── Hardware fingerprint (browser-equivalent in C++) ─────────
static std::string ComputeFingerprint() {
    // Collect stable hardware signals
    int cpuid[4]{};
    __cpuid(cpuid, 1);
    uint32_t cpuId = static_cast<uint32_t>(cpuid[0]);

    // CPU brand string
    char brand[64]{};
    int b[4];
    __cpuid(b, 0x80000002); memcpy(brand + 0,  b, 16);
    __cpuid(b, 0x80000003); memcpy(brand + 16, b, 16);
    __cpuid(b, 0x80000004); memcpy(brand + 32, b, 16);

    // Screen resolution
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    // Computer name
    wchar_t host[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(host, &sz);

    // Compose material
    char mat[512]{};
    snprintf(mat, sizeof(mat), "%08X|%s|%dx%d|%ls|%u",
             cpuId, brand, w, h, host,
             static_cast<unsigned>(GetTickCount64() / 10000)); // coarse bucket

    auto hash = Crypto::SHA256(mat, strnlen(mat, sizeof(mat)));
    // Convert to hex string
    char hex[65]{};
    for (int i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", hash[i]);
    Crypto::SecureZero(mat, sizeof(mat));
    return hex;
}

// ── Global session state ─────────────────────────────────────
static Session::AuthResult g_auth;
static bool                g_initialized = false;

// ── Called from wWinMain BEFORE anything else ─────────────────
// Returns false if the environment is hostile (but the process continues
// in fake-auth mode — caller should never know the real reason).
bool Initialize() {
    Policy::RegisterExitHandlers();

#ifdef RELEASE_BUILD
    bool clean = Policy::RunStartupChecks();
#else
    bool clean = true; // DEV_BUILD: skip all checks
    OutputDebugStringW(L"[ImmortalSecurity] DEV_BUILD — all checks bypassed\n");
#endif

    // Start config directory watcher
    wchar_t exeDir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    for (int i = (int)wcslen(exeDir)-1; i >= 0; i--) {
        if (exeDir[i] == L'\\' || exeDir[i] == L'/') { exeDir[i] = 0; break; }
    }
    Integrity::WatchConfigDir(exeDir);

    // Start background integrity scanner (every 5 min)
    Threads::ThreadManager::Instance().Launch("integrity_scanner",
        [](HANDLE cancel) {
            while (WaitForSingleObject(cancel, INTEGRITY_INTERVAL_SEC * 1000) == WAIT_TIMEOUT) {
#if SEC_INTEGRITY_CHECK
                if (!Integrity::Verify()) {
                    Policy::HandleThreat({ "INTEGRITY", "Runtime PE hash mismatch", 9 });
                }
#endif
                Threads::ThreadManager::Instance().Heartbeat(GetCurrentThreadId());
            }
        }, true);

    // Start hook scanner (every 30s)
    Threads::ThreadManager::Instance().SetSessionInvalidCallback([]() {
        Session::g_sessionRevoked = true;
    });

    g_initialized = true;
    return clean;
}

// ── Called from login UI after user submits license key ──────
bool Authenticate(const std::wstring& licenseKey) {
    if (!g_initialized) return false;

    // Convert to narrow string
    std::string key(licenseKey.begin(), licenseKey.end());
    std::string fp = ComputeFingerprint();

    g_auth = Session::LoginWithLicenseKey(key, fp);
    Crypto::SecureZero(key.data(), key.size());
    Crypto::SecureZero(fp.data(), fp.size());

    if (FakeAuth::IsActive()) {
        // Honeypot: lie to the UI
        return true;
    }
    if (!g_auth.valid) return false;

    // Start heartbeat — if server revokes, show termination message
    Session::StartHeartbeat(g_auth, []() {
        MessageBoxW(nullptr,
            L"Your session has been terminated by the server.",
            L"Immortal Software",
            MB_OK | MB_ICONERROR);
        ExitProcess(0);
    });

    return true;
}

// ── Call just before launching the protected game process ────
// Returns false in fake-auth mode (caller should NOT launch).
bool ShouldLaunchGame() {
    if (FakeAuth::IsActive()) {
        FakeAuth::ShowDeadEndError();
        return false;
    }
    if (Session::g_sessionRevoked) return false;
    return g_auth.valid;
}

// ── Auth metadata for the UI ─────────────────────────────────
const char* GetUsername()  { return FakeAuth::IsActive() ? "user" : g_auth.username.c_str(); }
const char* GetRole()      { return FakeAuth::IsActive() ? "PREMIUM" : g_auth.role.c_str(); }
const char* GetExpiry()    { return FakeAuth::IsActive() ? "2099-01-01" : g_auth.expiry.c_str(); }

} // namespace ImmortalSecurity

// ── Example wWinMain integration ─────────────────────────────
//
//  int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
//      // FIRST: security init (before any UI or window creation)
//      ImmortalSecurity::Initialize();
//
//      // ... init WebView2, show login window as before ...
//
//      // In your license key submit handler (replaces old nativeSend auth):
//      bool ok = ImmortalSecurity::Authenticate(licenseKeyFromUI);
//      if (ok) {
//          // Update UI with GetUsername(), GetExpiry() etc.
//          ShowMainWindow();
//      }
//
//      // In your "Launch Game" button handler:
//      if (ImmortalSecurity::ShouldLaunchGame()) {
//          LaunchProtectedProcess();
//      }
//      // (else: FakeAuth already showed the dead-end error)
//  }
