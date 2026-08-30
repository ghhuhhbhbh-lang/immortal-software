// ============================================================
//  Immortal Software — Security Integration Shim v2.1
// ============================================================
#include "Security.h"
#include <string>

namespace ImmortalSecurity {

static std::string ComputeFingerprint(const Session::HardwareInfo& hw) {
    char mat[1024]{};
    snprintf(mat, sizeof(mat), "%s|%s|%s|%s|%s|%s|%llu|%s",
             hw.cpuId.c_str(), hw.motherboardSerial.c_str(), hw.biosSerial.c_str(),
             hw.systemUuid.c_str(), hw.macAddress.c_str(), hw.processorName.c_str(),
             static_cast<unsigned long long>(hw.totalMemory), hw.screenResolution.c_str());
    auto hash = Crypto::SHA256(mat, strnlen(mat, sizeof(mat)));
    char hex[65]{};
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
    Crypto::SecureZero(mat, sizeof(mat));
    return hex;
}

static Session::AuthResult g_auth;
static std::string         g_fingerprint;
static bool                g_initialized = false;

bool Initialize() {
    Policy::RegisterExitHandlers();

    Policy::SetAuditCallback([](const Policy::ThreatEvent& ev) {
        if (g_auth.valid) {
            Session::ReportThreat(g_auth, ev.source, ev.detail, ev.severity);
        }
    });

#ifdef RELEASE_BUILD
    bool clean = Policy::RunStartupChecks();
#else
    bool clean = true;
    OutputDebugStringW(L"[ImmortalSecurity] DEV_BUILD — checks bypassed\n");
#endif

    wchar_t exeDir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    for (int i = static_cast<int>(wcslen(exeDir)) - 1; i >= 0; i--) {
        if (exeDir[i] == L'\\' || exeDir[i] == L'/') { exeDir[i] = 0; break; }
    }
    Integrity::WatchConfigDir(exeDir);

    Threads::ThreadManager::Instance().SetSessionInvalidCallback([]() {
        Session::g_sessionRevoked = true;
    });

    Threads::ThreadManager::Instance().Launch("integrity_scanner",
        [](HANDLE cancel) {
            while (WaitForSingleObject(cancel, INTEGRITY_INTERVAL_SEC * 1000) == WAIT_TIMEOUT) {
#if SEC_INTEGRITY_CHECK
                if (!Integrity::Verify()) {
                    Policy::HandleThreat({ "INTEGRITY", "Runtime PE hash mismatch", 9 });
                }
                if (!Integrity::ValidateWatchedConfigs()) {
                    Policy::HandleThreat({ "INTEGRITY", "Config HMAC failed", 8 });
                }
#endif
#if SEC_ANTI_TAMPER
                if (!AntiTamper::VerifyCriticalApis()) {
                    Policy::HandleThreat({ "ANTI_TAMPER", "API prologue changed at runtime", 9 });
                }
#endif
#if SEC_ANTI_DUMP
                if (AntiDump::DumpToolsPresent()) {
                    Policy::HandleThreat({ "ANTI_DUMP", "Dump tool appeared at runtime", 7 });
                }
#endif
                Threads::ThreadManager::Instance().Heartbeat(GetCurrentThreadId());
            }
        }, true);

    Threads::ThreadManager::Instance().Launch("security_pulse",
        [](HANDLE cancel) {
            while (WaitForSingleObject(cancel, TAMPER_SCAN_INTERVAL_SEC * 1000) == WAIT_TIMEOUT) {
#if SEC_ANTI_DEBUG
                if (AntiDebug::DebugScore() >= 18) {
                    Policy::HandleThreat({ "ANTI_DEBUG", "Late debugger attach", 9 });
                }
#endif
#if SEC_ANTI_INJECT
                if (AntiInject::ScanAllCritical() >= 2) {
                    Policy::HandleThreat({ "HOOK", "Hooks appeared at runtime", 8 });
                }
#endif
                Threads::ThreadManager::Instance().Heartbeat(GetCurrentThreadId());
            }
        }, true);

#if SEC_THREAD_CONTEXT_MON
    Threads::ThreadManager::Instance().StartContextMonitor();
#endif

    g_initialized = true;
    return clean;
}

bool Authenticate(const std::wstring& licenseKey) {
    if (!g_initialized) return false;

    std::string key(licenseKey.begin(), licenseKey.end());
    auto hw = Session::CollectHardwareInfo();
    g_fingerprint = ComputeFingerprint(hw);

    g_auth = Session::LoginWithLicenseKey(key, g_fingerprint, &hw);
    Crypto::SecureZero(key.data(), key.size());

    if (FakeAuth::IsActive()) return true;
    if (!g_auth.valid) return false;

    Session::StartHeartbeat(g_auth, []() {
        MessageBoxW(nullptr,
            L"Your session has been terminated by the server.",
            L"Immortal Software",
            MB_OK | MB_ICONERROR);
        ExitProcess(0);
    });

    Session::StartAttestation(g_auth, g_fingerprint,
        []() {
            Session::SecurityScores s;
#if SEC_INTEGRITY_CHECK
            s.integrityOk = Integrity::Verify();
            s.signedPe = Integrity::VerifyCodeSignature();
#endif
#if SEC_ANTI_DEBUG
            s.debugScore = AntiDebug::DebugScore();
#endif
#if SEC_ANTI_VM
            s.vmScore = AntiVM::GetRiskScore();
#endif
#if SEC_ANTI_TAMPER
            s.tamperScore = AntiTamper::TamperScore();
#endif
            return s;
        },
        []() {
            MessageBoxW(nullptr,
                L"Security attestation failed. Session ended.",
                L"Immortal Software",
                MB_OK | MB_ICONERROR);
            ExitProcess(0);
        });

    return true;
}

bool ShouldLaunchGame() {
    if (FakeAuth::IsActive()) {
        FakeAuth::ShowDeadEndError();
        return false;
    }
    if (Session::g_sessionRevoked) return false;
    return g_auth.valid;
}

const char* GetUsername()  { return FakeAuth::IsActive() ? "user" : g_auth.username.c_str(); }
const char* GetRole()      { return FakeAuth::IsActive() ? "PREMIUM" : g_auth.role.c_str(); }
const char* GetExpiry()    { return FakeAuth::IsActive() ? "2099-01-01" : g_auth.expiry.c_str(); }

} // namespace ImmortalSecurity
