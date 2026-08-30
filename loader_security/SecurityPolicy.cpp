#include "SecurityPolicy.h"
#include "IntegrityManager.h"
#include "AntiDebug.h"
#include "AntiVM.h"
#include "AntiInject.h"
#include "FakeAuthEngine.h"
#include "ThreadManager.h"
#include <windows.h>
#include <cstdlib>
#include <functional>

namespace Policy {

static std::function<void(const ThreatEvent&)> g_auditCb;

void SetAuditCallback(std::function<void(const ThreatEvent&)> cb) {
    g_auditCb = cb;
}

void HandleThreat(const ThreatEvent& ev) {
    if (g_auditCb) g_auditCb(ev);

    if (ev.severity >= 8) {
        // HARD FAIL — critical integrity breach
        // Zero any sensitive state before exit
        Shutdown();
        ExitProcess(0xC0000001); // STATUS_UNSUCCESSFUL
    } else {
        // SOFT FAIL — enter deception mode
        if (!FakeAuth::IsActive()) {
            FakeAuth::Activate(ev.source);
        }
    }
}

bool RunStartupChecks() {
#if SEC_INTEGRITY_CHECK
    if (!Integrity::Initialize()) {
        HandleThreat({ "INTEGRITY", "PE section hash failed to initialize", 9 });
        return false;
    }
    if (!Integrity::Verify()) {
        HandleThreat({ "INTEGRITY", "PE section hash mismatch — binary tampered", 10 });
        return false;
    }
#endif

#if SEC_ANTI_DEBUG
    AntiDebug::Init();
    uint32_t dbgScore = AntiDebug::DebugScore();
    if (dbgScore >= 10) {
        // Strong debugger signal: honeypot
        HandleThreat({ "ANTI_DEBUG", "Debugger detected at startup", dbgScore > 15 ? 9u : 5u });
        if (dbgScore >= 18) return false; // Hard fail: multiple definitive checks
    }
    if (AntiDebug::ParentIsSuspicious()) {
        HandleThreat({ "ANTI_DEBUG", "Suspicious parent process", 6 });
    }
#endif

#if SEC_ANTI_VM
    uint32_t vmScore = 0;
    if (!AntiVM::LoadCachedScore(vmScore))
        vmScore = AntiVM::GetRiskScore();
    AntiVM::SaveCachedScore(vmScore);
    if (vmScore >= 50) {
        HandleThreat({ "ANTI_VM", "VM/sandbox environment detected", 4 });
    }
#endif

#if SEC_ANTI_INJECT
    uint32_t hooked = AntiInject::ScanAllCritical();
    if (hooked > 0) {
        HandleThreat({ "HOOK_DETECTED", "API hooks found at startup", hooked > 3 ? 7u : 4u });
    }
    AntiInject::StartHookScanner();
#endif

    return !FakeAuth::IsActive();
}

static void CleanupOnExit() {
    // Clear Windows Credential Manager entries
    CredDeleteW(L"ImmortalSoftware_RefreshToken", CRED_TYPE_GENERIC, 0);
    // Delete temp files
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring cache = std::wstring(tmp) + L"isl_cache.bin";
    DeleteFileW(cache.c_str());
    // Stop all threads gracefully
    Threads::ThreadManager::Instance().StopAll();
}

void Shutdown() { CleanupOnExit(); }

void RegisterExitHandlers() {
    std::atexit(CleanupOnExit);
}

} // namespace Policy
