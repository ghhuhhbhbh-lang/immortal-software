#include "Security.h"
#include <wincred.h>
#include <cstdlib>

#pragma comment(lib, "advapi32.lib")

namespace Policy {

static std::function<void(const ThreatEvent&)> g_auditCb;

void SetAuditCallback(std::function<void(const ThreatEvent&)> cb) {
    g_auditCb = std::move(cb);
}

void HandleThreat(const ThreatEvent& ev) {
    if (g_auditCb) g_auditCb(ev);

#if !defined(RELEASE_BUILD) && defined(DEV_BUILD)
    OutputDebugStringA("[ImmortalSecurity] threat: ");
    OutputDebugStringA(ev.source);
    OutputDebugStringA(" — ");
    OutputDebugStringA(ev.detail ? ev.detail : "");
    OutputDebugStringA("\n");
#endif

    if (ev.severity >= 9) {
        Shutdown();
        ExitProcess(0xC0000001);
    }
    if (ev.severity >= 7) {
#if SEC_FAKE_AUTH
        if (!FakeAuth::IsActive()) FakeAuth::Activate(ev.source);
#endif
        // Mid-high: degrade silently into honeypot, do not hard-kill yet
        return;
    }
    if (ev.severity >= 4) {
#if SEC_FAKE_AUTH
        if (!FakeAuth::IsActive()) FakeAuth::Activate(ev.source);
#endif
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
#ifdef NDEBUG
    // Soft: missing Authenticode in unsigned builds should not hard-kill during bring-up
    if (!Integrity::VerifyCodeSignature()) {
        HandleThreat({ "INTEGRITY", "PE not Authenticode-signed", 4 });
    }
#endif
#endif

#if SEC_ANTI_TAMPER
    AntiTamper::Init();
    uint32_t tamper = AntiTamper::TamperScore();
    if (tamper >= 10) {
        HandleThreat({ "ANTI_TAMPER", "Critical API prologue / page tamper", 9 });
        return false;
    }
    if (tamper >= 5) {
        HandleThreat({ "ANTI_TAMPER", "Tamper indicators present", 6 });
    }
#endif

#if SEC_ANTI_DEBUG
    AntiDebug::Init();
    uint32_t dbgScore = AntiDebug::DebugScore();
    if (dbgScore >= 18) {
        HandleThreat({ "ANTI_DEBUG", "Strong debugger / analysis signal", 9 });
        return false;
    }
    if (dbgScore >= 10) {
        HandleThreat({ "ANTI_DEBUG", "Debugger heuristics triggered", 7 });
    }
    if (AntiDebug::ParentIsSuspicious()) {
        HandleThreat({ "ANTI_DEBUG", "Suspicious parent process", 6 });
    }
#endif

#if SEC_ANTI_DUMP
    AntiDump::Init();
    uint32_t dumpScore = AntiDump::DumpRiskScore();
    if (dumpScore >= 10) {
        HandleThreat({ "ANTI_DUMP", "Dump / debug-object artifacts", 8 });
    } else if (dumpScore >= 8) {
        HandleThreat({ "ANTI_DUMP", "Memory dump tool present", 6 });
    }
#endif

#if SEC_ANTI_TERMINATE
    AntiTerminate::Init();
#endif

#if SEC_ANTI_VM
    AntiVM::InitializeMLModel();
    uint32_t vmScore = 0;
    if (!AntiVM::LoadCachedScore(vmScore))
        vmScore = AntiVM::GetRiskScore();
    AntiVM::SaveCachedScore(vmScore);
    if (vmScore >= 75) {
        HandleThreat({ "ANTI_VM", "High-confidence VM/sandbox", 7 });
    } else if (vmScore >= 50) {
        HandleThreat({ "ANTI_VM", "VM/sandbox environment detected", 5 });
    }
    AntiVM::StartVMMonitoring();
#endif

#if SEC_ANTI_INJECT
    uint32_t hooked = AntiInject::ScanAllCritical();
    if (hooked >= 3) {
        HandleThreat({ "HOOK_DETECTED", "Multiple critical API hooks", 8 });
    } else if (hooked > 0) {
        HandleThreat({ "HOOK_DETECTED", "API hooks found at startup", 5 });
    }
    AntiInject::StartHookScanner();
#endif

#if SEC_ANTI_DUMP
    // Headers erased AFTER integrity + tamper baselines
    AntiDump::ErasePEHeaders();
#endif

    return !FakeAuth::IsActive();
}

static void CleanupOnExit() {
    CredDeleteW(L"ImmortalSoftware_RefreshToken", CRED_TYPE_GENERIC, 0);
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring cache = std::wstring(tmp) + L"isl_cache.bin";
    DeleteFileW(cache.c_str());
#if SEC_ANTI_DEBUG
    AntiDebug::StopMonitoring();
#endif
#if SEC_ANTI_VM
    AntiVM::StopVMMonitoring();
#endif
#if SEC_ANTI_TERMINATE
    AntiTerminate::Shutdown();
#endif
#if SEC_ANTI_INJECT
    AntiInject::StopHookScanner();
#endif
    Threads::ThreadManager::Instance().StopAll();
}

void Shutdown() { CleanupOnExit(); }

void RegisterExitHandlers() {
    std::atexit(CleanupOnExit);
}

} // namespace Policy
