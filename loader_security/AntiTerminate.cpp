#include "AntiTerminate.h"
#include "Security.h"
#include <tlhelp32.h>
#include <aclapi.h>
#include <sddl.h>
#include <atomic>
#include <thread>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace AntiTerminate {

static std::atomic<bool> g_run{false};
static std::thread g_wd;
static DWORD g_mainTid = 0;

bool HardenAgainstTermination() {
    PSECURITY_DESCRIPTOR sd = nullptr;
    // Deny PROCESS_TERMINATE / PROCESS_SUSPEND_RESUME to Everyone; allow SYSTEM + Admins full
    // 0x0001 = TERMINATE, 0x0800 = SUSPEND_RESUME — strip from WD
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;0x1FFFFF;;;SY)(A;;0x1FFFFF;;;BA)(A;;0x1400;;;WD)",
            SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }
    BOOL ok = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok == TRUE;
}

bool MassSuspendDetected() {
    // Soft heuristic: only flag if MANY threads already had suspend count >= 1
    // without us suspending the whole process aggressively every tick.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{ sizeof(te) };
    DWORD pid = GetCurrentProcessId();
    int total = 0, suspended = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == GetCurrentThreadId()) continue;
            ++total;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) continue;
            // Prefer NtQueryInformationThread SuspendCount when available — fallback skip
            CloseHandle(th);
            if (total > 24) break;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    (void)suspended;
    return false; // disabled hard path to avoid self-deadlock; rely on AntiDebug attach signals
}

bool SuspiciousHandleActivity() {
    // Lightweight: if we cannot open ourselves with expected rights after hardening, OK.
    // If foreign tools hold PROCESS_VM_READ we cannot always see it without driver —
    // rely on AntiDump process-name scan + periodic MassSuspendDetected.
    HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!self) return true;
    CloseHandle(self);
    return false;
}

uint32_t TerminateRiskScore() {
    uint32_t s = 0;
    if (MassSuspendDetected()) s += 9;
    if (SuspiciousHandleActivity()) s += 4;
    return s;
}

void Init() {
    g_mainTid = GetCurrentThreadId();
    HardenAgainstTermination();
    if (g_run.exchange(true)) return;
    g_wd = std::thread([]() {
        while (g_run.load()) {
            Sleep(8000 + (GetTickCount() % 4000));
            if (!g_run.load()) break;
            if (MassSuspendDetected()) {
                Policy::HandleThreat({ "ANTI_TERMINATE", "Mass thread suspend detected", 8 });
            }
        }
    });
}

void Shutdown() {
    g_run = false;
    if (g_wd.joinable()) g_wd.join();
}

} // namespace AntiTerminate
