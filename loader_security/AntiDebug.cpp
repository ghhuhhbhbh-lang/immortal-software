#include "AntiDebug.h"
#include "CryptoUtils.h"
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <intrin.h>

// NtQueryInformationProcess constants not always in SDK
#ifndef ProcessDebugPort
#  define ProcessDebugPort          7
#  define ProcessDebugObjectHandle  30
#  define ProcessDebugFlags         31
#endif

typedef NTSTATUS(NTAPI* fnNtQIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
static fnNtQIP NtQueryInfoProc = nullptr;

namespace AntiDebug {

static uint64_t g_baselineTSC = 0;

void Init() {
    NtQueryInfoProc = reinterpret_cast<fnNtQIP>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    // Warm up TSC baseline with a known-cost operation
    volatile int dummy = 0;
    uint64_t t0 = Crypto::ReadTSC();
    for (int i = 0; i < 1000; i++) dummy += i;
    g_baselineTSC = Crypto::ReadTSC() - t0;
}

bool NtDebugChecks() {
    if (!NtQueryInfoProc) return false;
    HANDLE debugObj = nullptr;
    NTSTATUS s = NtQueryInfoProc(GetCurrentProcess(),
        ProcessDebugObjectHandle, &debugObj, sizeof(debugObj), nullptr);
    if (NT_SUCCESS(s) && debugObj) { CloseHandle(debugObj); return true; }

    DWORD debugPort = 0;
    s = NtQueryInfoProc(GetCurrentProcess(),
        ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
    if (NT_SUCCESS(s) && debugPort != 0) return true;

    DWORD noDebug = 0;
    s = NtQueryInfoProc(GetCurrentProcess(),
        ProcessDebugFlags, &noDebug, sizeof(noDebug), nullptr);
    if (NT_SUCCESS(s) && noDebug == 0) return true;

    return false;
}

bool HardwareBreakpointsSet() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{ sizeof(te) };
    bool found = false;
    DWORD pid = GetCurrentProcessId();

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == GetCurrentThreadId()) continue;
            HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;
            CONTEXT ctx{ .ContextFlags = CONTEXT_DEBUG_REGISTERS };
            if (GetThreadContext(th, &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) found = true;
            }
            CloseHandle(th);
        } while (!found && Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return found;
}

bool TimingAnomalyDetected() {
    volatile uint64_t acc = 0;
    uint64_t t0 = Crypto::ReadTSC();
    // Perform a calibrated crypto op
    uint8_t buf[256]{};
    for (int i = 0; i < 256; i++) buf[i] = static_cast<uint8_t>(i);
    auto h = Crypto::SHA256(buf, sizeof(buf));
    acc = h[0]; // prevent optimization
    uint64_t delta = Crypto::ReadTSC() - t0;
    // If 10x slower than baseline, single-stepping or emulation
    return g_baselineTSC > 0 && delta > g_baselineTSC * 10ULL + RDTSC_THRESHOLD_CYCLES;
}

bool ParentIsSuspicious() {
    DWORD ppid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{ sizeof(pe) };
        DWORD myPid = GetCurrentProcessId();
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == myPid) { ppid = pe.th32ParentProcessID; break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (!ppid) return false;

    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!ph) return true; // can't inspect = suspicious

    wchar_t path[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(ph, 0, path, &sz);
    CloseHandle(ph);

    std::wstring name(path);
    // Convert to lowercase for comparison
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

    // Trusted launchers
    static const wchar_t* trusted[] = {
        L"explorer.exe", L"svchost.exe", L"services.exe",
        L"wininit.exe", L"winlogon.exe", nullptr
    };
    for (int i = 0; trusted[i]; i++) {
        if (name.find(trusted[i]) != std::wstring::npos) return false;
    }

    // Known debugger hosts
    static const wchar_t* suspect[] = {
        L"cmd.exe", L"powershell.exe", L"x64dbg.exe", L"x32dbg.exe",
        L"ollydbg.exe", L"idaq.exe", L"idaq64.exe", L"windbg.exe",
        L"dbgview.exe", L"procmon.exe", L"apimonitor.exe",
        L"cheatengine", L"scylla", nullptr
    };
    for (int i = 0; suspect[i]; i++) {
        if (name.find(suspect[i]) != std::wstring::npos) return true;
    }
    return false;
}

bool IsDebuggerAttached() {
    if (IsDebuggerPresent()) return true;
    if (NtDebugChecks()) return true;
    return false;
}

uint32_t DebugScore() {
    uint32_t score = 0;
    if (IsDebuggerPresent())     score += 10;
    if (NtDebugChecks())         score += 10;
    if (HardwareBreakpointsSet()) score += 8;
    if (TimingAnomalyDetected()) score += 6;
    if (ParentIsSuspicious())    score += 4;
    return score;
}

} // namespace AntiDebug
