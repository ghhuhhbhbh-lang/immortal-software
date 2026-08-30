#include "AntiDebug.h"
#include "Security.h"
#include "CryptoUtils.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <algorithm>
#include <atomic>
#include <thread>
#include <chrono>
#include <cmath>
#include <cstring>

#pragma comment(lib, "psapi.lib")

#ifndef ProcessDebugPort
#  define ProcessDebugPort          7
#  define ProcessDebugObjectHandle  30
#  define ProcessDebugFlags         31
#  define ProcessBreakOnTermination 29
#endif

#ifndef ThreadHideFromDebugger
#  define ThreadHideFromDebugger 0x11
#endif

typedef NTSTATUS(NTAPI* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fnNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static fnNtQIP g_NtQIP = nullptr;
static fnNtSetInformationThread g_NtSIT = nullptr;
static fnNtQuerySystemInformation g_NtQSI = nullptr;

namespace AntiDebug {

struct TimingProfile {
    uint64_t baseline_tsc = 0;
    uint64_t rdtsc_overhead = 0;
    double   cpu_hz = 0.0;
    bool     calibrated = false;
};

static TimingProfile g_timing{};
static std::atomic<bool> g_monitor{false};
static std::thread g_monitorThread;

static void ResolveNtdll() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    g_NtQIP = reinterpret_cast<fnNtQIP>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    g_NtSIT = reinterpret_cast<fnNtSetInformationThread>(GetProcAddress(ntdll, "NtSetInformationThread"));
    g_NtQSI = reinterpret_cast<fnNtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
}

static void CalibrateTiming() {
    const int N = 64;
    std::vector<uint64_t> samples;
    samples.reserve(N);
    for (int i = 0; i < N; ++i) {
        uint64_t a = __rdtsc();
        uint64_t b = __rdtsc();
        samples.push_back(b - a);
    }
    std::sort(samples.begin(), samples.end());
    g_timing.rdtsc_overhead = samples[N / 2];

    auto t0 = std::chrono::steady_clock::now();
    uint64_t s0 = __rdtsc();
    Sleep(20);
    uint64_t s1 = __rdtsc();
    auto t1 = std::chrono::steady_clock::now();
    double ns = static_cast<double>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
    if (ns > 0.0) g_timing.cpu_hz = static_cast<double>(s1 - s0) / ns * 1e9;

    volatile int dummy = 0;
    uint64_t c0 = __rdtsc();
    for (int i = 0; i < 2000; ++i) dummy += i * 3;
    g_timing.baseline_tsc = __rdtsc() - c0;
    (void)dummy;
    g_timing.calibrated = true;
}

void HideCurrentThread() {
    if (!g_NtSIT) return;
    ULONG hide = 1;
    g_NtSIT(GetCurrentThread(), ThreadHideFromDebugger, &hide, sizeof(hide));
}

bool PebBeingDebugged() {
#if defined(_M_X64) || defined(__x86_64__)
    auto* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
    auto* peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
    return peb && peb->BeingDebugged != 0;
}

bool NtGlobalFlagSet() {
#if defined(_M_X64) || defined(__x86_64__)
    auto* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    DWORD flags = *reinterpret_cast<DWORD*>(peb + 0xBC); // NtGlobalFlag x64
#else
    auto* peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    if (!peb) return false;
    DWORD flags = *reinterpret_cast<DWORD*>(peb + 0x68);
#endif
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    constexpr DWORD kDebugHeap = 0x70;
    return (flags & kDebugHeap) == kDebugHeap;
}

bool HeapFlagsSuspicious() {
    HANDLE h = GetProcessHeap();
    if (!h) return false;
    // Undocumented heap flags offsets vary; use HeapQueryInformation where available
    ULONG info = 0;
    if (!HeapQueryInformation(h, HeapCompatibilityInformation, &info, sizeof(info), nullptr))
        return false;
    return false; // informational only — keep false to avoid FP on modern heaps
}

bool NtDebugChecks() {
    if (!g_NtQIP) return false;

    HANDLE dbgObj = nullptr;
    NTSTATUS s = g_NtQIP(GetCurrentProcess(), ProcessDebugObjectHandle, &dbgObj, sizeof(dbgObj), nullptr);
    if (NT_SUCCESS(s) && dbgObj) {
        CloseHandle(dbgObj);
        return true;
    }

    ULONG_PTR port = 0;
    s = g_NtQIP(GetCurrentProcess(), ProcessDebugPort, &port, sizeof(port), nullptr);
    if (NT_SUCCESS(s) && port != 0) return true;

    ULONG flags = 0;
    s = g_NtQIP(GetCurrentProcess(), ProcessDebugFlags, &flags, sizeof(flags), nullptr);
    if (NT_SUCCESS(s) && flags == 0) return true; // NoDebugInherit cleared

    return false;
}

bool NtDebugChecksAdvanced() {
    if (NtDebugChecks()) return true;
    if (!g_NtQIP) return false;
    ULONG bot = 0;
    NTSTATUS s = g_NtQIP(GetCurrentProcess(), ProcessBreakOnTermination, &bot, sizeof(bot), nullptr);
    return NT_SUCCESS(s) && bot != 0;
}

bool KernelDebuggerPresent() {
    // SystemKernelDebuggerInformation = 0x23
    if (!g_NtQSI) return false;
    struct { BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent; } info{};
    NTSTATUS s = g_NtQSI(0x23, &info, sizeof(info), nullptr);
    if (!NT_SUCCESS(s)) return false;
    return info.DebuggerEnabled && !info.DebuggerNotPresent;
}

bool HardwareBreakpointsSet() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    if (ctx.Dr7 & 0xFF) return true;
    return false;
}

bool TimingAnomalyDetected() {
    if (!g_timing.calibrated) return false;

    const int samples = 8;
    uint64_t sum = 0;
    for (int i = 0; i < samples; ++i) {
        uint8_t buf[32];
        for (int j = 0; j < 32; ++j) buf[j] = static_cast<uint8_t>(j ^ i);
        uint64_t t0 = __rdtsc();
        auto h = Crypto::SHA256(buf, sizeof(buf));
        volatile uint8_t sink = h[0];
        (void)sink;
        sum += __rdtsc() - t0;
    }
    uint64_t avg = sum / samples;
    uint64_t threshold = g_timing.baseline_tsc * 12 + RDTSC_THRESHOLD_CYCLES;
    return avg > threshold;
}

bool ParentIsSuspicious() {
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD me = GetCurrentProcessId();
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == me) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!ppid) return false;

    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!ph) return true;
    wchar_t path[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(ph, 0, path, &sz);
    CloseHandle(ph);

    std::wstring name(path);
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

    static const wchar_t* trusted[] = {
        L"explorer.exe", L"svchost.exe", L"services.exe",
        L"wininit.exe", L"winlogon.exe", L"userinit.exe", nullptr
    };
    for (int i = 0; trusted[i]; ++i)
        if (name.find(trusted[i]) != std::wstring::npos) return false;

    static const wchar_t* suspect[] = {
        L"x64dbg", L"x32dbg", L"ollydbg", L"ida64", L"idaq", L"ida.exe",
        L"windbg", L"dbgview", L"procmon", L"apimonitor", L"cheatengine",
        L"scylla", L"xenshield", L"processhacker", L"httpdebugger",
        L"fiddler", L"wireshark", L"ghidra", nullptr
    };
    for (int i = 0; suspect[i]; ++i)
        if (name.find(suspect[i]) != std::wstring::npos) return true;
    return false;
}

bool HypervisorDetected() {
    int r[4]{};
    __cpuid(r, 1);
    if (r[2] & (1 << 31)) return true;
    __cpuid(r, 0x40000000);
    if (static_cast<uint32_t>(r[0]) >= 0x40000000u) {
        char sig[13]{};
        memcpy(sig, &r[1], 4);
        memcpy(sig + 4, &r[2], 4);
        memcpy(sig + 8, &r[3], 4);
        static const char* known[] = {
            "VMwareVMware", "XenVMMXenVMM", "Microsoft Hv", "KVMKVMKVM", "prl hyperv ", nullptr
        };
        for (int i = 0; known[i]; ++i)
            if (memcmp(sig, known[i], 12) == 0) return true;
    }
    return false;
}

bool DebuggerProcessesRunning() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring n(pe.szExeFile);
            std::transform(n.begin(), n.end(), n.begin(), ::towlower);
            static const wchar_t* tools[] = {
                L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida64.exe",
                L"ida.exe", L"windbg.exe", L"cheatengine-x86_64.exe",
                L"cheatengine.exe", L"processhacker.exe", L"x96dbg.exe", nullptr
            };
            for (int i = 0; tools[i]; ++i)
                if (n == tools[i]) { found = true; break; }
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool MemoryProtectionBypassed() {
    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(mod, &mbi, sizeof(mbi))) return false;
    return (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) != 0;
}

bool CloseHandleExceptionTrick() {
    // Invalid handle with EXCEPTION_INVALID_HANDLE — debuggers often swallow differently
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xDEADBEEF)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false; // exception = typically no debugger filter
    }
    return false;
}

bool OutputDebugStringCaught() {
    SetLastError(0);
    OutputDebugStringA("immortal-probe");
    // Under some older debuggers LastError becomes non-zero; keep soft
    return false;
}

bool IsDebuggerAttached() {
    if (IsDebuggerPresent()) return true;
    if (PebBeingDebugged()) return true;
    if (NtDebugChecks()) return true;
    return false;
}

uint32_t DebugScore() {
    uint32_t score = 0;
    if (IsDebuggerPresent())          score += 12;
    if (PebBeingDebugged())           score += 12;
    if (NtDebugChecks())              score += 12;
    if (NtDebugChecksAdvanced())      score += 6;
    if (NtGlobalFlagSet())            score += 8;
    if (KernelDebuggerPresent())      score += 10;
    if (HardwareBreakpointsSet())     score += 8;
    if (TimingAnomalyDetected())      score += 5;
    if (ParentIsSuspicious())         score += 5;
    if (HypervisorDetected())         score += 3;
    if (DebuggerProcessesRunning())   score += 8;
    if (MemoryProtectionBypassed())   score += 7;
    return score;
}

void Init() {
    ResolveNtdll();
    CalibrateTiming();
    HideCurrentThread();

    if (g_monitor.exchange(true)) return;
    g_monitorThread = std::thread([]() {
        while (g_monitor.load()) {
            Sleep(7000 + (GetTickCount() % 5000));
            if (!g_monitor.load()) break;
            if (IsDebuggerAttached() || DebuggerProcessesRunning()) {
                Policy::HandleThreat({ "ANTI_DEBUG", "Runtime debugger signal", 8 });
                break;
            }
            if (HardwareBreakpointsSet()) {
                Policy::HandleThreat({ "ANTI_DEBUG", "Hardware breakpoints set", 7 });
            }
        }
    });
}

void StopMonitoring() {
    g_monitor = false;
    if (g_monitorThread.joinable()) g_monitorThread.join();
}

} // namespace AntiDebug
