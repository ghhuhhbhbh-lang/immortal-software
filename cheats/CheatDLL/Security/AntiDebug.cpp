#include "AntiDebug.h"
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>

namespace AntiDebug {

static bool CheckPebBeingDebugged() {
#ifdef _WIN64
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    return peb->BeingDebugged != 0;
}

static bool CheckPebNtGlobalFlag() {
#ifdef _WIN64
    auto peb   = reinterpret_cast<PPEB>(__readgsqword(0x60));
    ULONG flags = *reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(peb) + 0xBC);
#else
    auto peb   = reinterpret_cast<PPEB>(__readfsdword(0x30));
    ULONG flags = *reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(peb) + 0x68);
#endif
    return (flags & 0x70) != 0;
}

static bool CheckHeapFlag() {
    HANDLE heap = GetProcessHeap();
    if (!heap) return false;
#ifdef _WIN64
    ULONG flags = *reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(heap) + 0x70);
    ULONG force = *reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(heap) + 0x74);
#else
    ULONG flags = *reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(heap) + 0x40);
    ULONG force = *reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(heap) + 0x44);
#endif
    return (flags & ~HEAP_GROWABLE) != 0 || force != 0;
}

static bool CheckParentDebugged() {
    DWORD myPid = GetCurrentProcessId(), parentPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) };
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (pe.th32ProcessID == myPid) { parentPid = pe.th32ParentProcessID; break; }
    }
    CloseHandle(snap);
    if (!parentPid) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPid);
    if (!h) return false;
    BOOL dbg = FALSE;
    CheckRemoteDebuggerPresent(h, &dbg);
    CloseHandle(h);
    return dbg == TRUE;
}

static bool CheckHardwareBreakpoints() {
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0xFF);
}

static bool CheckRdtscTiming() {
    ULONGLONG t1 = __rdtsc();
    volatile int d = 0;
    for (int i = 0; i < 100; i++) d += i;
    (void)d;
    return (__rdtsc() - t1) > 1'000'000;
}

static bool CheckRemoteDbg() {
    BOOL p = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &p);
    return p == TRUE;
}

Report Scan() {
    Report r;
    if (CheckPebBeingDebugged())  { r.pebFlag  = true; r.score +=  5; }
    if (CheckPebNtGlobalFlag())   { r.heapFlag = true; r.score +=  4; }
    if (CheckHeapFlag())          { r.heapFlag = true; r.score +=  3; }
    if (CheckParentDebugged())    { r.parentPid= true; r.score +=  5; }
    if (CheckHardwareBreakpoints()){ r.hwBreakpt=true; r.score +=  6; }
    if (CheckRdtscTiming())       { r.rdtsc    = true; r.score +=  3; }
    if (CheckRemoteDbg())         { r.remoteDbg= true; r.score +=  5; }
    return r;
}

bool Detected(uint32_t threshold) { return Scan().score >= threshold; }

} // namespace AntiDebug
