#include "AntiDump.h"
#include "Security.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "advapi32.lib")

#ifndef ProcessBreakOnTermination
#  define ProcessBreakOnTermination 29
#endif

typedef NTSTATUS(NTAPI* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fnNtSIP)(HANDLE, ULONG, PVOID, ULONG);

namespace AntiDump {

static bool g_inited = false;

void Init() {
    HardenProcessAccess();
    // Erase headers after other modules have baselined PE for integrity
    g_inited = true;
}

bool HardenProcessAccess() {
    // Enable BreakOnTermination so dumpers that kill us leave a trail / require SeDebug
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto NtSIP = reinterpret_cast<fnNtSIP>(GetProcAddress(ntdll, "NtSetInformationProcess"));
        if (NtSIP) {
            ULONG on = 1;
            NtSIP(GetCurrentProcess(), ProcessBreakOnTermination, &on, sizeof(on));
        }
    }

    // Restrict DACL: current user + SYSTEM only, strip world GENERIC_ALL
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;0x1F0FFF;;;SY)(A;;0x1F0FFF;;;BA)(A;;0x12089A;;;WD)",
            SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }
    BOOL ok = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok == TRUE;
}

void ErasePEHeaders() {
    HMODULE base = GetModuleHandleW(nullptr);
    if (!base) return;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);
    SIZE_T hdrSize = nt->OptionalHeader.SizeOfHeaders;
    if (hdrSize == 0 || hdrSize > 0x2000) hdrSize = 0x1000;

    DWORD old = 0;
    if (!VirtualProtect(base, hdrSize, PAGE_READWRITE, &old)) return;
    SecureZeroMemory(base, hdrSize);
    VirtualProtect(base, hdrSize, old, &old);
}

bool DumpToolsPresent() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring n(pe.szExeFile);
            std::transform(n.begin(), n.end(), n.begin(), ::towlower);
            static const wchar_t* tools[] = {
                L"procdump.exe", L"procdump64.exe", L"dumpcap.exe",
                L"processhacker.exe", L"processhacker2.exe",
                L"taskmgr.exe", // soft signal only counted low
                L"rammap.exe", L"rammap64.exe",
                L"hollows_hunter.exe", L"pe-sieve.exe",
                L"scylla_x64.exe", L"scylla_x86.exe",
                L"megadumper.exe", L"extremedumper.exe",
                nullptr
            };
            for (int i = 0; tools[i]; ++i) {
                if (n == tools[i]) {
                    // taskmgr alone is weak — skip hard flag
                    if (n == L"taskmgr.exe") continue;
                    found = true;
                    break;
                }
            }
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool DumpRelatedDebugArtifacts() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto NtQIP = reinterpret_cast<fnNtQIP>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!NtQIP) return false;
    HANDLE obj = nullptr;
    NTSTATUS s = NtQIP(GetCurrentProcess(), 30 /*DebugObjectHandle*/, &obj, sizeof(obj), nullptr);
    if (NT_SUCCESS(s) && obj) {
        CloseHandle(obj);
        return true;
    }
    return false;
}

uint32_t DumpRiskScore() {
    uint32_t s = 0;
    if (DumpToolsPresent()) s += 8;
    if (DumpRelatedDebugArtifacts()) s += 10;
    return s;
}

} // namespace AntiDump
