#include "AntiTamper.h"
#include "Security.h"
#include "CryptoUtils.h"
#include <psapi.h>
#include <vector>
#include <cstring>
#include <string>

#pragma comment(lib, "psapi.lib")

namespace AntiTamper {

struct ApiSnap {
    FARPROC ptr;
    std::array<uint8_t, 32> hash;
    char name[64];
};

static std::vector<ApiSnap> g_snaps;
static bool g_ready = false;

static void HashPrologue(FARPROC fn, std::array<uint8_t, 32>& out) {
    uint8_t buf[16]{};
    if (fn) memcpy(buf, reinterpret_cast<const void*>(fn), sizeof(buf));
    out = Crypto::SHA256(buf, sizeof(buf));
}

bool SnapshotCriticalApis() {
    g_snaps.clear();
    struct E { const wchar_t* dll; const char* fn; };
    static const E list[] = {
        { L"ntdll.dll", "NtProtectVirtualMemory" },
        { L"ntdll.dll", "NtWriteVirtualMemory" },
        { L"ntdll.dll", "NtCreateThreadEx" },
        { L"ntdll.dll", "NtMapViewOfSection" },
        { L"ntdll.dll", "LdrLoadDll" },
        { L"kernel32.dll", "VirtualProtect" },
        { L"kernel32.dll", "VirtualAlloc" },
        { L"kernel32.dll", "LoadLibraryW" },
        { L"kernel32.dll", "CreateRemoteThread" },
        { L"kernel32.dll", "WriteProcessMemory" },
        { L"kernelbase.dll", "VirtualProtect" },
        { nullptr, nullptr }
    };
    for (int i = 0; list[i].dll; ++i) {
        HMODULE m = GetModuleHandleW(list[i].dll);
        if (!m) continue;
        FARPROC p = GetProcAddress(m, list[i].fn);
        if (!p) continue;
        ApiSnap s{};
        s.ptr = p;
        strncpy_s(s.name, list[i].fn, _TRUNCATE);
        HashPrologue(p, s.hash);
        g_snaps.push_back(s);
    }
    g_ready = !g_snaps.empty();
    return g_ready;
}

bool VerifyCriticalApis() {
    if (!g_ready) return false;
    for (const auto& s : g_snaps) {
        std::array<uint8_t, 32> now{};
        HashPrologue(s.ptr, now);
        if (now != s.hash) return false;
        // Inline hook quick patterns
        const uint8_t* b = reinterpret_cast<const uint8_t*>(s.ptr);
        if (b[0] == 0xE9 || b[0] == 0xEB) return false;
        if (b[0] == 0xFF && b[1] == 0x25) return false;
        if (b[0] == 0x48 && b[1] == 0xB8) return false;
    }
    return true;
}

bool ExecutableWritablePages() {
    HMODULE base = GetModuleHandleW(nullptr);
    if (!base) return false;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        MEMORY_BASIC_INFORMATION mbi{};
        void* addr = reinterpret_cast<uint8_t*>(base) + sec->VirtualAddress;
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) continue;
        if (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_WRITECOPY))
            return true;
    }
    return false;
}

bool LdrAnomalies() {
    // Soft check: extremely few loaded modules is atypical for a GUI loader
    HMODULE mods[512]{};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return false;
    DWORD count = needed / sizeof(HMODULE);
    return count < 4;
}

uint32_t TamperScore() {
    uint32_t s = 0;
    if (!VerifyCriticalApis()) s += 10;
    if (ExecutableWritablePages()) s += 8;
    if (LdrAnomalies()) s += 5;
    return s;
}

void Init() {
    SnapshotCriticalApis();
}

} // namespace AntiTamper
