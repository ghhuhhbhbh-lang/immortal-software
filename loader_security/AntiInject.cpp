#include "AntiInject.h"
#include "CryptoUtils.h"
#include "Security.h"
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <functional>
#include <cstring>

namespace AntiInject {

static std::atomic<bool> g_scanRunning{ false };
static std::function<void()> g_onHookDetected;

// XOR hash of a function name (same algorithm must be used at call site)
static uint32_t XorHash(const char* s, uint32_t key = 0xDEAD1337u) {
    uint32_t h = key;
    while (*s) { h ^= static_cast<uint8_t>(*s++); h = (h << 5) | (h >> 27); }
    return h;
}

FARPROC ResolveAPI(HMODULE mod, uint32_t xorHash) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);
    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) return nullptr;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<uint8_t*>(mod) + expDir.VirtualAddress);
    auto* names   = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(mod) + exp->AddressOfNames);
    auto* funcs   = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(mod) + exp->AddressOfFunctions);
    auto* ordinals = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(mod) + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = reinterpret_cast<const char*>(
            reinterpret_cast<uint8_t*>(mod) + names[i]);
        if (XorHash(name) == xorHash) {
            return reinterpret_cast<FARPROC>(
                reinterpret_cast<uint8_t*>(mod) + funcs[ordinals[i]]);
        }
    }
    return nullptr;
}

bool FunctionHooked(FARPROC fn, const char* /*name*/) {
    if (!fn) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    // Detect common hook patterns:
    // E9 xx xx xx xx   = JMP rel32
    // FF 25 xx xx xx xx = JMP [mem64]
    // 48 B8 xx...      = MOV RAX, imm64
    // 68 xx xx xx xx C3= PUSH+RET thunk
    if (p[0] == 0xE9) return true;               // JMP rel32
    if (p[0] == 0xFF && p[1] == 0x25) return true; // JMP [mem]
    if (p[0] == 0x48 && p[1] == 0xB8) return true; // MOV RAX,imm64
    if (p[0] == 0xEB) return true;               // JMP short
    return false;
}

uint32_t ScanAllCritical() {
    struct Entry { const wchar_t* dll; const char* fn; };
    static const Entry critical[] = {
        { L"ntdll.dll",    "NtCreateThreadEx"   },
        { L"ntdll.dll",    "NtAllocateVirtualMemory" },
        { L"ntdll.dll",    "NtProtectVirtualMemory" },
        { L"ntdll.dll",    "NtWriteVirtualMemory" },
        { L"ntdll.dll",    "NtMapViewOfSection" },
        { L"ntdll.dll",    "NtQueueApcThread" },
        { L"ntdll.dll",    "LdrLoadDll" },
        { L"kernel32.dll", "VirtualProtect"     },
        { L"kernel32.dll", "VirtualAlloc"       },
        { L"kernel32.dll", "LoadLibraryA"       },
        { L"kernel32.dll", "LoadLibraryW"       },
        { L"kernel32.dll", "CreateRemoteThread" },
        { L"kernel32.dll", "WriteProcessMemory" },
        { L"kernel32.dll", "OpenProcess" },
        { nullptr, nullptr }
    };

    uint32_t hooked = 0;
    for (int i = 0; critical[i].dll; i++) {
        HMODULE mod = GetModuleHandleW(critical[i].dll);
        if (!mod) continue;
        FARPROC fn = GetProcAddress(mod, critical[i].fn);
        if (FunctionHooked(fn, critical[i].fn)) hooked++;
    }
    return hooked;
}

void StartHookScanner() {
    if (g_scanRunning.exchange(true)) return;
    if (!g_onHookDetected) {
        g_onHookDetected = []() {
            Policy::HandleThreat({ "HOOK", "Critical API inline hook detected", 8 });
        };
    }
    std::thread([]() {
        while (g_scanRunning) {
            uint32_t hooked = ScanAllCritical();
            if (hooked > 0 && g_onHookDetected) g_onHookDetected();
            for (int i = 0; i < 20 && g_scanRunning; i++)
                Sleep(1000);
        }
    }).detach();
}

void StopHookScanner() { g_scanRunning = false; }

bool SetGuardPage(void* buf, size_t size) {
    if (!buf || size == 0) return false;
    DWORD old = 0;
    // PAGE_GUARD must combine with a valid page type (not NOACCESS alone)
    return VirtualProtect(buf, size, PAGE_READONLY | PAGE_GUARD, &old) != 0;
}

void* AllocExecutable(const void* code, size_t size) {
    void* mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return nullptr;
    memcpy(mem, code, size);
    DWORD old;
    if (!VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return nullptr;
    }
    return mem;
}

void FreeExecutable(void* ptr, size_t size) {
    if (ptr) {
        DWORD old;
        VirtualProtect(ptr, size, PAGE_READWRITE, &old);
        Crypto::SecureZero(ptr, size);
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

void LockRegion(void* ptr, size_t size) {
    DWORD old;
    VirtualProtect(ptr, size, PAGE_NOACCESS, &old);
}

} // namespace AntiInject
