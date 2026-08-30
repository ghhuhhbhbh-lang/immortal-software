#include "AntiVM.h"
#include "CryptoUtils.h"
#include <windows.h>
#include <intrin.h>
#include <shlobj.h>
#include <fstream>
#include <algorithm>
#include <ctime>

#pragma comment(lib, "shlwapi.lib")

namespace AntiVM {

// CPUID check: hypervisor present bit
static bool CheckCPUID() {
    int info[4]{};
    __cpuid(info, 1);
    return (info[2] >> 31) & 1; // Hypervisor bit
}

// SMBIOS: read manufacturer from registry
static std::wstring GetSMBIOSManufacturer() {
    HKEY hk; wchar_t buf[256]{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hk) != 0) return {};
    DWORD sz = sizeof(buf);
    RegQueryValueExW(hk, L"SystemManufacturer", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hk);
    return buf;
}

static bool SuspiciousManufacturer(const std::wstring& m) {
    std::wstring lc = m;
    std::transform(lc.begin(), lc.end(), lc.begin(), ::towlower);
    static const wchar_t* sigs[] = {
        L"vmware", L"virtualbox", L"vbox", L"qemu",
        L"bochs", L"xen", L"parallels", L"hyper-v", L"kvm",
        L"innotek", nullptr
    };
    for (int i = 0; sigs[i]; i++)
        if (lc.find(sigs[i]) != std::wstring::npos) return true;
    return false;
}

static bool SuspiciousDriversPresent() {
    static const wchar_t* drivers[] = {
        L"\\\\.\\VBoxGuest", L"\\\\.\\vmci",
        L"\\\\.\\HGFS",     L"\\\\.\\xenbus",
        L"\\\\.\\VBoxMiniRdrDN", nullptr
    };
    for (int i = 0; drivers[i]; i++) {
        HANDLE h = CreateFileW(drivers[i], 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }
    return false;
}

static uint32_t GetUptimeMinutes() {
    return static_cast<uint32_t>(GetTickCount64() / 60000ULL);
}

static uint32_t GetTotalRAMMB() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    return static_cast<uint32_t>(ms.ullTotalPhys / (1024ULL * 1024ULL));
}

static bool SandboxUsername() {
    wchar_t user[256]{};
    DWORD sz = 256;
    GetUserNameW(user, &sz);
    std::wstring u = user;
    std::transform(u.begin(), u.end(), u.begin(), ::towlower);
    static const wchar_t* sigs[] = {
        L"sandbox", L"malware", L"virus", L"sample",
        L"cuckoo", L"tester", L"analyst", nullptr
    };
    for (int i = 0; sigs[i]; i++)
        if (u.find(sigs[i]) != std::wstring::npos) return true;
    return false;
}

VMSignals Collect() {
    VMSignals s{};
    s.cpuidHypervisor    = CheckCPUID();
    s.manufacturer       = GetSMBIOSManufacturer();
    s.smbiosSuspicious   = SuspiciousManufacturer(s.manufacturer);
    s.suspiciousDrivers  = SuspiciousDriversPresent();
    s.uptimeMinutes      = GetUptimeMinutes();
    s.lowUptimeMinutes   = s.uptimeMinutes < 30;
    s.ramMB              = GetTotalRAMMB();
    s.smallRamMB         = s.ramMB < 2048;
    s.sandboxUsername    = SandboxUsername();
    return s;
}

uint32_t RiskScore(const VMSignals& s) {
    uint32_t score = 0;
    if (s.cpuidHypervisor)   score += 25;
    if (s.smbiosSuspicious)  score += 35;
    if (s.suspiciousDrivers) score += 30;
    if (s.lowUptimeMinutes)  score += 15;
    if (s.smallRamMB)        score += 10;
    if (s.sandboxUsername)   score += 20;
    return min(score, 100u);
}

uint32_t GetRiskScore() {
    return RiskScore(Collect());
}

static std::wstring CacheFilePath() {
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    return std::wstring(tmp) + L"isl_cache.bin";
}

struct CacheEntry {
    uint64_t timestamp;
    uint32_t score;
    uint8_t  hmac[32];
};

void SaveCachedScore(uint32_t score) {
    CacheEntry e{};
    e.timestamp = static_cast<uint64_t>(time(nullptr));
    e.score = score;
    auto key = Crypto::DeriveKeyFromPE("vm-cache", 8);
    auto mac = Crypto::HMAC_SHA256(key.data(), key.size(), &e, sizeof(e) - 32);
    memcpy(e.hmac, mac.data(), 32);
    auto path = CacheFilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written;
    WriteFile(h, &e, sizeof(e), &written, nullptr);
    CloseHandle(h);
}

bool LoadCachedScore(uint32_t& outScore) {
    auto path = CacheFilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CacheEntry e{};
    DWORD read;
    bool ok = ReadFile(h, &e, sizeof(e), &read, nullptr) && read == sizeof(e);
    CloseHandle(h);
    if (!ok) return false;
    // Verify HMAC
    auto key = Crypto::DeriveKeyFromPE("vm-cache", 8);
    auto mac = Crypto::HMAC_SHA256(key.data(), key.size(), &e, sizeof(e) - 32);
    if (memcmp(mac.data(), e.hmac, 32) != 0) return false;
    // Check age
    uint64_t now = static_cast<uint64_t>(time(nullptr));
    if (now - e.timestamp > VM_CACHE_VALID_SEC) return false;
    outScore = e.score;
    return true;
}

} // namespace AntiVM
