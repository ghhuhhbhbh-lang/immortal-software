#include "IntegrityManager.h"
#include "CryptoUtils.h"
#include <vector>
#include <string>
#include <thread>
#include <atomic>

namespace Integrity {

static std::vector<SectionHash> g_baseline;
static std::array<uint8_t,32>   g_configKey{};
static std::wstring              g_watchDir;
static std::atomic<bool>         g_configTampered{ false };

// Hash a PE section by name
static bool HashSection(const char* name, SectionHash& out) {
    auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto* nt   = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec  = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (_strnicmp(reinterpret_cast<const char*>(sec->Name), name, 8) == 0) {
            const void* data = base + sec->VirtualAddress;
            SIZE_T size      = sec->Misc.VirtualSize;
            out.hash = Crypto::SHA256(data, size);
            strncpy_s(out.name, reinterpret_cast<const char*>(sec->Name), 8);
            return true;
        }
    }
    return false;
}

bool Initialize() {
    g_baseline.clear();
    // Derive HMAC key from PE checksum
    static const char salt[] = "integrity-key-v1";
    g_configKey = Crypto::DeriveKeyFromPE(salt, sizeof(salt) - 1);

    static const char* sections[] = { ".text", ".rdata", ".pdata", nullptr };
    for (int i = 0; sections[i]; i++) {
        SectionHash sh{};
        if (HashSection(sections[i], sh)) {
            g_baseline.push_back(sh);
        }
        // .pdata may not exist on all builds — skip gracefully
    }
    return !g_baseline.empty();
}

bool Verify() {
    if (g_baseline.empty()) return false;
    for (const auto& base : g_baseline) {
        SectionHash current{};
        if (!HashSection(base.name, current)) return false;
        if (current.hash != base.hash) return false;
    }
    return true;
}

bool SignConfigBuffer(const void* data, size_t dataLen, void* outBuf, size_t& outLen) {
    if (outLen < dataLen + 32) return false;
    memcpy(outBuf, data, dataLen);
    auto mac = Crypto::HMAC_SHA256(g_configKey.data(), 32, data, dataLen);
    memcpy(static_cast<uint8_t*>(outBuf) + dataLen, mac.data(), 32);
    outLen = dataLen + 32;
    return true;
}

bool VerifyConfigBuffer(const void* buf, size_t totalLen) {
    if (totalLen < 32) return false;
    size_t dataLen = totalLen - 32;
    const uint8_t* stored = static_cast<const uint8_t*>(buf) + dataLen;
    auto computed = Crypto::HMAC_SHA256(g_configKey.data(), 32, buf, dataLen);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ stored[i];
    return diff == 0;
}

void WatchConfigDir(const wchar_t* path) {
    g_watchDir = path;
    g_configTampered = false;

    std::thread([path = g_watchDir]() {
        HANDLE hDir = CreateFileW(path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
        if (hDir == INVALID_HANDLE_VALUE) return;

        alignas(DWORD) uint8_t buf[4096];
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        while (true) {
            ResetEvent(ov.hEvent);
            if (!ReadDirectoryChangesW(hDir, buf, sizeof(buf), FALSE,
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                nullptr, &ov, nullptr)) break;

            if (WaitForSingleObject(ov.hEvent, INFINITE) != WAIT_OBJECT_0) break;
            g_configTampered = true; // Signal: validate on next check
        }
        CloseHandle(ov.hEvent);
        CloseHandle(hDir);
    }).detach();
}

bool ValidateWatchedConfigs() {
    // Re-verification would enumerate config files in g_watchDir and check each HMAC.
    // Returns false if any config fails — caller enters lockdown.
    g_configTampered = false;
    return true; // Placeholder: real impl reads each .cfg and calls VerifyConfigBuffer
}

} // namespace Integrity
