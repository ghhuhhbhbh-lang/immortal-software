#include "IntegrityManager.h"
#include "CryptoUtils.h"
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <softpub.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace Integrity {

static std::vector<SectionHash> g_baseline;
static std::array<uint8_t,32>   g_configKey{};
static std::array<uint8_t,32>   g_diskHash{};
static bool                      g_diskReady = false;
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
    static const char salt[] = "integrity-key-v2";
    g_configKey = Crypto::DeriveKeyFromPE(salt, sizeof(salt) - 1);

    static const char* sections[] = { ".text", ".rdata", ".pdata", nullptr };
    for (int i = 0; sections[i]; i++) {
        SectionHash sh{};
        if (HashSection(sections[i], sh)) g_baseline.push_back(sh);
    }
    InitializeDiskImage();
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

bool InitializeDiskImage() {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD sz = GetFileSize(h, nullptr);
    if (sz == INVALID_FILE_SIZE || sz == 0 || sz > 64 * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    std::vector<uint8_t> buf(sz);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf.data(), sz, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd != sz) return false;
    g_diskHash = Crypto::SHA256(buf.data(), buf.size());
    g_diskReady = true;
    return true;
}

bool VerifyDiskImage() {
    if (!g_diskReady) return false;
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD sz = GetFileSize(h, nullptr);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(h); return false; }
    std::vector<uint8_t> buf(sz);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf.data(), sz, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd != sz) return false;
    return Crypto::SHA256(buf.data(), buf.size()) == g_diskHash;
}

bool VerifyCodeSignature() {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    return status == ERROR_SUCCESS;
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
    if (g_watchDir.empty()) return true;
    if (!g_configTampered.load()) return true;

    WIN32_FIND_DATAW fd{};
    std::wstring pattern = g_watchDir + L"\\*.cfg";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        g_configTampered = false;
        return true; // no configs yet
    }
    bool ok = true;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring path = g_watchDir + L"\\" + fd.cFileName;
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) { ok = false; break; }
        DWORD sz = GetFileSize(hf, nullptr);
        if (sz == INVALID_FILE_SIZE || sz < 32 || sz > 1 << 20) {
            CloseHandle(hf);
            ok = false;
            break;
        }
        std::vector<uint8_t> buf(sz);
        DWORD rd = 0;
        BOOL readOk = ReadFile(hf, buf.data(), sz, &rd, nullptr);
        CloseHandle(hf);
        if (!readOk || rd != sz || !VerifyConfigBuffer(buf.data(), buf.size())) {
            ok = false;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    g_configTampered = false;
    return ok;
}

} // namespace Integrity
