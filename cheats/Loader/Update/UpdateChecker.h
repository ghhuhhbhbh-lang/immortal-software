#pragma once
// Update/UpdateChecker.h — WinHTTP-based DLL update system.
// Checks the Immortal backend for a newer CheatDLL, downloads, verifies SHA-256.
#include <string>
#include <functional>
#include <cstdint>

namespace Update {

struct Info {
    std::string version;      // e.g. "2.1.0"
    std::string sha256;       // hex SHA-256 of the DLL
    std::string downloadUrl;  // relative path, e.g. "/api/update/download"
    bool        available = false;
};

enum class Result {
    Ok,
    NoUpdate,       // already on latest
    NetworkError,
    AuthError,
    HashMismatch,
    WriteError,
};

using ProgressCb = std::function<void(int pct)>; // 0-100

// Check server for new version. currentVersion like "2.0.0".
// Returns Info with available=true if a newer version exists.
Info Check(const std::string& apiBase, const std::string& accessToken,
           const std::string& currentVersion);

// Download DLL to destPath. Calls progressCb with 0-100 during transfer.
// Verifies SHA-256 before returning Ok.
Result Download(const std::string& apiBase, const std::string& accessToken,
                const std::string& downloadPath, const std::string& expectedSha256,
                const std::wstring& destPath, ProgressCb progressCb = {});

// SHA-256 of a file via Windows CNG (bcrypt.lib).
std::string FileSha256(const std::wstring& path);

// Simple semver comparison: returns true if a > b.
bool IsNewer(const std::string& a, const std::string& b);

} // namespace Update
