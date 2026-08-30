#pragma once
#include <windows.h>
#include <array>
#include <cstdint>

namespace Integrity {

struct SectionHash {
    char      name[8];
    std::array<uint8_t,32> hash;
};

// Compute hashes of .text, .rdata, .pdata at startup and store as baseline
bool Initialize();

// Re-verify hashes against stored baseline (call periodically)
bool Verify();

// Sign a config buffer and append HMAC footer (32 bytes)
bool SignConfigBuffer(const void* data, size_t dataLen,
                      void* outBuf, size_t& outLen);

// Verify a config buffer that has an HMAC footer
bool VerifyConfigBuffer(const void* buf, size_t totalLen);

// Install a file watch on the config directory
void WatchConfigDir(const wchar_t* path);

// Force an immediate re-check of the watched config dir
bool ValidateWatchedConfigs();

} // namespace Integrity
