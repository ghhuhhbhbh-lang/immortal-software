#pragma once
#include <windows.h>
#include <array>
#include <cstdint>

namespace Integrity {

struct SectionHash {
    char      name[8]{};
    std::array<uint8_t,32> hash{};
};

bool Initialize();
bool Verify();

bool InitializeDiskImage();
bool VerifyDiskImage();
bool VerifyCodeSignature();

bool SignConfigBuffer(const void* data, size_t dataLen,
                      void* outBuf, size_t& outLen);
bool VerifyConfigBuffer(const void* buf, size_t totalLen);
void WatchConfigDir(const wchar_t* path);
bool ValidateWatchedConfigs();

} // namespace Integrity
