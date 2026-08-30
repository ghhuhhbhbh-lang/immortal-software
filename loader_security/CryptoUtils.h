#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <cstdint>
#include <array>

namespace Crypto {

// SHA-256 of a memory buffer using Windows CNG
std::array<uint8_t,32> SHA256(const void* data, size_t len);

// HMAC-SHA256
std::array<uint8_t,32> HMAC_SHA256(const void* key, size_t keyLen,
                                   const void* data, size_t dataLen);

// Verify HMAC footer appended to a buffer (last 32 bytes = HMAC)
bool VerifyHMACFooter(const void* buf, size_t totalLen,
                      const void* key, size_t keyLen);

// XOR decrypt a compile-time obfuscated string (stack allocation only)
inline std::string DecryptStr(const char* enc, uint8_t key = 0x11) {
    std::string out;
    for (const char* p = enc; *p; ++p) out += static_cast<char>(*p ^ key);
    return out;
}

// Derive a 32-byte key from PE header checksum + a salt
std::array<uint8_t,32> DeriveKeyFromPE(const char* salt, size_t saltLen);

// Verify RSA/PKCS#1 signature using embedded public key blob
bool VerifySignature(const void* data, size_t dataLen,
                     const void* sig, size_t sigLen,
                     const BYTE* pubKeyBlob, DWORD blobLen);

// Read RDTSC counter
inline uint64_t ReadTSC() { return __rdtsc(); }

// SECURE zero that optimizer cannot remove
inline void SecureZero(void* p, size_t n) {
    volatile uint8_t* vp = static_cast<volatile uint8_t*>(p);
    while (n--) *vp++ = 0;
}

} // namespace Crypto
