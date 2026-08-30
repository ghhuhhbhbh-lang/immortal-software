#include "CryptoUtils.h"
#include <windows.h>
#include <algorithm>
#include <vector>
#include <cstring>
#include <stdexcept>

namespace Crypto {

std::array<uint8_t,32> SHA256(const void* data, size_t len) {
    std::array<uint8_t,32> result{};
    HCRYPTPROV prov = 0; HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return result;
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(hash, static_cast<const BYTE*>(data), static_cast<DWORD>(len), 0)) {
            DWORD sz = 32;
            CryptGetHashParam(hash, HP_HASHVAL, result.data(), &sz, 0);
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return result;
}

std::array<uint8_t,32> HMAC_SHA256(const void* key, size_t keyLen,
                                    const void* data, size_t dataLen) {
    std::array<uint8_t,32> result{};
    // Simple HMAC construction: ipad/opad with SHA-256
    uint8_t k[64]{}; uint8_t ipad[64], opad[64];
    if (keyLen > 64) {
        auto kh = SHA256(key, keyLen);
        memcpy(k, kh.data(), 32);
    } else {
        memcpy(k, key, keyLen);
    }
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    // inner = SHA256(ipad || data)
    std::vector<uint8_t> inner(64 + dataLen);
    memcpy(inner.data(), ipad, 64);
    memcpy(inner.data() + 64, data, dataLen);
    auto innerHash = SHA256(inner.data(), inner.size());
    // outer = SHA256(opad || inner)
    std::vector<uint8_t> outer(64 + 32);
    memcpy(outer.data(), opad, 64);
    memcpy(outer.data() + 64, innerHash.data(), 32);
    result = SHA256(outer.data(), outer.size());
    SecureZero(k, sizeof(k));
    SecureZero(ipad, sizeof(ipad));
    SecureZero(opad, sizeof(opad));
    return result;
}

bool VerifyHMACFooter(const void* buf, size_t totalLen, const void* key, size_t keyLen) {
    if (totalLen < 32) return false;
    const size_t dataLen = totalLen - 32;
    const uint8_t* stored = static_cast<const uint8_t*>(buf) + dataLen;
    auto computed = HMAC_SHA256(key, keyLen, buf, dataLen);
    // Constant-time compare
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ stored[i];
    return diff == 0;
}

std::array<uint8_t,32> DeriveKeyFromPE(const char* salt, size_t saltLen) {
    auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto* nt   = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

    // Mix: TimeDateStamp + SizeOfImage + entry RVA + salt (CheckSum is often 0 unsigned)
    uint32_t stamp = nt->FileHeader.TimeDateStamp;
    uint32_t img   = nt->OptionalHeader.SizeOfImage;
    uint32_t entry = nt->OptionalHeader.AddressOfEntryPoint;
    std::vector<uint8_t> material(12 + saltLen + 16);
    memcpy(material.data() + 0, &stamp, 4);
    memcpy(material.data() + 4, &img, 4);
    memcpy(material.data() + 8, &entry, 4);
    memcpy(material.data() + 12, salt, saltLen);

    // First 16 bytes of .text if present
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (_strnicmp(reinterpret_cast<const char*>(sec->Name), ".text", 5) == 0) {
            SIZE_T n = (std::min<SIZE_T>)(16, sec->Misc.VirtualSize);
            memcpy(material.data() + 12 + saltLen, base + sec->VirtualAddress, n);
            break;
        }
    }
    return SHA256(material.data(), material.size());
}

bool VerifySignature(const void* data, size_t dataLen,
                     const void* sig, size_t sigLen,
                     const BYTE* pubKeyBlob, DWORD blobLen) {
    HCRYPTPROV prov = 0; HCRYPTKEY key = 0; HCRYPTHASH hash = 0;
    bool ok = false;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;
    if (CryptImportKey(prov, pubKeyBlob, blobLen, 0, 0, &key)) {
        if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
            if (CryptHashData(hash, static_cast<const BYTE*>(data), static_cast<DWORD>(dataLen), 0)) {
                ok = (CryptVerifySignatureW(hash, static_cast<const BYTE*>(sig),
                                            static_cast<DWORD>(sigLen), key, nullptr, 0) == TRUE);
            }
            CryptDestroyHash(hash);
        }
        CryptDestroyKey(key);
    }
    CryptReleaseContext(prov, 0);
    return ok;
}

} // namespace Crypto
