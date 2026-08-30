#pragma once
// SharedLibs/CryptoPrimitives.h — compile-time XOR + runtime helpers.
// No standard library dependencies except <string> and <cstdint>.
#include <string>
#include <cstdint>
#include <cstring>

// ── Compile-time XOR string obfuscation ───────────────────────────────────────
template<uint8_t Key, size_t N>
struct XorBuf {
    char buf[N]{};
    constexpr XorBuf(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) buf[i] = s[i] ^ (Key + static_cast<uint8_t>(i));
    }
    std::string decrypt() const {
        std::string out(N - 1, '\0');
        for (size_t i = 0; i < N - 1; i++)
            out[i] = buf[i] ^ (Key + static_cast<uint8_t>(i));
        return out;
    }
};

// Unique key per call-site using line + counter so two XorStr("same") differ.
#define XOR_KEY(L, C) static_cast<uint8_t>(((L) * 31 + (C)) & 0xFF)
#define XorStr(s) (XorBuf<XOR_KEY(__LINE__, __COUNTER__), sizeof(s)>(s).decrypt())

// ── CRC32 IEEE 802.3 ──────────────────────────────────────────────────────────
inline uint32_t Crc32(const void* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
    }
    return ~crc;
}

// ── Secure memory wipe ────────────────────────────────────────────────────────
inline void SecureZero(void* p, size_t n) {
    volatile auto* vp = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; i++) vp[i] = 0;
}

// ── Repeating XOR stream cipher ───────────────────────────────────────────────
inline void XorCipher(const uint8_t* key, size_t keyLen,
                      uint8_t* data, size_t dataLen) {
    for (size_t i = 0; i < dataLen; i++)
        data[i] ^= key[i % keyLen];
}

// ── Constant-time byte comparison ─────────────────────────────────────────────
inline bool ConstTimeEqual(const void* a, const void* b, size_t n) {
    const auto* pa = static_cast<const uint8_t*>(a);
    const auto* pb = static_cast<const uint8_t*>(b);
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= pa[i] ^ pb[i];
    return acc == 0;
}

// ── Hex encoding ──────────────────────────────────────────────────────────────
inline std::string ToHex(const uint8_t* data, size_t len) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += HEX[data[i] >> 4];
        out += HEX[data[i] & 0x0F];
    }
    return out;
}
