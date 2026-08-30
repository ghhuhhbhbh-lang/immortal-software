#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <cstdint>
#include <atomic>
#include <functional>

namespace Session {

struct HardwareInfo {
    std::string cpuId;
    std::string motherboardSerial;
    std::string diskSerial;
    std::string biosSerial;
    std::string macAddress;
    std::string systemUuid;
    std::string processorName;
    uint64_t    totalMemory = 0;
    std::string screenResolution;
    std::string timezone;
};

struct AuthResult {
    bool        valid = false;
    std::string accessToken;
    std::string refreshToken;
    std::string username;
    std::string role;
    std::string expiry;
    std::string sessionId;
    uint64_t    issuedAt = 0;
};

struct SecurityScores {
    uint32_t debugScore = 0;
    uint32_t vmScore = 0;
    uint32_t tamperScore = 0;
    bool     integrityOk = true;
    bool     signedPe = false;
};

// Collect stable HW signals for license binding
HardwareInfo CollectHardwareInfo();

AuthResult LoginWithLicenseKey(const std::string& licenseKey,
                               const std::string& fingerprint,
                               const HardwareInfo* hw = nullptr);

bool RefreshAccessToken(AuthResult& inout);
bool StoreRefreshToken(const std::string& token);
bool LoadRefreshToken(std::string& outToken);
void ClearCredentials();
bool AccessTokenExpired(const AuthResult& auth);

void StartHeartbeat(const AuthResult& auth,
                    std::function<void()> revokeCallback);

// Periodic server attestation (integrity + scores)
void StartAttestation(const AuthResult& auth,
                      const std::string& fingerprint,
                      std::function<SecurityScores()> scoreProvider,
                      std::function<void()> revokeCallback);

// Push a client threat event to the API (best-effort)
void ReportThreat(const AuthResult& auth, const char* source, const char* detail, uint32_t severity);

extern std::atomic<bool> g_sessionRevoked;

// Resolved API endpoint (from env IMMORTAL_API_HOST / IMMORTAL_API_PORT / IMMORTAL_API_TLS)
void ResolveApiEndpoint(std::wstring& host, WORD& port, bool& useTls);

// True if last successful auth is within OFFLINE_GRACE_HOURS (local secure store)
bool WithinOfflineGrace();

} // namespace Session
