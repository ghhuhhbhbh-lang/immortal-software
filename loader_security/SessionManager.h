#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <atomic>

namespace Session {

struct AuthResult {
    bool        valid;
    std::string accessToken;   // 15-min JWT
    std::string username;
    std::string role;
    std::string expiry;
    uint64_t    issuedAt;      // seconds since epoch
};

// Authenticate with license key against Immortal backend
// fingerprint = SHA-256 hex of hardware signals
AuthResult LoginWithLicenseKey(const std::string& licenseKey,
                               const std::string& fingerprint);

// Refresh the access token using stored refresh token
bool RefreshAccessToken(AuthResult& inout);

// Store refresh token in Windows Credential Manager (DPAPI-encrypted)
bool StoreRefreshToken(const std::string& token);

// Load refresh token from Credential Manager
bool LoadRefreshToken(std::string& outToken);

// Clear stored credentials
void ClearCredentials();

// Token expiry check
bool AccessTokenExpired(const AuthResult& auth);

// Background heartbeat: ping /api/heartbeat every HEARTBEAT_INTERVAL_SEC
// Calls revokeCallback if server returns REVOKED
void StartHeartbeat(const AuthResult& auth,
                    std::function<void()> revokeCallback);

// Global revocation flag
extern std::atomic<bool> g_sessionRevoked;

} // namespace Session
