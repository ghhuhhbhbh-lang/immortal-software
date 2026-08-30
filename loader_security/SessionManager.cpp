#include "SessionManager.h"
#include "CryptoUtils.h"
#include "FakeAuthEngine.h"
#include <winhttp.h>
#include <wincred.h>
#include <sstream>
#include <chrono>
#include <thread>
#include <functional>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "advapi32.lib")

namespace Session {

std::atomic<bool> g_sessionRevoked{ false };

static const wchar_t* CRED_TARGET = L"ImmortalSoftware_RefreshToken";
static const wchar_t* API_HOST    = L"localhost"; // decrypted at runtime in prod

// Simple WinHTTP POST helper
static std::string HttpPost(const wchar_t* host, INTERNET_PORT port,
                            const wchar_t* path, const std::string& body,
                            const std::string& bearer = "") {
    HINTERNET hSession = WinHttpOpen(L"ImmortalLoader/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hSession) return {};
    HINTERNET hConn = WinHttpConnect(hSession, host, port, 0);
    std::string result;
    if (hConn) {
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", path,
            nullptr, nullptr, nullptr, 0);
        if (hReq) {
            std::wstring hdrs = L"Content-Type: application/json\r\n";
            if (!bearer.empty()) {
                hdrs += L"Authorization: Bearer ";
                hdrs += std::wstring(bearer.begin(), bearer.end());
                hdrs += L"\r\n";
            }
            WinHttpSendRequest(hReq, hdrs.c_str(), static_cast<DWORD>(-1L),
                const_cast<char*>(body.c_str()),
                static_cast<DWORD>(body.size()),
                static_cast<DWORD>(body.size()), 0);
            if (WinHttpReceiveResponse(hReq, nullptr)) {
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                    std::string chunk(avail, '\0');
                    DWORD read = 0;
                    WinHttpReadData(hReq, chunk.data(), avail, &read);
                    result += chunk.substr(0, read);
                }
            }
            WinHttpCloseHandle(hReq);
        }
        WinHttpCloseHandle(hConn);
    }
    WinHttpCloseHandle(hSession);
    return result;
}

// Minimal JSON field extractor — no external deps
static std::string JsonField(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    auto end = json.find('"', pos);
    return end != std::string::npos ? json.substr(pos, end - pos) : std::string{};
}

AuthResult LoginWithLicenseKey(const std::string& licenseKey,
                               const std::string& fingerprint) {
    // If honeypot active, return fake response
    if (FakeAuth::IsActive()) {
        return { true, "FAKE_TOKEN", "user", "PREMIUM", "2099-01-01", 0 };
    }

    // Build nonce + timestamp
    wchar_t buf[64]{};
    GUID g; CoCreateGuid(&g);
    StringFromGUID2(g, buf, 64);
    std::string nonce(buf, buf + wcslen(buf));
    auto ts = std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL;

    std::ostringstream body;
    body << R"({"licenseKey":")" << licenseKey
         << R"(","fingerprint":")" << fingerprint
         << R"(","nonce":")" << nonce
         << R"(","timestamp":)" << ts << "}";

    std::string resp = HttpPost(API_HOST, API_PORT,
        L"/api/auth/login/license", body.str());

    AuthResult r{};
    if (resp.empty()) { r.valid = false; return r; }

    r.accessToken = JsonField(resp, "accessToken");
    r.username    = JsonField(resp, "username");
    r.role        = JsonField(resp, "role");
    r.expiry      = JsonField(resp, "expiry");
    r.valid       = !r.accessToken.empty();
    r.issuedAt    = static_cast<uint64_t>(ts);

    if (r.valid) {
        std::string refresh = JsonField(resp, "refreshToken");
        if (!refresh.empty()) StoreRefreshToken(refresh);
        Crypto::SecureZero(refresh.data(), refresh.size());
    }
    return r;
}

bool RefreshAccessToken(AuthResult& auth) {
    std::string refresh;
    if (!LoadRefreshToken(refresh)) return false;
    std::string body = R"({"refreshToken":")" + refresh + R"("})";
    Crypto::SecureZero(refresh.data(), refresh.size());
    std::string resp = HttpPost(API_HOST, API_PORT, L"/api/auth/refresh", body);
    if (resp.empty()) return false;
    std::string tok = JsonField(resp, "accessToken");
    if (tok.empty()) return false;
    auth.accessToken = tok;
    auth.issuedAt = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL);
    return true;
}

bool StoreRefreshToken(const std::string& token) {
    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<wchar_t*>(CRED_TARGET);
    cred.CredentialBlobSize = static_cast<DWORD>(token.size());
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(token.c_str()));
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    return CredWriteW(&cred, 0) != 0;
}

bool LoadRefreshToken(std::string& outToken) {
    PCREDENTIALW pCred = nullptr;
    if (!CredReadW(CRED_TARGET, CRED_TYPE_GENERIC, 0, &pCred)) return false;
    outToken.assign(reinterpret_cast<char*>(pCred->CredentialBlob),
                    pCred->CredentialBlobSize);
    CredFree(pCred);
    return true;
}

void ClearCredentials() {
    CredDeleteW(CRED_TARGET, CRED_TYPE_GENERIC, 0);
}

bool AccessTokenExpired(const AuthResult& auth) {
    auto now = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL);
    return (now - auth.issuedAt) >= TOKEN_MAX_LIFETIME_SEC;
}

void StartHeartbeat(const AuthResult& auth, std::function<void()> revokeCallback) {
    Threads::ThreadManager::Instance().Launch("license_heartbeat",
        [auth, revokeCallback](HANDLE cancel) mutable {
            while (WaitForSingleObject(cancel, HEARTBEAT_INTERVAL_SEC * 1000) == WAIT_TIMEOUT) {
                // Auto-refresh if expired
                if (AccessTokenExpired(auth)) {
                    if (!RefreshAccessToken(auth)) { revokeCallback(); return; }
                }
                std::string body = R"({"sessionCheck":true})";
                std::string resp = HttpPost(API_HOST, API_PORT,
                    L"/api/auth/me", body, auth.accessToken);
                if (resp.find("REVOKED") != std::string::npos ||
                    resp.find("suspended") != std::string::npos) {
                    g_sessionRevoked = true;
                    revokeCallback();
                    return;
                }
                Threads::ThreadManager::Instance().Heartbeat(GetCurrentThreadId());
            }
        }, true);
}

} // namespace Session
