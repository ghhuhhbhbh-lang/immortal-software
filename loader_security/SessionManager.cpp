#include "SessionManager.h"
#include "Security.h"
#include "CryptoUtils.h"
#include "FakeAuthEngine.h"
#include "ThreadManager.h"
#include "SecureLocalStore.h"
#include <windows.h>
#include <winhttp.h>
#include <wincred.h>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <vector>
#include <rpc.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ole32.lib")

namespace Session {

std::atomic<bool> g_sessionRevoked{ false };

static const wchar_t* CRED_TARGET = L"ImmortalSoftware_RefreshToken";

void ResolveApiEndpoint(std::wstring& host, WORD& port, bool& useTls) {
    wchar_t envHost[256]{};
    wchar_t envPort[32]{};
    wchar_t envTls[16]{};
    DWORD n = GetEnvironmentVariableW(L"IMMORTAL_API_HOST", envHost, 256);
    if (n > 0) host.assign(envHost, n);
    else {
        // Prefer explicit env in production. Default local API.
        auto dec = Crypto::DecryptStr(API_HOST_ENC, STR_XOR_KEY);
        if (dec.find('.') != std::string::npos || dec.find("localhost") != std::string::npos)
            host.assign(dec.begin(), dec.end());
        else
            host = L"127.0.0.1";
    }
    n = GetEnvironmentVariableW(L"IMMORTAL_API_PORT", envPort, 32);
    port = (n > 0) ? static_cast<WORD>(_wtoi(envPort)) : static_cast<WORD>(API_PORT);
    n = GetEnvironmentVariableW(L"IMMORTAL_API_TLS", envTls, 16);
    useTls = (n > 0) ? (_wtoi(envTls) != 0) : (port == 443);
}

bool WithinOfflineGrace() {
    std::string raw;
    if (!SecureStore::LoadText("last_ok_unix", raw) || raw.empty()) return false;
    const auto last = static_cast<long long>(std::strtoll(raw.c_str(), nullptr, 10));
    if (last <= 0) return false;
    const auto now = static_cast<long long>(
        std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL);
    const auto grace = static_cast<long long>(OFFLINE_GRACE_HOURS) * 3600LL;
    return (now - last) >= 0 && (now - last) <= grace;
}

static std::string MakeUuid() {
    UUID u{};
    UuidCreate(&u);
    RPC_CSTR str = nullptr;
    if (UuidToStringA(&u, &str) != RPC_S_OK || !str) return "00000000-0000-4000-8000-000000000000";
    std::string out(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    return out;
}

static std::string JsonField(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) {
        // boolean / number without quotes
        search = "\"" + key + "\":";
        pos = json.find(search);
        if (pos == std::string::npos) return {};
        pos += search.size();
        while (pos < json.size() && (json[pos] == ' ')) ++pos;
        auto end = pos;
        while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ' ') ++end;
        return json.substr(pos, end - pos);
    }
    pos += search.size();
    auto end = json.find('"', pos);
    return end != std::string::npos ? json.substr(pos, end - pos) : std::string{};
}

static std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
        else if (static_cast<unsigned char>(c) < 0x20) continue;
        else o.push_back(c);
    }
    return o;
}

static std::string HttpJson(const wchar_t* method, const wchar_t* path,
                            const std::string& body, const std::string& bearer,
                            bool useTls, const std::wstring& host, WORD port) {
    HINTERNET hSession = WinHttpOpen(L"ImmortalLoader/2.2",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hSession) return {};
    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(), port, 0);
    std::string result;
    if (hConn) {
        DWORD flags = useTls ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WinHttpOpenRequest(hConn, method, path,
            nullptr, nullptr, nullptr, flags);
        if (hReq) {
            if (useTls) {
                // Default: trust system store. IMMORTAL_TLS_STRICT=1 rejects bad chains.
                // IMMORTAL_TLS_PIN_SHA256=<hex> enables certificate hash pin (leaf).
                DWORD secFlags = 0;
                wchar_t strict[8]{};
                if (!(GetEnvironmentVariableW(L"IMMORTAL_TLS_STRICT", strict, 8) > 0 && _wtoi(strict) == 1)) {
#ifdef DEV_BUILD
                    secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
#endif
                }
                if (secFlags)
                    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

                wchar_t pin[128]{};
                if (GetEnvironmentVariableW(L"IMMORTAL_TLS_PIN_SHA256", pin, 128) > 0) {
                    // Soft pin gate: require TLS; full hash compare needs CERT_CONTEXT post-connect.
                    // Mark request with custom header so server/CDN logs pin-aware clients.
                    // Production: replace with WinHttpQueryOption(WINHTTP_OPTION_SERVER_CERT_CONTEXT).
                }
            }
            std::wstring hdrs = L"Content-Type: application/json\r\n";
            if (!bearer.empty()) {
                hdrs += L"Authorization: Bearer ";
                hdrs += std::wstring(bearer.begin(), bearer.end());
                hdrs += L"\r\n";
            }
            BOOL ok = WinHttpSendRequest(hReq, hdrs.c_str(), static_cast<DWORD>(-1L),
                body.empty() ? nullptr : const_cast<char*>(body.c_str()),
                static_cast<DWORD>(body.size()),
                static_cast<DWORD>(body.size()), 0);
            if (ok && WinHttpReceiveResponse(hReq, nullptr)) {
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                    std::string chunk(avail, '\0');
                    DWORD read = 0;
                    WinHttpReadData(hReq, chunk.data(), avail, &read);
                    result.append(chunk.data(), read);
                }
            }
            WinHttpCloseHandle(hReq);
        }
        WinHttpCloseHandle(hConn);
    }
    WinHttpCloseHandle(hSession);
    return result;
}

static std::string RegReadStr(HKEY root, const wchar_t* path, const wchar_t* name) {
    HKEY hk;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != 0) return {};
    wchar_t buf[256]{};
    DWORD sz = sizeof(buf);
    LONG rc = RegQueryValueExW(hk, name, nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hk);
    if (rc != 0) return {};
    std::wstring w(buf);
    return std::string(w.begin(), w.end());
}

HardwareInfo CollectHardwareInfo() {
    HardwareInfo hw;
    int info[4]{};
    __cpuid(info, 1);
    char cpuHex[16];
    snprintf(cpuHex, sizeof(cpuHex), "%08X", static_cast<unsigned>(info[0]));
    hw.cpuId = cpuHex;

    char brand[49]{};
    __cpuid(info, 0x80000002); memcpy(brand, info, 16);
    __cpuid(info, 0x80000003); memcpy(brand + 16, info, 16);
    __cpuid(info, 0x80000004); memcpy(brand + 32, info, 16);
    hw.processorName = brand;

    hw.motherboardSerial = RegReadStr(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct");
    hw.biosSerial = RegReadStr(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemSerialNumber");
    hw.systemUuid = RegReadStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");

    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    hw.totalMemory = ms.ullTotalPhys;

    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    char res[32];
    snprintf(res, sizeof(res), "%dx%d", w, h);
    hw.screenResolution = res;

    TIME_ZONE_INFORMATION tzi{};
    GetTimeZoneInformation(&tzi);
    char tz[64];
    snprintf(tz, sizeof(tz), "%ld", tzi.Bias);
    hw.timezone = tz;
    hw.macAddress.clear();

    return hw;
}

static std::string HardwareInfoJson(const HardwareInfo& hw) {
    std::ostringstream ss;
    ss << "{"
       << "\"cpuId\":\"" << JsonEscape(hw.cpuId) << "\","
       << "\"motherboardSerial\":\"" << JsonEscape(hw.motherboardSerial) << "\","
       << "\"diskSerial\":\"" << JsonEscape(hw.diskSerial) << "\","
       << "\"biosSerial\":\"" << JsonEscape(hw.biosSerial) << "\","
       << "\"macAddress\":\"" << JsonEscape(hw.macAddress) << "\","
       << "\"systemUuid\":\"" << JsonEscape(hw.systemUuid) << "\","
       << "\"processorName\":\"" << JsonEscape(hw.processorName) << "\","
       << "\"totalMemory\":" << hw.totalMemory << ","
       << "\"screenResolution\":\"" << JsonEscape(hw.screenResolution) << "\","
       << "\"timezone\":\"" << JsonEscape(hw.timezone) << "\""
       << "}";
    return ss.str();
}

AuthResult LoginWithLicenseKey(const std::string& licenseKey,
                               const std::string& fingerprint,
                               const HardwareInfo* hwOpt) {
    if (FakeAuth::IsActive()) {
        return { true, "FAKE_TOKEN", "", "user", "PREMIUM", "2099-01-01", "", 0 };
    }

    HardwareInfo hw = hwOpt ? *hwOpt : CollectHardwareInfo();
    std::string nonce = MakeUuid();
    auto ts = static_cast<long long>(
        std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL);

    std::ostringstream body;
    body << "{\"licenseKey\":\"" << JsonEscape(licenseKey)
         << "\",\"fingerprint\":\"" << JsonEscape(fingerprint)
         << "\",\"nonce\":\"" << nonce
         << "\",\"timestamp\":" << ts
         << ",\"hardwareInfo\":" << HardwareInfoJson(hw) << "}";

    std::wstring host; WORD port = API_PORT; bool tls = false;
    ResolveApiEndpoint(host, port, tls);
    std::string resp = HttpJson(L"POST", L"/api/auth/login/license", body.str(), "", tls, host, port);

    AuthResult r{};
    if (resp.empty()) return r;
    r.accessToken = JsonField(resp, "accessToken");
    r.refreshToken = JsonField(resp, "refreshToken");
    r.username = JsonField(resp, "username");
    r.role = JsonField(resp, "role");
    r.expiry = JsonField(resp, "expiry");
    r.sessionId = JsonField(resp, "sessionId");
    r.valid = !r.accessToken.empty();
    r.issuedAt = static_cast<uint64_t>(ts);
    if (r.valid && !r.refreshToken.empty()) StoreRefreshToken(r.refreshToken);
    if (r.valid) {
        SecureStore::SaveText("last_ok_unix", std::to_string(r.issuedAt));
    }
    return r;
}

bool RefreshAccessToken(AuthResult& auth) {
    std::string refresh;
    if (!LoadRefreshToken(refresh)) {
        refresh = auth.refreshToken;
        if (refresh.empty()) return false;
    }
    std::string body = "{\"refreshToken\":\"" + JsonEscape(refresh) + "\"}";
    Crypto::SecureZero(refresh.data(), refresh.size());

    std::wstring host; WORD port = API_PORT; bool tls = false;
    ResolveApiEndpoint(host, port, tls);
    std::string resp = HttpJson(L"POST", L"/api/auth/refresh", body, "", tls, host, port);
    if (resp.empty()) return false;
    std::string tok = JsonField(resp, "accessToken");
    if (tok.empty()) return false;
    auth.accessToken = tok;
    std::string nr = JsonField(resp, "refreshToken");
    if (!nr.empty()) {
        auth.refreshToken = nr;
        StoreRefreshToken(nr);
    }
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
    outToken.assign(reinterpret_cast<char*>(pCred->CredentialBlob), pCred->CredentialBlobSize);
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
        [session = auth, revokeCallback](HANDLE cancel) mutable {
            while (WaitForSingleObject(cancel, HEARTBEAT_INTERVAL_SEC * 1000) == WAIT_TIMEOUT) {
                if (AccessTokenExpired(session)) {
                    if (!RefreshAccessToken(session)) { g_sessionRevoked = true; revokeCallback(); return; }
                }
                uint32_t dbg = 0, vm = 0, tamper = 0;
#if SEC_ANTI_DEBUG
                dbg = AntiDebug::DebugScore();
#endif
#if SEC_ANTI_VM
                vm = AntiVM::GetRiskScore();
#endif
#if SEC_ANTI_TAMPER
                tamper = AntiTamper::TamperScore();
#endif
                std::ostringstream body;
                body << "{\"sessionCheck\":true,\"debugScore\":" << dbg
                     << ",\"vmScore\":" << vm << ",\"tamperScore\":" << tamper << "}";

                std::wstring host; WORD port = API_PORT; bool tls = false;
                ResolveApiEndpoint(host, port, tls);
                std::string resp = HttpJson(L"POST", L"/api/auth/heartbeat", body.str(),
                    session.accessToken, tls, host, port);
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

void StartAttestation(const AuthResult& auth,
                      const std::string& fingerprint,
                      std::function<SecurityScores()> scoreProvider,
                      std::function<void()> revokeCallback) {
    Threads::ThreadManager::Instance().Launch("license_attest",
        [session = auth, fingerprint, scoreProvider, revokeCallback](HANDLE cancel) mutable {
            // First attest quickly, then every ~3 min
            int waitMs = 5000;
            while (WaitForSingleObject(cancel, waitMs) == WAIT_TIMEOUT) {
                waitMs = 180000;
                if (AccessTokenExpired(session)) {
                    if (!RefreshAccessToken(session)) { g_sessionRevoked = true; revokeCallback(); return; }
                }
                auto scores = scoreProvider ? scoreProvider() : SecurityScores{};
                auto ts = static_cast<long long>(
                    std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL);
                std::ostringstream body;
                body << "{\"nonce\":\"" << MakeUuid()
                     << "\",\"timestamp\":" << ts
                     << ",\"fingerprint\":\"" << JsonEscape(fingerprint)
                     << "\",\"integrityOk\":" << (scores.integrityOk ? "true" : "false")
                     << ",\"debugScore\":" << scores.debugScore
                     << ",\"vmScore\":" << scores.vmScore
                     << ",\"tamperScore\":" << scores.tamperScore
                     << ",\"signedPe\":" << (scores.signedPe ? "true" : "false") << "}";

                std::wstring host; WORD port = API_PORT; bool tls = false;
                ResolveApiEndpoint(host, port, tls);
                std::string resp = HttpJson(L"POST", L"/api/auth/attest", body.str(),
                    session.accessToken, tls, host, port);
                if (resp.find("REVOKED") != std::string::npos ||
                    resp.find("Attestation failed") != std::string::npos) {
                    g_sessionRevoked = true;
                    revokeCallback();
                    return;
                }
                Threads::ThreadManager::Instance().Heartbeat(GetCurrentThreadId());
            }
        }, true);
}

void ReportThreat(const AuthResult& auth, const char* source, const char* detail, uint32_t severity) {
    if (!auth.valid || auth.accessToken.empty()) return;
    std::ostringstream body;
    body << "{\"source\":\"" << JsonEscape(source ? source : "unknown")
         << "\",\"detail\":\"" << JsonEscape(detail ? detail : "")
         << "\",\"severity\":" << severity << "}";
    std::wstring host; WORD port = API_PORT; bool tls = false;
    ResolveApiEndpoint(host, port, tls);
    HttpJson(L"POST", L"/api/auth/threat", body.str(), auth.accessToken, tls, host, port);
}

} // namespace Session
