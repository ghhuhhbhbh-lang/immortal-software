#include "SecurityManager.h"
#include "SelfDestruct.h"
#include "DiscordWebhook.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
// Pull in the full loader_security suite.
#include "../../../loader_security/Security.h"
#include "../../../loader_security/ImmortalSecurity.h"

#include <winhttp.h>
#include <windows.h>
#include <algorithm>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <ctime>
#pragma comment(lib, "winhttp.lib")

namespace SecurityManager {

// ──────────────────── state ────────────────────

static std::string          g_apiUrl;
static std::string          g_accessToken;
static std::string          g_licenseHash;   // first 12 hex chars of SHA-256(key)
static std::string          g_fingerprint;   // first 16 hex chars of HWID hash
static std::string          g_username;
static std::string          g_role;
static std::string          g_expiry;
static std::atomic<bool>    g_revoked{ false };
static std::atomic<int>     g_pipeLostCount{ 0 };
static std::function<void()> g_revokeCb;
static std::mutex           g_mtx;

// ──────────────────── helpers ────────────────────

static std::string IsoNow() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[32]{};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "%04d-%02d-%02dT%02d:%02d:%02dZ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string HexFirst(const std::string& raw, size_t n) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < raw.size() && out.size() < n * 2; ++i) {
        out += hex[(uint8_t(raw[i]) >> 4) & 0xF];
        out += hex[ uint8_t(raw[i])       & 0xF];
    }
    return out.substr(0, n);
}

// ──────────────────── API revocation call ────────────────────

static void ReportEventToServer(const char* eventType,
                                const char* severity,
                                const char* reason,
                                bool        revoke) {
    if (g_apiUrl.empty() || g_accessToken.empty()) return;

    // Build JSON payload.
    char payload[1024]{};
    _snprintf_s(payload, sizeof(payload), _TRUNCATE,
        "{\"eventType\":\"%s\","
        "\"severity\":\"%s\","
        "\"reason\":\"%s\","
        "\"loaderVersion\":\"" IMMORTAL_VERSION "\","
        "\"fingerprint\":\"%s\","
        "\"revoke\":%s}",
        eventType, severity, reason,
        g_fingerprint.c_str(),
        revoke ? "true" : "false");

    // Parse host from g_apiUrl (e.g. "http://localhost:3000").
    std::string url = g_apiUrl;
    bool https = url.rfind("https", 0) == 0;
    size_t hostStart = url.find("://");
    if (hostStart == std::string::npos) return;
    hostStart += 3;
    size_t portPos = url.find(':', hostStart);
    size_t slashPos = url.find('/', hostStart);
    size_t hostEnd = url.size();
    if (slashPos != std::string::npos) hostEnd = slashPos;
    if (portPos != std::string::npos && portPos < hostEnd) hostEnd = portPos;
    std::string host = url.substr(hostStart, hostEnd - hostStart);
    INTERNET_PORT port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    if (portPos != std::string::npos && (slashPos == std::string::npos || portPos < slashPos)) {
        size_t portLen = (slashPos == std::string::npos) ? std::string::npos : (slashPos - portPos - 1);
        port = static_cast<INTERNET_PORT>(std::stoi(url.substr(portPos + 1, portLen)));
    }

    std::wstring wHost(host.begin(), host.end());
    std::string token = g_accessToken;
    std::string body  = payload;

    std::thread([wHost, port, https, token, body] {
        HINTERNET hSession = WinHttpOpen(
            L"ImmortalLoader/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;

        HINTERNET hConn = WinHttpConnect(hSession, wHost.c_str(), port, 0);
        if (!hConn) { WinHttpCloseHandle(hSession); return; }

        DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WinHttpOpenRequest(
            hConn, L"POST", L"/api/security/event",
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return; }

        std::wstring authHdr = L"Authorization: Bearer " + std::wstring(token.begin(), token.end());
        const wchar_t* hdrs = L"Content-Type: application/json";
        WinHttpAddRequestHeaders(hReq, authHdr.c_str(), static_cast<DWORD>(authHdr.size()),
                                 WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpSendRequest(hReq, hdrs, static_cast<DWORD>(wcslen(hdrs)),
                           const_cast<char*>(body.c_str()),
                           static_cast<DWORD>(body.size()),
                           static_cast<DWORD>(body.size()), 0);
        WinHttpReceiveResponse(hReq, nullptr);
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
    }).detach();
}

// ──────────────────── central threat router ────────────────────

// This overrides Policy::SetAuditCallback so we handle ALL events from
// the loader_security suite — integrity checks, anti-debug, hooks, etc.
static void OnThreatEvent(const Policy::ThreatEvent& ev) {
    const char* source   = ev.source ? ev.source : "UNKNOWN";
    const char* detail   = ev.detail ? ev.detail : "";
    uint32_t    severity = ev.severity;

    // Map severity number to string.
    const char* sevStr = (severity >= 9) ? "CRITICAL"
                       : (severity >= 7) ? "HIGH"
                       : (severity >= 4) ? "MEDIUM"
                       : "INFO";

    // Determine action label for logging and Discord.
    const char* action = "LOGGED";
    bool revoke    = false;
    bool selfDel   = false;
    bool shutdown_ = false;

    if (severity >= 9) {
        action    = "LICENSE REVOKED + SELF-DELETE + SHUTDOWN";
        revoke    = true;
        selfDel   = true;
        shutdown_ = true;
    } else if (severity >= 7) {
        action = "LICENSE SUSPENDED + SESSION TERMINATED";
        revoke = true;
    } else if (severity >= 4) {
        action = "HONEYPOT ACTIVATED";
        revoke = false;
    }

    // 1. Report to server (async).
    ReportEventToServer(source, sevStr, detail, revoke);

    // 2. Discord alert (async, fire-and-forget).
    std::string ts = IsoNow();
    DiscordWebhook::Alert alert{
        source, sevStr, detail,
        IMMORTAL_VERSION,
        g_licenseHash.empty() ? "—" : g_licenseHash.c_str(),
        g_fingerprint.empty() ? "—" : g_fingerprint.c_str(),
        action, ts.c_str()
    };
    DiscordWebhook::SendAlert(alert);

    if (revoke) {
        g_revoked = true;
        // Notify the UI layer (JS) via the registered callback.
        if (g_revokeCb) {
            std::thread(g_revokeCb).detach();
        }
    }

    if (selfDel) {
        // Give the server report and Discord send a moment to start.
        Sleep(1500);
        SelfDestruct::ScheduleSelfDelete();
    }

    if (shutdown_) {
        Sleep(500);
        SelfDestruct::ShutdownSystem();
        ExitProcess(0xDEADCAFE); // fallback if shutdown denied
    }
}

// ──────────────────── public API ────────────────────

bool Initialize() {
    Policy::RegisterExitHandlers();

    // Override the audit callback AFTER ImmortalSecurity sets its own.
    // This runs immediately at startup, before Authenticate() is called.
    Policy::SetAuditCallback(OnThreatEvent);

    bool clean = Policy::RunStartupChecks();

    // Watch the loader's own directory for config tamper.
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring dir(exePath);
    auto last = dir.rfind(L'\\');
    if (last != std::wstring::npos) dir = dir.substr(0, last);
    Integrity::WatchConfigDir(dir.c_str());

    // Start thread-context anomaly monitor (catches debugger injection mid-run).
    if constexpr (SEC_THREAD_CONTEXT_MON) {
        Threads::ThreadManager::Instance().StartContextMonitor();
    }

    return clean;
}

bool Authenticate(const std::wstring& licenseKey,
                  const std::string&  apiUrl,
                  const std::string&  accessToken) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_apiUrl       = apiUrl;
    g_accessToken  = accessToken;

    // Derive license hash (first 12 chars of SHA-256).
    std::string keyNarrow(licenseKey.begin(), licenseKey.end());
    auto hash = Crypto::SHA256(keyNarrow.data(), keyNarrow.size());
    g_licenseHash = HexFirst(std::string(hash.begin(), hash.end()), 12);

    // Hardware fingerprint.
    Session::HardwareInfo hw = Session::CollectHardwareInfo();
    std::string hwRaw = hw.cpuId + hw.diskSerial + hw.systemUuid + hw.biosSerial;
    auto hwHash = Crypto::SHA256(hwRaw.data(), hwRaw.size());
    g_fingerprint = HexFirst(std::string(hwHash.begin(), hwHash.end()), 16);

    // Call into loader_security Authenticate flow.
    bool ok = ImmortalSecurity::Authenticate(licenseKey);

    if (ok) {
        g_username = ImmortalSecurity::GetUsername();
        g_role     = "USER";
        g_expiry   = ImmortalSecurity::GetExpiry();

        // Wire revocation callback from SessionManager.
        Threads::ThreadManager::Instance().SetSessionInvalidCallback([]{
            OnThreatEvent({ "SESSION_REVOKED", "Server-side revocation received", 9 });
        });
    }

    return ok;
}

bool ShouldLaunchGame() {
    if (g_revoked) return false;
    return ImmortalSecurity::ShouldLaunchGame();
}

const char* GetUsername() { return g_username.c_str(); }
const char* GetRole()     { return g_role.c_str(); }
const char* GetExpiry()   { return g_expiry.c_str(); }

void OnPipeLost() {
    int lost = ++g_pipeLostCount;
    if (lost >= 5) {
        OnThreatEvent({ "PIPE_LOST", "DLL heartbeat lost — possible ejection or crash", 7 });
    }
}

void SetRevocationCallback(std::function<void()> cb) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_revokeCb = std::move(cb);
}

void Shutdown() {
    Policy::Shutdown();
}

} // namespace SecurityManager
