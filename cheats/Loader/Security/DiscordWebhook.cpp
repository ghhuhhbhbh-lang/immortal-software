#include "DiscordWebhook.h"
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <string>
#include <thread>
#include <fstream>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

namespace DiscordWebhook {

// ──────────────────── URL resolution ────────────────────

std::string GetWebhookUrl() {
    static std::string cached;
    if (!cached.empty()) return cached;

    // 1. Environment variable
    char env[512]{};
    if (GetEnvironmentVariableA("IMMORTAL_DISCORD_WEBHOOK", env, sizeof(env)) > 0) {
        cached = env;
        return cached;
    }

    // 2. %APPDATA%\ImmortalSoftware\webhook.url
    wchar_t appData[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData);
    std::wstring path = std::wstring(appData) + L"\\ImmortalSoftware\\webhook.url";
    std::ifstream f(path);
    if (f) {
        std::string line;
        std::getline(f, line);
        if (!line.empty() && line.find("discord.com/api/webhooks/") != std::string::npos) {
            cached = line;
        }
    }
    return cached;
}

// ──────────────────── JSON builder ────────────────────

static std::string Esc(const char* s) {
    if (!s) return "";
    std::string out;
    for (const char* p = s; *p; ++p) {
        if (*p == '"')  out += "\\\"";
        else if (*p == '\\') out += "\\\\";
        else if (*p == '\n') out += "\\n";
        else out += *p;
    }
    return out;
}

static int ColorForSeverity(const char* sev) {
    if (!sev) return 0x808080;
    std::string s = sev;
    if (s == "CRITICAL") return 0xFF0000; // red
    if (s == "HIGH")     return 0xFF6600; // orange
    if (s == "MEDIUM")   return 0xFFCC00; // yellow
    return 0x00AAFF;                       // blue
}

static std::string BuildPayload(const Alert& a) {
    int color = ColorForSeverity(a.severity);

    // Embed fields.
    auto field = [](const char* name, const char* value, bool inline_ = true) -> std::string {
        return std::string("{\"name\":\"") + name + "\",\"value\":\"" + Esc(value) + "\",\"inline\":" +
               (inline_ ? "true" : "false") + "}";
    };

    std::string fields =
        field("Event", a.eventType) + "," +
        field("Severity", a.severity) + "," +
        field("Loader", a.loaderVersion) + "," +
        field("License", a.licenseHash ? a.licenseHash : "—") + "," +
        field("Device", a.fingerprint ? a.fingerprint : "—") + "," +
        field("Action", a.action, false) + "," +
        field("Reason", a.reason, false) + "," +
        field("Time", a.timestamp, false);

    std::string severityLabel = a.severity ? std::string(a.severity) : "INFO";
    std::string emoji = (severityLabel == "CRITICAL") ? "🚨"
                      : (severityLabel == "HIGH")     ? "⚠️"
                      : (severityLabel == "MEDIUM")   ? "🟡" : "ℹ️";

    return "{\"embeds\":[{"
           "\"title\":\"" + emoji + " IMMORTAL — Security Alert\","
           "\"description\":\"Threat detected in the active loader session.\","
           "\"color\":" + std::to_string(color) + ","
           "\"fields\":[" + fields + "],"
           "\"footer\":{\"text\":\"Immortal Software · Auto-Detection System\"}"
           "}]}";
}

// ──────────────────── WinHTTP sender ────────────────────

static void SendSync(const std::string& url, const std::string& payload) {
    // Parse discord.com path from full URL.
    // Expected: https://discord.com/api/webhooks/ID/TOKEN
    const std::wstring host = L"discord.com";

    std::string path = url;
    auto pos = path.find("discord.com");
    if (pos == std::string::npos) return;
    std::string urlPath = path.substr(pos + 11); // strip "discord.com"
    std::wstring wPath(urlPath.begin(), urlPath.end());

    HINTERNET hSession = WinHttpOpen(
        L"ImmortalLoader/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return; }

    HINTERNET hReq = WinHttpOpenRequest(
        hConn, L"POST", wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return; }

    // Force TLS 1.2 / 1.3.
    DWORD sec = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURE_PROTOCOLS, &sec, sizeof(sec));

    const wchar_t* headers = L"Content-Type: application/json";
    BOOL sent = WinHttpSendRequest(
        hReq, headers, static_cast<DWORD>(wcslen(headers)),
        const_cast<char*>(payload.c_str()),
        static_cast<DWORD>(payload.size()),
        static_cast<DWORD>(payload.size()), 0);

    if (sent) WinHttpReceiveResponse(hReq, nullptr);

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
}

// ──────────────────── public API ────────────────────

void SendAlert(const Alert& alert) {
    std::string url = GetWebhookUrl();
    if (url.empty()) return; // no webhook configured — silent skip

    // Capture by value so the detached thread owns everything.
    Alert a = alert;
    std::string aEventType   = a.eventType    ? a.eventType    : "";
    std::string aSeverity    = a.severity     ? a.severity     : "";
    std::string aReason      = a.reason       ? a.reason       : "";
    std::string aVersion     = a.loaderVersion? a.loaderVersion: "";
    std::string aLicense     = a.licenseHash  ? a.licenseHash  : "";
    std::string aFingerprint = a.fingerprint  ? a.fingerprint  : "";
    std::string aAction      = a.action       ? a.action       : "";
    std::string aTimestamp   = a.timestamp    ? a.timestamp    : "";

    Alert copy{
        aEventType.c_str(), aSeverity.c_str(), aReason.c_str(),
        aVersion.c_str(),   aLicense.c_str(),  aFingerprint.c_str(),
        aAction.c_str(),    aTimestamp.c_str()
    };

    std::string payload = BuildPayload(copy);

    std::thread([url, payload] {
        SendSync(url, payload);
    }).detach();
}

} // namespace DiscordWebhook
