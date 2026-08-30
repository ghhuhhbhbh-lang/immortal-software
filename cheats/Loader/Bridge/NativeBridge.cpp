#include "NativeBridge.h"
#include <sstream>
#include <mutex>

namespace NativeBridge {

static Microsoft::WRL::ComPtr<ICoreWebView2> g_wv;
static std::mutex g_mtx;

void SetController(Microsoft::WRL::ComPtr<ICoreWebView2> wv) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_wv = wv;
}

static void Post(const std::string& json) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_wv) return;
    std::wstring wjson(json.begin(), json.end());
    g_wv->PostWebMessageAsJson(wjson.c_str());
}

// ──────────────────── helpers ────────────────────

static std::string Esc(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '"')  { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c == '\n') { out += "\\n";  }
        else if (c == '\r') { out += "\\r";  }
        else                { out += c; }
    }
    return out;
}

// ──────────────────── public API ────────────────────

void PostAuthOk(const std::string& username, const std::string& expiry,
                const std::string& plan) {
    std::ostringstream ss;
    ss << "{\"action\":\"authOk\","
       << "\"username\":\"" << Esc(username) << "\","
       << "\"expiry\":\""   << Esc(expiry)   << "\","
       << "\"plan\":\""     << Esc(plan)     << "\"}";
    Post(ss.str());
}

void PostAuthFail(const std::string& reason) {
    Post("{\"action\":\"authFail\",\"reason\":\"" + Esc(reason) + "\"}");
}

void PostSessionExpired() {
    Post("{\"action\":\"sessionExpired\"}");
}

void PostApiStatus(bool ok) {
    Post(std::string("{\"action\":\"apiStatus\",\"ok\":") + (ok ? "true" : "false") + "}");
}

void PostPipeStatus(bool connected, const std::string& error) {
    std::ostringstream ss;
    ss << "{\"action\":\"pipeStatus\",\"connected\":"
       << (connected ? "true" : "false");
    if (!error.empty())
        ss << ",\"error\":\"" << Esc(error) << "\"";
    ss << "}";
    Post(ss.str());
}

void PostGameStatus(bool running) {
    Post(std::string("{\"action\":\"gameStatus\",\"running\":") + (running ? "true" : "false") + "}");
}

void PostUpdateAvailable(const std::string& version) {
    Post("{\"action\":\"updateAvailable\",\"version\":\"" + Esc(version) + "\"}");
}

void PostUpdateProgress(int pct) {
    Post("{\"action\":\"updateProgress\",\"pct\":" + std::to_string(pct) + "}");
}

void PostUpdateDone(bool success, const std::string& error) {
    std::ostringstream ss;
    ss << "{\"action\":\"updateDone\",\"success\":" << (success ? "true" : "false");
    if (!error.empty())
        ss << ",\"error\":\"" << Esc(error) << "\"";
    ss << "}";
    Post(ss.str());
}

void PostError(const std::string& message) {
    Post("{\"action\":\"error\",\"message\":\"" + Esc(message) + "\"}");
}

void PostRaw(const std::string& json) {
    Post(json);
}

} // namespace NativeBridge
