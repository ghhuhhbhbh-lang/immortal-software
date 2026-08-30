#include "FakeAuthEngine.h"
#include "CryptoUtils.h"
#include <windows.h>
#include <winhttp.h>
#include <atomic>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

#pragma comment(lib, "winhttp.lib")

namespace FakeAuth {

static std::atomic<bool> g_active{ false };
static const char*       g_reason = "unknown";

void Activate(const char* reason) {
    g_active = true;
    g_reason = reason;
    // Launch decoy traffic in background, non-blocking
    std::thread([]() { SendDecoyTraffic("localhost"); }).detach();
}

bool IsActive() { return g_active.load(); }

std::string GenerateFakeLicenseResponse() {
    // Produce a plausible-looking JWT-like response (not actually valid)
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::ostringstream ss;
    ss << R"({"accessToken":"eyJhbGciOiJIUzI1NiJ9.)"
       << std::hex << std::setw(16) << std::setfill('0') << now
       << R"(.FAKE_SIG_HONEYPOT","expiresIn":900,)"
       << R"("username":"user","role":"PREMIUM","valid":true})";
    return ss.str();
}

void SendDecoyTraffic(const char* /*apiHost*/) {
    // Send a handful of plausible-but-meaningless requests to waste analyst time
    HINTERNET hSession = WinHttpOpen(L"Immortal/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hSession) return;
    static const wchar_t* decoyPaths[] = {
        L"/api/auth/me", L"/api/licenses/status", L"/api/heartbeat", nullptr
    };
    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 3000, 0);
    if (hConnect) {
        for (int i = 0; decoyPaths[i]; i++) {
            HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", decoyPaths[i],
                nullptr, nullptr, nullptr, 0);
            if (hReq) {
                WinHttpSendRequest(hReq, nullptr, 0, nullptr, 0, 0, 0);
                WinHttpCloseHandle(hReq);
            }
            Sleep(200);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
}

void ShowDeadEndError() {
    // Plausible non-auth error — confuses reverse engineers
    static const wchar_t* messages[] = {
        L"Game files appear to be corrupted. Please verify game integrity via Steam.",
        L"Display driver is outdated or incompatible. Please update your GPU drivers.",
        L"DirectX 12 feature level 12_0 is required. Your hardware may not be supported.",
    };
    // Pick based on tick count to vary
    int idx = static_cast<int>(GetTickCount64() % 3);
    MessageBoxW(nullptr, messages[idx],
        L"Immortal Software — Launch Error", MB_OK | MB_ICONWARNING);
}

const wchar_t* FakeLicenseMessage() {
    return L"License Valid  ✓  Expires: 2099-01-01";
}

} // namespace FakeAuth
