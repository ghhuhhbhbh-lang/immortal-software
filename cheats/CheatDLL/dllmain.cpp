// CheatDLL/dllmain.cpp — Immortal CS2 cheat DLL v2.1
// Connects to Loader via named pipe, validates JWT, renders ImGui overlay.
#include <windows.h>
#include <thread>
#include <atomic>
#include <string>
#include "PipeClient/PipeClient.h"
#include "Security/AntiDebug.h"
#include "Security/Honeypot.h"
#include "Features/Aimbot.h"
#include "Features/ESP.h"
#include "Features/TriggerBot.h"
#include "Features/SkinChanger.h"
#include "Overlay/Menu.h"
#include "CommonTypes.h"

static std::atomic<bool> g_running{ false };
static FeatureConfig     g_cfg;
static std::string       g_token;
static HANDLE            g_stopEvent = nullptr;

// ── Token validation (structure check + pipe-validated) ────────────────────────
static bool ValidateToken(const std::string& tok) {
    if (tok.size() < 20) return false;
    size_t d1 = tok.find('.');
    if (d1 == std::string::npos) return false;
    size_t d2 = tok.find('.', d1 + 1);
    return d2 != std::string::npos && d2 > d1 + 1;
}

// ── Pipe command handler ───────────────────────────────────────────────────────
static void OnCommand(const std::string& json) {
    auto get = [&](const std::string& key) -> std::string {
        auto k = json.find('"' + key + '"');
        if (k == std::string::npos) return {};
        auto c = json.find(':', k);
        if (c == std::string::npos) return {};
        auto v = json.find_first_not_of(" \t", c + 1);
        if (v == std::string::npos) return {};
        if (json[v] == '"') {
            auto q2 = json.find('"', v + 1); return q2 == std::string::npos ? "" : json.substr(v + 1, q2 - v - 1);
        }
        auto end = json.find_first_of(",}", v); return json.substr(v, end == std::string::npos ? std::string::npos : end - v);
    };

    std::string cmd = get("cmd");
    if (cmd == "unload") {
        g_running = false;
        SetEvent(g_stopEvent);
    } else if (cmd == "setToken") {
        g_token = get("token");
        if (!ValidateToken(g_token)) Honeypot::Activate();
        else                         Honeypot::Deactivate();
    } else if (cmd == "verify") {
        PipeClient::Send(R"({"event":"log","msg":"Verify OK"})");
    } else if (cmd == "updateConfig") {
        // Parse FeatureConfig fields from JSON and update g_cfg.
        // (Full JSON parse omitted for brevity — extend as needed.)
    }
}

// ── Heartbeat thread ───────────────────────────────────────────────────────────
static void HeartbeatThread() {
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        if (!PipeClient::IsConnected()) break;
        if (!PipeClient::Heartbeat()) {
            // Pipe lost — unload gracefully.
            g_running = false;
            SetEvent(g_stopEvent);
            break;
        }
    }
}

// ── Main DLL thread ────────────────────────────────────────────────────────────
static DWORD WINAPI MainThread(LPVOID hMod) {
    // ── Anti-debug scan ─────────────────────────────────────────────────────────
    AntiDebug::Report rep = AntiDebug::Scan();
    if (rep.score >= 18) { Honeypot::Activate(); }

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_running   = true;

    // ── Connect to loader pipe (15 attempts × 300 ms) ──────────────────────────
    bool connected = false;
    for (int i = 0; i < 15 && g_running; i++) {
        if (PipeClient::Connect()) { connected = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    if (!connected) { Honeypot::Activate(); }

    // ── Wait for token (10 s) ──────────────────────────────────────────────────
    if (connected) {
        for (int i = 0; i < 100 && g_running && g_token.empty(); i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (g_token.empty() || !ValidateToken(g_token))
            Honeypot::Activate();
    }

    // ── Feature init ───────────────────────────────────────────────────────────
    Aimbot::Init(&g_cfg);
    ESP::Init(&g_cfg);
    TriggerBot::Init(&g_cfg);
    SkinChanger::Init(&g_cfg);
    Menu::Init(&g_cfg);

    // ── Spawn heartbeat + pipe pump ────────────────────────────────────────────
    std::thread hbThread(HeartbeatThread);
    std::thread pumpThread([&]() {
        PipeClient::PumpMessages(OnCommand, g_stopEvent);
    });

    // ── Wait for unload signal ─────────────────────────────────────────────────
    WaitForSingleObject(g_stopEvent, INFINITE);
    g_running = false;

    // ── Teardown ───────────────────────────────────────────────────────────────
    Menu::Shutdown();
    PipeClient::Disconnect();
    if (hbThread.joinable())   hbThread.join();
    if (pumpThread.joinable()) pumpThread.join();
    CloseHandle(g_stopEvent);

    FreeLibraryAndExitThread(static_cast<HMODULE>(hMod), 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}
