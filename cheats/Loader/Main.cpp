// Loader/Main.cpp — Immortal Software Loader v3.1
// WebView2 host with built-in injector, named-pipe DLL bridge, and auto-update.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dwmapi.h>
#include <wrl.h>
#include <string>
#include <functional>
#include <filesystem>
#include <thread>
#include <atomic>
#include <mutex>
#include <sstream>
#include <fstream>
#include <WebView2.h>
#pragma comment(lib, "dwmapi.lib")

#include "Injection/InjectionEngine.h"
#include "Core/PipeServer.h"
#include "Core/ConfigStore.h"
#include "Update/UpdateChecker.h"
#include "CommonTypes.h"
#include "CryptoPrimitives.h"

#ifdef RELEASE_BUILD
#  include "Security/SecurityManager.h"
   namespace Sec = SecurityManager;
#else
   namespace Sec {
     inline bool Initialize()                    { return true; }
     inline bool Authenticate(const std::wstring&,
                              const std::string&,
                              const std::string&) { return true; }
     inline bool ShouldLaunchGame()              { return true; }
     inline const char* GetUsername()            { return "dev"; }
     inline const char* GetRole()                { return "OWNER"; }
     inline const char* GetExpiry()              { return "2099-12-31"; }
     inline void OnPipeLost()                    {}
     inline void Shutdown()                      {}
     inline void SetRevocationCallback(std::function<void()>) {}
   }
#endif

using namespace Microsoft::WRL;

// ── Build version — update this on each release ───────────────────────────────
static constexpr char CHEAT_VERSION[] = "2.1.0";

// ── Globals ────────────────────────────────────────────────────────────────────
static ComPtr<ICoreWebView2Controller> g_ctrl;
static ComPtr<ICoreWebView2>           g_wv;
static HWND                            g_hwnd = nullptr;
static ConfigStore::Config             g_cfg;
static std::string                     g_accessToken;

static DWORD   g_cs2Pid  = 0;
static HMODULE g_dllBase = nullptr;
static std::wstring g_dllPath;

static std::atomic<int>  g_missedBeats{ 0 };
static std::atomic<bool> g_pipeWatchRunning{ false };
static std::atomic<bool> g_gameWatchRunning{ false };
static std::thread g_pipeWatchThread;
static std::thread g_gameWatchThread;

constexpr int MAX_MISSED  = 5;
constexpr int BEAT_MS     = 3000;

// ── Helpers ────────────────────────────────────────────────────────────────────
static void PostJsonA(const std::string& json) {
    if (!g_wv) return;
    std::wstring w(json.begin(), json.end());
    g_wv->PostWebMessageAsJson(w.c_str());
}

static std::string JsonGet(const std::string& json, const std::string& key) {
    auto k = json.find('"' + key + '"');
    if (k == std::string::npos) return {};
    auto c = json.find(':', k);
    if (c == std::string::npos) return {};
    auto v = json.find_first_not_of(" \t", c + 1);
    if (v == std::string::npos) return {};
    if (json[v] == '"') {
        auto q2 = json.find('"', v + 1);
        return q2 == std::string::npos ? "" : json.substr(v + 1, q2 - v - 1);
    }
    auto end = json.find_first_of(",}", v);
    return json.substr(v, end == std::string::npos ? std::string::npos : end - v);
}

static std::filesystem::path GuiFolder() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    auto exe = std::filesystem::path(buf).parent_path();
    // Prefer packaged ui/ next to the EXE, then walk up to the repo GUI folder.
    const std::filesystem::path candidates[] = {
        exe / L"ui",
        exe / L"Emulator Loader GUI",
        exe.parent_path() / L"Emulator Loader GUI",                 // .../bin
        exe.parent_path().parent_path() / L"Emulator Loader GUI",   // .../cheats
        exe.parent_path().parent_path().parent_path() / L"Emulator Loader GUI", // repo root
        exe / L"../Emulator Loader GUI",
        exe / L"../../Emulator Loader GUI",
        exe / L"../../../Emulator Loader GUI",
    };
    for (const auto& c : candidates) {
        std::error_code ec;
        auto resolved = std::filesystem::weakly_canonical(c, ec);
        const auto& path = ec ? c : resolved;
        if (std::filesystem::exists(path / L"index.html")) return path;
    }
    return exe;
}

static void ApplyDarkChrome(HWND hwnd) {
    // Windows 11 / 10 dark title bar — kills the light "Imm..." caption strip.
    const BOOL dark = TRUE;
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    // Prefer dark caption color when supported (Win11 22H2+).
    const COLORREF caption = RGB(11, 11, 14);
    const DWORD DWMWA_CAPTION_COLOR = 35;
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
    const COLORREF border = RGB(88, 28, 135);
    const DWORD DWMWA_BORDER_COLOR = 34;
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));

    // App logo in title bar + taskbar.
    HICON hiBig = static_cast<HICON>(LoadImageW(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101), IMAGE_ICON,
        GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0));
    HICON hiSmall = static_cast<HICON>(LoadImageW(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
    if (!hiBig) {
        // Fallback: logo.ico next to EXE / ui folder
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::filesystem::path dir = std::filesystem::path(exe).parent_path();
        for (auto rel : { L"logo.ico", L"ui\\logo.ico" }) {
            auto p = dir / rel;
            if (!std::filesystem::exists(p)) continue;
            hiBig = static_cast<HICON>(LoadImageW(nullptr, p.c_str(), IMAGE_ICON,
                GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_LOADFROMFILE));
            hiSmall = static_cast<HICON>(LoadImageW(nullptr, p.c_str(), IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_LOADFROMFILE));
            if (hiBig) break;
        }
    }
    if (hiBig) {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hiBig));
        SetClassLongPtrW(hwnd, GCLP_HICON, reinterpret_cast<LONG_PTR>(hiBig));
    }
    if (hiSmall) {
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hiSmall));
        SetClassLongPtrW(hwnd, GCLP_HICONSM, reinterpret_cast<LONG_PTR>(hiSmall));
    }
}

static void ResizeWebView() {
    if (!g_ctrl || !g_hwnd) return;
    RECT rc{};
    GetClientRect(g_hwnd, &rc);
    // Fill client area exactly — no 1px white gutter on the right/bottom.
    g_ctrl->put_Bounds(rc);
    ComPtr<ICoreWebView2Controller2> c2;
    if (SUCCEEDED(g_ctrl.As(&c2)) && c2) {
        COREWEBVIEW2_COLOR bg{ 255, 0, 0, 0 }; // A,R,G,B — opaque black
        c2->put_DefaultBackgroundColor(bg);
    }
}

// ── DLL extraction (from embedded RCDATA resource 100) ────────────────────────
static bool ExtractEmbeddedDll(std::wstring& outPath) {
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(100), RT_RCDATA);
    if (!hRes) return false;
    void*  data = LockResource(LoadResource(nullptr, hRes));
    DWORD  size = SizeofResource(nullptr, hRes);
    if (!data || size == 0) return false;

    wchar_t tmp[MAX_PATH]{}; GetTempPathW(MAX_PATH, tmp);
    GUID g{}; CoCreateGuid(&g);
    wchar_t guid[40]{}; StringFromGUID2(g, guid, 40);
    outPath = std::wstring(tmp) + std::wstring(guid).substr(1, 36) + L".dll";

    std::ofstream f(outPath, std::ios::binary);
    if (!f) return false;
    // TODO: AES-256 decrypt with HWID-derived key before writing.
    f.write(reinterpret_cast<const char*>(data), size);
    return true;
}

// ── Update checker thread (runs once after authOk) ────────────────────────────
static void RunUpdateCheck() {
    PostJsonA(R"({"action":"log","msg":"Checking for DLL update..."})");
    auto info = Update::Check(g_cfg.api_url, g_accessToken, CHEAT_VERSION);
    if (!info.available) {
        PostJsonA(R"({"action":"log","msg":"DLL is up to date."})");
        return;
    }

    std::string msg = R"({"action":"loadProgress","msg":"Update available: )" + info.version + R"("})";
    PostJsonA(msg);

    wchar_t tmp[MAX_PATH]{}; GetTempPathW(MAX_PATH, tmp);
    std::wstring dest = std::wstring(tmp) + L"CheatDLL_update.dll";

    auto result = Update::Download(
        g_cfg.api_url, g_accessToken,
        info.downloadUrl, info.sha256, dest,
        [](int pct) {
            std::string p = R"({"action":"loadProgress","msg":"Downloading update: )" +
                            std::to_string(pct) + R"(%"})";
            PostJsonA(p);
        });

    if (result == Update::Result::Ok) {
        g_dllPath = dest; // use downloaded DLL for next inject
        PostJsonA(R"({"action":"log","msg":"DLL update downloaded and verified."})");
    } else {
        std::string err = R"({"action":"log","msg":"Update failed: )";
        if (result == Update::Result::HashMismatch) err += "hash mismatch";
        else                                        err += "network error";
        err += "\"}";
        PostJsonA(err);
    }
}

// ── Pipe watch (heartbeat) thread ─────────────────────────────────────────────
static void PipeWatchLoop() {
    while (g_pipeWatchRunning) {
        std::this_thread::sleep_for(std::chrono::milliseconds(BEAT_MS));
        if (!PipeServer::IsClientConnected()) { g_missedBeats = 0; continue; }
        if (++g_missedBeats >= MAX_MISSED) {
            g_missedBeats = 0;
            Sec::OnPipeLost();
            PostJsonA(R"({"action":"log","msg":"Security Error — heartbeat lost. Restart Loader."})");
            PostJsonA(R"({"action":"pipeStatus","connected":false,"error":"Security Error - Restart Loader"})");
        }
    }
}

// ── Game watch thread ─────────────────────────────────────────────────────────
static void GameWatchLoop() {
    bool last = false;
    while (g_gameWatchRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        DWORD pid = InjectionEngine::FindGamePid(L"cs2.exe");
        bool ready = pid != 0;
        if (ready != last) { last = ready; PostMessageW(g_hwnd, WM_APP + 2, pid, ready ? 1 : 0); }
    }
}

// ── Message handlers ──────────────────────────────────────────────────────────
static void HandleAuthOk(const std::string& json) {
    std::string key   = JsonGet(json, "key");
    std::string token = JsonGet(json, "token");
    if (!key.empty()) g_cfg.last_prefix = key.substr(0, 4);
    if (!token.empty()) g_accessToken = token;
    ConfigStore::Save(g_cfg);

    if (!key.empty()) {
        // Wire revocation callback so the server can kill this session.
        Sec::SetRevocationCallback([]{
            PostJsonA(R"({"action":"sessionRevoked","reason":"License revoked by security system"})");
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            PostQuitMessage(0);
        });
        Sec::Authenticate(std::wstring(key.begin(), key.end()),
                          g_cfg.api_url, g_accessToken);
    }

    // Start pipe server — DLL connects after injection.
    if (!PipeServer::IsClientConnected()) {
        PipeServer::Callbacks cbs;
        cbs.onMessage = [](const std::string& msg) {
            if (msg.find("\"heartbeat\"") != std::string::npos) {
                g_missedBeats = 0;
                PostJsonA(R"({"action":"pipeStatus","connected":true})");
            }
            if (msg.find("\"log\"") != std::string::npos) PostJsonA(msg);
        };
        cbs.onConnect = []() {
            PostJsonA(R"({"action":"pipeStatus","connected":true})");
        };
        cbs.onDisconnect = []() {
            PostJsonA(R"({"action":"pipeStatus","connected":false})");
            Sec::OnPipeLost();
        };
        PipeServer::Start(cbs);
        g_pipeWatchRunning = true;
        g_pipeWatchThread = std::thread(PipeWatchLoop);
    }

    // Start game watch.
    if (!g_gameWatchRunning) {
        g_gameWatchRunning = true;
        g_gameWatchThread = std::thread(GameWatchLoop);
    }

    // Check for DLL update in background.
    std::thread(RunUpdateCheck).detach();
}

static void HandleLoadPrivate(const std::string&) {
    if (!Sec::ShouldLaunchGame()) {
        PostJsonA(R"({"action":"loadError","error":"Session invalid — re-authenticate"})");
        return;
    }
    PostJsonA(R"({"action":"loadProgress","msg":"Locating CS2..."})");

    DWORD pid = InjectionEngine::FindGamePid(L"cs2.exe");
    if (pid == 0) {
        PostJsonA(R"({"action":"loadError","error":"CS2 is not running"})");
        return;
    }
    g_cs2Pid = pid;

    PostJsonA(R"({"action":"loadProgress","msg":"Preparing module..."})");

    // Prefer downloaded update, then embedded resource, then side-file.
    std::wstring dllPath; bool extracted = false;
    if (!g_dllPath.empty() && std::filesystem::exists(g_dllPath)) {
        dllPath = g_dllPath;
    } else if (FindResourceW(nullptr, MAKEINTRESOURCEW(100), RT_RCDATA)) {
        extracted = ExtractEmbeddedDll(dllPath);
    } else {
        wchar_t exe[MAX_PATH]{}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
        auto side = std::filesystem::path(exe).parent_path() / L"CheatDLL.dll";
        if (std::filesystem::exists(side)) dllPath = side.wstring();
    }

    if (dllPath.empty()) {
        PostJsonA(R"({"action":"loadError","error":"CheatDLL module not found"})");
        return;
    }

    PostJsonA(R"({"action":"loadProgress","msg":"Injecting..."})");
    auto res = InjectionEngine::InjectFromPath(pid, dllPath);
    if (extracted) DeleteFileW(dllPath.c_str());

    if (res == InjectionEngine::Result::Ok) {
        g_dllBase = reinterpret_cast<HMODULE>(1); // opaque mark: loaded
        PipeServer::Send(R"({"cmd":"setToken","token":")" + g_accessToken + "\"}");
        PostJsonA(R"({"action":"loadDone"})");
    } else {
        PostJsonA(R"({"action":"loadError","error":"Injection failed: )" +
                  std::string(InjectionEngine::ResultString(res)) + "\"}");
    }
}

static void HandleExit(const std::string&) {
    if (g_cs2Pid && g_dllBase) {
        PipeServer::Send(R"({"cmd":"unload"})");
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        g_dllBase = nullptr;
    }
    PipeServer::Stop();
    g_pipeWatchRunning = false;
    g_gameWatchRunning = false;
    if (g_pipeWatchThread.joinable()) g_pipeWatchThread.join();
    if (g_gameWatchThread.joinable()) g_gameWatchThread.join();
    PostQuitMessage(0);
}

static void HandleGameStatus(DWORD pid, bool ready) {
    std::string msg = R"({"action":"gameStatus","ready":)" +
                      std::string(ready ? "true" : "false") + "}";
    PostJsonA(msg);
    g_cs2Pid = ready ? pid : 0;
}

static void HandleSetHotkey(const std::string& json) {
    std::string vkStr = JsonGet(json, "vk"), modStr = JsonGet(json, "mod");
    if (vkStr.empty()) return;
    DWORD vk = static_cast<DWORD>(std::stoul(vkStr));
    DWORD mod = modStr.empty() ? 0 : static_cast<DWORD>(std::stoul(modStr));
    UnregisterHotKey(g_hwnd, 1);
    if (RegisterHotKey(g_hwnd, 1, mod, vk)) {
        g_cfg.hotkey_vk = vk; g_cfg.hotkey_mod = mod;
        ConfigStore::Save(g_cfg);
        wchar_t name[32]{}; UINT sc = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC) << 16;
        GetKeyNameTextW(sc, name, 32);
        if (!name[0]) swprintf(name, 32, L"VK%02X", vk);
        std::string label(name, name + wcslen(name));
        PostJsonA(R"({"action":"hotkeySet","name":")" + label + "\"}");
    }
}

// ── WebView message dispatcher ─────────────────────────────────────────────────
static void OnWebMessage(ICoreWebView2WebMessageReceivedEventArgs* args) {
    LPWSTR raw = nullptr;
    if (FAILED(args->TryGetWebMessageAsString(&raw)) || !raw) return;
    std::wstring ws(raw); CoTaskMemFree(raw);
    std::string json(ws.begin(), ws.end());
    std::string action = JsonGet(json, "action");

    if (action == "uiReady") {
        PostJsonA(R"({"action":"setApi","url":")" + g_cfg.api_url + "\"}");
        wchar_t name[32]{}; UINT sc = MapVirtualKeyW(g_cfg.hotkey_vk, MAPVK_VK_TO_VSC) << 16;
        GetKeyNameTextW(sc, name, 32);
        if (!name[0]) wcscpy_s(name, L"INSERT");
        std::string n(name, name + wcslen(name));
        PostJsonA(R"({"action":"hotkeySet","name":")" + n + "\"}");
    }
    else if (action == "authOk")       HandleAuthOk(json);
    else if (action == "load_private") HandleLoadPrivate(json);
    else if (action == "setHotkey")    HandleSetHotkey(json);
    else if (action == "exit")         HandleExit(json);
    else if (action == "emuStart")     PostJsonA(R"({"action":"emuActive","active":true})");
    else if (action == "emuStop")      PostJsonA(R"({"action":"emuActive","active":false})");
    else if (action == "triggerVerify") PipeServer::Send(R"({"cmd":"verify"})");
    else if (action == "sessionRevoked") HandleExit(json);
    else if (action == "loadSpoofer") {
        wchar_t exeBuf[MAX_PATH]{}; GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
        auto spoofer = std::filesystem::path(exeBuf).parent_path() / L"Spoofer.dll";
        if (!std::filesystem::exists(spoofer)) {
            PostJsonA(R"({"action":"spoofDone","success":false,"error":"Spoofer not found"})");
            return;
        }
        STARTUPINFOW si{ sizeof(si) }; PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + spoofer.wstring() + L"\" --spoof";
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 30000);
            DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            PostJsonA(code == 0 ? R"({"action":"spoofDone","success":true})"
                                : R"({"action":"spoofDone","success":false,"error":"Spoofer exited with error"})");
        } else {
            PostJsonA(R"({"action":"spoofDone","success":false,"error":"Failed to launch spoofer"})");
        }
    }
}

// ── WndProc ────────────────────────────────────────────────────────────────────
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_SIZE:    ResizeWebView(); return 0;
    case WM_SETFOCUS:
        if (g_ctrl) g_ctrl->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
        return 0;
    case WM_HOTKEY:
        if (wp == 1) { bool v = IsWindowVisible(hwnd); ShowWindow(hwnd, v ? SW_HIDE : SW_SHOW); if (!v) SetForegroundWindow(hwnd); }
        return 0;
    case WM_APP + 2:
        HandleGameStatus(static_cast<DWORD>(wp), lp != 0);
        return 0;
    case WM_DESTROY:
        HandleExit({});
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    ConfigStore::Load(g_cfg);

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"ImmortalLoader";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(WS_EX_APPWINDOW, L"ImmortalLoader", L"Immortal Software",
                              WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 980, 640,
                              nullptr, nullptr, hInst, nullptr);
    ApplyDarkChrome(g_hwnd);
    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    if (g_cfg.hotkey_vk)
        RegisterHotKey(g_hwnd, 1, g_cfg.hotkey_mod, g_cfg.hotkey_vk);

    // ── WebView2 init ───────────────────────────────────────────────────────────
    auto guiPath = GuiFolder();
    CreateCoreWebView2EnvironmentWithOptions(nullptr, nullptr, nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [guiPath](HRESULT, ICoreWebView2Environment* env) -> HRESULT {
                env->CreateCoreWebView2Controller(g_hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [guiPath](HRESULT, ICoreWebView2Controller* ctrl) -> HRESULT {
                            g_ctrl = ctrl;
                            ctrl->get_CoreWebView2(&g_wv);

                            // Kill WebView2 default white flash / side gutter.
                            {
                                ComPtr<ICoreWebView2Controller2> c2;
                                if (SUCCEEDED(ctrl->QueryInterface(IID_PPV_ARGS(&c2))) && c2) {
                                    COREWEBVIEW2_COLOR bg{ 255, 0, 0, 0 };
                                    c2->put_DefaultBackgroundColor(bg);
                                }
                            }

                            // Virtual host → GUI folder
                            ComPtr<ICoreWebView2_3> wv3;
                            g_wv.As(&wv3);
                            wv3->SetVirtualHostNameToFolderMapping(
                                L"immortal.loader",
                                guiPath.wstring().c_str(),
                                COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_ALLOW);

                            // Security settings
                            ComPtr<ICoreWebView2Settings> settings;
                            g_wv->get_Settings(&settings);
                            settings->put_IsScriptEnabled(TRUE);
                            settings->put_AreDevToolsEnabled(FALSE);
                            settings->put_IsStatusBarEnabled(FALSE);
                            settings->put_AreDefaultContextMenusEnabled(FALSE);
                            settings->put_IsZoomControlEnabled(FALSE);

                            // Inject IMMORTAL_API into every page
                            std::string apiJs = "window.IMMORTAL_API = '" + g_cfg.api_url + "'; window.IMMORTAL_SECURE_STORAGE = true;";
                            std::wstring apiJsW(apiJs.begin(), apiJs.end());
                            g_wv->AddScriptToExecuteOnDocumentCreated(apiJsW.c_str(), nullptr);

                            // Bridge
                            EventRegistrationToken tok;
                            g_wv->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* a) {
                                        OnWebMessage(a); return S_OK;
                                    }).Get(), &tok);

                            ResizeWebView();
                            g_wv->Navigate(L"https://immortal.loader/index.html");
                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return 0;
}
