// Immortal Software — WebView2 host EXE for Loader GUI
// Packages as ImmortalLoader.exe next to ui/ (or same folder as index.html).
// Bridge only: auth/session UI pipeline. No process-injection path.
#include <windows.h>
#include <shellapi.h>
#include <wrl.h>
#include <string>
#include <filesystem>
#include <thread>
#include <atomic>

#include <WebView2.h>

using namespace Microsoft::WRL;
namespace fs = std::filesystem;

static ComPtr<ICoreWebView2Controller> g_controller;
static ComPtr<ICoreWebView2> g_webview;
static HWND g_hwnd = nullptr;
static std::atomic<bool> g_loadBusy{false};
static fs::path g_uiRoot;
static fs::path g_portalHtml;

static fs::path ExeDir() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return fs::path(buf).parent_path();
}

static bool HasIndex(const fs::path& dir) {
    return fs::exists(dir / L"index.html");
}

// Prefer packaged layout: <exe>/ui/index.html, then same folder, then legacy tree walk.
static fs::path ResolveUiRoot() {
    const fs::path exe = ExeDir();
    const fs::path candidates[] = {
        exe / L"ui",
        exe,
        exe.parent_path(),
        exe.parent_path().parent_path(),
        exe.parent_path().parent_path().parent_path(),
        exe.parent_path().parent_path().parent_path().parent_path(),
    };
    for (const auto& c : candidates) {
        if (HasIndex(c)) return fs::weakly_canonical(c);
    }
    return exe;
}

static fs::path ResolvePortalHtml(const fs::path& ui) {
    const fs::path candidates[] = {
        ui.parent_path() / L"portal" / L"index.html",
        ExeDir() / L"portal" / L"index.html",
        ExeDir().parent_path() / L"portal" / L"index.html",
        ui / L"portal" / L"index.html",
    };
    for (const auto& c : candidates) {
        if (fs::exists(c)) return fs::weakly_canonical(c);
    }
    return {};
}

static std::wstring PathToFileUrl(const fs::path& p) {
    std::wstring path = p.wstring();
    for (auto& c : path) if (c == L'\\') c = L'/';
    if (path.size() > 1 && path[1] == L':') return L"file:///" + path;
    return L"file://" + path;
}

static std::wstring EscapeJsString(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t c : s) {
        if (c == L'\\' || c == L'\'') out.push_back(L'\\');
        out.push_back(c);
    }
    return out;
}

static void ResizeWebView() {
    if (!g_controller) return;
    RECT rc{};
    GetClientRect(g_hwnd, &rc);
    g_controller->put_Bounds(rc);
}

static void PostJson(const wchar_t* json) {
    if (g_webview) g_webview->PostWebMessageAsJson(json);
}

static std::wstring ExtractAction(const std::wstring& s) {
    const std::wstring key = L"\"action\"";
    size_t p = s.find(key);
    if (p == std::wstring::npos) return L"";
    p = s.find(L':', p + key.size());
    if (p == std::wstring::npos) return L"";
    p = s.find(L'"', p);
    if (p == std::wstring::npos) return L"";
    size_t end = s.find(L'"', p + 1);
    if (end == std::wstring::npos) return L"";
    return s.substr(p + 1, end - p - 1);
}

static std::wstring ExtractStringField(const std::wstring& s, const wchar_t* field) {
    std::wstring key = L"\"";
    key += field;
    key += L"\"";
    size_t p = s.find(key);
    if (p == std::wstring::npos) return L"";
    p = s.find(L':', p + key.size());
    if (p == std::wstring::npos) return L"";
    p = s.find(L'"', p);
    if (p == std::wstring::npos) return L"";
    size_t end = s.find(L'"', p + 1);
    if (end == std::wstring::npos) return L"";
    return s.substr(p + 1, end - p - 1);
}

static void OpenPortal() {
    if (g_portalHtml.empty() || !fs::exists(g_portalHtml)) {
        PostJson(L"{\"action\":\"loadError\",\"error\":\"Key portal not found next to loader\"}");
        return;
    }
    ShellExecuteW(nullptr, L"open", g_portalHtml.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static void PostLoadProgress(const wchar_t* msg) {
    std::wstring json = L"{\"action\":\"loadProgress\",\"msg\":\"";
    json += msg;
    json += L"\"}";
    PostJson(json.c_str());
}

static void RunStagedPipeline(const wchar_t* kind) {
    if (g_loadBusy.exchange(true)) {
        PostJson(L"{\"action\":\"loadError\",\"error\":\"Another load is already in progress\"}");
        return;
    }

    std::wstring mode = kind ? kind : L"load_private";
    std::thread([mode]() {
        struct BusyGuard {
            ~BusyGuard() { g_loadBusy = false; }
        } guard;

        Sleep(180);
        PostLoadProgress(L"Binding session…");
        Sleep(280);
        PostLoadProgress(L"Checking license channel…");
        Sleep(260);
        if (mode == L"loadSpoofer") {
            PostLoadProgress(L"Refreshing identity envelope…");
            Sleep(320);
            PostJson(L"{\"action\":\"spoofDone\",\"success\":true,\"msg\":\"Spoof pipeline acknowledged\"}");
        } else {
            PostLoadProgress(L"Preparing module slot…");
            Sleep(300);
            PostLoadProgress(L"Hand-off ready…");
            Sleep(220);
            PostJson(L"{\"action\":\"loadDone\",\"msg\":\"Session pipeline complete\"}");
        }
    }).detach();
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_SIZE:
        ResizeWebView();
        return 0;
    case WM_SETFOCUS:
        if (g_controller) g_controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

static void OnWebMessage(ICoreWebView2WebMessageReceivedEventArgs* args) {
    LPWSTR raw = nullptr;
    if (FAILED(args->TryGetWebMessageAsString(&raw)) || !raw) return;
    std::wstring s(raw);
    CoTaskMemFree(raw);

    const std::wstring action = ExtractAction(s);
    if (action.empty()) return;

    if (action == L"uiReady") {
        PostJson(L"{\"action\":\"hostReady\",\"version\":\"2.3.1\",\"bridge\":\"webview2\"}");
        PostJson(L"{\"action\":\"focusKey\"}");
        PostJson(L"{\"action\":\"gameStatus\",\"ready\":true,\"detail\":\"Host online\"}");
        return;
    }
    if (action == L"ping") {
        PostJson(L"{\"action\":\"pong\"}");
        return;
    }
    if (action == L"exit") {
        PostQuitMessage(0);
        return;
    }
    if (action == L"openPortal") {
        OpenPortal();
        return;
    }
    if (action == L"sessionRevoked") {
        PostJson(L"{\"action\":\"loadError\",\"error\":\"Session revoked\"}");
        PostJson(L"{\"action\":\"gameStatus\",\"ready\":false,\"detail\":\"Session revoked\"}");
        return;
    }
    if (action == L"authOk") {
        PostJson(L"{\"action\":\"gameStatus\",\"ready\":true,\"detail\":\"Authenticated\"}");
        return;
    }
    if (action == L"authFail") {
        std::wstring err = ExtractStringField(s, L"error");
        std::wstring json = L"{\"action\":\"authFail\",\"error\":\"";
        json += err.empty() ? L"Authentication failed" : err;
        json += L"\"}";
        PostJson(json.c_str());
        return;
    }
    if (action == L"load_private" || action == L"loadSpoofer") {
        RunStagedPipeline(action.c_str());
        return;
    }
    if (action == L"emuStart" || action == L"emuStop") {
        const bool on = (action == L"emuStart");
        PostJson(on
            ? L"{\"action\":\"emuActive\",\"active\":true,\"detail\":\"UI console armed\"}"
            : L"{\"action\":\"emuActive\",\"active\":false}");
        return;
    }
    if (action == L"setHotkey") {
        PostJson(L"{\"action\":\"hotkeySet\",\"ok\":true}");
        return;
    }
}

static HRESULT InitWebView() {
    g_uiRoot = ResolveUiRoot();
    g_portalHtml = ResolvePortalHtml(g_uiRoot);

    if (!HasIndex(g_uiRoot)) {
        MessageBoxW(g_hwnd,
            L"Could not find Loader UI (index.html).\n"
            L"Place ImmortalLoader.exe next to ui\\ or the GUI folder.",
            L"Immortal Software", MB_ICONERROR);
        return E_FAIL;
    }

    return CreateCoreWebView2EnvironmentWithOptions(
        nullptr, nullptr, nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
                if (FAILED(hr) || !env) return hr;
                return env->CreateCoreWebView2Controller(
                    g_hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [](HRESULT hr2, ICoreWebView2Controller* controller) -> HRESULT {
                            if (FAILED(hr2) || !controller) return hr2;
                            g_controller = controller;
                            controller->get_CoreWebView2(&g_webview);
                            ResizeWebView();

                            ComPtr<ICoreWebView2Settings> settings;
                            g_webview->get_Settings(&settings);
                            if (settings) {
                                settings->put_IsScriptEnabled(TRUE);
                                settings->put_IsWebMessageEnabled(TRUE);
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->put_AreDevToolsEnabled(FALSE);
                            }

                            EventRegistrationToken token{};
                            g_webview->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                        OnWebMessage(args);
                                        return S_OK;
                                    }).Get(), &token);

                            ComPtr<ICoreWebView2_3> wv3;
                            std::wstring nav = PathToFileUrl(g_uiRoot / L"index.html");
                            if (SUCCEEDED(g_webview.As(&wv3))) {
                                if (SUCCEEDED(wv3->SetVirtualHostNameToFolderMapping(
                                        L"immortal.loader", g_uiRoot.wstring().c_str(),
                                        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_ALLOW))) {
                                    nav = L"https://immortal.loader/index.html";
                                }
                            }

                            std::wstring boot =
                                L"window.IMMORTAL_API=window.IMMORTAL_API||'http://127.0.0.1:3000';"
                                L"window.IMMORTAL_HOST_BRIDGE='webview2';"
                                L"window.IMMORTAL_HOST_VERSION='2.3.1';"
                                L"window.IMMORTAL_IS_WEBVIEW=true;";
                            if (!g_portalHtml.empty()) {
                                boot += L"window.IMMORTAL_PORTAL='";
                                boot += EscapeJsString(PathToFileUrl(g_portalHtml));
                                boot += L"';";
                            }

                            g_webview->AddScriptToExecuteOnDocumentCreated(boot.c_str(), nullptr);
                            g_webview->Navigate(nav.c_str());
                            g_controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
                            return S_OK;
                        }).Get());
            }).Get());
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR, int show) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.lpszClassName = L"ImmortalLoaderHost";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&wc);

    g_hwnd = CreateWindowExW(0, wc.lpszClassName, L"Immortal Software",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720,
        nullptr, nullptr, hi, nullptr);

    if (FAILED(InitWebView())) {
        MessageBoxW(g_hwnd,
            L"WebView2 Runtime is required.\nInstall the Evergreen Runtime from Microsoft.",
            L"Immortal Software", MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hwnd, show);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return 0;
}
