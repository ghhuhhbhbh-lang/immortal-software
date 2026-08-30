// Immortal Software — minimal WebView2 host for Emulator Loader GUI
#include <windows.h>
#include <wrl.h>
#include <string>
#include <filesystem>

#include <WebView2.h>

using namespace Microsoft::WRL;

static ComPtr<ICoreWebView2Controller> g_controller;
static ComPtr<ICoreWebView2> g_webview;
static HWND g_hwnd = nullptr;

static std::filesystem::path GuiFolder() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::filesystem::path exe(buf);
    auto gui = exe.parent_path().parent_path().parent_path().parent_path();
    if (!std::filesystem::exists(gui / L"index.html")) {
        gui = exe.parent_path().parent_path();
    }
    if (!std::filesystem::exists(gui / L"index.html")) {
        gui = std::filesystem::weakly_canonical(exe.parent_path() / L"..");
    }
    return gui;
}

static std::wstring IndexUrl() {
    auto gui = GuiFolder();
    std::wstring path = (gui / L"index.html").wstring();
    for (auto& c : path) if (c == L'\\') c = L'/';
    if (path.size() > 1 && path[1] == L':') return L"file:///" + path;
    return L"file://" + path;
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
    if (s.find(L"\"uiReady\"") != std::wstring::npos) {
        PostJson(L"{\"action\":\"focusKey\"}");
    }
    if (s.find(L"\"exit\"") != std::wstring::npos) {
        PostQuitMessage(0);
    }
}

static HRESULT InitWebView() {
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

                            // Prefer https://immortal.loader virtual host (better CORS / cookies than file://)
                            ComPtr<ICoreWebView2_3> wv3;
                            std::wstring nav = IndexUrl();
                            if (SUCCEEDED(g_webview.As(&wv3))) {
                                const auto folder = GuiFolder().wstring();
                                if (SUCCEEDED(wv3->SetVirtualHostNameToFolderMapping(
                                        L"immortal.loader", folder.c_str(),
                                        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_ALLOW))) {
                                    nav = L"https://immortal.loader/index.html";
                                }
                            }

                            // Inject API base before page scripts when possible
                            g_webview->AddScriptToExecuteOnDocumentCreated(
                                L"window.IMMORTAL_API=window.IMMORTAL_API||'http://127.0.0.1:3000';",
                                nullptr);

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
