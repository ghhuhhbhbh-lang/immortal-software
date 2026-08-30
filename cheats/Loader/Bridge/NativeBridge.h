#pragma once
#include <wrl.h>
#include <WebView2.h>
#include <string>

// NativeBridge: typed outbound messages from C++ → JavaScript.
// All PostMsg* functions JSON-serialize and call PostWebMessageAsJson on the
// provided WebView2 controller. The JS side handles each "action" string in
// handleNativeMessage().
namespace NativeBridge {

void SetController(Microsoft::WRL::ComPtr<ICoreWebView2> wv);

// Auth / session
void PostAuthOk(const std::string& username, const std::string& expiry,
                const std::string& plan);
void PostAuthFail(const std::string& reason);
void PostSessionExpired();

// Status dots
void PostApiStatus(bool ok);
void PostPipeStatus(bool connected, const std::string& error = "");
void PostGameStatus(bool running);

// Update flow
void PostUpdateAvailable(const std::string& version);
void PostUpdateProgress(int pct);
void PostUpdateDone(bool success, const std::string& error = "");

// Generic error overlay
void PostError(const std::string& message);

// Forward a raw JSON string as-is.
void PostRaw(const std::string& json);

} // namespace NativeBridge
