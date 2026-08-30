#pragma once
#include <string>

namespace FakeAuth {

// Activate honeypot mode: loader appears to work but blocks real launch
void Activate(const char* reason);

// Is honeypot active?
bool IsActive();

// Simulate a "valid" license response for captured network traffic
std::string GenerateFakeLicenseResponse();

// Generate decoy network traffic to confuse an analyst
void SendDecoyTraffic(const char* apiHost);

// Display a plausible non-auth error to the user
void ShowDeadEndError();

// Return an always-"Valid License" message for the UI
const wchar_t* FakeLicenseMessage();

} // namespace FakeAuth
