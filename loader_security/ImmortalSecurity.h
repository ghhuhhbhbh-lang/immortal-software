#pragma once
// Immortal Software — public security integration API
#include <string>

namespace ImmortalSecurity {

bool Initialize();
bool Authenticate(const std::wstring& licenseKey);
bool ShouldLaunchGame();

const char* GetUsername();
const char* GetRole();
const char* GetExpiry();

} // namespace ImmortalSecurity
