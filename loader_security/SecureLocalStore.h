#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace SecureStore {

// Local encrypted blob under %LOCALAPPDATA%/ImmortalSoftware/
bool SaveBlob(const char* name, const std::vector<uint8_t>& data);
bool LoadBlob(const char* name, std::vector<uint8_t>& out);
bool DeleteBlob(const char* name);

// Convenience for UTF-8 strings (XOR+length MAC lite - not a substitute for DPAPI in enterprise)
bool SaveText(const char* name, const std::string& text);
bool LoadText(const char* name, std::string& out);

} // namespace SecureStore
