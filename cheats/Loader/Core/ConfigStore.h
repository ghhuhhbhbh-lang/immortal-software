#pragma once
#include <string>
#include <windows.h>
#include "../../SharedLibs/CommonTypes.h"

// HMAC-SHA256-protected config persistence.
// Config is stored in %APPDATA%\ImmortalSoftware\config.dat
namespace ConfigStore {

struct Config {
    std::string api_url = "http://127.0.0.1:3000";
    std::string last_prefix;
    UINT        hotkey_vk  = VK_INSERT;
    UINT        hotkey_mod = 0;
    FeatureConfig features{};
};

bool Load(Config& out);
bool Save(const Config& cfg);
Config Defaults();

// Back-compat helpers for FeatureConfig-only callers.
inline bool Load(FeatureConfig& out) {
    Config c;
    bool ok = Load(c);
    out = c.features;
    return ok;
}
inline bool Save(const FeatureConfig& features) {
    Config c = Defaults();
    c.features = features;
    return Save(c);
}

} // namespace ConfigStore
