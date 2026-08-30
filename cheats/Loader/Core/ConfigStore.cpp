#include "ConfigStore.h"
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace ConfigStore {

static constexpr ULONG HMAC_SIZE = 32;

static constexpr uint8_t k_hmacKey[] = {
    0x49, 0x4D, 0x4C, 0x54, 0x53, 0x4F, 0x46, 0x54,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

static bool ComputeHmac(const void* data, SIZE_T dataLen, uint8_t outHmac[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                     BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return false;

    DWORD objLen = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(DWORD), &cbData, 0);
    std::vector<uint8_t> hashObj(objLen);

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj.data(), objLen,
                                         (PUCHAR)k_hmacKey, sizeof(k_hmacKey), 0)))
        goto done;

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0)))
        goto done;

    ok = BCRYPT_SUCCESS(BCryptFinishHash(hHash, outHmac, HMAC_SIZE, 0));

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool ConstTimeEqual32(const uint8_t* a, const uint8_t* b) {
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

static std::wstring ConfigPath() {
    wchar_t appData[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData)))
        GetTempPathW(MAX_PATH, appData);

    std::wstring dir = std::wstring(appData) + L"\\ImmortalSoftware";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\config.dat";
}

static void JsonEscape(const std::string& in, std::string& out) {
    out.clear();
    out.reserve(in.size() + 8);
    for (char c : in) {
        if (c == '\\' || c == '"') { out.push_back('\\'); out.push_back(c); }
        else out.push_back(c);
    }
}

static std::string EncodeJson(const Config& c) {
    const FeatureConfig& f = c.features;
    std::string apiEsc;
    JsonEscape(c.api_url, apiEsc);
    std::string prefixEsc;
    JsonEscape(c.last_prefix, prefixEsc);

    char buf[1536];
    snprintf(buf, sizeof(buf),
        "{"
        "\"api_url\":\"%s\","
        "\"last_prefix\":\"%s\","
        "\"hotkey_vk\":%u,"
        "\"hotkey_mod\":%u,"
        "\"aimbotEnabled\":%s,"
        "\"aimbotFov\":%.2f,"
        "\"aimbotSmooth\":%.2f,"
        "\"aimbotBone\":%d,"
        "\"aimbotVisCheck\":%s,"
        "\"espEnabled\":%s,"
        "\"espBoxes\":%s,"
        "\"espHealth\":%s,"
        "\"espDistance\":%s,"
        "\"espTeamCheck\":%s,"
        "\"triggerEnabled\":%s,"
        "\"triggerDelayMs\":%d,"
        "\"skinEnabled\":%s,"
        "\"skinModelIndex\":%d,"
        "\"menuKey\":%d"
        "}",
        apiEsc.c_str(),
        prefixEsc.c_str(),
        static_cast<unsigned>(c.hotkey_vk),
        static_cast<unsigned>(c.hotkey_mod),
        f.aimbotEnabled  ? "true" : "false",
        f.aimbotFov,
        f.aimbotSmooth,
        f.aimbotBone,
        f.aimbotVisCheck ? "true" : "false",
        f.espEnabled     ? "true" : "false",
        f.espBoxes       ? "true" : "false",
        f.espHealth      ? "true" : "false",
        f.espDistance    ? "true" : "false",
        f.espTeamCheck   ? "true" : "false",
        f.triggerEnabled ? "true" : "false",
        f.triggerDelayMs,
        f.skinEnabled    ? "true" : "false",
        f.skinModelIndex,
        f.menuKey);
    return buf;
}

static bool BoolField(const std::string& json, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    auto pos = json.find(pat);
    if (pos == std::string::npos) return false;
    pos += pat.size();
    return json.compare(pos, 4, "true") == 0;
}

static float FloatField(const std::string& json, const char* key, float def) {
    std::string pat = std::string("\"") + key + "\":";
    auto pos = json.find(pat);
    if (pos == std::string::npos) return def;
    return static_cast<float>(atof(json.c_str() + pos + pat.size()));
}

static int IntField(const std::string& json, const char* key, int def) {
    std::string pat = std::string("\"") + key + "\":";
    auto pos = json.find(pat);
    if (pos == std::string::npos) return def;
    return atoi(json.c_str() + pos + pat.size());
}

static std::string StringField(const std::string& json, const char* key, const std::string& def) {
    std::string pat = std::string("\"") + key + "\":\"";
    auto pos = json.find(pat);
    if (pos == std::string::npos) return def;
    pos += pat.size();
    std::string out;
    for (size_t i = pos; i < json.size(); ++i) {
        if (json[i] == '\\' && i + 1 < json.size()) { out.push_back(json[++i]); continue; }
        if (json[i] == '"') break;
        out.push_back(json[i]);
    }
    return out;
}

static Config DecodeJson(const std::string& json) {
    Config c = Defaults();
    c.api_url     = StringField(json, "api_url", c.api_url);
    c.last_prefix = StringField(json, "last_prefix", "");
    c.hotkey_vk   = static_cast<UINT>(IntField(json, "hotkey_vk",  static_cast<int>(VK_INSERT)));
    c.hotkey_mod  = static_cast<UINT>(IntField(json, "hotkey_mod", 0));

    FeatureConfig& f = c.features;
    f.aimbotEnabled  = BoolField(json, "aimbotEnabled");
    f.aimbotFov      = FloatField(json, "aimbotFov",     5.f);
    f.aimbotSmooth   = FloatField(json, "aimbotSmooth",  8.f);
    f.aimbotBone     = IntField(json, "aimbotBone",      6);
    f.aimbotVisCheck = BoolField(json, "aimbotVisCheck");
    f.espEnabled     = BoolField(json, "espEnabled");
    f.espBoxes       = BoolField(json, "espBoxes");
    f.espHealth      = BoolField(json, "espHealth");
    f.espDistance    = BoolField(json, "espDistance");
    f.espTeamCheck   = BoolField(json, "espTeamCheck");
    f.triggerEnabled = BoolField(json, "triggerEnabled");
    f.triggerDelayMs = IntField(json, "triggerDelayMs",  80);
    f.skinEnabled    = BoolField(json, "skinEnabled");
    f.skinModelIndex = IntField(json, "skinModelIndex",  0);
    f.menuKey        = IntField(json, "menuKey",         VK_INSERT);
    return c;
}

Config Defaults() {
    Config c{};
    c.api_url    = "http://127.0.0.1:3000";
    c.hotkey_vk  = VK_INSERT;
    c.hotkey_mod = 0;
    c.features   = FeatureConfig{};
    return c;
}

bool Load(Config& out) {
    std::wstring path = ConfigPath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { out = Defaults(); return false; }

    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart < HMAC_SIZE || sz.QuadPart > 8192) {
        CloseHandle(h);
        out = Defaults();
        return false;
    }

    std::vector<uint8_t> buf(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr);
    CloseHandle(h);

    if (read != buf.size()) { out = Defaults(); return false; }

    uint8_t computed[32]{};
    if (!ComputeHmac(buf.data() + HMAC_SIZE, buf.size() - HMAC_SIZE, computed)) {
        out = Defaults(); return false;
    }
    if (!ConstTimeEqual32(buf.data(), computed)) { out = Defaults(); return false; }

    std::string json(buf.begin() + HMAC_SIZE, buf.end());
    out = DecodeJson(json);
    return true;
}

bool Save(const Config& cfg) {
    std::string json = EncodeJson(cfg);
    uint8_t hmac[32]{};
    if (!ComputeHmac(json.data(), json.size(), hmac)) return false;

    std::wstring path = ConfigPath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    WriteFile(h, hmac, HMAC_SIZE, &written, nullptr);
    WriteFile(h, json.data(), static_cast<DWORD>(json.size()), &written, nullptr);
    CloseHandle(h);
    return true;
}

} // namespace ConfigStore
