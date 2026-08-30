#include "SecureLocalStore.h"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "shell32.lib")

namespace SecureStore {
namespace {

std::filesystem::path StoreDir() {
    wchar_t path[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path)))
        return {};
    auto dir = std::filesystem::path(path) / L"ImmortalSoftware" / L"secure";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

std::vector<uint8_t> XorPad(const std::vector<uint8_t>& in, uint8_t key) {
    std::vector<uint8_t> out = in;
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<uint8_t>(out[i] ^ static_cast<uint8_t>(key + (i * 31)));
    return out;
}

} // namespace

bool SaveBlob(const char* name, const std::vector<uint8_t>& data) {
    if (!name || !*name) return false;
    auto dir = StoreDir();
    if (dir.empty()) return false;
    auto path = dir / name;
    auto enc = XorPad(data, 0x5A);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    const uint32_t n = static_cast<uint32_t>(enc.size());
    f.write(reinterpret_cast<const char*>(&n), 4);
    if (!enc.empty()) f.write(reinterpret_cast<const char*>(enc.data()), enc.size());
    return static_cast<bool>(f);
}

bool LoadBlob(const char* name, std::vector<uint8_t>& out) {
    out.clear();
    if (!name || !*name) return false;
    auto dir = StoreDir();
    if (dir.empty()) return false;
    auto path = dir / name;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    uint32_t n = 0;
    f.read(reinterpret_cast<char*>(&n), 4);
    if (!f || n > 8 * 1024 * 1024) return false;
    std::vector<uint8_t> enc(n);
    if (n) f.read(reinterpret_cast<char*>(enc.data()), n);
    if (!f) return false;
    out = XorPad(enc, 0x5A);
    return true;
}

bool DeleteBlob(const char* name) {
    if (!name || !*name) return false;
    auto dir = StoreDir();
    if (dir.empty()) return false;
    std::error_code ec;
    return std::filesystem::remove(dir / name, ec);
}

bool SaveText(const char* name, const std::string& text) {
    return SaveBlob(name, std::vector<uint8_t>(text.begin(), text.end()));
}

bool LoadText(const char* name, std::string& out) {
    std::vector<uint8_t> blob;
    if (!LoadBlob(name, blob)) return false;
    out.assign(blob.begin(), blob.end());
    return true;
}

} // namespace SecureStore
