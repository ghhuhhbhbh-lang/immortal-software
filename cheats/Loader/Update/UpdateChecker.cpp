// Update/UpdateChecker.cpp
#include "UpdateChecker.h"
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace Update {

// ── Tiny JSON value extractor (no deps) ───────────────────────────────────────
static std::string JsonStr(const std::string& json, const std::string& key) {
    auto k = json.find("\"" + key + "\"");
    if (k == std::string::npos) return {};
    auto colon = json.find(':', k);
    if (colon == std::string::npos) return {};
    auto q1 = json.find('"', colon + 1);
    if (q1 == std::string::npos) return {};
    auto q2 = json.find('"', q1 + 1);
    return q2 == std::string::npos ? "" : json.substr(q1 + 1, q2 - q1 - 1);
}

// ── WinHTTP helpers ────────────────────────────────────────────────────────────
struct WinHttpGuard {
    HINTERNET h = nullptr;
    ~WinHttpGuard() { if (h) WinHttpCloseHandle(h); }
};

static bool ParseUrl(const std::string& url,
                     std::wstring& host, INTERNET_PORT& port,
                     std::wstring& path, bool& https) {
    std::wstring w(url.begin(), url.end());
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t szHost[256]{}, szPath[1024]{};
    uc.lpszHostName    = szHost;  uc.dwHostNameLength    = 256;
    uc.lpszUrlPath     = szPath;  uc.dwUrlPathLength     = 1024;
    if (!WinHttpCrackUrl(w.c_str(), 0, 0, &uc)) return false;
    host  = szHost;
    path  = szPath;
    port  = uc.nPort;
    https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

static std::string HttpGet(const std::string& apiBase,
                            const std::string& endpoint,
                            const std::string& token) {
    std::wstring host; INTERNET_PORT port; std::wstring path; bool https;
    if (!ParseUrl(apiBase + endpoint, host, port, path, https)) return {};

    WinHttpGuard sess{ WinHttpOpen(L"Immortal-Loader/2.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0) };
    if (!sess.h) return {};

    WinHttpGuard conn{ WinHttpConnect(sess.h, host.c_str(), port, 0) };
    if (!conn.h) return {};

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    WinHttpGuard req{ WinHttpOpenRequest(conn.h, L"GET", path.c_str(),
                                         nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags) };
    if (!req.h) return {};

    if (!token.empty()) {
        std::wstring auth = L"Authorization: Bearer " + std::wstring(token.begin(), token.end());
        WinHttpAddRequestHeaders(req.h, auth.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return {};
    if (!WinHttpReceiveResponse(req.h, nullptr)) return {};

    DWORD status = 0; DWORD statusSz = sizeof(DWORD);
    WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &status, &statusSz, nullptr);
    if (status != 200) return {};

    std::string body;
    char buf[4096]; DWORD read = 0;
    while (WinHttpReadData(req.h, buf, sizeof(buf), &read) && read)
        body.append(buf, read);
    return body;
}

static bool HttpDownload(const std::string& apiBase,
                          const std::string& endpoint,
                          const std::string& token,
                          const std::wstring& destPath,
                          ProgressCb progressCb) {
    std::wstring host; INTERNET_PORT port; std::wstring path; bool https;
    if (!ParseUrl(apiBase + endpoint, host, port, path, https)) return false;

    WinHttpGuard sess{ WinHttpOpen(L"Immortal-Loader/2.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0) };
    if (!sess.h) return false;
    WinHttpGuard conn{ WinHttpConnect(sess.h, host.c_str(), port, 0) };
    if (!conn.h) return false;
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    WinHttpGuard req{ WinHttpOpenRequest(conn.h, L"GET", path.c_str(),
                                         nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags) };
    if (!req.h) return false;

    if (!token.empty()) {
        std::wstring auth = L"Authorization: Bearer " + std::wstring(token.begin(), token.end());
        WinHttpAddRequestHeaders(req.h, auth.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }
    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return false;
    if (!WinHttpReceiveResponse(req.h, nullptr)) return false;

    DWORD status = 0; DWORD statusSz = sizeof(DWORD);
    WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &status, &statusSz, nullptr);
    if (status != 200) return false;

    // Content-Length for progress
    DWORD contentLen = 0; DWORD clSz = sizeof(DWORD);
    WinHttpQueryHeaders(req.h, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &contentLen, &clSz, nullptr);

    std::ofstream out(destPath, std::ios::binary);
    if (!out) return false;

    char buf[65536]; DWORD read = 0; DWORD total = 0;
    while (WinHttpReadData(req.h, buf, sizeof(buf), &read) && read) {
        out.write(buf, read);
        total += read;
        if (progressCb && contentLen > 0)
            progressCb(static_cast<int>(total * 100 / contentLen));
    }
    out.close();
    if (progressCb) progressCb(100);
    return total > 0;
}

// ── SHA-256 via CNG ────────────────────────────────────────────────────────────
std::string FileSha256(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};

    DWORD hashObjLen = 0, szRet = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PBYTE>(&hashObjLen), sizeof(DWORD), &szRet, 0);
    std::vector<uint8_t> hashObj(hashObjLen);

    BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjLen, nullptr, 0, 0);
    BCryptHashData(hHash, data.data(), static_cast<ULONG>(data.size()), 0);

    uint8_t hash[32]{};
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    static constexpr char HEX[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (uint8_t b : hash) { hex += HEX[b >> 4]; hex += HEX[b & 0x0F]; }
    return hex;
}

// ── Semver comparison ──────────────────────────────────────────────────────────
bool IsNewer(const std::string& a, const std::string& b) {
    auto parse = [](const std::string& v) {
        int ma = 0, mi = 0, pa = 0;
        sscanf_s(v.c_str(), "%d.%d.%d", &ma, &mi, &pa);
        return ma * 1000000 + mi * 1000 + pa;
    };
    return parse(a) > parse(b);
}

// ── Public API ─────────────────────────────────────────────────────────────────
Info Check(const std::string& apiBase, const std::string& accessToken,
           const std::string& currentVersion) {
    Info info;
    std::string body = HttpGet(apiBase, "/api/update/check", accessToken);
    if (body.empty()) return info;

    info.version     = JsonStr(body, "version");
    info.sha256      = JsonStr(body, "sha256");
    info.downloadUrl = JsonStr(body, "downloadUrl");
    info.available   = !info.version.empty() && IsNewer(info.version, currentVersion);
    return info;
}

Result Download(const std::string& apiBase, const std::string& accessToken,
                const std::string& downloadPath, const std::string& expectedSha256,
                const std::wstring& destPath, ProgressCb progressCb) {
    if (!HttpDownload(apiBase, downloadPath, accessToken, destPath, progressCb))
        return Result::NetworkError;

    std::string actual = FileSha256(destPath);
    if (actual != expectedSha256) {
        DeleteFileW(destPath.c_str());
        return Result::HashMismatch;
    }
    return Result::Ok;
}

} // namespace Update
