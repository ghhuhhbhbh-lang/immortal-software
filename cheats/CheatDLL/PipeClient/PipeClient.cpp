#include "PipeClient.h"
#include <atomic>
#include <mutex>
#include "../../SharedLibs/CommonTypes.h"
#include "../../SharedLibs/CryptoPrimitives.h"

namespace PipeClient {

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static std::atomic<bool> g_connected{ false };
static std::mutex g_mtx;

static bool WriteFrame(const std::string& json) {
    if (json.size() > PIPE_MAX_PAYLOAD) return false;
    PipeHeader hdr{};
    hdr.magic      = PIPE_MAGIC;
    hdr.version    = PIPE_VERSION;
    hdr.type       = static_cast<uint8_t>(DllEvent::Heartbeat);
    hdr.payloadLen = static_cast<uint32_t>(json.size());
    hdr.crc32      = Crc32(json.data(), json.size());

    DWORD written = 0;
    if (!WriteFile(g_pipe, &hdr, sizeof(hdr), &written, nullptr)) return false;
    if (written != sizeof(hdr)) return false;
    if (!json.empty()) {
        if (!WriteFile(g_pipe, json.data(), hdr.payloadLen, &written, nullptr)) return false;
        if (written != hdr.payloadLen) return false;
    }
    return true;
}

bool Connect() {
    HANDLE h = CreateFileW(
        IMMORTAL_PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = PIPE_READMODE_BYTE; SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_pipe != INVALID_HANDLE_VALUE) CloseHandle(g_pipe);
    g_pipe = h;
    g_connected = true;
    return true;
}

void Disconnect() {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_pipe != INVALID_HANDLE_VALUE) { CloseHandle(g_pipe); g_pipe = INVALID_HANDLE_VALUE; }
    g_connected = false;
}

bool IsConnected() { return g_connected; }

bool Send(const std::string& json) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_pipe == INVALID_HANDLE_VALUE) return false;
    if (!WriteFrame(json)) { g_connected = false; return false; }
    return true;
}

bool Heartbeat() { return Send(R"({"heartbeat":true})"); }

void PumpMessages(std::function<void(const std::string&)> cb, HANDLE stopEvent) {
    while (true) {
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) break;
        if (!g_connected) break;

        PipeHeader hdr{};
        DWORD read = 0;
        BOOL ok = ReadFile(g_pipe, &hdr, sizeof(hdr), &read, nullptr);
        if (!ok || read != sizeof(hdr)) { g_connected = false; break; }
        if (hdr.magic != PIPE_MAGIC || hdr.payloadLen > PIPE_MAX_PAYLOAD) continue;

        std::string payload(hdr.payloadLen, '\0');
        if (hdr.payloadLen > 0) {
            ok = ReadFile(g_pipe, payload.data(), hdr.payloadLen, &read, nullptr);
            if (!ok || read != hdr.payloadLen) { g_connected = false; break; }
        }

        if (Crc32(payload.data(), payload.size()) != hdr.crc32) continue; // corrupt frame
        if (cb) cb(payload);
    }
}

} // namespace PipeClient
