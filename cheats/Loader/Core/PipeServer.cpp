#include "PipeServer.h"
#include "../../SharedLibs/CommonTypes.h"
#include "../../SharedLibs/CryptoPrimitives.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace PipeServer {

static constexpr int MAX_MISSED_BEATS = 5;
static constexpr int BEAT_INTERVAL_MS = 3000;

// ──────────────────── state ────────────────────

static Callbacks      g_cbs{};
static HANDLE         g_stopEvent    = nullptr;
static HANDLE         g_clientPipe   = INVALID_HANDLE_VALUE;
static std::thread    g_serverThread;
static std::atomic<bool> g_clientConnected{ false };

static std::mutex     g_writeMtx;
static std::atomic<int>  g_missedBeats{ 0 };
static std::atomic<DWORD> g_lastBeat{ 0 };

// ──────────────────── write helper ────────────────────

static bool WriteFrame(HANDLE pipe, const std::string& json) {
    if (json.size() > PIPE_MAX_PAYLOAD) return false;
    PipeHeader hdr{};
    hdr.magic      = PIPE_MAGIC;
    hdr.version    = PIPE_VERSION;
    hdr.type       = static_cast<uint8_t>(HostCmd::UpdateConfig);
    hdr.payloadLen = static_cast<uint32_t>(json.size());
    hdr.crc32      = Crc32(json.data(), json.size());

    DWORD w = 0;
    if (!WriteFile(pipe, &hdr, sizeof(hdr), &w, nullptr) || w != sizeof(hdr)) return false;
    if (!json.empty()) {
        if (!WriteFile(pipe, json.data(), hdr.payloadLen, &w, nullptr) || w != hdr.payloadLen)
            return false;
    }
    return true;
}

// ──────────────────── server thread ────────────────────

static void ServerThread(Callbacks cbs) {
    while (true) {
        if (WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;

        // Create a fresh pipe instance each connection cycle.
        HANDLE hPipe = CreateNamedPipeW(
            IMMORTAL_PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,          // single-instance
            4096, 4096,
            0, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(200);
            continue;
        }

        // Overlapped connect so we can honor stopEvent.
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ConnectNamedPipe(hPipe, &ov);

        HANDLE waitSet[2] = { ov.hEvent, g_stopEvent };
        DWORD  wr = WaitForMultipleObjects(2, waitSet, FALSE, INFINITE);

        if (wr != WAIT_OBJECT_0) {
            // Stop requested.
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            CloseHandle(ov.hEvent);
            break;
        }
        CloseHandle(ov.hEvent);

        DWORD dummy = 0;
        GetOverlappedResult(hPipe, &ov, &dummy, FALSE);

        {
            std::lock_guard<std::mutex> lk(g_writeMtx);
            g_clientPipe = hPipe;
        }
        g_clientConnected = true;
        g_missedBeats     = 0;
        g_lastBeat        = GetTickCount();

        if (cbs.onConnect) cbs.onConnect();

        // Read loop.
        while (true) {
            if (WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) goto cleanup;

            PipeHeader hdr{};
            DWORD read = 0;
            BOOL ok = ReadFile(hPipe, &hdr, sizeof(hdr), &read, nullptr);
            if (!ok || read != sizeof(hdr)) break;

            if (hdr.magic != PIPE_MAGIC || hdr.payloadLen > PIPE_MAX_PAYLOAD) continue;

            std::string payload(hdr.payloadLen, '\0');
            if (hdr.payloadLen > 0) {
                ok = ReadFile(hPipe, payload.data(), hdr.payloadLen, &read, nullptr);
                if (!ok || read != hdr.payloadLen) break;
            }

            if (Crc32(payload.data(), payload.size()) != hdr.crc32) continue;

            // Heartbeat tracking.
            if (payload.find("heartbeat") != std::string::npos) {
                g_missedBeats = 0;
                g_lastBeat    = GetTickCount();
            }

            if (cbs.onMessage) cbs.onMessage(payload);
        }

    cleanup:
        {
            std::lock_guard<std::mutex> lk(g_writeMtx);
            g_clientPipe = INVALID_HANDLE_VALUE;
        }
        g_clientConnected = false;
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        if (cbs.onDisconnect) cbs.onDisconnect();
    }
}

// ──────────────────── public API ────────────────────

bool Start(Callbacks cbs) {
    if (g_stopEvent) return false; // already running
    g_cbs       = cbs;
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) return false;
    g_serverThread = std::thread(ServerThread, cbs);
    return true;
}

void Stop() {
    if (g_stopEvent) {
        SetEvent(g_stopEvent);
        if (g_serverThread.joinable()) g_serverThread.join();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }
}

bool IsClientConnected() { return g_clientConnected; }

bool Send(const std::string& json) {
    std::lock_guard<std::mutex> lk(g_writeMtx);
    if (g_clientPipe == INVALID_HANDLE_VALUE) return false;
    return WriteFrame(g_clientPipe, json);
}

void ResetHeartbeat() {
    g_missedBeats = 0;
    g_lastBeat    = GetTickCount();
}

bool HeartbeatOk() {
    if (!g_clientConnected) return false;
    DWORD now = GetTickCount();
    DWORD last = g_lastBeat.load();
    if (now - last > static_cast<DWORD>(BEAT_INTERVAL_MS)) {
        int missed = ++g_missedBeats;
        g_lastBeat = now;
        return missed < MAX_MISSED_BEATS;
    }
    return true;
}

} // namespace PipeServer
