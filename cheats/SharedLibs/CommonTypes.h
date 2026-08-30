#pragma once
// SharedLibs/CommonTypes.h — IPC protocol shared between Loader and CheatDLL.
// Include this on both sides. No external dependencies.
#include <cstdint>
#include <string>

// ── Pipe name ──────────────────────────────────────────────────────────────────
#define IMMORTAL_PIPE_NAME  L"\\\\.\\pipe\\CheatPipe"

// ── Wire format ────────────────────────────────────────────────────────────────
constexpr uint32_t PIPE_MAGIC   = 0x494D4C54; // "IMLT"
constexpr uint8_t  PIPE_VERSION = 1;
constexpr uint32_t PIPE_MAX_PAYLOAD = 4096;

#pragma pack(push, 1)
struct PipeHeader {
    uint32_t magic;       // PIPE_MAGIC
    uint8_t  version;     // PIPE_VERSION
    uint8_t  type;        // HostCmd or DllEvent (cast from enum)
    uint16_t reserved;
    uint32_t payloadLen;  // bytes after header (JSON payload)
    uint32_t crc32;       // CRC32 of the payload only
};
#pragma pack(pop)

// ── Commands: Loader → DLL ─────────────────────────────────────────────────────
enum class HostCmd : uint8_t {
    Ping        = 0x01,
    SetToken    = 0x02,
    Verify      = 0x03,
    UpdateConfig= 0x04,
    Shutdown    = 0x05,
};

// ── Events: DLL → Loader ──────────────────────────────────────────────────────
enum class DllEvent : uint8_t {
    Heartbeat     = 0x10,
    FeatureStatus = 0x11,
    ThreatAlert   = 0x12,
    Log           = 0x13,
};

// ── Feature configuration (sent via UpdateConfig) ──────────────────────────────
struct FeatureConfig {
    // Aimbot
    bool  aimbotEnabled    = false;
    float aimbotFov        = 5.0f;
    float aimbotSmooth     = 8.0f;
    int   aimbotBone       = 6;   // head
    bool  aimbotVisCheck   = true;

    // ESP
    bool  espEnabled       = false;
    bool  espBoxes         = true;
    bool  espHealth        = true;
    bool  espDistance      = true;
    bool  espTeamCheck     = true;

    // TriggerBot
    bool  triggerEnabled   = false;
    int   triggerDelayMs   = 80;

    // SkinChanger
    bool  skinEnabled      = false;
    int   skinModelIndex   = 0;

    // Misc
    int   menuKey          = 0x2D; // INSERT
};

// ── Error codes ────────────────────────────────────────────────────────────────
enum class ImmortalError : uint32_t {
    Ok              = 0,
    PipeTimeout     = 1,
    TokenInvalid    = 2,
    DebugDetected   = 3,
    GameNotRunning  = 4,
    DllNotLoaded    = 5,
    NetworkError    = 6,
    HashMismatch    = 7,
};

inline const char* ErrorString(ImmortalError e) {
    switch (e) {
        case ImmortalError::Ok:             return "OK";
        case ImmortalError::PipeTimeout:    return "Pipe timeout";
        case ImmortalError::TokenInvalid:   return "Token invalid";
        case ImmortalError::DebugDetected:  return "Debugger detected";
        case ImmortalError::GameNotRunning: return "Game not running";
        case ImmortalError::DllNotLoaded:   return "DLL not loaded";
        case ImmortalError::NetworkError:   return "Network error";
        case ImmortalError::HashMismatch:   return "Hash mismatch";
        default:                            return "Unknown";
    }
}
