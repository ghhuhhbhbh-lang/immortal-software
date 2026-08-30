#pragma once
#include <cstdint>
#include <functional>

namespace Policy {

enum class FailMode { HARD_EXIT, SOFT_HONEYPOT, LOG_ONLY };

struct ThreatEvent {
    const char* source;   // "INTEGRITY", "ANTI_DEBUG", "ANTI_VM", "HOOK", etc.
    const char* detail;
    uint32_t    severity; // 0-10
};

// Central threat handler — routes to correct fail mode
void HandleThreat(const ThreatEvent& ev);

// Register a callback to send events to the server
void SetAuditCallback(std::function<void(const ThreatEvent&)> cb);

// Startup: run full security gauntlet
// Returns true = clean environment, false = threat detected (honeypot activated)
bool RunStartupChecks();

// Called at exit: zero all secrets, clear credential cache
void Shutdown();

// Register atexit handler for Shutdown()
void RegisterExitHandlers();

} // namespace Policy
