#pragma once
#include <cstdint>

namespace AntiDebug {

struct Report {
    uint32_t score  = 0; // ≥18 → honeypot
    bool pebFlag    = false;
    bool heapFlag   = false;
    bool parentPid  = false;
    bool rdtsc      = false;
    bool hwBreakpt  = false;
    bool remoteDbg  = false;
};

Report Scan();
bool   Detected(uint32_t threshold = 18);

} // namespace AntiDebug
