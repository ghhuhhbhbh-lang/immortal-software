#pragma once
#include <windows.h>
#include <cstdint>

namespace AntiDebug {

// Returns true if a debugger is detected (any method)
bool IsDebuggerAttached();

// Hardware breakpoint scan: checks Dr0-Dr3 on all threads
bool HardwareBreakpointsSet();

// RDTSC timing: returns true if slowdown detected (emulator/single-step)
bool TimingAnomalyDetected();

// NtQueryInformationProcess triple-check
bool NtDebugChecks();

// Check if parent process is a trusted launcher (explorer.exe, service host)
bool ParentIsSuspicious();

// Combined score: 0 = clean, higher = more suspicious
uint32_t DebugScore();

// Initialize: snapshots baseline timing
void Init();

} // namespace AntiDebug
