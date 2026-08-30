#pragma once
#include <cstdint>

namespace AntiTerminate {

void Init();
void Shutdown();

// Restrict who can terminate / suspend this process
bool HardenAgainstTermination();

// Detect if our threads are being mass-suspended (debugger/suspend attach)
bool MassSuspendDetected();

// Detect foreign OpenProcess with dangerous access masks via periodic self-check
bool SuspiciousHandleActivity();

uint32_t TerminateRiskScore();

} // namespace AntiTerminate
