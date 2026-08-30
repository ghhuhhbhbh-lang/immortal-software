#pragma once
#include <windows.h>
#include <cstdint>

namespace AntiDebug {

void Init();
void StopMonitoring();

bool IsDebuggerAttached();
bool HardwareBreakpointsSet();
bool TimingAnomalyDetected();
bool NtDebugChecks();
bool NtDebugChecksAdvanced();
bool ParentIsSuspicious();
bool HypervisorDetected();
bool DebuggerProcessesRunning();
bool MemoryProtectionBypassed();
bool KernelDebuggerPresent();
bool PebBeingDebugged();
bool NtGlobalFlagSet();
bool HeapFlagsSuspicious();
bool CloseHandleExceptionTrick();
bool OutputDebugStringCaught();

// Combined score: 0 = clean, higher = more suspicious
uint32_t DebugScore();

// Soft anti-attach: hide thread from debugger (irreversible for that thread)
void HideCurrentThread();

} // namespace AntiDebug
