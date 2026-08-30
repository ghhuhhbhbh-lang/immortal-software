#pragma once
#include <cstdint>

namespace AntiDump {

// Snapshot + harden against PE dumps / MiniDumpWriteDump class tools
void Init();

// Zero DOS/NT headers in memory (after Init baselines are taken)
void ErasePEHeaders();

// Deny PROCESS_VM_READ / PROCESS_DUP_HANDLE via DACL where possible
bool HardenProcessAccess();

// Detect common dump / memory-tool process names
bool DumpToolsPresent();

// Query ProcessDebugObject / BreakOnTermination style dump signals
bool DumpRelatedDebugArtifacts();

uint32_t DumpRiskScore();

} // namespace AntiDump
