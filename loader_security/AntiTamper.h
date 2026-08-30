#pragma once
#include <cstdint>

namespace AntiTamper {

void Init();

// Hash critical IAT / export stubs we care about
bool SnapshotCriticalApis();
bool VerifyCriticalApis();

// Detect remapped / writable executable pages in our image
bool ExecutableWritablePages();

// Detect LDR module list anomalies (manual mapped / unlinked modules)
bool LdrAnomalies();

uint32_t TamperScore();

} // namespace AntiTamper
