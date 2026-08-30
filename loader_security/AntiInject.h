#pragma once
#include <windows.h>
#include <cstdint>

namespace AntiInject {

// Start background hook-scan thread (checks every 30s)
void StartHookScanner();
void StopHookScanner();

// Scan first 16 bytes of a target function for inline hook signatures
bool FunctionHooked(FARPROC fn, const char* name);

// Scan all critical WinAPI functions; returns count of hooked ones
uint32_t ScanAllCritical();

// Dynamic import: resolve API by XOR-hashed name (defeats IAT scanners)
FARPROC ResolveAPI(HMODULE mod, uint32_t xorHash);

// Place guard pages around a buffer; returns true on success
bool SetGuardPage(void* buf, size_t size);

// Allocate W^X compliant executable region:
// 1. Alloc RW, 2. Copy code, 3. Switch to RX, 4. Return ptr
void* AllocExecutable(const void* code, size_t size);
void  FreeExecutable(void* ptr, size_t size);

// Enforce W^X: change a region to NOACCESS after use
void LockRegion(void* ptr, size_t size);

} // namespace AntiInject
