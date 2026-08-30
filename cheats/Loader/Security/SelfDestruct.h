#pragma once
#include <windows.h>
#include <string>

// SelfDestruct — graceful incident response for critical security breaches.
// Implements: system shutdown (via SeShutdownPrivilege), self-delete of the
// loader EXE (both reboot-time and best-effort immediate), and a combined
// "nuke" path that revokes, deletes, then shuts down.
//
// IMPORTANT: No kernel hooks, no file destruction beyond the loader EXE itself.
// All paths call ExitProcess — never NtRaiseHardError or BSODs.
namespace SelfDestruct {

// Schedule the running EXE for deletion. Two-phase:
//   1. MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT (guaranteed on next boot)
//   2. Spawn cmd.exe child that waits 3 s then calls del (best-effort now)
// Does not crash the process — caller should call ExitProcess afterward.
void ScheduleSelfDelete();

// Acquire SeShutdownPrivilege and call ExitWindowsEx(EWX_SHUTDOWN|EWX_FORCE).
// Returns false if privilege elevation fails (e.g. running without admin rights);
// in that case the caller should fall back to just ScheduleSelfDelete + ExitProcess.
bool ShutdownSystem();

// Full incident response:
//   1. Schedule self-delete of the EXE
//   2. Attempt system shutdown (best-effort)
//   3. ExitProcess(0xDEADCAFE) if shutdown was denied
void NukeAndBurn(const char* reason);

// Graceful terminate — no self-delete, no shutdown.
// Zeroes sensitive memory then calls ExitProcess(0).
void GracefulExit();

} // namespace SelfDestruct
