#pragma once
#include <windows.h>
#include <string>

namespace InjectionEngine {

enum class Result {
    Ok,
    ProcessNotFound,
    OpenFailed,
    AllocFailed,
    WriteFailed,
    RemoteThreadFailed,
    DllNotFound,
    ResourceLoadFailed,
};

// Inject from a path on disk.
Result InjectFromPath(DWORD pid, const std::wstring& dllPath);

// Inject directly from a memory buffer (embedded RCDATA).
// The engine writes the DLL to a temp file, injects, then erases the temp file.
Result InjectFromMemory(DWORD pid, const void* dllData, size_t dllSize);

// Load CheatDLL.dll from RCDATA resource 100 and inject into pid.
Result InjectEmbedded(DWORD pid);

// Returns the PID of cs2.exe (or 0 if not running).
DWORD FindGamePid(const wchar_t* processName = L"cs2.exe");

const char* ResultString(Result r);

} // namespace InjectionEngine
