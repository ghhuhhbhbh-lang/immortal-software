#include "SelfDestruct.h"
#ifndef SHTDN_REASON_MAJOR_SECURITY
#define SHTDN_REASON_MAJOR_SECURITY 0x00050000
#endif
#ifndef SHTDN_REASON_MINOR_OTHER
#define SHTDN_REASON_MINOR_OTHER 0x00000000
#endif
#include <string>
#include <cstring>

namespace SelfDestruct {

// ──────────────────── privilege helper ────────────────────

static bool AcquirePrivilege(const wchar_t* privName) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, privName, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    bool ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}

// ──────────────────── self-delete ────────────────────

void ScheduleSelfDelete() {
    // Path of the running EXE.
    wchar_t selfPath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    // Phase 1: guaranteed on next reboot.
    MoveFileExW(selfPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

    // Phase 2: best-effort immediate deletion via cmd child.
    // cmd /c timeout /t 3 /nobreak >nul & del /f /q "<path>"
    wchar_t tmpDir[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmpDir);

    wchar_t batPath[MAX_PATH]{};
    swprintf_s(batPath, L"%s~isl_%08X.bat", tmpDir,
               static_cast<unsigned>(GetTickCount64() & 0xFFFFFFFF));

    // Write batch file.
    HANDLE hBat = CreateFileW(batPath, GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH,
                              nullptr);
    if (hBat != INVALID_HANDLE_VALUE) {
        // Convert wchar paths to narrow for the batch.
        char narrow[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, selfPath, -1, narrow, MAX_PATH, nullptr, nullptr);

        char bat[2048]{};
        _snprintf_s(bat, sizeof(bat), _TRUNCATE,
                    "@echo off\r\n"
                    "timeout /t 3 /nobreak >nul 2>&1\r\n"
                    "del /f /q \"%s\" >nul 2>&1\r\n"
                    "del /f /q \"%%~f0\" >nul 2>&1\r\n",
                    narrow);

        DWORD written = 0;
        WriteFile(hBat, bat, static_cast<DWORD>(strlen(bat)), &written, nullptr);
        CloseHandle(hBat);

        // Spawn detached.
        wchar_t cmdLine[MAX_PATH + 64]{};
        swprintf_s(cmdLine, L"cmd.exe /c \"%s\"", batPath);
        STARTUPINFOW si{sizeof(si)};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS,
                       nullptr, nullptr, &si, &pi);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread)  CloseHandle(pi.hThread);
    }
}

// ──────────────────── shutdown ────────────────────

bool ShutdownSystem() {
    if (!AcquirePrivilege(SE_SHUTDOWN_NAME)) return false;
    const UINT flags = EWX_SHUTDOWN | EWX_FORCE;
    const DWORD reason = SHTDN_REASON_MAJOR_SECURITY | SHTDN_REASON_MINOR_OTHER;
    return ExitWindowsEx(flags, reason) != 0;
}

// ──────────────────── combined ────────────────────

void NukeAndBurn(const char* /*reason*/) {
    ScheduleSelfDelete();
    if (!ShutdownSystem()) {
        // Shutdown failed (non-admin?) — at minimum kill the process.
        ExitProcess(0xDEADCAFE);
    }
    // If shutdown succeeded the OS will power off shortly;
    // but exit now so nothing else runs.
    ExitProcess(0xDEADCAFE);
}

void GracefulExit() {
    ExitProcess(0);
}

} // namespace SelfDestruct
