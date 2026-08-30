#include "InjectionEngine.h"
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>

// NtCreateThreadEx typedefs (undocumented, used as fallback).
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

namespace InjectionEngine {

// ──────────────────────────── helpers ────────────────────────────

static HMODULE SafeGetModule(const wchar_t* name) {
    return GetModuleHandleW(name);
}

// RAII process handle.
struct ProcHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit ProcHandle(DWORD pid, DWORD access)
        : h(OpenProcess(access, FALSE, pid)) {}
    ~ProcHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() const { return h; }
    bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
};

// Remote-thread injection — tries CreateRemoteThread, then NtCreateThreadEx.
static bool RemoteLoadLibrary(HANDLE hProc, const std::wstring& dllPath) {
    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);

    void* remoteMem = VirtualAllocEx(hProc, nullptr, pathBytes,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    auto freeRemote = [&] { VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE); };

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, dllPath.c_str(), pathBytes, &written)
        || written != pathBytes) {
        freeRemote();
        return false;
    }

    HMODULE hKernel = SafeGetModule(L"kernel32.dll");
    auto pLoadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(hKernel, "LoadLibraryW"));

    // Primary path: CreateRemoteThread.
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLib, remoteMem, 0, nullptr);
    if (!hThread) {
        // Fallback: NtCreateThreadEx (works on some anti-cheat setups).
        HMODULE hNtdll = SafeGetModule(L"ntdll.dll");
        auto pNtCTE = reinterpret_cast<pfnNtCreateThreadEx>(
            GetProcAddress(hNtdll, "NtCreateThreadEx"));
        if (pNtCTE) {
            NTSTATUS status = pNtCTE(&hThread, THREAD_ALL_ACCESS, nullptr,
                                     hProc, pLoadLib, remoteMem,
                                     0, 0, 0, 0, nullptr);
            if (status != 0 || !hThread) { freeRemote(); return false; }
        } else {
            freeRemote();
            return false;
        }
    }

    WaitForSingleObject(hThread, 8000);
    CloseHandle(hThread);
    freeRemote();
    return true;
}

// Write buffer to a temp file; returns path. Caller deletes after inject.
static std::wstring WriteTempDll(const void* data, size_t size) {
    wchar_t tmpDir[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmpDir);

    wchar_t tmpFile[MAX_PATH]{};
    // Use a non-obvious name.
    swprintf_s(tmpFile, L"%s%08X.tmp", tmpDir, GetTickCount());

    HANDLE h = CreateFileW(tmpFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    DWORD written = 0;
    WriteFile(h, data, static_cast<DWORD>(size), &written, nullptr);
    CloseHandle(h);

    if (written != static_cast<DWORD>(size)) {
        DeleteFileW(tmpFile);
        return {};
    }
    return tmpFile;
}

// Overwrite file contents with zeros then delete — rudimentary wipe.
static void SecureDeleteFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz{};
        GetFileSizeEx(h, &sz);
        if (sz.QuadPart > 0 && sz.QuadPart < 32 * 1024 * 1024) {
            std::vector<char> zeros(static_cast<size_t>(sz.QuadPart), 0);
            DWORD w = 0;
            SetFilePointer(h, 0, nullptr, FILE_BEGIN);
            WriteFile(h, zeros.data(), static_cast<DWORD>(zeros.size()), &w, nullptr);
        }
        CloseHandle(h);
    }
    DeleteFileW(path.c_str());
}

// ──────────────────────────── public API ────────────────────────────

DWORD FindGamePid(const wchar_t* processName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

Result InjectFromPath(DWORD pid, const std::wstring& dllPath) {
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        return Result::DllNotFound;

    ProcHandle hProc(pid, PROCESS_ALL_ACCESS);
    if (!hProc.valid()) return Result::OpenFailed;

    return RemoteLoadLibrary(hProc, dllPath) ? Result::Ok : Result::RemoteThreadFailed;
}

Result InjectFromMemory(DWORD pid, const void* dllData, size_t dllSize) {
    if (!dllData || dllSize == 0) return Result::DllNotFound;

    std::wstring tmp = WriteTempDll(dllData, dllSize);
    if (tmp.empty()) return Result::WriteFailed;

    ProcHandle hProc(pid, PROCESS_ALL_ACCESS);
    if (!hProc.valid()) {
        SecureDeleteFile(tmp);
        return Result::OpenFailed;
    }

    bool ok = RemoteLoadLibrary(hProc, tmp);
    // Give LoadLibraryW a moment before wiping the file.
    Sleep(500);
    SecureDeleteFile(tmp);

    return ok ? Result::Ok : Result::RemoteThreadFailed;
}

Result InjectEmbedded(DWORD pid) {
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(100), RT_RCDATA);
    if (!hRes) return Result::ResourceLoadFailed;

    HGLOBAL hGlob = LoadResource(nullptr, hRes);
    if (!hGlob) return Result::ResourceLoadFailed;

    void* data = LockResource(hGlob);
    DWORD size = SizeofResource(nullptr, hRes);
    if (!data || size == 0) return Result::ResourceLoadFailed;

    return InjectFromMemory(pid, data, size);
}

const char* ResultString(Result r) {
    switch (r) {
    case Result::Ok:                 return "Ok";
    case Result::ProcessNotFound:    return "ProcessNotFound";
    case Result::OpenFailed:         return "OpenFailed";
    case Result::AllocFailed:        return "AllocFailed";
    case Result::WriteFailed:        return "WriteFailed";
    case Result::RemoteThreadFailed: return "RemoteThreadFailed";
    case Result::DllNotFound:        return "DllNotFound";
    case Result::ResourceLoadFailed: return "ResourceLoadFailed";
    default:                         return "Unknown";
    }
}

} // namespace InjectionEngine
