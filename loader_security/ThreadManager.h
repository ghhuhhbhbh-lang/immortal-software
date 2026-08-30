#pragma once
#include <windows.h>
#include <functional>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace Threads {

struct WorkerInfo {
    DWORD       threadId{};
    std::string purpose;
    HANDLE      hThread{ nullptr };
    HANDLE      cancelEvent{ nullptr };
    std::atomic<uint64_t> lastHeartbeat{ 0 };
    std::atomic<int>      crashCount{ 0 };
    std::atomic<ULONG_PTR> lastRip{ 0 };
    std::function<void(HANDLE cancelEvent)> fn;
    int  maxRestarts{ 3 };
    bool critical{ false };
};

class ThreadManager {
public:
    static ThreadManager& Instance();

    DWORD Launch(const char* purpose, std::function<void(HANDLE)> fn,
                 bool critical = false, int maxRestarts = 3);

    void Heartbeat(DWORD threadId);
    void Stop(DWORD threadId);
    void StopAll();
    void SetSessionInvalidCallback(std::function<void()> cb);
    bool AllHealthy() const;

    bool ContextAnomalyDetected();
    void StartContextMonitor();

private:
    ThreadManager() = default;
    void WatchdogLoop(HANDLE cancelEvent);
    void RestartWorker(WorkerInfo& w);
    void ContextMonitorLoop(HANDLE cancelEvent);

    mutable std::mutex               m_mutex;
    std::vector<WorkerInfo*>         m_workers;
    std::function<void()>            m_onSessionInvalid;
    HANDLE                           m_watchdogCancel{ nullptr };
    HANDLE                           m_ctxCancel{ nullptr };
    DWORD                            m_watchdogId{ 0 };
    DWORD                            m_ctxMonId{ 0 };
};

} // namespace Threads
