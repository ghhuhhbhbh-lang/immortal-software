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
    DWORD       threadId;
    std::string purpose;
    HANDLE      hThread;
    HANDLE      cancelEvent;
    std::atomic<uint64_t> lastHeartbeat;
    std::atomic<int>      crashCount;
    std::function<void(HANDLE cancelEvent)> fn;
    int  maxRestarts{ 3 };
    bool critical{ false };  // if true, crash = session invalidated
};

class ThreadManager {
public:
    static ThreadManager& Instance();

    // Register and launch a worker thread
    // fn receives a cancelEvent; it must monitor it and return when signaled
    DWORD Launch(const char* purpose, std::function<void(HANDLE)> fn,
                 bool critical = false, int maxRestarts = 3);

    // Worker must call this every ~10s to signal health
    void Heartbeat(DWORD threadId);

    // Request graceful stop of a worker
    void Stop(DWORD threadId);

    // Stop all workers (call before process exit)
    void StopAll();

    // Called by watchdog on session invalidation
    void SetSessionInvalidCallback(std::function<void()> cb);

    // Returns true if all workers are healthy
    bool AllHealthy() const;

private:
    ThreadManager() = default;
    void WatchdogLoop(HANDLE cancelEvent);
    void RestartWorker(WorkerInfo& w);

    mutable std::mutex               m_mutex;
    std::vector<WorkerInfo*>         m_workers;
    std::function<void()>            m_onSessionInvalid;
    HANDLE                           m_watchdogCancel{ nullptr };
    DWORD                            m_watchdogId{ 0 };
};

} // namespace Threads
