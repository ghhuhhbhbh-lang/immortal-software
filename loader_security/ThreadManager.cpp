#include "ThreadManager.h"
#include <algorithm>
#include <chrono>

namespace Threads {

static uint64_t NowSec() {
    return static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count() / 1'000'000'000LL);
}

ThreadManager& ThreadManager::Instance() {
    static ThreadManager inst;
    return inst;
}

static DWORD WINAPI WorkerThunk(LPVOID param) {
    auto* w = static_cast<WorkerInfo*>(param);
    w->lastHeartbeat = NowSec();
    try { w->fn(w->cancelEvent); }
    catch (...) {}
    return 0;
}

DWORD ThreadManager::Launch(const char* purpose, std::function<void(HANDLE)> fn,
                             bool critical, int maxRestarts) {
    auto* w = new WorkerInfo{};
    w->purpose     = purpose;
    w->fn          = fn;
    w->maxRestarts = maxRestarts;
    w->critical    = critical;
    w->cancelEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    w->crashCount  = 0;
    w->lastHeartbeat = NowSec();
    w->hThread = CreateThread(nullptr, 0, WorkerThunk, w, 0, &w->threadId);

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_workers.push_back(w);

        // Start watchdog on first launch
        if (!m_watchdogId) {
            HANDLE wdCancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            m_watchdogCancel = wdCancel;
            auto* self = this;
            CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                auto* pair = static_cast<std::pair<ThreadManager*, HANDLE>*>(p);
                pair->first->WatchdogLoop(pair->second);
                delete pair;
                return 0;
            }, new std::pair<ThreadManager*, HANDLE>(self, wdCancel), 0, &m_watchdogId);
        }
    }
    return w->threadId;
}

void ThreadManager::Heartbeat(DWORD threadId) {
    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto* w : m_workers)
        if (w->threadId == threadId) { w->lastHeartbeat = NowSec(); break; }
}

void ThreadManager::Stop(DWORD threadId) {
    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto* w : m_workers) {
        if (w->threadId == threadId) {
            SetEvent(w->cancelEvent);
            break;
        }
    }
}

void ThreadManager::StopAll() {
    std::lock_guard<std::mutex> lk(m_mutex);
    if (m_watchdogCancel) { SetEvent(m_watchdogCancel); }
    for (auto* w : m_workers) SetEvent(w->cancelEvent);
    // Give workers 5s to clean up
    for (auto* w : m_workers) {
        WaitForSingleObject(w->hThread, 5000);
        CloseHandle(w->hThread);
        CloseHandle(w->cancelEvent);
        delete w;
    }
    m_workers.clear();
}

void ThreadManager::SetSessionInvalidCallback(std::function<void()> cb) {
    m_onSessionInvalid = cb;
}

bool ThreadManager::AllHealthy() const {
    uint64_t now = NowSec();
    std::lock_guard<std::mutex> lk(m_mutex);
    for (const auto* w : m_workers) {
        if (now - w->lastHeartbeat.load() > WORKER_TIMEOUT_SEC) return false;
    }
    return true;
}

void ThreadManager::WatchdogLoop(HANDLE cancelEvent) {
    while (WaitForSingleObject(cancelEvent, WATCHDOG_PING_SEC * 1000) == WAIT_TIMEOUT) {
        uint64_t now = NowSec();
        std::vector<WorkerInfo*> hung;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            for (auto* w : m_workers) {
                if (now - w->lastHeartbeat.load() > WORKER_TIMEOUT_SEC)
                    hung.push_back(w);
            }
        }
        for (auto* w : hung) {
            // 1. Signal cancel
            SetEvent(w->cancelEvent);
            // 2. Wait 5s
            if (WaitForSingleObject(w->hThread, 5000) == WAIT_TIMEOUT) {
                // 3. Worker refused to stop — session invalid, safe exit
                if (m_onSessionInvalid) m_onSessionInvalid();
                ExitProcess(0xDEAD);
            }
            // 4. Restart if under limit
            w->crashCount++;
            if (w->crashCount <= w->maxRestarts) {
                RestartWorker(*w);
            } else {
                if (w->critical && m_onSessionInvalid) m_onSessionInvalid();
            }
        }
    }
}

void ThreadManager::RestartWorker(WorkerInfo& w) {
    CloseHandle(w.hThread);
    ResetEvent(w.cancelEvent);
    w.lastHeartbeat = NowSec();
    w.hThread = CreateThread(nullptr, 0, WorkerThunk, &w, 0, &w.threadId);
}

} // namespace Threads
