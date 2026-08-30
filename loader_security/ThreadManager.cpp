#include "ThreadManager.h"
#include "Security.h"
#include <intrin.h>
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
#if defined(_M_X64) || defined(__x86_64__)
    w->lastRip = reinterpret_cast<ULONG_PTR>(_ReturnAddress());
#endif
    try { w->fn(w->cancelEvent); }
    catch (...) {}
    return 0;
}

DWORD ThreadManager::Launch(const char* purpose, std::function<void(HANDLE)> fn,
                             bool critical, int maxRestarts) {
    auto* w = new WorkerInfo{};
    w->purpose     = purpose ? purpose : "worker";
    w->fn          = std::move(fn);
    w->maxRestarts = maxRestarts;
    w->critical    = critical;
    w->cancelEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    w->crashCount  = 0;
    w->lastHeartbeat = NowSec();
    w->hThread = CreateThread(nullptr, 0, WorkerThunk, w, 0, &w->threadId);

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_workers.push_back(w);

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
    if (m_watchdogCancel) SetEvent(m_watchdogCancel);
    if (m_ctxCancel) SetEvent(m_ctxCancel);
    for (auto* w : m_workers) SetEvent(w->cancelEvent);
    for (auto* w : m_workers) {
        WaitForSingleObject(w->hThread, 5000);
        CloseHandle(w->hThread);
        CloseHandle(w->cancelEvent);
        delete w;
    }
    m_workers.clear();
}

void ThreadManager::SetSessionInvalidCallback(std::function<void()> cb) {
    m_onSessionInvalid = std::move(cb);
}

bool ThreadManager::AllHealthy() const {
    uint64_t now = NowSec();
    std::lock_guard<std::mutex> lk(m_mutex);
    for (const auto* w : m_workers) {
        if (now - w->lastHeartbeat.load() > WORKER_TIMEOUT_SEC) return false;
    }
    return true;
}

bool ThreadManager::ContextAnomalyDetected() {
    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto* w : m_workers) {
        if (!w->hThread) continue;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        // Avoid suspending critical UI; only sample if we can suspend briefly
        DWORD prev = SuspendThread(w->hThread);
        if (prev == static_cast<DWORD>(-1)) continue;
        bool bad = false;
        if (GetThreadContext(w->hThread, &ctx)) {
#if defined(_M_X64) || defined(__x86_64__)
            ULONG_PTR rip = ctx.Rip;
#else
            ULONG_PTR rip = ctx.Eip;
#endif
            w->lastRip = rip;
            if (rip == 0) bad = true;
        }
        ResumeThread(w->hThread);
        if (bad && w->critical) return true;
    }
    return false;
}

void ThreadManager::StartContextMonitor() {
#if !SEC_THREAD_CONTEXT_MON
    return;
#endif
    if (m_ctxMonId) return;
    m_ctxCancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto* self = this;
    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* pair = static_cast<std::pair<ThreadManager*, HANDLE>*>(p);
        pair->first->ContextMonitorLoop(pair->second);
        delete pair;
        return 0;
    }, new std::pair<ThreadManager*, HANDLE>(self, m_ctxCancel), 0, &m_ctxMonId);
}

void ThreadManager::ContextMonitorLoop(HANDLE cancelEvent) {
    while (WaitForSingleObject(cancelEvent, 15000) == WAIT_TIMEOUT) {
        if (ContextAnomalyDetected()) {
            Policy::HandleThreat({ "THREAD_CTX", "Critical worker context anomaly", 8 });
        }
        // Also ensure heartbeats aren't silently frozen across all workers
        if (!AllHealthy()) {
            Policy::HandleThreat({ "THREAD_WD", "Worker heartbeat timeout", 7 });
        }
    }
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
            SetEvent(w->cancelEvent);
            if (WaitForSingleObject(w->hThread, 5000) == WAIT_TIMEOUT) {
                if (m_onSessionInvalid) m_onSessionInvalid();
                ExitProcess(0xDEAD);
            }
            w->crashCount++;
            if (w->crashCount <= w->maxRestarts) {
                RestartWorker(*w);
            } else if (w->critical && m_onSessionInvalid) {
                m_onSessionInvalid();
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
