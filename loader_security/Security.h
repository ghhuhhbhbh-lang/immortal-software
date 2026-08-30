#pragma once

// ============================================================
//  Immortal Software — Master Security Configuration
//  Build: RELEASE_BUILD or DEV_BUILD via preprocessor define
// ============================================================

#define IMMORTAL_VERSION  "2.0.0"
#define IMMORTAL_BRAND    L"Immortal Software"

// ── Build mode detection ─────────────────────────────────────
#ifndef RELEASE_BUILD
#  ifdef NDEBUG
#    define RELEASE_BUILD 1
#  else
#    define DEV_BUILD 1
#  endif
#endif

#ifdef RELEASE_BUILD
#  pragma comment(linker, "/GUARD:CF")
#  pragma comment(linker, "/DYNAMICBASE")
#  pragma optimize("gs", on)
#endif

// ── Security feature toggles (all OFF in DEV_BUILD) ─────────
#ifdef RELEASE_BUILD
#  define SEC_INTEGRITY_CHECK       1
#  define SEC_ANTI_DEBUG            1
#  define SEC_ANTI_VM               1
#  define SEC_ANTI_INJECT           1
#  define SEC_ANTI_DUMP             1
#  define SEC_FAKE_AUTH             1
#  define SEC_THREAD_MANAGER        1
#  define SEC_ENCRYPTED_STRINGS     1
#  define SEC_GUARD_PAGES           1
#  define SEC_CONFIG_HMAC           1
#else
#  define SEC_INTEGRITY_CHECK       0
#  define SEC_ANTI_DEBUG            0
#  define SEC_ANTI_VM               0
#  define SEC_ANTI_INJECT           0
#  define SEC_ANTI_DUMP             0
#  define SEC_FAKE_AUTH             0
#  define SEC_THREAD_MANAGER        1   // on in dev too — good practice
#  define SEC_ENCRYPTED_STRINGS     0
#  define SEC_GUARD_PAGES           0
#  define SEC_CONFIG_HMAC           0
#endif

// ── Timing thresholds ────────────────────────────────────────
#define RDTSC_THRESHOLD_CYCLES      5'000'000ULL   // ~2ms at 3GHz
#define HEARTBEAT_INTERVAL_SEC      60
#define INTEGRITY_INTERVAL_SEC      300
#define WATCHDOG_PING_SEC           30
#define WORKER_TIMEOUT_SEC          90
#define TOKEN_MAX_LIFETIME_SEC      900             // 15 minutes
#define VM_CACHE_VALID_SEC          7200            // 2 hours
#define RATE_LIMIT_WINDOW_SEC       3600
#define RATE_LIMIT_MAX_ATTEMPTS     3

// ── API endpoint (encrypted at rest, decrypted on stack) ─────
#define API_HOST_ENC                "xbd}nji|~z)txx"  // XOR-0x11 of real host
#define API_PORT                    3000

// ── XOR key for string encryption (derived at build time) ─────
constexpr uint8_t STR_XOR_KEY      = 0x11;

// ── Forward declarations ─────────────────────────────────────
struct SecurityContext;

// ── Secure zero helper ───────────────────────────────────────
template<typename T>
inline void SecureErase(T& v) {
    volatile T* p = &v;
    *p = T{};
}

inline void SecureEraseBuffer(void* buf, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(buf);
    while (len--) *p++ = 0;
}

// ── Includes shared across modules ───────────────────────────
#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <array>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ntdll.lib")

// ── Sub-module headers ────────────────────────────────────────
#include "IntegrityManager.h"
#include "AntiDebug.h"
#include "AntiVM.h"
#include "AntiInject.h"
#include "FakeAuthEngine.h"
#include "ThreadManager.h"
#include "SecurityPolicy.h"
#include "SessionManager.h"
#include "CryptoUtils.h"
