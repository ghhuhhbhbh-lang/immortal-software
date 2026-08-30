#include "Honeypot.h"
#include <atomic>
#include <windows.h>

namespace Honeypot {

static std::atomic<bool> g_active{ false };

// xorshift32 PRNG seeded lazily.
static uint32_t NextRand() {
    static uint32_t s = 0;
    if (!s) s = GetTickCount() ^ 0xDEADBEEF;
    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
    return s;
}

static float RandF(float lo, float hi) {
    return lo + (hi - lo) * static_cast<float>(NextRand() & 0xFFFF) / 65535.f;
}

void Activate()   { g_active = true;  }
void Deactivate() { g_active = false; }
bool IsActive()   { return g_active;  }

void PerturbAimAngle(float& pitch, float& yaw) {
    if (!g_active) return;
    float sign = (NextRand() & 1) ? 1.f : -1.f;
    pitch += sign * RandF(0.5f, 4.0f);
    yaw   += sign * RandF(0.5f, 4.0f);
}

int PerturbTriggerDelay(int baseMs) {
    if (!g_active) return baseMs;
    int mult = 3 + static_cast<int>(NextRand() % 6); // 3-8×
    return baseMs * mult;
}

void PerturbEspBox(float& x, float& y, float& w, float& h) {
    if (!g_active) return;
    auto jitter = [](float v, float range) {
        return v + range * (static_cast<float>(Honeypot::IsActive()) *
               ((static_cast<float>(::GetTickCount() & 0xFF) / 127.5f) - 1.0f));
    };
    x += RandF(-6.f, 6.f);
    y += RandF(-4.f, 4.f);
    w += RandF(-3.f, 3.f);
    h += RandF(-3.f, 3.f);
    (void)jitter;
}

} // namespace Honeypot
