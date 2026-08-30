#pragma once

// Honeypot mode — silently degrades features instead of crashing.
// Activated on: debug detection, invalid token, failed pipe auth.
namespace Honeypot {
    void Activate();
    void Deactivate();
    bool IsActive();

    // Feature perturbations (apply only when IsActive()).
    void PerturbAimAngle(float& pitch, float& yaw);   // ±4° random offset
    int  PerturbTriggerDelay(int baseMs);              // 3-8× multiplier
    void PerturbEspBox(float& x, float& y, float& w, float& h); // ±jitter
}
