#pragma once
#include "CommonTypes.h"

namespace Aimbot {
    void Init(FeatureConfig* cfg);
    void Tick();   // call every game frame when enabled
    void Shutdown();

    // Perturb angles if honeypot is active.
    void PerturbAngles(float& pitch, float& yaw);
}
