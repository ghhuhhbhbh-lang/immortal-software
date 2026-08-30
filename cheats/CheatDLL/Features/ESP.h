#pragma once
#include "CommonTypes.h"

namespace ESP {
    void Init(FeatureConfig* cfg);
    void Render();  // call each render frame when enabled
    void Shutdown();
}
