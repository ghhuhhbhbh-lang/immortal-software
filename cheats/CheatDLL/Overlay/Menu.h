#pragma once
#include "CommonTypes.h"

// ImGui menu overlay — rendered via DirectX 11 hook.
namespace Menu {
    void Init(FeatureConfig* cfg);
    void Render();    // called each Present hook
    void Shutdown();
    bool IsOpen();
    void Toggle();
}
