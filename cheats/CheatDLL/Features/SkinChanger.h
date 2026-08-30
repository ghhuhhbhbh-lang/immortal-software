#pragma once
#include "CommonTypes.h"

namespace SkinChanger {
    void Init(FeatureConfig* cfg);
    void Apply();   // call on item equip events
    void Shutdown();
}
