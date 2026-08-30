// Feature stubs — wire real implementations later; keeps Release link clean.
#include "Features/Aimbot.h"
#include "Features/ESP.h"
#include "Features/TriggerBot.h"
#include "Features/SkinChanger.h"
#include "Overlay/Menu.h"
#include "Overlay/ThemeConfig.h"

namespace Aimbot {
    static FeatureConfig* g_cfg = nullptr;
    void Init(FeatureConfig* cfg) { g_cfg = cfg; }
    void Tick() {}
    void Shutdown() { g_cfg = nullptr; }
    void PerturbAngles(float&, float&) {}
}

namespace ESP {
    static FeatureConfig* g_cfg = nullptr;
    void Init(FeatureConfig* cfg) { g_cfg = cfg; }
    void Render() {}
    void Shutdown() { g_cfg = nullptr; }
}

namespace TriggerBot {
    static FeatureConfig* g_cfg = nullptr;
    void Init(FeatureConfig* cfg) { g_cfg = cfg; }
    void Tick() {}
    void Shutdown() { g_cfg = nullptr; }
}

namespace SkinChanger {
    static FeatureConfig* g_cfg = nullptr;
    void Init(FeatureConfig* cfg) { g_cfg = cfg; }
    void Apply() {}
    void Shutdown() { g_cfg = nullptr; }
}

namespace Menu {
    static FeatureConfig* g_cfg = nullptr;
    static bool g_open = false;
    void Init(FeatureConfig* cfg) { g_cfg = cfg; g_open = false; }
    void Render() {}
    void Shutdown() { g_cfg = nullptr; g_open = false; }
    bool IsOpen() { return g_open; }
    void Toggle() { g_open = !g_open; }
}

namespace Theme {
    void Apply() {}
    bool BeginFrame(bool menuOpen, float& outAlpha, float& outScale) {
        outAlpha = menuOpen ? 1.f : 0.f;
        outScale = menuOpen ? 1.f : 0.95f;
        return menuOpen;
    }
}
