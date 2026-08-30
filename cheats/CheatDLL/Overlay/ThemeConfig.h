#pragma once
// Design tokens matching the Loader UI.
// Include ImGui headers before this file.

namespace Theme {

// ── Colour palette ─────────────────────────────────────────────────────────────
static constexpr float kBg[4]           = { 0.043f, 0.043f, 0.055f, 0.96f }; // #0B0B0E
static constexpr float kPanel[4]        = { 0.078f, 0.078f, 0.118f, 0.85f }; // glass panel
static constexpr float kAccent[4]       = { 0.545f, 0.361f, 0.965f, 1.00f }; // #8B5CF6
static constexpr float kAccentHov[4]    = { 0.655f, 0.545f, 0.980f, 1.00f }; // #A78BFA
static constexpr float kAccentActive[4] = { 0.420f, 0.255f, 0.820f, 1.00f };
static constexpr float kText[4]         = { 0.945f, 0.961f, 0.980f, 1.00f }; // #F1F5F9
static constexpr float kTextDim[4]      = { 0.600f, 0.620f, 0.680f, 1.00f };
static constexpr float kBorder[4]       = { 0.545f, 0.361f, 0.965f, 0.20f };
static constexpr float kDanger[4]       = { 0.800f, 0.220f, 0.220f, 1.00f };
static constexpr float kSuccess[4]      = { 0.220f, 0.800f, 0.420f, 1.00f };

// Apply to ImGuiStyle — call once after ImGui::CreateContext().
void Apply();

// Per-frame animation gate. Call at the top of your render loop.
// Returns false while the menu is fully closed (skip rendering).
// outAlpha / outScale are the current animation values.
bool BeginFrame(bool menuOpen, float& outAlpha, float& outScale);

} // namespace Theme
