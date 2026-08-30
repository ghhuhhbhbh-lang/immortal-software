#pragma once
#include <string>
#include <cstdint>

// Sends rich embeds to a Discord webhook for CRITICAL / HIGH security events.
// Webhook URL is read from (first match wins):
//   1. Environment variable  IMMORTAL_DISCORD_WEBHOOK
//   2. %APPDATA%\ImmortalSoftware\webhook.url  (plain text, one line)
// If neither is set, SendAlert is a no-op (non-fatal).
//
// All sends are fire-and-forget (detached thread) — they must not block
// the security response path.
namespace DiscordWebhook {

struct Alert {
    const char* eventType;   // e.g. "SECURITY_CODE_PATCH_DETECTED"
    const char* severity;    // "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
    const char* reason;      // human-readable reason
    const char* loaderVersion;
    const char* licenseHash; // first 8 chars of SHA-256(key)
    const char* fingerprint; // first 16 chars of device SHA-256
    const char* action;      // e.g. "LICENSE REVOKED + SHUTDOWN"
    const char* timestamp;   // ISO 8601
};

// Send a rich embed to the configured webhook.
// Returns immediately — send happens on a detached thread.
void SendAlert(const Alert& alert);

// Load the webhook URL (cached after first call).
std::string GetWebhookUrl();

} // namespace DiscordWebhook
