#pragma once
#include <cstdint>
#include <string>

namespace AntiVM {

struct VMSignals {
    bool cpuidHypervisor;       // CPUID bit 31 of ECX
    bool smbiosSuspicious;      // VMware/VirtualBox/QEMU in SMBIOS
    bool suspiciousDrivers;     // vboxguest, vmci, xen, etc.
    bool lowUptimeMinutes;      // uptime < 30 minutes
    bool smallRamMB;            // < 2048 MB total RAM
    bool sandboxUsername;       // "SANDBOX", "MALWARE", "VIRUS", etc.
    uint32_t uptimeMinutes;
    uint32_t ramMB;
    std::wstring manufacturer;
};

// Collect all VM/sandbox indicators
VMSignals Collect();

// Compute 0-100 risk score from signals
uint32_t RiskScore(const VMSignals& sig);

// High-level: collect + score
uint32_t GetRiskScore();

// Cache management: load/save last known score (valid VM_CACHE_VALID_SEC)
void     SaveCachedScore(uint32_t score);
bool     LoadCachedScore(uint32_t& outScore);  // returns false if stale/absent

} // namespace AntiVM
