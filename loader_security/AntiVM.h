#pragma once
#include <cstdint>
#include <string>

namespace AntiVM {

// Enhanced CPUID analysis structure
struct CPUIDSignals {
    bool cpuidHypervisor = false;        // CPUID bit 31 of ECX
    bool vm_brand_detected = false;      // VM signature in processor brand
    uint32_t extended_cpuid_limit = 0;   // Maximum extended CPUID function
};

// Comprehensive VM detection signals
struct VMSignals {
    CPUIDSignals cpuid_signals;         // Enhanced CPUID analysis
    bool smbiosSuspicious = false;      // VMware/VirtualBox/QEMU in SMBIOS
    bool suspiciousDrivers = false;     // vboxguest, vmci, xen, etc.
    bool lowUptimeMinutes = false;      // uptime < 30 minutes
    bool smallRamMB = false;            // < 2048 MB total RAM
    bool sandboxUsername = false;       // "SANDBOX", "MALWARE", "VIRUS", etc.
    bool wmi_artifacts = false;         // WMI-based VM detection
    bool mac_addresses_suspicious = false; // Known VM MAC prefixes
    bool registry_artifacts = false;    // VM-related registry keys
    uint32_t uptimeMinutes = 0;
    uint32_t ramMB = 0;
    std::wstring manufacturer;
    
    // Legacy compatibility
    bool cpuidHypervisor() const { return cpuid_signals.cpuidHypervisor; }
};

// Machine learning behavior profile
struct BehaviorProfile {
    double cpu_timing_variance = 0.0;
    double memory_access_pattern = 0.0;
    double network_latency_profile = 0.0;
    int hardware_quirks_score = 0;
    double entropy_score = 0.0;
    bool has_vm_artifacts = false;
};

// Collect all VM/sandbox indicators with enhanced analysis
VMSignals Collect();

// ML-based risk scoring (0-100) from signals
uint32_t RiskScore(const VMSignals& sig);

// High-level: collect + score
uint32_t GetRiskScore();

// Advanced behavioral analysis
BehaviorProfile AnalyzeBehavior();

// Cache management: load/save last known score (valid VM_CACHE_VALID_SEC)
void SaveCachedScore(uint32_t score);
bool LoadCachedScore(uint32_t& outScore);  // returns false if stale/absent

// Initialize ML weights and calibration
void InitializeMLModel();

// Real-time VM detection monitoring
void StartVMMonitoring();
void StopVMMonitoring();
bool IsVMMonitoringActive();

// Advanced detection methods
bool DetectNestedVirtualization();
bool DetectContainerEnvironment();
bool DetectCloudEnvironment();

} // namespace AntiVM
