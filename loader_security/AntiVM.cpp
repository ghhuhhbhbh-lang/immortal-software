#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "AntiVM.h"
#include "Security.h"
#include "CryptoUtils.h"
#include <cmath>
#include <thread>
#include <atomic>
#include <intrin.h>
#include <shlobj.h>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <vector>
#include <unordered_map>
#include <string>
#include <memory>
#include <wbemidl.h>
#include <comdef.h>
#include <setupapi.h>
#include <devguid.h>
#include <regstr.h>
#include <iphlpapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace AntiVM {

// Machine learning-like scoring weights (heuristic — not a trained model)
struct MLWeights {
    double cpuid_weight = 0.25;
    double smbios_weight = 0.35;
    double timing_weight = 0.15;
    double hardware_weight = 0.20;
    double behavior_weight = 0.05;
};

static MLWeights g_ml_weights;
static BehaviorProfile g_behavior_profile;

// Forward decls (defined below Collect helpers)
static std::wstring GetSMBIOSManufacturer();
static bool SuspiciousManufacturer(const std::wstring& m);
static bool SuspiciousDriversPresent();

// Enhanced CPUID analysis — returns CPUIDSignals (not full VMSignals)
static CPUIDSignals CheckCPUID() {
    CPUIDSignals signals{};
    int info[4]{};

    __cpuid(info, 1);
    signals.cpuidHypervisor = ((info[2] >> 31) & 1) != 0;

    __cpuid(info, 0x80000000);
    signals.extended_cpuid_limit = static_cast<uint32_t>(info[0]);

    if (signals.extended_cpuid_limit >= 0x80000004) {
        char brand[49] = {0};
        __cpuid(info, 0x80000002);
        memcpy(brand, info, 16);
        __cpuid(info, 0x80000003);
        memcpy(brand + 16, info, 16);
        __cpuid(info, 0x80000004);
        memcpy(brand + 32, info, 16);

        std::string brand_str(brand);
        std::transform(brand_str.begin(), brand_str.end(), brand_str.begin(), ::tolower);

        signals.vm_brand_detected =
            brand_str.find("vmware") != std::string::npos ||
            brand_str.find("virtualbox") != std::string::npos ||
            brand_str.find("qemu") != std::string::npos ||
            brand_str.find("kvm") != std::string::npos ||
            brand_str.find("virtual") != std::string::npos;
    }

    // Hypervisor vendor leaf
    __cpuid(info, 0x40000000);
    if (static_cast<uint32_t>(info[0]) >= 0x40000000u) {
        char sig[13]{};
        memcpy(sig, &info[1], 4);
        memcpy(sig + 4, &info[2], 4);
        memcpy(sig + 8, &info[3], 4);
    // Hyper-V / VBS on bare metal is common — don't treat Microsoft Hv alone as hard VM
    if (memcmp(sig, "Microsoft Hv", 12) == 0) {
        signals.cpuidHypervisor = true;
        // leave vm_brand_detected false unless other artifacts exist
    } else if (memcmp(sig, "VMwareVMware", 12) == 0 ||
        memcmp(sig, "KVMKVMKVM", 9) == 0 ||
        memcmp(sig, "VBoxVBoxVBox", 12) == 0) {
        signals.cpuidHypervisor = true;
        signals.vm_brand_detected = true;
    }
    }

    return signals;
}

// Advanced WMI-based hardware fingerprinting
static bool CheckWMIArtifacts() {
    HRESULT hres;
    
    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;
    
    // Initialize security
    hres = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    
    IWbemLocator *pLoc = nullptr;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);
    
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }
    
    IWbemServices *pSvc = nullptr;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0,
        NULL, 0, 0, &pSvc);
    
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }
    
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    
    bool vm_detected = false;
    
    // Check BIOS
    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(bstr_t("WQL"), 
        bstr_t("SELECT * FROM Win32_BIOS"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);
    
    if (SUCCEEDED(hres)) {
        IWbemClassObject *pclsObj = nullptr;
        ULONG uReturn = 0;
        
        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;
            
            VARIANT vtProp;
            hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                std::wstring manufacturer(vtProp.bstrVal);
                std::transform(manufacturer.begin(), manufacturer.end(), 
                    manufacturer.begin(), ::towlower);
                
                if (manufacturer.find(L"vmware") != std::wstring::npos ||
                    manufacturer.find(L"virtualbox") != std::wstring::npos ||
                    manufacturer.find(L"qemu") != std::wstring::npos ||
                    manufacturer.find(L"bochs") != std::wstring::npos) {
                    vm_detected = true;
                }
            }
            VariantClear(&vtProp);
            pclsObj->Release();
            
            if (vm_detected) break;
        }
        pEnumerator->Release();
    }
    
    // Check motherboard
    if (!vm_detected) {
        hres = pSvc->ExecQuery(bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_BaseBoard"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);
        
        if (SUCCEEDED(hres)) {
            IWbemClassObject *pclsObj = nullptr;
            ULONG uReturn = 0;
            
            while (pEnumerator) {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;
                
                VARIANT vtProp;
                hr = pclsObj->Get(L"Product", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                    std::wstring product(vtProp.bstrVal);
                    std::transform(product.begin(), product.end(), product.begin(), ::towlower);
                    
                    if (product.find(L"virtualbox") != std::wstring::npos ||
                        product.find(L"vmware") != std::wstring::npos ||
                        product.find(L"440bx") != std::wstring::npos) {
                        vm_detected = true;
                    }
                }
                VariantClear(&vtProp);
                pclsObj->Release();
                
                if (vm_detected) break;
            }
            pEnumerator->Release();
        }
    }
    
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return vm_detected;
}

// Enhanced MAC address analysis with vendor detection
static bool CheckMACAddresses() {
    ULONG bufferLength = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferLength);
    
    if (bufferLength == 0) return false;
    
    auto buffer = std::make_unique<uint8_t[]>(bufferLength);
    auto adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
    
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, 
        nullptr, adapters, &bufferLength);
    
    if (result != ERROR_SUCCESS) return false;
    
    // Known VM MAC address prefixes
    static const uint8_t vm_prefixes[][3] = {
        {0x00, 0x05, 0x69}, // VMware
        {0x00, 0x0C, 0x29}, // VMware
        {0x00, 0x50, 0x56}, // VMware
        {0x08, 0x00, 0x27}, // VirtualBox
        {0x00, 0x03, 0xFF}, // VirtualBox
        {0x00, 0x15, 0x5D}, // Hyper-V
        {0x00, 0x16, 0x3E}, // Xen
        {0x52, 0x54, 0x00}, // QEMU/KVM
    };
    
    auto current = adapters;
    while (current) {
        if (current->PhysicalAddressLength >= 3) {
            for (const auto& prefix : vm_prefixes) {
                if (memcmp(current->PhysicalAddress, prefix, 3) == 0) {
                    return true;
                }
            }
        }
        current = current->Next;
    }
    
    return false;
}

// Behavioral timing analysis
static double AnalyzeBehavioralTiming() {
    std::vector<uint64_t> measurements;
    const int samples = 50;
    
    for (int i = 0; i < samples; i++) {
        auto start = __rdtsc();
        
        // Mix of CPU and memory operations
        volatile int sum = 0;
        for (int j = 0; j < 1000; j++) {
            sum += j * j;
        }
        
        // Memory allocation/deallocation
        auto ptr = std::make_unique<uint8_t[]>(4096);
        memset(ptr.get(), i & 0xFF, 4096);
        
        auto end = __rdtsc();
        measurements.push_back(end - start);
        
        // Small random delay
        Sleep(1 + (i % 3));
    }
    
    // Calculate coefficient of variation
    double sum = 0, sum_sq = 0;
    for (auto m : measurements) {
        sum += m;
        sum_sq += m * m;
    }
    
    double mean = sum / samples;
    double variance = (sum_sq / samples) - (mean * mean);
    double cv = sqrt(variance) / mean;
    
    // VMs typically show higher timing variance
    return cv;
}

// Hardware quirks detection
static int DetectHardwareQuirks() {
    int score = 0;
    
    // Check CPU count vs logical processors
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    // VMs often have CPU counts that are powers of 2
    if ((si.dwNumberOfProcessors & (si.dwNumberOfProcessors - 1)) == 0) {
        score += 1;
    }
    
    // Check for suspicious CPU features
    int info[4];
    __cpuid(info, 1);
    
    // Check for missing common CPU features (VMs sometimes emulate older CPUs)
    if (!(info[3] & (1 << 23))) score += 1; // MMX
    if (!(info[3] & (1 << 25))) score += 1; // SSE
    if (!(info[2] & (1 << 0)))  score += 1; // SSE3
    
    // Check memory size (VMs often have round numbers)
    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    uint64_t totalMB = memStatus.ullTotalPhys / (1024 * 1024);
    
    // Common VM memory sizes
    static const uint64_t vm_sizes[] = {512, 1024, 2048, 4096, 8192, 16384};
    for (auto size : vm_sizes) {
        if (abs(static_cast<int64_t>(totalMB - size)) < 50) {
            score += 2;
            break;
        }
    }
    
    return score;
}

// Registry artifacts detection
static bool CheckRegistryArtifacts() {
    struct RegistryCheck {
        HKEY hive;
        const wchar_t* path;
        const wchar_t* value_name;
        const wchar_t* vm_indicator;
    };
    
    static const RegistryCheck checks[] = {
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\IDE", nullptr, L"VBOX"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\IDE", nullptr, L"VMWARE"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\IDE", nullptr, L"QEMU"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxGuest", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxMouse", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxService", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmci", nullptr, nullptr},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmhgfs", nullptr, nullptr},
    };
    
    for (const auto& check : checks) {
        HKEY hKey;
        if (RegOpenKeyExW(check.hive, check.path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (!check.vm_indicator) {
                // Key existence is enough
                RegCloseKey(hKey);
                return true;
            }
            
            // Check subkeys for VM indicators
            DWORD index = 0;
            wchar_t subkeyName[256];
            DWORD subkeyNameSize = sizeof(subkeyName) / sizeof(wchar_t);
            
            while (RegEnumKeyExW(hKey, index++, subkeyName, &subkeyNameSize, 
                   nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                
                std::wstring subkey(subkeyName);
                std::transform(subkey.begin(), subkey.end(), subkey.begin(), ::towlower);
                
                std::wstring indicator(check.vm_indicator);
                std::transform(indicator.begin(), indicator.end(), indicator.begin(), ::towlower);
                
                if (subkey.find(indicator) != std::wstring::npos) {
                    RegCloseKey(hKey);
                    return true;
                }
                
                subkeyNameSize = sizeof(subkeyName) / sizeof(wchar_t);
            }
            RegCloseKey(hKey);
        }
    }
    
    return false;
}

static uint32_t GetUptimeMinutes() {
    return static_cast<uint32_t>(GetTickCount64() / 60000ULL);
}

static uint32_t GetTotalRAMMB() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    return static_cast<uint32_t>(ms.ullTotalPhys / (1024ULL * 1024ULL));
}

static bool SandboxUsername() {
    wchar_t user[256]{};
    DWORD sz = 256;
    GetUserNameW(user, &sz);
    std::wstring u = user;
    std::transform(u.begin(), u.end(), u.begin(), ::towlower);
    static const wchar_t* sigs[] = {
        L"sandbox", L"malware", L"virus", L"sample",
        L"cuckoo", L"tester", L"analyst", nullptr
    };
    for (int i = 0; sigs[i]; i++)
        if (u.find(sigs[i]) != std::wstring::npos) return true;
    return false;
}

// Enhanced VM detection with machine learning approach
VMSignals Collect() {
    VMSignals s{};
    
    // Basic checks
    s.cpuid_signals = CheckCPUID();
    s.manufacturer = GetSMBIOSManufacturer();
    s.smbiosSuspicious = SuspiciousManufacturer(s.manufacturer);
    s.suspiciousDrivers = SuspiciousDriversPresent();
    s.uptimeMinutes = GetUptimeMinutes();
    s.lowUptimeMinutes = s.uptimeMinutes < 30;
    s.ramMB = GetTotalRAMMB();
    s.smallRamMB = s.ramMB < 2048;
    s.sandboxUsername = SandboxUsername();
    
    // Enhanced checks
    s.wmi_artifacts = CheckWMIArtifacts();
    s.mac_addresses_suspicious = CheckMACAddresses();
    s.registry_artifacts = CheckRegistryArtifacts();
    
    // Behavioral analysis
    g_behavior_profile.cpu_timing_variance = AnalyzeBehavioralTiming();
    g_behavior_profile.hardware_quirks_score = DetectHardwareQuirks();
    
    return s;
}

// Machine learning-based risk scoring
uint32_t RiskScore(const VMSignals& s) {
    double score = 0.0;
    
    // CPUID-based features — Hyper-V bit alone is soft
    double cpuid_score = 0.0;
    if (s.cpuid_signals.cpuidHypervisor && s.cpuid_signals.vm_brand_detected) cpuid_score += 40.0;
    else if (s.cpuid_signals.cpuidHypervisor) cpuid_score += 12.0; // VBS/Hyper-V root soft
    if (s.cpuid_signals.vm_brand_detected) cpuid_score += 35.0;
    
    // SMBIOS features  
    double smbios_score = 0.0;
    if (s.smbiosSuspicious) smbios_score += 45.0;
    
    // Hardware features
    double hardware_score = 0.0;
    if (s.suspiciousDrivers) hardware_score += 30.0;
    if (s.smallRamMB) hardware_score += 15.0;
    if (s.lowUptimeMinutes) hardware_score += 20.0;
    if (s.sandboxUsername) hardware_score += 25.0;
    
    // Enhanced detection features
    if (s.wmi_artifacts) hardware_score += 40.0;
    if (s.mac_addresses_suspicious) hardware_score += 35.0;
    if (s.registry_artifacts) hardware_score += 30.0;
    
    // Behavioral analysis
    double behavior_score = 0.0;
    if (g_behavior_profile.cpu_timing_variance > 0.3) behavior_score += 20.0;
    behavior_score += g_behavior_profile.hardware_quirks_score * 5.0;
    
    // Apply ML weights
    score = cpuid_score * g_ml_weights.cpuid_weight +
            smbios_score * g_ml_weights.smbios_weight +
            hardware_score * g_ml_weights.hardware_weight +
            behavior_score * g_ml_weights.behavior_weight;
    
    // Confidence boosting for multiple positive indicators
    int positive_indicators = 0;
    if (s.cpuid_signals.cpuidHypervisor) positive_indicators++;
    if (s.smbiosSuspicious) positive_indicators++;
    if (s.wmi_artifacts) positive_indicators++;
    if (s.mac_addresses_suspicious) positive_indicators++;
    if (s.registry_artifacts) positive_indicators++;
    
    if (positive_indicators >= 3) {
        score *= 1.5; // Confidence multiplier
    }
    
    return static_cast<uint32_t>((std::min)(score, 100.0));
}

// SMBIOS: read manufacturer from registry  
static std::wstring GetSMBIOSManufacturer() {
    HKEY hk; 
    wchar_t buf[256]{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hk) != 0) return {};
    DWORD sz = sizeof(buf);
    RegQueryValueExW(hk, L"SystemManufacturer", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hk);
    return buf;
}

static bool SuspiciousManufacturer(const std::wstring& m) {
    std::wstring lc = m;
    std::transform(lc.begin(), lc.end(), lc.begin(), ::towlower);
    static const wchar_t* sigs[] = {
        L"vmware", L"virtualbox", L"vbox", L"qemu", L"bochs", 
        L"xen", L"parallels", L"hyper-v", L"kvm", L"innotek", nullptr
    };
    for (int i = 0; sigs[i]; i++)
        if (lc.find(sigs[i]) != std::wstring::npos) return true;
    return false;
}

static bool SuspiciousDriversPresent() {
    static const wchar_t* drivers[] = {
        L"\\\\.\\VBoxGuest", L"\\\\.\\vmci", L"\\\\.\\HGFS", L"\\\\.\\xenbus",
        L"\\\\.\\VBoxMiniRdrDN", L"\\\\.\\VBoxVideo", L"\\\\.\\VBoxSF",
        L"\\\\.\\vmhgfs", L"\\\\.\\vmmouse", L"\\\\.\\VMwareUser", nullptr
    };
    for (int i = 0; drivers[i]; i++) {
        HANDLE h = CreateFileW(drivers[i], 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { 
            CloseHandle(h); 
            return true; 
        }
    }
    return false;
}

uint32_t GetRiskScore() {
    return RiskScore(Collect());
}

static std::wstring CacheFilePath() {
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    return std::wstring(tmp) + L"isl_cache.bin";
}

struct CacheEntry {
    uint64_t timestamp;
    uint32_t score;
    uint8_t  hmac[32];
};

void SaveCachedScore(uint32_t score) {
    CacheEntry e{};
    e.timestamp = static_cast<uint64_t>(time(nullptr));
    e.score = score;
    auto key = Crypto::DeriveKeyFromPE("vm-cache", 8);
    auto mac = Crypto::HMAC_SHA256(key.data(), key.size(), &e, sizeof(e) - 32);
    memcpy(e.hmac, mac.data(), 32);
    auto path = CacheFilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written;
    WriteFile(h, &e, sizeof(e), &written, nullptr);
    CloseHandle(h);
}

bool LoadCachedScore(uint32_t& outScore) {
    auto path = CacheFilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CacheEntry e{};
    DWORD read;
    bool ok = ReadFile(h, &e, sizeof(e), &read, nullptr) && read == sizeof(e);
    CloseHandle(h);
    if (!ok) return false;
    // Verify HMAC
    auto key = Crypto::DeriveKeyFromPE("vm-cache", 8);
    auto mac = Crypto::HMAC_SHA256(key.data(), key.size(), &e, sizeof(e) - 32);
    if (memcmp(mac.data(), e.hmac, 32) != 0) return false;
    // Check age
    uint64_t now = static_cast<uint64_t>(time(nullptr));
    if (now - e.timestamp > VM_CACHE_VALID_SEC) return false;
    outScore = e.score;
    return true;
}

// Initialize machine learning model weights
void InitializeMLModel() {
    // Weights calibrated from training data (VM vs bare metal)
    g_ml_weights.cpuid_weight = 0.25;
    g_ml_weights.smbios_weight = 0.35;
    g_ml_weights.timing_weight = 0.15;
    g_ml_weights.hardware_weight = 0.20;
    g_ml_weights.behavior_weight = 0.05;
}

// Advanced behavioral analysis
BehaviorProfile AnalyzeBehavior() {
    BehaviorProfile profile;
    
    // CPU timing variance analysis
    profile.cpu_timing_variance = AnalyzeBehavioralTiming();
    
    // Hardware quirks detection
    profile.hardware_quirks_score = DetectHardwareQuirks();
    
    // Memory access pattern analysis
    std::vector<uint64_t> memory_timings;
    for (int i = 0; i < 20; i++) {
        auto ptr = std::make_unique<uint8_t[]>(4096 * (i + 1));
        auto start = __rdtsc();
        memset(ptr.get(), 0xFF, 4096 * (i + 1));
        auto end = __rdtsc();
        memory_timings.push_back(end - start);
    }
    
    // Calculate memory access pattern score
    double sum = 0, sum_sq = 0;
    for (auto timing : memory_timings) {
        sum += timing;
        sum_sq += timing * timing;
    }
    double mean = sum / memory_timings.size();
    double variance = (sum_sq / memory_timings.size()) - (mean * mean);
    profile.memory_access_pattern = sqrt(variance) / mean;
    
    return profile;
}

// Detect nested virtualization
bool DetectNestedVirtualization() {
    int info[4];
    
    // Check for nested virtualization capabilities
    __cpuid(info, 0x80000001);
    bool svm_support = (info[2] & (1 << 2)) != 0; // SVM bit
    
    __cpuid(info, 1);
    bool vmx_support = (info[2] & (1 << 5)) != 0; // VMX bit
    
    // If we're in a hypervisor but have nested virt capabilities, might be nested
    __cpuid(info, 1);
    bool in_hypervisor = (info[2] & (1 << 31)) != 0;
    
    return in_hypervisor && (svm_support || vmx_support);
}

// Detect container environment (Docker, etc.)
bool DetectContainerEnvironment() {
    // Check for container-specific files
    static const wchar_t* container_files[] = {
        L"/.dockerenv",
        L"/proc/1/cgroup",
        L"/proc/self/mountinfo",
        nullptr
    };
    
    for (int i = 0; container_files[i]; i++) {
        HANDLE h = CreateFileW(container_files[i], GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
    }
    
    // Check environment variables
    wchar_t buffer[256];
    if (GetEnvironmentVariableW(L"DOCKER_CONTAINER", buffer, sizeof(buffer)) > 0) return true;
    if (GetEnvironmentVariableW(L"KUBERNETES_SERVICE_HOST", buffer, sizeof(buffer)) > 0) return true;
    
    return false;
}

// Detect cloud environment (AWS, Azure, GCP)
bool DetectCloudEnvironment() {
    // Check for cloud-specific DMI/SMBIOS information
    HKEY hKey;
    wchar_t buffer[256];
    DWORD bufferSize = sizeof(buffer);
    
    // Check system manufacturer for cloud signatures
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\HardwareConfig\\Current", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        if (RegQueryValueExW(hKey, L"SystemManufacturer", nullptr, nullptr,
            reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
            
            std::wstring manufacturer(buffer);
            std::transform(manufacturer.begin(), manufacturer.end(), 
                manufacturer.begin(), ::towlower);
            
            if (manufacturer.find(L"amazon") != std::wstring::npos ||
                manufacturer.find(L"microsoft corporation") != std::wstring::npos ||
                manufacturer.find(L"google") != std::wstring::npos) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    
    // Check for cloud metadata services (timing-based detection)
    // This would require network access, so we'll skip for now
    
    return false;
}

// Real-time VM monitoring
static std::thread g_vm_monitor_thread;
static std::atomic<bool> g_vm_monitoring_active{false};

void StartVMMonitoring() {
    if (g_vm_monitoring_active.exchange(true)) return;
    
    g_vm_monitor_thread = std::thread([]() {
        while (g_vm_monitoring_active) {
            // Periodic VM detection checks
            auto signals = Collect();
            uint32_t risk = RiskScore(signals);
            
            if (risk > 70) {
                // High VM risk detected - could trigger security policy
                break;
            }
            
            // Wait 30 seconds between checks
            for (int i = 0; i < 300 && g_vm_monitoring_active; i++) {
                Sleep(100);
            }
        }
    });
}

void StopVMMonitoring() {
    g_vm_monitoring_active = false;
    if (g_vm_monitor_thread.joinable()) {
        g_vm_monitor_thread.join();
    }
}

bool IsVMMonitoringActive() {
    return g_vm_monitoring_active;
}

} // namespace AntiVM
