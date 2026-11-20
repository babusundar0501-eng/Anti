#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <cmath>
#include <array>
#include <thread>
#include <mutex>
#include <unordered_set>

namespace fs = std::filesystem;

class NextGenEDREngine {
private:
    std::mutex log_mtx;

    void alert(const std::string& module, const std::string& severity, const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mtx);
        std::cout << "[" << severity << "] [" << module << "] " << msg << "\n";
    }

public:
    // =========================================================================
    // MODULE 1: SHANNON ENTROPY ANALYZER (Zero-Day Packed/Encrypted Malware)
    // High entropy (> 7.2 out of 8.0) indicates encryption or obfuscation.
    // =========================================================================
    double calculate_entropy(const std::vector<uint8_t>& buffer) {
        if (buffer.empty()) return 0.0;
        std::array<size_t, 256> freq{};
        for (uint8_t byte : buffer) freq[byte]++;

        double entropy = 0.0;
        double len = static_cast<double>(buffer.size());
        for (size_t count : freq) {
            if (count > 0) {
                double p = count / len;
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }

    // =========================================================================
    // MODULE 2: PE HEADER & SUSPICIOUS API COMBINATION INSPECTOR
    // Detects executable binaries importing process-injection APIs.
    // =========================================================================
    bool inspect_pe_heuristics(const std::vector<uint8_t>& data, const fs::path& path) {
        // Check DOS 'MZ' magic bytes
        if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z') return false;

        std::string raw_str(data.begin(), data.end());
        int injection_score = 0;

        const std::vector<std::string> high_risk_apis = {
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "SetWindowsHookEx",
            "IsDebuggerPresent"
        };

        for (const auto& api : high_risk_apis) {
            if (raw_str.find(api) != std::string::npos) {
                injection_score++;
            }
        }

        double entropy = calculate_entropy(data);

        if (injection_score >= 3 || (entropy > 7.35 && path.extension() == ".exe")) {
            alert("HEURISTIC-AI", "CRITICAL",
                  path.string() + " | Injection APIs: " + std::to_string(injection_score) +
                  " | Entropy: " + std::to_string(entropy));
            return true;
        }
        return false;
    }

    // =========================================================================
    // MODULE 3: LIVE PROCESS MEMORY (RAM) SCANNER
    // Hunts fileless malware & shellcode injected into running processes.
    // =========================================================================
    void scan_live_memory() {
        alert("RAM-HUNTER", "INFO", "Scanning active process memory spaces...");
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        const std::string eicar_sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

        if (Process32First(snapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == GetCurrentProcessId()) continue;

                HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    MEMORY_BASIC_INFORMATION mbi{};
                    unsigned char* addr = nullptr;

                    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
                        // Look for executable, committed, private memory (classic shellcode indicator)
                        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                           (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ)) {

                            std::vector<char> mem_buf(mbi.RegionSize);
                            SIZE_T bytes_read = 0;
                            if (ReadProcessMemory(hProcess, mbi.BaseAddress, mem_buf.data(), mbi.RegionSize, &bytes_read)) {
                                std::string mem_str(mem_buf.begin(), mem_buf.begin() + bytes_read);
                                if (mem_str.find(eicar_sig) != std::string::npos) {
                                    alert("RAM-HUNTER", "CRITICAL",
                                          "Fileless payload detected in PID " + std::to_string(pe32.th32ProcessID));
                                }
                            }
                        }
                        addr += mbi.RegionSize;
                    }
                    CloseHandle(hProcess);
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }

    // =========================================================================
    // MODULE 4: RANSOMWARE CANARY TRAP (Active Behavioral Defense)
    // Places a bait file and watches for unauthorized encryption/modification.
    // =========================================================================
    void deploy_ransomware_canary(const fs::path& folder) {
        fs::path canary = folder / "!000_system_canary.txt";
        {
            std::ofstream out(canary);
            out << "DO_NOT_MODIFY_EDR_CANARY_TRAP_9948172";
        }
        // Hide the canary file from normal users
        SetFileAttributesA(canary.string().c_str(), FILE_ATTRIBUTE_HIDDEN);

        alert("RANSOM-SHIELD", "ACTIVE", "Canary trap armed at: " + canary.string());

        HANDLE hDir = CreateFileA(
            folder.string().c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );

        if (hDir == INVALID_HANDLE_VALUE) return;

        char buffer[1024];
        DWORD bytesReturned;
        while (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), FALSE,
               FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME,
               &bytesReturned, NULL, NULL)) {

            FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
            std::wstring changed_file(fni->FileName, fni->FileNameLength / sizeof(WCHAR));

            if (changed_file.find(L"!000_system_canary.txt") != std::wstring::npos) {
                alert("RANSOM-SHIELD", "EMERGENCY",
                      "RANSOMWARE BEHAVIOR DETECTED! Canary file was altered/encrypted!");
                // In kernel mode, your minifilter driver immediately blocks the offending PID here.
                break;
            }
        }
        CloseHandle(hDir);
    }

    // =========================================================================
    // DISK SCANNER ORCHESTRATOR
    // =========================================================================
    void scan_file(const fs::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return;

        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

        if (inspect_pe_heuristics(buffer, path)) {
            fs::create_directories("./quarantine");
            fs::rename(path, fs::path("./quarantine") / (path.filename().string() + ".edr_locked"));
            alert("QUARANTINE", "ACTION", "Neutralized: " + path.string());
        }
    }
};

int main() {
    fs::create_directories("./protected_zone");
    NextGenEDREngine edr;

    // 1. Scan live RAM for injected shellcode
    edr.scan_live_memory();

    // 2. Scan files on disk using Entropy + PE Import Heuristics
    for (const auto& entry : fs::recursive_directory_iterator("./protected_zone")) {
        if (entry.is_regular_file()) {
            edr.scan_file(entry.path());
        }
    }

    // 3. Arm real-time Ransomware Canary Trap (runs continuously)
    edr.deploy_ransomware_canary("./protected_zone");

    return 0;
}
