// ============================================================================
// KAWAIIAUTH NATIVE C++ LOADER BOILERPLATE (MSVC x64 C++20)
// ============================================================================
#include <iostream>
#include <string>
#include <windows.h>
#include "kawaii_auth.hpp"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

static std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

int main() {
    std::cout << "========================================================\n";
    std::cout << "  KawaiiAuth Native Client Loader v1.0\n";
    std::cout << "========================================================\n\n";

    // 1. Initialize Client with Dynamic Asymmetric Session Bridge
    KawaiiAuth::Client auth(
        "kawaii_demo_app",            // App ID (Scoped Multi-Tenant)
        "demo_app_secret",            // Shared Application Secret
        "1.0",                        // Version check
        "http://127.0.0.1:8080"       // Gateway Endpoint
    );

    // 2. Execute Evasion Gates: Hide Thread (0x11), HWBP & Section Integrity
    if (!auth.Initialize(true)) {
        std::cout << "[-] Security policy violated: Debugger or Patch detected.\n\n";
        system("pause");
        ExitProcess(0);
    }

    // 3. Authenticate with Hardware-Locked License Key
    std::string key;
    std::cout << "[*] Enter License Key (or press Enter for demo key): ";
    std::getline(std::cin, key);
    key = Trim(key);
    if (key.empty()) {
        key = "KAWAII-DEMO-KEY1";
        std::cout << "[*] Using Default Demo Key: " << key << "\n";
    }

    std::cout << "[*] Verifying with authentication server...\n";
    auto resp = auth.LicenseOnly(key);
    if (!resp.success) {
        std::cout << "\n[-] Authentication Failed: " << resp.message << "\n\n";
        system("pause");
        return 1;
    }

    std::cout << "\n[+] ====================================================\n";
    std::cout << "[+] Authentication SUCCESSFUL!\n";
    std::cout << "[+] Key / User   : " << resp.user.username << "\n";
    std::cout << "[+] Access Level : VIP Tier " << resp.user.level << "\n";
    std::cout << "[+] HWID Locked  : " << (resp.user.hwid.empty() ? "None" : resp.user.hwid.substr(0, 16) + "...") << "\n";
    std::cout << "[+] ====================================================\n\n";

    // 4. Demonstrate Downloading Payload by File ID
    std::cout << "[*] Fetching secure file payload with File ID...\n";
    std::vector<uint8_t> payload = auth.DownloadFile("n.txt");
    if (!payload.empty()) {
        std::cout << "    [+] Downloaded payload successfully (" << payload.size() << " bytes) in RAM!\n";
    } else {
        std::cout << "    [-] No payload downloaded (or not configured yet)\n";
    }

    std::cout << "\n[+] Loader ready. Protected application running.\n\n";
    system("pause");
    return 0;
}
