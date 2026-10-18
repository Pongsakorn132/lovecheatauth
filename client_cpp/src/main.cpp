// ============================================================================
// KAWAIIAUTH NATIVE C++ LOADER BOILERPLATE (MSVC x64 C++20)
// ============================================================================
#include <iostream>
#include <string>
#include <fstream>
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

static std::string LoadSavedKey() {
    std::ifstream file("license.key");
    if (!file.is_open()) return "";
    std::string key;
    std::getline(file, key);
    return Trim(key);
}

static void SaveKey(const std::string& key) {
    if (key.empty()) return;
    std::ofstream file("license.key", std::ios::trunc);
    if (file.is_open()) {
        file << key << std::endl;
    }
}

int main() {
    // 1. Initialize Client with Dynamic Asymmetric Session Bridge
    KawaiiAuth::Client auth(
        "kawaii_demo_app",            // App ID (Scoped Multi-Tenant)
        "demo_app_secret",            // Shared Application Secret
        "1.0",                        // Version check
        "http://127.0.0.1:8080"       // Gateway Endpoint (Change to "https://auth.yourdomain.com" for production)
    );

    // 2. Execute Evasion Gates: Hide Thread (0x11), HWBP & Section Integrity
    if (!auth.Initialize(true)) {
        ExitProcess(0); // Security policy violated: Debugger or Patch detected
    }

    // 3. Authenticate with Hardware-Locked License Key (With Remember Key System)
    std::string savedKey = LoadSavedKey();
    std::string key;

    if (!savedKey.empty()) {
        std::cout << "Enter License Key [Press Enter for saved: " << savedKey << "]: ";
    } else {
        std::cout << "Enter License Key: ";
    }

    std::getline(std::cin, key);
    key = Trim(key);
    if (key.empty() && !savedKey.empty()) {
        key = savedKey;
    }

    auto resp = auth.LicenseOnly(key);
    if (!resp.success) {
        std::cout << "[-] Auth Rejected: " << resp.message << std::endl;
        return 1;
    }

    // Automatically remember key on successful login
    SaveKey(key);

    std::cout << "[+] Authenticated! Access Level: VIP Tier " << resp.user.level << std::endl;
    return 0;
}
