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

int main() {
    // 1. Initialize Client with Dynamic Asymmetric Session Bridge
    KawaiiAuth::Client auth(
        "kawaii_demo_app",            // App ID (Scoped Multi-Tenant)
        "demo_app_secret",            // Shared Application Secret
        "1.0",                        // Version check
        "https://auth.yourdomain.com" // Production Gateway Endpoint
    );

    // 2. Execute Evasion Gates: Hide Thread (0x11), HWBP & Section Integrity
    if (!auth.Initialize(true)) {
        ExitProcess(0); // Security policy violated: Debugger or Patch detected
    }

    // 3. Authenticate with Hardware-Locked License Key
    std::string key;
    std::cout << "Enter License Key: ";
    std::getline(std::cin, key);

    auto resp = auth.LicenseOnly(key);
    if (!resp.success) {
        std::cout << "[-] Auth Rejected: " << resp.message << std::endl;
        return 1;
    }

    std::cout << "[+] Authenticated! Access Level: VIP Tier " << resp.user.level << std::endl;
    return 0;
}
