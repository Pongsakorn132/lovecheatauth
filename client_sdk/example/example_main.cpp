/**
 * ============================================================================
 * KawaiiAuth SDK - Example Usage
 * ============================================================================
 * 
 * How to use KawaiiAuth in your cheat / loader / application:
 *   1. Copy `include/KawaiiAuth.h` into your project.
 *   2. Copy `lib/KawaiiAuth.lib` into your project directory.
 *   3. In your code:
 *        #include "KawaiiAuth.h"
 *      (KawaiiAuth.lib will be auto-linked by MSVC!)
 * ============================================================================
 */

#include "KawaiiAuth.h"
#include <iostream>
#include <fstream>
#include <string>

static std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << "  KawaiiAuth SDK Integration Demo" << std::endl;
    std::cout << "==================================================" << std::endl;

    // 1. Run local security checks (Anti-Debug, Hardware Breakpoint detection)
    std::cout << "[*] Running security checks..." << std::endl;
    if (!KawaiiAuth::RunSecurityChecks()) {
        std::cout << "[!] Security check failed: Debugger or reverse engineering tool detected!" << std::endl;
        return 1;
    }
    std::cout << "[+] Environment is clean and secure." << std::endl;

    // 2. Initialize KawaiiAuth SDK
    std::cout << "[*] Initializing KawaiiAuth..." << std::endl;
    KawaiiAuth::Config config;
    config.app_id = "kawaii_demo_app";
    config.app_secret = "demo_app_secret";
    config.version = "1.0";
    config.api = "http://127.0.0.1:8080";

    if (!KawaiiAuth::Init(config)) {
        std::cout << "[!] Initialization failed: " << KawaiiAuth::GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Initialized with server! HWID: " << KawaiiAuth::GetHWID().substr(0, 16) << "..." << std::endl;

    // 3. Authenticate with License Key
    std::cout << "\nEnter License Key (or press Enter for demo key KAWAII-DEMO-KEY1): ";
    std::string licenseKey;
    std::getline(std::cin, licenseKey);
    licenseKey = Trim(licenseKey);
    if (licenseKey.empty()) {
        licenseKey = "KAWAII-DEMO-KEY1";
    }

    std::cout << "[*] Authenticating with key: " << licenseKey << "..." << std::endl;
    auto result = KawaiiAuth::LicenseLogin(licenseKey);

    if (!result) {
        std::cout << "[!] Login failed: " << result.message << std::endl;
        return 1;
    }

    std::cout << "[+] Authentication SUCCESSFUL!" << std::endl;
    std::cout << "    User / Key  : " << result.user.username << std::endl;
    std::cout << "    Access Tier : Level " << result.user.level << std::endl;
    std::cout << "    Time Left   : " << KawaiiAuth::GetFormattedTimeLeft() << std::endl;

    // 4. Session Verification (Guaranteed against replay attacks)
    auto session = KawaiiAuth::CheckSession();
    if (session.authed) {
        std::cout << "[+] Session verified active & secure on server." << std::endl;
    } else {
        std::cout << "[!] Warning: Session invalid: " << session.message << std::endl;
    }

    // 5. Download protected payload by File ID from Server/Cloudflare R2 and save as cxwq.txt
    std::cout << "\n--- [Payload Download & Save Test] ---" << std::endl;

    // Use File ID configured in Web Dashboard (e.g. "n.txt" or "n_txt" or custom ID)
    std::string targetFileId = "n.txt";
    std::cout << "[*] Downloading payload with File ID: " << targetFileId << "..." << std::endl;

    std::vector<uint8_t> fileBytes = KawaiiAuth::DownloadFile(targetFileId);

    if (!fileBytes.empty()) {
        std::cout << "[+] Downloaded payload successfully (" << fileBytes.size() << " bytes) in RAM!" << std::endl;

        // Save downloaded payload to cxwq.txt
        std::ofstream outFile("cxwq.txt", std::ios::binary);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(fileBytes.data()), fileBytes.size());
            outFile.close();
            std::cout << "[+] Successfully saved to 'cxwq.txt' (" << fileBytes.size() << " bytes)!" << std::endl;
        } else {
            std::cout << "[!] Failed to open 'cxwq.txt' for writing." << std::endl;
        }
    } else {
        std::cout << "[!] Failed to download payload with File ID: " << targetFileId << std::endl;
    }

    // 6. Send Audit Log
    KawaiiAuth::Log("Demo application authenticated successfully");

    std::cout << "\n==================================================" << std::endl;
    std::cout << "  Ready! You can now execute protected cheat/app." << std::endl;
    std::cout << "==================================================" << std::endl;

    return 0;
}
