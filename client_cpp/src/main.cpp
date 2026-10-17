#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <chrono>
#include <ctime>
#include "kawaii_auth.hpp"
#include "skCrypter.hpp"
#include "security.hpp"

void DisplayBanner() {
    std::cout << R"(
  _  __                     _ _                 _   _     
 | |/ /__ ___      ____ _  (_|_)   /\         | | | |    
 | ' / _` \ \ /\ / / _` | | | |  /  \  _   _ _| |_| |__  
 | . \ (_| |\ V  V / (_| | | | | / /\ \| | | |_   _| '_ \ 
 |_|\_\__,_| \_/\_/ \__,_| |_|_|/_/  \_\__,_|  |_| |_| |_|
        [ Native C++ Hardened & Obfuscated Client ]
    )" << std::endl;
}

int main() {
    SetConsoleTitleA(skCrypt("KawaiiAuth C++ Hardened Client [v1.0]"));
    DisplayBanner();

    // 1. Pre-Execution Evasion Check
    std::cout << "[*] Executing Anti-Debug & Integrity Evasion Gates..." << std::endl;
    if (!KawaiiSecurity::ExecuteEvasionGates()) {
        std::cerr << "[-] Security violation: Debugger or reverse engineering tool detected!" << std::endl;
        std::cout << "\nTerminating immediately...";
        Sleep(2000);
        return 1;
    }
    std::cout << "[+] Evasion Gates: PASSED (Thread hidden, no debugger attached)" << std::endl;

    // 2. In-Memory Section Hash
    std::string textHash = KawaiiSecurity::ComputeTextSectionHash();
    std::cout << "[+] In-Memory .text Hash: " << (textHash.empty() ? "(N/A)" : textHash.substr(0, 16) + "...") << std::endl;

    // 3. Obfuscated Client Config (All strings encrypted at compile-time via skCrypt)
    const std::string APP_ID = skCrypt("kawaii_demo_app");
    const std::string APP_SECRET = skCrypt("demo_app_secret");
    const std::string APP_VERSION = skCrypt("1.0");
    const std::string SERVER_HOST = skCrypt("127.0.0.1");
    const INTERNET_PORT SERVER_PORT = 8080;
    const bool USE_SSL = false;

    KawaiiAuth::Client auth(APP_ID, APP_SECRET, APP_VERSION, SERVER_HOST, SERVER_PORT, USE_SSL);

    std::cout << "[+] Hardware Identifier (HWID): " << auth.GetHWID() << std::endl;
    std::cout << "[*] Negotiating dynamic cryptographic session with gateway..." << std::endl;

    // Initialize with integrity enforcement
    if (!auth.Initialize(false)) {
        std::cerr << "[-] Handshake failed: " << auth.GetLastResponse().message << std::endl;
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Handshake OK! Session: " << auth.GetSessionToken() << std::endl;
    std::cout << "\nSelect Authentication Mode:" << std::endl;
    std::cout << "[1] Login (Username & Password)" << std::endl;
    std::cout << "[2] Register (Username, Password & Key)" << std::endl;
    std::cout << "[3] License Key Only (Direct 1-Step Auth)" << std::endl;
    std::cout << "[4] Check Session Status (API Check Session)" << std::endl;
    std::cout << "\nChoice [1-4]: ";

    int choice = 3;
    if (!(std::cin >> choice)) {
        choice = 3;
    }

    KawaiiAuth::Response resp;

    if (choice == 1) {
        std::string user, pass;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "Password: "; std::cin >> pass;
        resp = auth.Login(user, pass);
    } else if (choice == 2) {
        std::string user, pass, key;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "Password: "; std::cin >> pass;
        std::cout << "License Key: "; std::cin >> key;
        resp = auth.Register(user, pass, key);
    } else if (choice == 4) {
        std::cout << "\n[*] Checking session status via /api/v1/action..." << std::endl;
        KawaiiAuth::SessionStatus st = auth.CheckSession();
        std::cout << "[+] Session Success: " << (st.success ? "YES" : "NO") << std::endl;
        std::cout << "[+] Is Authed: " << (st.authed ? "YES (Authenticated)" : "NO (Unauthenticated)") << std::endl;
        std::cout << "[+] Message: " << st.message << std::endl;
        std::cout << "[+] Time Remaining: " << st.session_time_left << " seconds" << std::endl;

        std::cout << "\n[*] Also check /api/auth/session token? (y/n): ";
        char c;
        if (std::cin >> c && (c == 'y' || c == 'Y')) {
            std::string t;
            std::cout << "Enter session token (or press Enter for current): ";
            std::cin.ignore();
            std::getline(std::cin, t);
            auto authSt = auth.CheckAuthSession(t);
            std::cout << "[+] Auth Session Success: " << (authSt.success ? "YES" : "NO") << std::endl;
            std::cout << "[+] Authed: " << (authSt.authed ? "YES" : "NO") << std::endl;
            std::cout << "[+] PIN Required: " << (authSt.pin_required ? "YES" : "NO") << std::endl;
            std::cout << "[+] Need Connect: " << (authSt.need_connect ? "YES" : "NO") << std::endl;
            std::cout << "[+] Time Left: " << authSt.session_time_left << " seconds" << std::endl;
            std::cout << "[+] Message: " << authSt.message << std::endl;
        }

        std::cout << "\nPress Enter to terminate...";
        std::cin.ignore();
        std::cin.get();
        return 0;
    } else {
        std::string key;
        std::cout << "License Key (default 'KAWAII-DEMO-KEY2'): ";
        std::cin >> key;
        if (key.empty()) key = skCrypt("KAWAII-DEMO-KEY2");
        resp = auth.LicenseOnly(key);
    }

    std::cout << "\n--------------------------------------------------" << std::endl;
    if (!resp.success) {
        std::cerr << "[-] Authentication Error: " << resp.message << std::endl;
    } else {
        std::cout << "[+] " << resp.message << std::endl;
        std::cout << "[+] Authenticated as: " << resp.user.username << std::endl;
        
        std::time_t expTime = static_cast<std::time_t>(resp.user.expires_at);
        std::cout << "[+] Expires At: " << std::asctime(std::localtime(&expTime));

        // Check Session API
        std::cout << skCrypt("[*] Checking session authentication status via API...") << std::endl;
        KawaiiAuth::SessionStatus sess = auth.CheckSession();
        std::cout << "[+] Session Authed: " << (sess.authed ? "AUTHENTICATED (OK)" : "UNAUTHENTICATED") << std::endl;
        std::cout << "[+] Session Time Left: " << sess.session_time_left << " seconds" << std::endl;

        // Fetch Protected Variable
        std::cout << skCrypt("[*] Fetching protected server variable...") << std::endl;
        std::string secretVar = auth.FetchVariable(skCrypt("TEST"));
        std::cout << "[+] Received Variable: " << (secretVar.empty() ? "(none)" : secretVar) << std::endl;

        // Heartbeat Test
        if (auth.Ping()) {
            std::cout << "[+] Heartbeat ping OK (Session active)" << std::endl;
        }

        auth.SendLog(skCrypt("Client verified integrity and passed evasion checks"));
        std::cout << "[+] Sent telemetry log to server" << std::endl;
    }
    std::cout << "--------------------------------------------------" << std::endl;

    std::cout << "\nPress Enter to terminate...";
    std::cin.ignore();
    std::cin.get();
    return 0;
}
