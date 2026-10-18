#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <conio.h>
#include <windows.h>

#include "kawaii_auth.hpp"
#include "skCrypter.hpp"
#include "security.hpp"

// ANSI Color Palette for Modern Windows Terminal
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_RED     "\033[91m"
#define CLR_GREEN   "\033[92m"
#define CLR_YELLOW  "\033[93m"
#define CLR_BLUE    "\033[94m"
#define CLR_MAGENTA "\033[95m"
#define CLR_CYAN    "\033[96m"
#define CLR_WHITE   "\033[97m"
#define CLR_GRAY    "\033[90m"

void EnableConsoleVirtualTerminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

void PrintBanner() {
    std::cout << CLR_CYAN << R"(
  _  __                     _ _                 _   _     
 | |/ /__ ___      ____ _  (_|_)   /\         | | | |    
 | ' / _` \ \ /\ / / _` | | | |  /  \  _   _ _| |_| |__  
 | . \ (_| |\ V  V / (_| | | | | / /\ \| | | |_   _| '_ \ 
 |_|\_\__,_| \_/\_/ \__,_| |_|_|/_/  \_\__,_|  |_| |_| |_|
)" << CLR_RESET;
    std::cout << CLR_MAGENTA << "       [ Enterprise Hardened Client • Anti-Replay v2.0 ]" << CLR_RESET << std::endl;
    std::cout << CLR_GRAY << "  ════════════════════════════════════════════════════════════════" << CLR_RESET << std::endl;
}

void PrintStatus(const std::string& tag, const std::string& message, const std::string& color = CLR_GREEN) {
    std::cout << " " << color << "[" << tag << "]" << CLR_RESET << " " << message << std::endl;
}

std::string FormatDuration(uint64_t totalSeconds) {
    if (totalSeconds == 0) return "Expired / None";
    uint64_t days = totalSeconds / 86400;
    uint64_t hours = (totalSeconds % 86400) / 3600;
    uint64_t minutes = (totalSeconds % 3600) / 60;
    uint64_t seconds = totalSeconds % 60;

    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0 || days > 0) oss << hours << "h ";
    if (minutes > 0 || hours > 0 || days > 0) oss << minutes << "m ";
    oss << seconds << "s";
    return oss.str();
}

std::string FormatTimestamp(uint64_t timestamp) {
    if (timestamp == 0) return "N/A";
    std::time_t t = static_cast<std::time_t>(timestamp);
    char buf[64] = { 0 };
    std::tm* tm_info = std::localtime(&t);
    if (tm_info && std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info)) {
        return std::string(buf);
    }
    return "N/A";
}

std::string ReadPasswordMasked() {
    std::string pass;
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!pass.empty()) {
                pass.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= 32 && ch <= 126) {
            pass.push_back(ch);
            std::cout << "*";
        }
    }
    std::cout << std::endl;
    return pass;
}

std::string Trim(std::string str) {
    while (!str.empty() && (str.back() == ' ' || str.back() == '\r' || str.back() == '\n' || str.back() == '\t')) {
        str.pop_back();
    }
    while (!str.empty() && (str.front() == ' ' || str.front() == '\t')) {
        str.erase(0, 1);
    }
    return str;
}

std::string LoadSavedKey() {
    std::ifstream file("license.key");
    if (!file.is_open()) return "";
    std::string key;
    std::getline(file, key);
    return Trim(key);
}

void SaveKey(const std::string& key) {
    if (key.empty()) return;
    std::ofstream file("license.key", std::ios::trunc);
    if (file.is_open()) {
        file << key << std::endl;
    }
}

void DisplayProfileCard(const KawaiiAuth::UserData& user, const KawaiiAuth::SessionStatus& sess) {
    std::cout << "\n" << CLR_CYAN << " ╔════════════════════════════════════════════════════════════════╗" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║" << CLR_BOLD << CLR_WHITE << "                   AUTHENTICATION SUCCESSFUL                    " << CLR_RESET << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ╠══════════════════════╦═════════════════════════════════════════╣" << CLR_RESET << std::endl;

    auto printRow = [](const std::string& label, const std::string& value, const std::string& valColor = CLR_WHITE) {
        std::cout << CLR_CYAN << " ║ " << CLR_YELLOW << std::left << std::setw(20) << label 
                  << CLR_CYAN << " ║ " << valColor << std::left << std::setw(39) << value 
                  << CLR_CYAN << " ║" << CLR_RESET << std::endl;
    };

    printRow("User / Key", user.username.empty() ? "(License User)" : user.username, CLR_GREEN);
    printRow("Access Tier", "VIP Member (Level " + std::to_string(user.level) + ")", CLR_MAGENTA);
    
    uint64_t now = static_cast<uint64_t>(time(nullptr));
    uint64_t timeLeft = (user.expires_at > now) ? (user.expires_at - now) : 0;
    printRow("Subscription Left", FormatDuration(timeLeft), (timeLeft > 0 ? CLR_GREEN : CLR_RED));
    printRow("Expires At", FormatTimestamp(user.expires_at), CLR_WHITE);
    
    std::string sessDisplay = sess.authed ? ("AUTHED (" + FormatDuration(sess.session_time_left) + " left)") : "NOT AUTHED";
    printRow("Session Shield", sessDisplay, sess.authed ? CLR_GREEN : CLR_RED);
    printRow("Anti-Replay Guard", "ACTIVE (Cryptographic Nonce & Seq)", CLR_CYAN);
    printRow("Hardware Lock", "HWID VERIFIED", CLR_GREEN);

    std::cout << CLR_CYAN << " ╚══════════════════════╩═════════════════════════════════════════╝" << CLR_RESET << std::endl;
}

int main() {
    EnableConsoleVirtualTerminal();
    SetConsoleTitleA(skCrypt("KawaiiAuth • Next-Gen Secure Client [v1.0]"));

    PrintBanner();

    // 1. Pre-Execution Evasion & Anti-Debug Check
    PrintStatus("INIT", "Checking system evasion gates & anti-debugging policies...", CLR_CYAN);
    if (!KawaiiSecurity::ExecuteEvasionGates()) {
        PrintStatus("FAIL", "Security policy violation: Unauthorized analysis tool detected!", CLR_RED);
        std::cout << "\n" << CLR_RED << "Terminating process in 3 seconds..." << CLR_RESET << std::endl;
        Sleep(3000);
        return 1;
    }
    PrintStatus(" OK ", "Evasion gates passed (Thread hidden, no debugger attached)", CLR_GREEN);

    // 2. In-Memory Section Hash Verification
    std::string textHash = KawaiiSecurity::ComputeTextSectionHash();
    if (!textHash.empty()) {
        PrintStatus(" OK ", "In-Memory .text section integrity: " + textHash.substr(0, 16) + "...", CLR_GREEN);
    }

    // 3. Obfuscated Client Configuration
    const std::string APP_ID = skCrypt("kawaii_demo_app");
    const std::string APP_SECRET = skCrypt("demo_app_secret");
    const std::string APP_VERSION = skCrypt("1.0");
    const std::string API = skCrypt("http://127.0.0.1:8080");

    KawaiiAuth::Client auth(APP_ID, APP_SECRET, APP_VERSION, API);

    PrintStatus("HWID", "Hardware Identifier: " + auth.GetHWID(), CLR_BLUE);
    PrintStatus("INIT", "Negotiating dynamic cryptographic session with gateway...", CLR_CYAN);

    // Initialize Gateway Handshake with Anti-Replay
    if (!auth.Initialize(false)) {
        PrintStatus("FAIL", "Gateway handshake failed: " + auth.GetLastResponse().message, CLR_RED);
        std::cout << "\n" << CLR_YELLOW << "Press Enter to exit..." << CLR_RESET;
        std::cin.get();
        return 1;
    }

    std::string tokenShort = auth.GetSessionToken();
    if (tokenShort.length() > 16) tokenShort = tokenShort.substr(0, 16) + "...";
    PrintStatus(" OK ", "Gateway connected! Active Session: " + tokenShort, CLR_GREEN);

    // Check for saved license key
    std::string savedKey = LoadSavedKey();

    // 4. Interactive Main Menu
    std::cout << "\n" << CLR_CYAN << " ╔════════════════════════════════════════════════════════════════╗" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║" << CLR_BOLD << CLR_WHITE << "                  SELECT AUTHENTICATION MODE                    " << CLR_RESET << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ╠════════════════════════════════════════════════════════════════╣" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║ " << CLR_GREEN   << "[1] License Key Only (Instant 1-Step Auth)" << CLR_YELLOW << "  ★ Recommended " << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║ " << CLR_WHITE   << "[2] Account Login (Username & Password)                     " << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║ " << CLR_WHITE   << "[3] Account Register (Create Username, Password & Key)      " << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║ " << CLR_WHITE   << "[4] Session Status & Anti-Replay Diagnostics                " << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ║ " << CLR_GRAY    << "[0] Exit Application                                        " << CLR_CYAN << "║" << CLR_RESET << std::endl;
    std::cout << CLR_CYAN << " ╚════════════════════════════════════════════════════════════════╝" << CLR_RESET << std::endl;

    std::cout << "\n" << CLR_BOLD << CLR_CYAN << " Choice [1-4, default 1]: " << CLR_RESET;

    std::string choiceInput;
    std::getline(std::cin, choiceInput);
    int choice = 1;
    if (!choiceInput.empty()) {
        try {
            choice = std::stoi(choiceInput);
        } catch (...) {
            choice = 1;
        }
    }

    if (choice == 0) {
        std::cout << CLR_GRAY << "\nExiting application. Goodbye!" << CLR_RESET << std::endl;
        return 0;
    }

    KawaiiAuth::Response resp;

    if (choice == 2) {
        // Option 2: Account Login
        std::cout << "\n" << CLR_CYAN << "─── [ Account Login ] ──────────────────────────────────────────" << CLR_RESET << std::endl;
        std::string user, pass;
        std::cout << CLR_WHITE << " Enter Username: " << CLR_RESET;
        std::getline(std::cin, user);
        user = Trim(user);
        std::cout << CLR_WHITE << " Enter Password: " << CLR_RESET;
        pass = ReadPasswordMasked();

        PrintStatus("WAIT", "Authenticating credentials...", CLR_CYAN);
        resp = auth.Login(user, pass);

    } else if (choice == 3) {
        // Option 3: Account Register
        std::cout << "\n" << CLR_CYAN << "─── [ Account Registration ] ───────────────────────────────────" << CLR_RESET << std::endl;
        std::string user, pass, key;
        std::cout << CLR_WHITE << " Desired Username: " << CLR_RESET;
        std::getline(std::cin, user);
        user = Trim(user);
        std::cout << CLR_WHITE << " Desired Password: " << CLR_RESET;
        pass = ReadPasswordMasked();
        std::cout << CLR_WHITE << " License Key: " << CLR_RESET;
        std::getline(std::cin, key);
        key = Trim(key);

        PrintStatus("WAIT", "Registering account & binding license...", CLR_CYAN);
        resp = auth.Register(user, pass, key);

    } else if (choice == 4) {
        // Option 4: Session Status Diagnostic
        std::cout << "\n" << CLR_CYAN << "─── [ Session Diagnostics ] ────────────────────────────────────" << CLR_RESET << std::endl;
        PrintStatus("WAIT", "Querying /api/v1/action with cryptographic nonce & seq...", CLR_CYAN);
        KawaiiAuth::SessionStatus st = auth.CheckSession();
        
        std::cout << "\n" << CLR_CYAN << " ╔══════════════════════╦═════════════════════════════════════════╗" << CLR_RESET << std::endl;
        auto printDiag = [](const std::string& label, const std::string& val, const std::string& col = CLR_WHITE) {
            std::cout << CLR_CYAN << " ║ " << CLR_YELLOW << std::left << std::setw(20) << label 
                      << CLR_CYAN << " ║ " << col << std::left << std::setw(39) << val 
                      << CLR_CYAN << " ║" << CLR_RESET << std::endl;
        };
        printDiag("Gateway Response", st.success ? "SUCCESS" : "FAILED", st.success ? CLR_GREEN : CLR_RED);
        printDiag("Session Authed", st.authed ? "YES (Authenticated)" : "NO (Unauthenticated)", st.authed ? CLR_GREEN : CLR_YELLOW);
        printDiag("Message", st.message, CLR_WHITE);
        printDiag("Session Time Left", FormatDuration(st.session_time_left), CLR_CYAN);
        if (st.authed) {
            printDiag("Bound User", st.user.username + " (Lvl " + std::to_string(st.user.level) + ")", CLR_GREEN);
            printDiag("Subscription Left", FormatDuration(st.user.expires_at > (uint64_t)time(nullptr) ? st.user.expires_at - (uint64_t)time(nullptr) : 0), CLR_GREEN);
        }
        std::cout << CLR_CYAN << " ╚══════════════════════╩═════════════════════════════════════════╝" << CLR_RESET << std::endl;

        std::cout << "\n" << CLR_YELLOW << "Press Enter to exit..." << CLR_RESET;
        std::cin.get();
        return 0;

    } else {
        // Option 1 (Default): License Key Only
        std::cout << "\n" << CLR_CYAN << "─── [ License Key Access ] ─────────────────────────────────────" << CLR_RESET << std::endl;
        
        std::string prompt = " Enter License Key";
        if (!savedKey.empty()) {
            prompt += " [Press Enter for saved: " + savedKey + "]";
        } else {
            prompt += " (e.g. KAWAII-DEMO-KEY2)";
        }
        prompt += ": ";

        std::cout << CLR_WHITE << prompt << CLR_RESET;
        std::string key;
        std::getline(std::cin, key);
        key = Trim(key);

        if (key.empty()) {
            key = !savedKey.empty() ? savedKey : std::string(skCrypt("KAWAII-DEMO-KEY2"));
        }

        PrintStatus("WAIT", "Activating license with hardware lock & anti-replay...", CLR_CYAN);
        resp = auth.LicenseOnly(key);

        if (resp.success) {
            SaveKey(key);
        }
    }

    // 5. Result Evaluation
    if (!resp.success) {
        std::cout << "\n";
        PrintStatus("FAIL", "Authentication Rejected: " + resp.message, CLR_RED);
        std::cout << "\n" << CLR_YELLOW << "Press Enter to exit..." << CLR_RESET;
        std::cin.get();
        return 1;
    }

    // Immediate Session Verification after Auth
    KawaiiAuth::SessionStatus sess = auth.CheckSession();

    // Display Beautiful Profile Card
    DisplayProfileCard(resp.user, sess);

    // 6. Post-Authentication Asset Decryption & Telemetry
    std::cout << "\n" << CLR_CYAN << "─── [ Launching Protected Assets ] ─────────────────────────────" << CLR_RESET << std::endl;
    PrintStatus("LOAD", "Requesting protected server variables...", CLR_CYAN);
    std::string secretVar = auth.FetchVariable(skCrypt("payload_offset"));
    if (!secretVar.empty()) {
        PrintStatus(" OK ", "Decrypted server variable [payload_offset]: " + secretVar, CLR_GREEN);
    } else {
        PrintStatus("INFO", "Server variable [payload_offset]: (none or default)", CLR_GRAY);
    }

    // Dynamic Server-Decrypted Payload Streaming
    PrintStatus("LOAD", "Streaming protected binary payload from gateway into memory...", CLR_CYAN);
    KawaiiAuth::ProtectedPayload payload = auth.FetchProtectedPayload(skCrypt("core_module.bin"));
    if (payload.success && !payload.data.empty()) {
        PrintStatus(" OK ", "Decrypted in-memory payload [" + payload.name + "]: " + std::to_string(payload.size) + " bytes verified", CLR_GREEN);
        PrintStatus(" OK ", "Payload SHA-256 integrity: " + payload.hash.substr(0, 16) + "...", CLR_GREEN);
    } else {
        PrintStatus("WARN", "Protected payload: " + (payload.message.empty() ? "None available" : payload.message), CLR_YELLOW);
    }

    // Heartbeat verification
    if (auth.Ping()) {
        PrintStatus(" OK ", "Heartbeat ping verified (AES encrypted session synchronized)", CLR_GREEN);
    }

    // Audit telemetry
    auth.SendLog(skCrypt("Client successfully passed evasion gates and authenticated"));
    PrintStatus(" OK ", "Audit telemetry logged securely", CLR_GREEN);

    std::cout << "\n" << CLR_BOLD << CLR_GREEN << " [★] Software unlocked successfully! Ready to use." << CLR_RESET << std::endl;
    std::cout << CLR_GRAY << "\nPress Enter to terminate application..." << CLR_RESET;
    std::cin.get();
    return 0;
}
