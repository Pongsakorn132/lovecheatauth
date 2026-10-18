#pragma once

/**
 * ============================================================================
 * KawaiiAuth SDK - Enterprise C++ Authentication Library
 * ============================================================================
 * 
 * Usage in any C++ Project:
 *   #include "KawaiiAuth.h"
 *   (KawaiiAuth.lib will be automatically linked via MSVC #pragma comment)
 * 
 * Example:
 *   if (!KawaiiAuth::Init("kawaii_demo_app", "demo_app_secret", "1.0", "http://127.0.0.1:8080")) {
 *       std::cout << "Init error: " << KawaiiAuth::GetLastError() << std::endl;
 *       return 1;
 *   }
 *   
 *   auto auth = KawaiiAuth::LicenseLogin("YOUR-LICENSE-KEY");
 *   if (!auth) {
 *       std::cout << "Auth failed: " << auth.message << std::endl;
 *       return 1;
 *   }
 *   
 *   std::cout << "Logged in! Expiry left: " << KawaiiAuth::GetFormattedTimeLeft() << std::endl;
 * ============================================================================
 */

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

#if defined(_MSC_VER) && !defined(KAWAII_AUTH_NO_AUTOLINK)
    #pragma comment(lib, "KawaiiAuth.lib")
    #pragma comment(lib, "wininet.lib")
    #pragma comment(lib, "bcrypt.lib")
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "user32.lib")
#endif

namespace KawaiiAuth {

    struct Config {
        std::string app_id;
        std::string app_secret;
        std::string version = "1.0";
        std::string api = "http://127.0.0.1:8080";
        bool enforce_integrity = false;
        bool ignore_ssl_errors = false;
    };

    struct UserInfo {
        std::string username;
        uint64_t expires_at = 0;
        uint64_t seconds_left = 0;
        int level = 0;
        std::string hwid;
    };

    struct ProtectedPayload {
        bool success = false;
        std::string message;
        std::string name;
        std::string hash;
        size_t size = 0;
        std::vector<uint8_t> data;

        explicit operator bool() const { return success; }
    };

    struct AuthResult {
        bool success = false;
        std::string message;
        UserInfo user;

        explicit operator bool() const { return success; }
    };

    struct SessionInfo {
        bool success = false;
        bool authed = false;
        std::string message;
        std::string session_token;
        uint64_t session_expires_at = 0;
        uint64_t session_time_left = 0;
        UserInfo user;

        explicit operator bool() const { return authed; }
    };

    // ========================================================================
    // GLOBAL CONVENIENCE API (Single-Instance / Quick Integration)
    // ========================================================================

    /**
     * @brief Initialize the global KawaiiAuth instance
     */
    bool Init(const Config& config);
    bool Init(
        const std::string& app_id,
        const std::string& app_secret,
        const std::string& version = "1.0",
        const std::string& api = "http://127.0.0.1:8080",
        bool enforce_integrity = false
    );

    /**
     * @brief Authenticate using only a License Key
     */
    AuthResult LicenseLogin(const std::string& license_key);

    /**
     * @brief Authenticate using a Username & Password
     */
    AuthResult Login(const std::string& username, const std::string& password);

    /**
     * @brief Register a new user with Username, Password, and License Key
     */
    AuthResult Register(const std::string& username, const std::string& password, const std::string& license_key);

    /**
     * @brief Verify the current session status against the server
     */
    SessionInfo CheckSession();

    /**
     * @brief Check if the client is currently authenticated
     */
    bool IsAuthed();

    /**
     * @brief Ping the server to check connectivity
     */
    bool Ping();

    /**
     * @brief Fetch a protected server-side variable (e.g. game offset, payload)
     */
    std::string GetVariable(const std::string& var_key);

    /**
     * @brief Download a protected file from the server
     */
    std::vector<uint8_t> DownloadFile(const std::string& file_name);

    /**
     * @brief Fetch protected server-side payload with in-memory SHA-256 integrity verification
     */
    ProtectedPayload FetchProtectedPayload(const std::string& payload_name);

    /**
     * @brief Send an audit log message to the server
     */
    bool Log(const std::string& message);

    /**
     * @brief Run local anti-debugging, hardware breakpoint and evasion checks
     * @return true if environment is safe, false if debugger or analysis tool is detected
     */
    bool RunSecurityChecks();

    /**
     * @brief Quick accessors for the current authenticated session
     */
    UserInfo GetUser();
    std::string GetHWID();
    std::string GetSessionToken();
    std::string GetLastError();
    uint64_t GetSecondsLeft();
    std::string GetFormattedTimeLeft();

    /**
     * @brief Server metadata & update status
     */
    std::string GetLatestVersion();
    std::string GetDownloadUrl();
    bool IsUpdateRequired();
    bool IsMaintenance();

    // ========================================================================
    // KEY & OFFSET BROKER API (Zero-Server-Footprint Protected Binary Loader)
    // ========================================================================

    /**
     * @brief Fetch an offset variable from server and parse as memory address/offset
     * @param var_key Name of the variable on dashboard (e.g. "OFFSET_UWORLD")
     * @param default_val Fallback value if variable is missing or invalid
     * @return Parsed uintptr_t offset
     */
    uintptr_t GetBrokerOffset(const std::string& var_key, uintptr_t default_val = 0);

    /**
     * @brief Fetch a secret broker / decryption key from server using file_id (or variable key)
     * @param file_id File ID from Application Files & Payloads (e.g. "core_module") or variable key
     */
    std::string GetBrokerKey(const std::string& file_id);
    std::string GetFileKey(const std::string& file_id);

    /**
     * @brief Decrypt in-memory binary payload with AES-256 using key fetched from server by file_id
     * @param file_id File ID from Application Files & Payloads (e.g. "core_module")
     * @param encrypted_data Raw encrypted binary data
     * @param custom_iv Optional custom IV. If empty, reads prepended 16-byte IV from ciphertext.
     * @return Decrypted executable/DLL payload bytes in RAM
     */
    std::vector<uint8_t> UnlockBrokerMemory(
        const std::string& file_id,
        const std::vector<uint8_t>& encrypted_data,
        const std::string& custom_iv = ""
    );

    /**
     * @brief Zero-Server-Footprint Broker Unlock:
     * Request decryption key directly from server by file_id, decrypt local payload into RAM,
     * and securely zero memory of key. The client code never handles or stores any decryption key.
     * 
     * @param file_id File ID (fileid) registered on dashboard (e.g. "core_module" or UUID)
     * @param file_path Optional local file path (e.g. "core_module.bin"). If empty, tries file_id, file_id + ".bin", or registered file_name.
     * @param custom_iv Optional custom IV. If empty, reads prepended 16-byte IV.
     * @return Decrypted executable/DLL payload bytes in RAM (never touches disk)
     */
    std::vector<uint8_t> UnlockBrokerFile(
        const std::string& file_id,
        const std::string& file_path = "",
        const std::string& custom_iv = ""
    );

    /**
     * @brief Standalone helper to decrypt binary buffer with AES-256-CBC in RAM
     */
    std::vector<uint8_t> DecryptBrokerPayload(
        const std::vector<uint8_t>& encrypted_data,
        const std::string& key,
        const std::string& custom_iv = ""
    );

    /**
     * @brief Standalone helper to encrypt binary buffer with AES-256-CBC (prepends 16-byte IV)
     */
    std::vector<uint8_t> EncryptBrokerPayload(
        const std::vector<uint8_t>& raw_data,
        const std::string& key,
        const std::string& custom_iv = ""
    );


    // ========================================================================
    // OBJECT-ORIENTED CLIENT CLASS (For advanced / multi-instance use cases)
    // ========================================================================

    class Client {
    public:
        explicit Client(const Config& config);
        Client(
            const std::string& app_id,
            const std::string& app_secret,
            const std::string& version = "1.0",
            const std::string& api = "http://127.0.0.1:8080"
        );
        ~Client();

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
        Client(Client&&) noexcept;
        Client& operator=(Client&&) noexcept;

        bool Initialize(bool enforce_integrity = false);
        AuthResult Register(const std::string& username, const std::string& password, const std::string& license_key);
        AuthResult Login(const std::string& username, const std::string& password);
        AuthResult LicenseOnly(const std::string& license_key);
        bool Ping();
        SessionInfo CheckSession();
        bool IsAuthed() const;

        std::string FetchVariable(const std::string& var_key);
        std::vector<uint8_t> DownloadFile(const std::string& file_name);
        ProtectedPayload FetchProtectedPayload(const std::string& payload_name);
        bool SendLog(const std::string& log_message);

        // Key & Offset Broker Methods
        uintptr_t GetBrokerOffset(const std::string& var_key, uintptr_t default_val = 0);
        std::string GetBrokerKey(const std::string& file_id);
        std::string GetFileKey(const std::string& file_id);
        std::vector<uint8_t> UnlockBrokerMemory(
            const std::string& file_id,
            const std::vector<uint8_t>& encrypted_data,
            const std::string& custom_iv = ""
        );
        std::vector<uint8_t> UnlockBrokerFile(
            const std::string& file_id,
            const std::string& file_path = "",
            const std::string& custom_iv = ""
        );
        std::vector<uint8_t> DecryptBrokerPayload(
            const std::vector<uint8_t>& encrypted_data,
            const std::string& key,
            const std::string& custom_iv = ""
        );
        std::vector<uint8_t> EncryptBrokerPayload(
            const std::vector<uint8_t>& raw_data,
            const std::string& key,
            const std::string& custom_iv = ""
        );

        void SetIgnoreSslErrors(bool ignore);

        const std::string& GetHWID() const;
        const std::string& GetSessionToken() const;
        const AuthResult& GetLastResponse() const;
        UserInfo GetUser() const;
        uint64_t GetSecondsLeft() const;
        std::string GetFormattedTimeLeft() const;

        const std::string& GetLatestVersion() const;
        const std::string& GetDownloadUrl() const;
        bool IsUpdateRequired() const;
        bool IsMaintenance() const;

    public:
        class Impl;
    private:
        std::unique_ptr<Impl> m_impl;
    };

} // namespace KawaiiAuth
