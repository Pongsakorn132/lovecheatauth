#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace KawaiiAuth {

    struct UserData {
        std::string username;
        uint64_t expires_at = 0;
        int level = 0;
        std::string hwid;
    };

    struct Response {
        bool success = false;
        std::string message;
        UserData user;

        Response() = default;
        Response(bool s, const std::string& m) : success(s), message(m) {}
        Response(bool s, const std::string& m, const UserData& u) : success(s), message(m), user(u) {}
    };

    class Client {
    public:
        Client(
            const std::string& app_id,
            const std::string& app_secret,
            const std::string& version,
            const std::string& host,
            INTERNET_PORT port = 8080,
            bool use_ssl = false
        );
        ~Client();

        // Core lifecycle
        bool Initialize(bool enforce_integrity = false);
        Response Register(const std::string& username, const std::string& password, const std::string& license_key);
        Response Login(const std::string& username, const std::string& password);
        Response LicenseOnly(const std::string& license_key);
        bool Ping();

        // Assets and Telemetry
        std::string FetchVariable(const std::string& var_key);
        std::vector<uint8_t> DownloadFile(const std::string& file_name);
        bool SendLog(const std::string& log_message);

        // Accessors
        const std::string& GetHWID() const { return m_hwid; }
        const std::string& GetSessionToken() const { return m_session_token; }
        const Response& GetLastResponse() const { return m_last_response; }

    private:
        std::string m_app_id;
        std::string m_app_secret;
        std::string m_version;
        std::string m_host;
        INTERNET_PORT m_port;
        bool m_use_ssl;

        std::string m_session_token;
        std::string m_session_key_hex;
        std::string m_session_iv_hex;
        std::string m_hwid;
        Response m_last_response;

        HINTERNET m_hInternet = nullptr;
        HINTERNET m_hConnect = nullptr;

        // Internal Helpers
        std::string ComputeHWID();
        std::string HashSHA256(const std::string& input);
        std::string EncryptAES256(const std::string& plaintext);
        std::string DecryptAES256(const std::string& ciphertext_b64);
        std::string SendHttpRequest(const std::string& path, const std::string& post_data, const std::string& extra_header = "");
    };

}
