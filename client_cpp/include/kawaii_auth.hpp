#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <wininet.h>

#include <wincrypt.h>

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

    struct HttpResponse {
        int statusCode = 0;
        std::string body;
        std::string signature;
        std::string timestamp;
        std::string algorithm;
    };

    struct SessionStatus {
        bool success = false;
        bool authed = false;
        std::string message;
        std::string session_token;
        uint64_t session_expires_at = 0;
        uint64_t session_time_left = 0;
        UserData user;

        SessionStatus() = default;
    };

    class Client {
    public:
        Client(
            const std::string& app_id,
            const std::string& app_secret,
            const std::string& version,
            const std::string& api = "http://127.0.0.1:8080"
        );
        ~Client();

        // Core lifecycle
        bool Initialize(bool enforce_integrity = false);
        Response Register(const std::string& username, const std::string& password, const std::string& license_key);
        Response Login(const std::string& username, const std::string& password);
        Response LicenseOnly(const std::string& license_key);
        bool Ping();
        SessionStatus CheckSession();
        bool IsAuthed();

        // Assets and Telemetry
        std::string FetchVariable(const std::string& var_key);
        std::vector<uint8_t> DownloadFile(const std::string& file_name);
        bool SendLog(const std::string& log_message);

        // Verification & Security
        bool VerifyServerSignature(const std::string& body, const std::string& timestamp, const std::string& sig_b64);

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
        uint64_t m_request_seq = 0;

        HINTERNET m_hInternet = nullptr;
        HINTERNET m_hConnect = nullptr;

        // Internal Helpers
        std::string GenerateNonce(size_t byte_count = 16);
        std::string ComputeHWID();
        std::string HashSHA256(const std::string& input);
        std::string EncryptAES256WithKey(const std::string& plaintext, const std::string& keyHex, const std::string& ivHex);
        std::string DecryptAES256WithKey(const std::string& ciphertext_b64, const std::string& keyHex, const std::string& ivHex);
        std::string EncryptAES256(const std::string& plaintext);
        std::string DecryptAES256(const std::string& ciphertext_b64);
        HttpResponse SendHttpRequest(const std::string& path, const std::string& post_data, const std::string& extra_header = "");
    };

}
