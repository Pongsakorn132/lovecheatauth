#include "KawaiiAuth.h"
#include "KawaiiAuth_impl.hpp"

namespace KawaiiAuth {

    // ========================================================================
    // Global Static State (Thread-Safe)
    // ========================================================================
    static std::mutex g_authMutex;
    static std::unique_ptr<Client> g_defaultClient = nullptr;
    static std::string g_lastGlobalError = "";

    // ========================================================================
    // Client Class Implementation (PIMPL forwarding)
    // ========================================================================
    Client::Client(const Config& config) 
        : m_impl(std::make_unique<Impl>(config)) {}

    Client::Client(
        const std::string& app_id,
        const std::string& app_secret,
        const std::string& version,
        const std::string& api
    ) {
        Config cfg;
        cfg.app_id = app_id;
        cfg.app_secret = app_secret;
        cfg.version = version;
        cfg.api = api;
        m_impl = std::make_unique<Impl>(cfg);
    }

    Client::~Client() = default;

    Client::Client(Client&&) noexcept = default;
    Client& Client::operator=(Client&&) noexcept = default;

    bool Client::Initialize(bool enforce_integrity) {
        return m_impl->Initialize(enforce_integrity);
    }

    AuthResult Client::Register(const std::string& username, const std::string& password, const std::string& license_key) {
        return m_impl->Register(username, password, license_key);
    }

    AuthResult Client::Login(const std::string& username, const std::string& password) {
        return m_impl->Login(username, password);
    }

    AuthResult Client::LicenseOnly(const std::string& license_key) {
        return m_impl->LicenseOnly(license_key);
    }

    bool Client::Ping() {
        return m_impl->Ping();
    }

    SessionInfo Client::CheckSession() {
        return m_impl->CheckSession();
    }

    bool Client::IsAuthed() const {
        return m_impl->CheckSession().authed;
    }

    std::string Client::FetchVariable(const std::string& var_key) {
        return m_impl->FetchVariable(var_key);
    }

    std::vector<uint8_t> Client::DownloadFile(const std::string& file_id) {
        return m_impl->DownloadFile(file_id);
    }

    ProtectedPayload Client::FetchProtectedPayload(const std::string& file_id) {
        return m_impl->FetchProtectedPayload(file_id);
    }

    bool Client::SendLog(const std::string& log_message) {
        return m_impl->SendLog(log_message);
    }

    void Client::SetIgnoreSslErrors(bool ignore) {
        m_impl->SetIgnoreSslErrors(ignore);
    }

    const std::string& Client::GetHWID() const {
        return m_impl->m_hwid;
    }

    const std::string& Client::GetSessionToken() const {
        return m_impl->m_session_token;
    }

    const AuthResult& Client::GetLastResponse() const {
        return m_impl->m_last_response;
    }

    UserInfo Client::GetUser() const {
        return m_impl->m_last_response.user;
    }

    uint64_t Client::GetSecondsLeft() const {
        return m_impl->GetSecondsLeft();
    }

    std::string Client::GetFormattedTimeLeft() const {
        return m_impl->GetFormattedTimeLeft();
    }

    const std::string& Client::GetLatestVersion() const {
        return m_impl->GetLatestVersion();
    }

    const std::string& Client::GetDownloadUrl() const {
        return m_impl->GetDownloadUrl();
    }

    bool Client::IsUpdateRequired() const {
        return m_impl->IsUpdateRequired();
    }

    bool Client::IsMaintenance() const {
        return m_impl->IsMaintenance();
    }


    // ========================================================================
    // Global Convenience Functions Implementation
    // ========================================================================

    bool Init(const Config& config) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        g_defaultClient = std::make_unique<Client>(config);
        bool ok = g_defaultClient->Initialize(config.enforce_integrity);
        if (!ok) {
            g_lastGlobalError = g_defaultClient->GetLastResponse().message;
        }
        return ok;
    }

    bool Init(
        const std::string& app_id,
        const std::string& app_secret,
        const std::string& version,
        const std::string& api,
        bool enforce_integrity
    ) {
        Config cfg;
        cfg.app_id = app_id;
        cfg.app_secret = app_secret;
        cfg.version = version;
        cfg.api = api;
        cfg.enforce_integrity = enforce_integrity;
        return Init(cfg);
    }

    AuthResult LicenseLogin(const std::string& license_key) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) {
            g_lastGlobalError = "KawaiiAuth is not initialized. Call KawaiiAuth::Init() first.";
            return { false, g_lastGlobalError };
        }
        auto res = g_defaultClient->LicenseOnly(license_key);
        if (!res) g_lastGlobalError = res.message;
        return res;
    }

    AuthResult Login(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) {
            g_lastGlobalError = "KawaiiAuth is not initialized. Call KawaiiAuth::Init() first.";
            return { false, g_lastGlobalError };
        }
        auto res = g_defaultClient->Login(username, password);
        if (!res) g_lastGlobalError = res.message;
        return res;
    }

    AuthResult Register(const std::string& username, const std::string& password, const std::string& license_key) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) {
            g_lastGlobalError = "KawaiiAuth is not initialized. Call KawaiiAuth::Init() first.";
            return { false, g_lastGlobalError };
        }
        auto res = g_defaultClient->Register(username, password, license_key);
        if (!res) g_lastGlobalError = res.message;
        return res;
    }

    SessionInfo CheckSession() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) {
            SessionInfo s;
            s.success = false;
            s.authed = false;
            s.message = "KawaiiAuth is not initialized. Call KawaiiAuth::Init() first.";
            return s;
        }
        return g_defaultClient->CheckSession();
    }

    bool IsAuthed() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return false;
        return g_defaultClient->IsAuthed();
    }

    bool Ping() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return false;
        return g_defaultClient->Ping();
    }

    std::string GetVariable(const std::string& var_key) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return "";
        return g_defaultClient->FetchVariable(var_key);
    }

    std::vector<uint8_t> DownloadFile(const std::string& file_id) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return {};
        return g_defaultClient->DownloadFile(file_id);
    }

    ProtectedPayload FetchProtectedPayload(const std::string& file_id) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) {
            ProtectedPayload p;
            p.success = false;
            p.message = "KawaiiAuth is not initialized. Call KawaiiAuth::Init() first.";
            return p;
        }
        return g_defaultClient->FetchProtectedPayload(file_id);
    }

    bool Log(const std::string& message) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return false;
        return g_defaultClient->SendLog(message);
    }

    bool RunSecurityChecks() {
        return KawaiiSecurity::ExecuteEvasionGates();
    }

    UserInfo GetUser() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return {};
        return g_defaultClient->GetUser();
    }

    std::string GetHWID() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return "";
        return g_defaultClient->GetHWID();
    }

    std::string GetSessionToken() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return "";
        return g_defaultClient->GetSessionToken();
    }

    std::string GetLastError() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        return g_lastGlobalError;
    }

    uint64_t GetSecondsLeft() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return 0;
        return g_defaultClient->GetSecondsLeft();
    }

    std::string GetFormattedTimeLeft() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return "Expired / None";
        return g_defaultClient->GetFormattedTimeLeft();
    }

    std::string GetLatestVersion() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return "";
        return g_defaultClient->GetLatestVersion();
    }

    std::string GetDownloadUrl() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return "";
        return g_defaultClient->GetDownloadUrl();
    }

    bool IsUpdateRequired() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return false;
        return g_defaultClient->IsUpdateRequired();
    }

    bool IsMaintenance() {
        std::lock_guard<std::mutex> lock(g_authMutex);
        if (!g_defaultClient) return false;
        return g_defaultClient->IsMaintenance();
    }

} // namespace KawaiiAuth
