#include "kawaii_auth.hpp"
#include "json.hpp"
#include "skCrypter.hpp"
#include "security.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <bcrypt.h>
#include <intrin.h>

using json = nlohmann::json;

namespace KawaiiAuth {

    static std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    static std::string Base64Encode(const std::vector<uint8_t>& data) {
        DWORD len = 0;
        CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
        std::string result(len, '\0');
        CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &len);
        if (!result.empty() && result.back() == '\0') result.pop_back();
        return result;
    }

    static std::vector<uint8_t> Base64Decode(const std::string& b64) {
        DWORD len = 0;
        CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.length()), CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr);
        std::vector<uint8_t> result(len);
        CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.length()), CRYPT_STRING_BASE64, result.data(), &len, nullptr, nullptr);
        return result;
    }

    Client::Client(
        const std::string& app_id,
        const std::string& app_secret,
        const std::string& version,
        const std::string& host,
        INTERNET_PORT port,
        bool use_ssl
    ) : m_app_id(app_id),
        m_app_secret(app_secret),
        m_version(version),
        m_host(host),
        m_port(port),
        m_use_ssl(use_ssl)
    {
        m_hwid = ComputeHWID();
        m_hInternet = InternetOpenA(skCrypt("KawaiiAuth-Native/1.0"), INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (m_hInternet) {
            m_hConnect = InternetConnectA(m_hInternet, m_host.c_str(), m_port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        }
    }

    Client::~Client() {
        if (m_hConnect) InternetCloseHandle(m_hConnect);
        if (m_hInternet) InternetCloseHandle(m_hInternet);
    }

    std::string Client::HashSHA256(const std::string& input) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::string hashHex = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
            DWORD hashObjSize = 0, dataLen = 0;
            BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjSize, sizeof(DWORD), &dataLen, 0);
            std::vector<uint8_t> hashObj(hashObjSize);
            std::vector<uint8_t> hashVal(32);

            if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0) == 0) {
                BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.length(), 0);
                BCryptFinishHash(hHash, hashVal.data(), (ULONG)hashVal.size(), 0);
                BCryptDestroyHash(hHash);

                std::ostringstream oss;
                for (uint8_t b : hashVal) {
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                }
                hashHex = oss.str();
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        return hashHex;
    }

    std::string Client::ComputeHWID() {
        std::ostringstream raw;

        // 1. Volume Serial Number
        DWORD volSerial = 0;
        char rootPath[] = { 'C', ':', '\\', '\0' };
        if (GetVolumeInformationA(rootPath, nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0)) {
            raw << "VOL:" << std::hex << volSerial << ";";
        }

        // 2. Hardware CPU Signature (Pinned to Core 0 + Masked APIC ID)
        DWORD_PTR oldMask = SetThreadAffinityMask(GetCurrentThread(), 1);
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        // Mask out bits 24-31 (Initial APIC ID) from EBX so it never varies by scheduled core
        int ebxStable = cpuInfo[1] & 0x00FFFFFF;
        raw << "CPU:" << std::hex << cpuInfo[0] << "-" << ebxStable << "-" << cpuInfo[2] << "-" << cpuInfo[3] << ";";
        if (oldMask) SetThreadAffinityMask(GetCurrentThread(), oldMask);

        // 3. Motherboard UUID (SMBIOS Type 1)
        DWORD smbiosSize = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (smbiosSize > 0) {
            std::vector<uint8_t> smbios(smbiosSize);
            if (GetSystemFirmwareTable('RSMB', 0, smbios.data(), smbiosSize) == smbiosSize) {
                const uint8_t* p = smbios.data();
                const uint8_t* end = p + smbiosSize;
                while (p + 4 < end) {
                    uint8_t type = p[0];
                    uint8_t length = p[1];
                    if (type == 1 && length >= 0x18) {
                        raw << "UUID:";
                        for (int i = 8; i < 24; ++i) {
                            raw << std::hex << std::setw(2) << std::setfill('0') << (int)p[i];
                        }
                        raw << ";";
                        break;
                    }
                    p += length;
                    while (p + 1 < end && (p[0] != 0 || p[1] != 0)) p++;
                    p += 2;
                }
            }
        }

        // 4. Computer Name
        char compName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD compLen = sizeof(compName);
        if (GetComputerNameA(compName, &compLen)) {
            raw << "NAME:" << compName << ";";
        }

        return HashSHA256(raw.str());
    }

    std::string Client::EncryptAES256(const std::string& plaintext) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::string resultB64 = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return "";
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        DWORD keyObjSize = 0, dataLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(DWORD), &dataLen, 0);
        std::vector<uint8_t> keyObj(keyObjSize);

        auto keyBytes = HexToBytes(m_session_key_hex);
        auto ivBytes = HexToBytes(m_session_iv_hex);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize, keyBytes.data(), (ULONG)keyBytes.size(), 0) == 0) {
            DWORD outSize = 0;
            BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.length(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), nullptr, 0, &outSize, BCRYPT_BLOCK_PADDING);
            std::vector<uint8_t> cipherBytes(outSize);
            
            ivBytes = HexToBytes(m_session_iv_hex);
            if (BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.length(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), cipherBytes.data(), outSize, &outSize, BCRYPT_BLOCK_PADDING) == 0) {
                cipherBytes.resize(outSize);
                resultB64 = Base64Encode(cipherBytes);
            }
            BCryptDestroyKey(hKey);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return resultB64;
    }

    std::string Client::DecryptAES256(const std::string& ciphertext_b64) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::string plaintext = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return "";
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        DWORD keyObjSize = 0, dataLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(DWORD), &dataLen, 0);
        std::vector<uint8_t> keyObj(keyObjSize);

        auto keyBytes = HexToBytes(m_session_key_hex);
        auto ivBytes = HexToBytes(m_session_iv_hex);
        auto cipherBytes = Base64Decode(ciphertext_b64);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize, keyBytes.data(), (ULONG)keyBytes.size(), 0) == 0) {
            DWORD outSize = 0;
            BCryptDecrypt(hKey, cipherBytes.data(), (ULONG)cipherBytes.size(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), nullptr, 0, &outSize, BCRYPT_BLOCK_PADDING);
            std::vector<uint8_t> plainBytes(outSize);

            ivBytes = HexToBytes(m_session_iv_hex);
            if (BCryptDecrypt(hKey, cipherBytes.data(), (ULONG)cipherBytes.size(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), plainBytes.data(), outSize, &outSize, BCRYPT_BLOCK_PADDING) == 0) {
                plainBytes.resize(outSize);
                plaintext = std::string(plainBytes.begin(), plainBytes.end());
            }
            BCryptDestroyKey(hKey);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    std::string Client::SendHttpRequest(const std::string& path, const std::string& post_data, const std::string& extra_header) {
        if (!m_hConnect) return "";

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (m_use_ssl) flags |= INTERNET_FLAG_SECURE;

        HINTERNET hRequest = HttpOpenRequestA(m_hConnect, skCrypt("POST"), path.c_str(), nullptr, nullptr, nullptr, flags, 0);
        if (!hRequest) return "";

        std::string headers = skCrypt("Content-Type: application/json\r\n");
        if (!extra_header.empty()) {
            headers += extra_header + "\r\n";
        }

        BOOL sent = HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)post_data.c_str(), (DWORD)post_data.length());
        if (!sent) {
            InternetCloseHandle(hRequest);
            return "";
        }

        std::string responseStr = "";
        char buffer[4096];
        DWORD bytesRead = 0;

        while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            responseStr.append(buffer, bytesRead);
        }

        InternetCloseHandle(hRequest);
        return responseStr;
    }

    bool Client::Initialize(bool enforce_integrity) {
        // 1. Anti-Debug and Evasion Gate
        if (!KawaiiSecurity::ExecuteEvasionGates()) {
            m_last_response = { false, skCrypt("Security policy violation: unauthorized debugger or analysis tool detected") };
            return false;
        }

        std::string textHash = enforce_integrity ? KawaiiSecurity::ComputeTextSectionHash() : "";

        json initPayload = {
            { skCrypt("app_id"), m_app_id },
            { skCrypt("version"), m_version },
            { skCrypt("client_hash"), textHash }
        };

        std::string response = SendHttpRequest(skCrypt("/api/v1/init"), initPayload.dump());
        if (response.empty()) {
            m_last_response = { false, skCrypt("Connection failed to authentication server") };
            return false;
        }

        try {
            auto j = json::parse(response);
            if (j.value(skCrypt("success"), false)) {
                m_session_token = j.value(skCrypt("session_token"), "");
                m_session_key_hex = j.value(skCrypt("session_key"), "");
                m_session_iv_hex = j.value(skCrypt("session_iv"), "");
                m_last_response = { true, j.value(skCrypt("message"), skCrypt("Initialized")) };
                return true;
            } else {
                m_last_response = { false, j.value(skCrypt("message"), skCrypt("Initialization rejected")) };
                return false;
            }
        } catch (...) {
            m_last_response = { false, skCrypt("JSON parse failure on /init") };
            return false;
        }
    }

    Response Client::Login(const std::string& username, const std::string& password) {
        if (m_session_token.empty()) return { false, skCrypt("Session uninitialized") };

        json payload = {
            { skCrypt("action"), skCrypt("login") },
            { skCrypt("username"), username },
            { skCrypt("password"), password },
            { skCrypt("hwid"), m_hwid },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        std::string rawResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        try {
            auto outer = json::parse(rawResp);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            Response r;
            r.success = inner.value(skCrypt("success"), false);
            r.message = inner.value(skCrypt("message"), "");
            if (r.success && inner.contains(skCrypt("user"))) {
                auto u = inner[skCrypt("user")];
                r.user.username = u.value(skCrypt("username"), "");
                r.user.expires_at = u.value(skCrypt("expires_at"), 0ULL);
                r.user.level = u.value(skCrypt("level"), 0);
                r.user.hwid = u.value(skCrypt("hwid"), "");
            }
            m_last_response = r;
            return r;
        } catch (...) {
            return { false, skCrypt("Decryption or response parse error") };
        }
    }

    Response Client::Register(const std::string& username, const std::string& password, const std::string& license_key) {
        if (m_session_token.empty()) return { false, skCrypt("Session uninitialized") };

        json payload = {
            { skCrypt("action"), skCrypt("register") },
            { skCrypt("username"), username },
            { skCrypt("password"), password },
            { skCrypt("key"), license_key },
            { skCrypt("hwid"), m_hwid },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        std::string rawResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        try {
            auto outer = json::parse(rawResp);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            Response r;
            r.success = inner.value(skCrypt("success"), false);
            r.message = inner.value(skCrypt("message"), "");
            if (r.success && inner.contains(skCrypt("user"))) {
                auto u = inner[skCrypt("user")];
                r.user.username = u.value(skCrypt("username"), "");
                r.user.expires_at = u.value(skCrypt("expires_at"), 0ULL);
                r.user.level = u.value(skCrypt("level"), 0);
                r.user.hwid = u.value(skCrypt("hwid"), "");
            }
            m_last_response = r;
            return r;
        } catch (...) {
            return { false, skCrypt("Decryption or registration parse error") };
        }
    }

    Response Client::LicenseOnly(const std::string& license_key) {
        if (m_session_token.empty()) return { false, skCrypt("Session uninitialized") };

        json payload = {
            { skCrypt("action"), skCrypt("license_only") },
            { skCrypt("key"), license_key },
            { skCrypt("hwid"), m_hwid },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        std::string rawResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        try {
            auto outer = json::parse(rawResp);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            Response r;
            r.success = inner.value(skCrypt("success"), false);
            r.message = inner.value(skCrypt("message"), "");
            if (r.success && inner.contains(skCrypt("user"))) {
                auto u = inner[skCrypt("user")];
                r.user.username = u.value(skCrypt("username"), "");
                r.user.expires_at = u.value(skCrypt("expires_at"), 0ULL);
                r.user.level = u.value(skCrypt("level"), 0);
                r.user.hwid = u.value(skCrypt("hwid"), "");
            }
            m_last_response = r;
            return r;
        } catch (...) {
            return { false, skCrypt("Decryption or license parse error") };
        }
    }

    bool Client::Ping() {
        if (m_session_token.empty()) return false;
        json payload = {
            { skCrypt("action"), skCrypt("ping") },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        std::string rawResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        try {
            auto outer = json::parse(rawResp);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);
            return inner.value(skCrypt("success"), false);
        } catch (...) {
            return false;
        }
    }

    std::string Client::FetchVariable(const std::string& var_key) {
        if (m_session_token.empty()) return "";
        json payload = {
            { skCrypt("action"), skCrypt("fetch_var") },
            { skCrypt("var_key"), var_key },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        std::string rawResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        try {
            auto outer = json::parse(rawResp);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);
            if (inner.value(skCrypt("success"), false)) {
                return inner.value(skCrypt("var_value"), "");
            }
        } catch (...) {}
        return "";
    }

    std::vector<uint8_t> Client::DownloadFile(const std::string& file_name) {
        if (m_session_token.empty()) return {};
        json payload = {
            { skCrypt("action"), skCrypt("download_file") },
            { skCrypt("file_name"), file_name },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        std::string rawResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        try {
            auto outer = json::parse(rawResp);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);
            if (inner.value(skCrypt("success"), false)) {
                std::string b64 = inner.value(skCrypt("file_data"), "");
                return Base64Decode(b64);
            }
        } catch (...) {}
        return {};
    }

    bool Client::SendLog(const std::string& log_message) {
        if (m_session_token.empty()) return false;
        json payload = {
            { skCrypt("action"), skCrypt("log") },
            { skCrypt("log_message"), log_message },
            { skCrypt("timestamp"), (uint64_t)time(nullptr) }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;
        SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        return true;
    }

}
