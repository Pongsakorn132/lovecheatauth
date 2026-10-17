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

    // Server RSA Public Key (Used strictly for signature verification)
    static const char* SERVER_PUBLIC_KEY_PEM = 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtM89CKg1mvXbUws2w75s\n"
        "ktY8G+hpGSdP0Y03Jsxu9XqypEwji2b8kS5+EC1Ew0oQ3gFffTI5aAt306waqBe6\n"
        "U4Fn1Qbs+uwy/yNYnqg73Tr0dJT2GxQg+OcX32cPRA/SzqRwpJ9BR2E/lnivflrC\n"
        "UD3WERT5BqRbqbPF8nq/DQVkbUVdHQGsG7HaxyTHtgre5zTdZ/BkZHXMtsubEEgN\n"
        "6xfh/gwkF6bNFZvygKJ9J1NHcNOa/wjX7oXjOfVQqy2UevJ7uK+tK+rZh6DlElPG\n"
        "z82Z8BVMXlwEI6/xdUjSMhWNgW4i9S84Wxp9vjeB9tCnmd3hSREuxjoFxMjK6Wq0\n"
        "/QIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

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

    static void ParseServerUrl(const std::string& input, std::string& outHost, INTERNET_PORT& outPort, bool& outSsl) {
        std::string str = input;
        outSsl = false;
        outPort = 8080;

        if (str.rfind("https://", 0) == 0) {
            outSsl = true;
            outPort = 443;
            str = str.substr(8);
        } else if (str.rfind("http://", 0) == 0) {
            outSsl = false;
            outPort = 80;
            str = str.substr(7);
        }

        size_t slashPos = str.find('/');
        if (slashPos != std::string::npos) {
            str = str.substr(0, slashPos);
        }

        size_t colonPos = str.find(':');
        if (colonPos != std::string::npos) {
            outHost = str.substr(0, colonPos);
            try {
                int p = std::stoi(str.substr(colonPos + 1));
                if (p > 0 && p <= 65535) {
                    outPort = static_cast<INTERNET_PORT>(p);
                }
            } catch (...) {}
        } else {
            outHost = str;
            if (!outSsl && (outHost == "127.0.0.1" || outHost == "localhost")) {
                outPort = 8080;
            }
        }

        if (outHost.empty()) {
            outHost = "127.0.0.1";
            outPort = 8080;
            outSsl = false;
        }
    }

    Client::Client(
        const std::string& app_id,
        const std::string& app_secret,
        const std::string& version,
        const std::string& api
    ) : m_app_id(app_id),
        m_app_secret(app_secret),
        m_version(version)
    {
        ParseServerUrl(api, m_host, m_port, m_use_ssl);
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

    std::string Client::GenerateNonce(size_t byte_count) {
        std::vector<uint8_t> buffer(byte_count);
        if (BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            for (size_t i = 0; i < byte_count; ++i) {
                buffer[i] = static_cast<uint8_t>(rand() ^ (time(nullptr) & 0xFF));
            }
        }
        std::ostringstream oss;
        for (uint8_t b : buffer) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
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

    bool Client::VerifyServerSignature(const std::string& body, const std::string& timestamp, const std::string& sig_b64) {
        if (sig_b64.empty() || timestamp.empty()) {
            return false;
        }

        // Verify timestamp freshness (drift within +/- 120s)
        try {
            uint64_t ts = std::stoull(timestamp);
            uint64_t current_time = static_cast<uint64_t>(time(nullptr));
            int64_t diff = static_cast<int64_t>(current_time) - static_cast<int64_t>(ts);
            if (std::abs(diff) > 120) {
                return false;
            }
        } catch (...) {
            return false;
        }

        // Decode Public Key PEM to DER
        DWORD derLen = 0;
        if (!CryptStringToBinaryA(SERVER_PUBLIC_KEY_PEM, 0, CRYPT_STRING_BASE64HEADER, nullptr, &derLen, nullptr, nullptr)) {
            return false;
        }
        std::vector<uint8_t> derBytes(derLen);
        if (!CryptStringToBinaryA(SERVER_PUBLIC_KEY_PEM, 0, CRYPT_STRING_BASE64HEADER, derBytes.data(), &derLen, nullptr, nullptr)) {
            return false;
        }

        // Decode DER to CERT_PUBLIC_KEY_INFO
        CERT_PUBLIC_KEY_INFO* pPubKeyInfo = nullptr;
        DWORD infoLen = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, derBytes.data(), derLen, CRYPT_DECODE_ALLOC_FLAG, nullptr, &pPubKeyInfo, &infoLen)) {
            return false;
        }

        // Import public key to BCRYPT_KEY_HANDLE
        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pPubKeyInfo, 0, nullptr, &hKey)) {
            LocalFree(pPubKeyInfo);
            return false;
        }
        LocalFree(pPubKeyInfo);

        // Compute SHA-256 hash of "timestamp.body"
        std::string dataToVerify = timestamp + "." + body;
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
            BCryptDestroyKey(hKey);
            return false;
        }

        DWORD hashObjSize = 0, dataLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjSize, sizeof(DWORD), &dataLen, 0);
        std::vector<uint8_t> hashObj(hashObjSize);
        std::vector<uint8_t> hashVal(32);

        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool hashOk = false;
        if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0) == 0) {
            BCryptHashData(hHash, (PUCHAR)dataToVerify.data(), (ULONG)dataToVerify.length(), 0);
            BCryptFinishHash(hHash, hashVal.data(), (ULONG)hashVal.size(), 0);
            BCryptDestroyHash(hHash);
            hashOk = true;
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (!hashOk) {
            BCryptDestroyKey(hKey);
            return false;
        }

        // Decode base64 signature
        std::vector<uint8_t> sigBytes = Base64Decode(sig_b64);
        if (sigBytes.empty()) {
            BCryptDestroyKey(hKey);
            return false;
        }

        // Verify signature with PKCS#1 padding (RSA-SHA256 / ed256)
        BCRYPT_PKCS1_PADDING_INFO padInfo;
        padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

        NTSTATUS status = BCryptVerifySignature(
            hKey,
            &padInfo,
            hashVal.data(),
            (ULONG)hashVal.size(),
            sigBytes.data(),
            (ULONG)sigBytes.size(),
            BCRYPT_PAD_PKCS1
        );

        BCryptDestroyKey(hKey);
        return (status == 0);
    }

    std::string Client::EncryptAES256WithKey(const std::string& plaintext, const std::string& keyHex, const std::string& ivHex) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::string resultB64 = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return "";
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        DWORD keyObjSize = 0, dataLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(DWORD), &dataLen, 0);
        std::vector<uint8_t> keyObj(keyObjSize);

        auto keyBytes = HexToBytes(keyHex);
        auto ivBytes = HexToBytes(ivHex);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize, keyBytes.data(), (ULONG)keyBytes.size(), 0) == 0) {
            DWORD outSize = 0;
            BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.length(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), nullptr, 0, &outSize, BCRYPT_BLOCK_PADDING);
            std::vector<uint8_t> cipherBytes(outSize);
            
            ivBytes = HexToBytes(ivHex);
            if (BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.length(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), cipherBytes.data(), outSize, &outSize, BCRYPT_BLOCK_PADDING) == 0) {
                cipherBytes.resize(outSize);
                resultB64 = Base64Encode(cipherBytes);
            }
            BCryptDestroyKey(hKey);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return resultB64;
    }

    std::string Client::DecryptAES256WithKey(const std::string& ciphertext_b64, const std::string& keyHex, const std::string& ivHex) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::string plaintext = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return "";
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        DWORD keyObjSize = 0, dataLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(DWORD), &dataLen, 0);
        std::vector<uint8_t> keyObj(keyObjSize);

        auto keyBytes = HexToBytes(keyHex);
        auto ivBytes = HexToBytes(ivHex);
        auto cipherBytes = Base64Decode(ciphertext_b64);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize, keyBytes.data(), (ULONG)keyBytes.size(), 0) == 0) {
            DWORD outSize = 0;
            BCryptDecrypt(hKey, cipherBytes.data(), (ULONG)cipherBytes.size(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), nullptr, 0, &outSize, BCRYPT_BLOCK_PADDING);
            std::vector<uint8_t> plainBytes(outSize);

            ivBytes = HexToBytes(ivHex);
            if (BCryptDecrypt(hKey, cipherBytes.data(), (ULONG)cipherBytes.size(), nullptr, ivBytes.data(), (ULONG)ivBytes.size(), plainBytes.data(), outSize, &outSize, BCRYPT_BLOCK_PADDING) == 0) {
                plainBytes.resize(outSize);
                plaintext = std::string(plainBytes.begin(), plainBytes.end());
            }
            BCryptDestroyKey(hKey);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    std::string Client::EncryptAES256(const std::string& plaintext) {
        return EncryptAES256WithKey(plaintext, m_session_key_hex, m_session_iv_hex);
    }

    std::string Client::DecryptAES256(const std::string& ciphertext_b64) {
        return DecryptAES256WithKey(ciphertext_b64, m_session_key_hex, m_session_iv_hex);
    }

    HttpResponse Client::SendHttpRequest(const std::string& path, const std::string& post_data, const std::string& extra_header) {
        HttpResponse response;
        if (!m_hConnect) return response;

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (m_use_ssl) flags |= INTERNET_FLAG_SECURE;

        HINTERNET hRequest = HttpOpenRequestA(m_hConnect, skCrypt("POST"), path.c_str(), nullptr, nullptr, nullptr, flags, 0);
        if (!hRequest) return response;

        std::string headers = skCrypt("Content-Type: application/json\r\n");
        if (!extra_header.empty()) {
            headers += extra_header + "\r\n";
        }

        BOOL sent = HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)post_data.c_str(), (DWORD)post_data.length());
        if (!sent) {
            InternetCloseHandle(hRequest);
            return response;
        }

        // 1. Get Status Code
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusSize, nullptr)) {
            response.statusCode = static_cast<int>(statusCode);
        }

        // 2. Query Raw Headers
        DWORD dwSize = 0;
        HttpQueryInfoA(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, nullptr, &dwSize, nullptr);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwSize > 0) {
            std::vector<char> headerBuf(dwSize + 1, 0);
            if (HttpQueryInfoA(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, headerBuf.data(), &dwSize, nullptr)) {
                std::string rawHeaders(headerBuf.data(), dwSize);
                std::stringstream ss(rawHeaders);
                std::string line;
                while (std::getline(ss, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    auto colonPos = line.find(':');
                    if (colonPos != std::string::npos) {
                        std::string headerName = line.substr(0, colonPos);
                        std::string headerVal = line.substr(colonPos + 1);
                        while (!headerVal.empty() && (headerVal.front() == ' ' || headerVal.front() == '\t')) {
                            headerVal.erase(0, 1);
                        }
                        std::string lowerName = headerName;
                        for (char& c : lowerName) c = static_cast<char>(tolower(c));

                        if (lowerName == "x-signature" || lowerName == "signature") {
                            if (response.signature.empty()) response.signature = headerVal;
                        } else if (lowerName == "x-timestamp" || lowerName == "timestamp") {
                            if (response.timestamp.empty()) response.timestamp = headerVal;
                        } else if (lowerName == "x-signature-algorithm" || lowerName == "x-ed256" || lowerName == "ed256") {
                            if (response.algorithm.empty()) response.algorithm = headerVal;
                        }
                    }
                }
            }
        }

        // 3. Read Body
        char buffer[4096];
        DWORD bytesRead = 0;
        while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.body.append(buffer, bytesRead);
        }

        InternetCloseHandle(hRequest);
        return response;
    }

    bool Client::Initialize(bool enforce_integrity) {
        // 1. Anti-Debug and Evasion Gate
        if (!KawaiiSecurity::ExecuteEvasionGates()) {
            m_last_response = { false, skCrypt("Security policy violation: unauthorized debugger or analysis tool detected") };
            return false;
        }

        m_request_seq = 0;
        std::string textHash = enforce_integrity ? KawaiiSecurity::ComputeTextSectionHash() : "";
        std::string nonce = GenerateNonce(16);
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json initPayload = {
            { skCrypt("app_id"), m_app_id },
            { skCrypt("version"), m_version },
            { skCrypt("client_hash"), textHash },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce }
        };

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/init"), initPayload.dump());
        if (httpResp.body.empty()) {
            m_last_response = { false, skCrypt("Connection failed to authentication server") };
            return false;
        }

        // Verify RSA Signature with server public key
        if (!VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            m_last_response = { false, skCrypt("Server response signature verification failed (tampering detected)") };
            return false;
        }

        try {
            auto j = json::parse(httpResp.body);
            if (!j.value(skCrypt("success"), false)) {
                m_last_response = { false, j.value(skCrypt("message"), skCrypt("Initialization rejected")) };
                return false;
            }

            // Decrypt encrypted session payload with HashSHA256(m_app_secret)
            if (!j.contains(skCrypt("data")) || !j.contains(skCrypt("iv"))) {
                m_last_response = { false, skCrypt("Missing encrypted session payload in init response") };
                return false;
            }

            std::string ivHex = j[skCrypt("iv")];
            std::string encData = j[skCrypt("data")];
            std::string appSecretHash = HashSHA256(m_app_secret);
            std::string dec = DecryptAES256WithKey(encData, appSecretHash, ivHex);

            auto inner = json::parse(dec);
            if (inner.value(skCrypt("success"), false)) {
                m_session_token = inner.value(skCrypt("session_token"), "");
                m_session_key_hex = inner.value(skCrypt("session_key"), "");
                m_session_iv_hex = inner.value(skCrypt("session_iv"), "");
                m_last_response = { true, inner.value(skCrypt("message"), skCrypt("Initialized")) };
                return true;
            } else {
                m_last_response = { false, inner.value(skCrypt("message"), skCrypt("Initialization rejected")) };
                return false;
            }
        } catch (...) {
            m_last_response = { false, skCrypt("JSON parse or decryption failure on /init") };
            return false;
        }
    }

    Response Client::Login(const std::string& username, const std::string& password) {
        if (m_session_token.empty()) return { false, skCrypt("Session uninitialized") };

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("login") },
            { skCrypt("username"), username },
            { skCrypt("password"), password },
            { skCrypt("hwid"), m_hwid },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty()) {
            return { false, skCrypt("Connection failed to authentication server") };
        }
        if (!VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return { false, skCrypt("Server response signature verification failed") };
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                return { false, skCrypt("Replay attack detected: response nonce mismatch") };
            }

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

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("register") },
            { skCrypt("username"), username },
            { skCrypt("password"), password },
            { skCrypt("key"), license_key },
            { skCrypt("hwid"), m_hwid },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty()) {
            return { false, skCrypt("Connection failed to authentication server") };
        }
        if (!VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return { false, skCrypt("Server response signature verification failed") };
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                return { false, skCrypt("Replay attack detected: response nonce mismatch") };
            }

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

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("license_only") },
            { skCrypt("key"), license_key },
            { skCrypt("hwid"), m_hwid },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty()) {
            return { false, skCrypt("Connection failed to authentication server") };
        }
        if (!VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return { false, skCrypt("Server response signature verification failed") };
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                return { false, skCrypt("Replay attack detected: response nonce mismatch") };
            }

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

            // Immediately check and verify session status after using license key
            if (r.success) {
                SessionStatus st = CheckSession();
                if (!st.authed) {
                    r.success = false;
                    r.message = skCrypt("Session authentication verification failed after license activation");
                    m_last_response = r;
                    return r;
                }
            }

            return r;
        } catch (...) {
            return { false, skCrypt("Decryption or license parse error") };
        }
    }

    bool Client::Ping() {
        if (m_session_token.empty()) return false;

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("ping") },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty() || !VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return false;
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                return false;
            }
            return inner.value(skCrypt("success"), false);
        } catch (...) {
            return false;
        }
    }

    SessionStatus Client::CheckSession() {
        SessionStatus status;
        if (m_session_token.empty()) {
            status.success = false;
            status.message = skCrypt("Session uninitialized");
            return status;
        }

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("check_session") },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty() || !VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            status.success = false;
            status.message = skCrypt("Connection failed or signature mismatch");
            return status;
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);

            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                status.success = false;
                status.message = skCrypt("Replay attack detected: response nonce mismatch");
                return status;
            }

            status.success = inner.value(skCrypt("success"), false);
            status.authed = inner.value(skCrypt("authed"), false);
            status.message = inner.value(skCrypt("message"), "");
            status.session_token = inner.value(skCrypt("session_token"), m_session_token);
            status.session_expires_at = inner.value(skCrypt("session_expires_at"), 0ULL);
            status.session_time_left = inner.value(skCrypt("session_time_left"), 0ULL);

            if (inner.contains(skCrypt("user")) && !inner[skCrypt("user")].is_null()) {
                auto u = inner[skCrypt("user")];
                status.user.username = u.value(skCrypt("username"), "");
                status.user.expires_at = u.value(skCrypt("expires_at"), 0ULL);
                status.user.level = u.value(skCrypt("level"), 0);
                status.user.hwid = u.value(skCrypt("hwid"), "");
            }
            return status;
        } catch (...) {
            status.success = false;
            status.message = skCrypt("Response parsing failed");
            return status;
        }
    }

    bool Client::IsAuthed() {
        return CheckSession().authed;
    }

    std::string Client::FetchVariable(const std::string& var_key) {
        if (m_session_token.empty()) return "";

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("fetch_var") },
            { skCrypt("var_key"), var_key },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty() || !VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return "";
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);
            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                return "";
            }
            if (inner.value(skCrypt("success"), false)) {
                return inner.value(skCrypt("var_value"), "");
            }
        } catch (...) {}
        return "";
    }

    std::vector<uint8_t> Client::DownloadFile(const std::string& file_name) {
        if (m_session_token.empty()) return {};

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("download_file") },
            { skCrypt("file_name"), file_name },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty() || !VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return {};
        }

        try {
            auto outer = json::parse(httpResp.body);
            std::string dec = DecryptAES256(outer.value(skCrypt("data"), ""));
            auto inner = json::parse(dec);
            if (inner.contains(skCrypt("req_nonce")) && inner[skCrypt("req_nonce")] != nonce) {
                return {};
            }
            if (inner.value(skCrypt("success"), false)) {
                std::string b64 = inner.value(skCrypt("file_data"), "");
                return Base64Decode(b64);
            }
        } catch (...) {}
        return {};
    }

    bool Client::SendLog(const std::string& log_message) {
        if (m_session_token.empty()) return false;

        std::string nonce = GenerateNonce(16);
        uint64_t seq = ++m_request_seq;
        uint64_t ts = static_cast<uint64_t>(time(nullptr));

        json payload = {
            { skCrypt("action"), skCrypt("log") },
            { skCrypt("log_message"), log_message },
            { skCrypt("timestamp"), ts },
            { skCrypt("nonce"), nonce },
            { skCrypt("seq"), seq }
        };

        std::string enc = EncryptAES256(payload.dump());
        json reqBody = { { skCrypt("data"), enc } };
        std::string header = std::string(skCrypt("X-Session-Token: ")) + m_session_token;

        HttpResponse httpResp = SendHttpRequest(skCrypt("/api/v1/action"), reqBody.dump(), header);
        if (httpResp.body.empty() || !VerifyServerSignature(httpResp.body, httpResp.timestamp, httpResp.signature)) {
            return false;
        }
        return true;
    }

}
