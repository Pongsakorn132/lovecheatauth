# KawaiiAuth — C++ Client Integration Guide

This guide walks you through integrating the KawaiiAuth native C++ SDK into your loader, trainer, internal DLL, or standalone application.

---

## 1. Visual Studio 2022 Setup

### Step 1: Add Files to Project
Copy the following files into your solution directory:
- `include/kawaii_auth.hpp`
- `include/json.hpp`
- `src/kawaii_auth.cpp`

### Step 2: Include Directory
1. Open Project Properties (`Alt + F7`).
2. Navigate to **C/C++** -> **General** -> **Additional Include Directories**.
3. Add `$(ProjectDir)include` (or the folder containing `kawaii_auth.hpp` and `json.hpp`).

### Step 3: Linker Dependencies
The SDK uses native Windows cryptographic and networking libraries. They are automatically linked via `#pragma comment(lib, ...)` in `kawaii_auth.hpp`, but you can explicitly confirm them in:
- **Linker** -> **Input** -> **Additional Dependencies**:
  - `wininet.lib`
  - `bcrypt.lib`
  - `crypt32.lib`

### Step 4: C++ Standard
- Set **C/C++** -> **Language** -> **C++ Language Standard** to **ISO C++20 Standard (`/std:c++20`)** or **C++17 (`/std:c++17`)**.

---

## 2. Quick Integration Example

```cpp
#include "kawaii_auth.hpp"
#include <iostream>

int main() {
    // 1. Initialize Client instance
    // Note: Use HTTPS in production by setting use_ssl = true and port = 443
    KawaiiAuth::Client auth(
        "kawaii_demo_app",       // App ID
        "demo_app_secret",        // App Secret
        "1.0",                    // Version
        "auth.yourdomain.com",   // Host
        443,                     // Port
        true                     // SSL enabled
    );

    // 2. Perform Handshake
    if (!auth.Initialize()) {
        std::cerr << "[-] Error initializing: " << auth.GetLastResponse().message << std::endl;
        return 1;
    }

    // 3. Authenticate with Key Only
    auto resp = auth.LicenseOnly("KAWAII-XXXX-XXXX-XXXX");
    if (!resp.success) {
        std::cerr << "[-] Authentication failed: " << resp.message << std::endl;
        return 1;
    }

    std::cout << "[+] Logged in as: " << resp.user.username << std::endl;
    std::cout << "[+] Subscription Level: " << resp.user.level << std::endl;

    // 4. Fetch encrypted payload offset / secret variable
    std::string offset = auth.FetchVariable("payload_offset");
    std::cout << "[+] Decrypted Server Offset: " << offset << std::endl;

    // 5. Keep-alive heartbeat (call in background thread every 60s)
    if (auth.Ping()) {
        std::cout << "[+] Session verified active" << std::endl;
    }

    return 0;
}
```

---

## 3. Anti-Tamper & Security Recommendations

1. **String Encryption:**
   Do not leave plain API endpoints, App IDs, or variable keys in the `.rdata` section. Wrap strings using compile-time string encryption (e.g. `skCrypter` or XOR macros):
   ```cpp
   #define XOR(s) /* compile-time XOR macro */
   KawaiiAuth::Client auth(XOR("kawaii_demo_app"), ...);
   ```

2. **Integrity Validation:**
   Enable `hash_check` in the web panel. On startup, compute the SHA-256 hash of your executable's `.text` section and pass it as `client_hash` during `auth.Initialize()`.

3. **Memory Wiping:**
   Sensitive variables (like decrypted payloads or keys) should be zeroed out using `SecureZeroMemory()` or `RtlSecureZeroMemory()` immediately after use.
