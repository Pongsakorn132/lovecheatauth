# KawaiiAuth — Modern Licensing & Authentication Engine

KawaiiAuth is a high-performance, secure license authentication platform engineered with a KeyAuth-inspired architecture. It replaces outdated, vulnerable legacy backends with modern zero-dependency Node.js runtime and native Windows C++ client bindings.

---

## Architecture Overview

```
                      +-----------------------------+
                      |     Web Dashboard UI        |
                      |   (http://localhost:8080)   |
                      +--------------+--------------+
                                     |
                                Admin API
                                     v
+------------------------+     +--------------------+     +---------------------+
|     C++ Client App     | <-> |  KawaiiAuth Server | <-> | SQLite Database     |
| (Native WinINet/BCrypt)|     |  (AES-256 Engine)  |     | (Auto-WAL Mode)     |
+------------------------+     +--------------------+     +---------------------+
```

---

## Directory Layout

```
lovecheatauth/
├── server/                   # Backend server & Web Dashboard
│   ├── src/
│   │   ├── server.js         # HTTP server entrypoint
│   │   ├── database.js       # Native node:sqlite schema & transactions
│   │   ├── crypto.js         # AES-256-CBC, SHA-256 & dynamic session crypto
│   │   ├── routes/
│   │   │   ├── api.js        # Protected client gateway & action handlers
│   │   │   └── admin.js      # Reseller/Admin API & key generator
│   │   └── public/
│   │       └── index.html    # Single-page Web Control Center
│   └── package.json
│
├── client_cpp/               # Native C++ SDK & Example Client
│   ├── include/
│   │   ├── kawaii_auth.hpp   # Core client header
│   │   └── json.hpp          # Single-header nlohmann/json
│   ├── src/
│   │   ├── kawaii_auth.cpp   # Native WinINet, BCrypt AES, & HWID engine
│   │   └── main.cpp          # Full console test & demo application
│   └── CMakeLists.txt        # Cross-compiler build definition
│
├── docs/                     # Full technical manuals
│   ├── API_SPECIFICATION.md
│   ├── CLIENT_INTEGRATION_GUIDE.md
│   └── DEPLOYMENT_MANUAL.md
│
├── docker-compose.yml
└── README.md
```

---

## Quickstart

### 1. Launch Backend Server
```powershell
cd server
node src/server.js
```
The server will start on port `8080`, automatically initialize the database, seed a demo app (`KawaiiDemo`), generate demo keys, and host the web dashboard at:
👉 **http://localhost:8080/dashboard**

### 2. Build and Run C++ Client
Open `client_cpp/CMakeLists.txt` in Visual Studio 2022 or compile using CMake:
```powershell
cd client_cpp
cmake -B build
cmake --build build --config Release
.\build\Release\KawaiiClient.exe
```

---

## Security Features
- **Dynamic Session Handshake:** Each client session negotiates an ephemeral 256-bit AES key and 128-bit IV during `/api/v1/init`.
- **Replay Attack Defense:** Every encrypted packet embeds timestamps and nonces; stale packets are discarded immediately.
- **Hardware ID Enforcement (HWID):** Collects Volume Serial Number, CPUID, and Computer Name into a cryptographic SHA-256 hash.
- **Protected Variables & Files:** Delivers sensitive offsets, shellcodes, and payloads strictly through authenticated, encrypted in-memory streams.
