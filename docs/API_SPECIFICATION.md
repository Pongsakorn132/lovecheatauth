# KawaiiAuth — Core API Specification (v1.0)

This document outlines the protocol lifecycle, endpoint definitions, dynamic encryption mechanisms, and JSON schemas between client applications and the KawaiiAuth Server.

---

## 1. Cryptographic Handshake & Protocol Flow

Every client session starts with an unauthenticated handshake to negotiate session tokens and dynamic symmetric keys:

```
Client                                                  Server
  │                                                       │
  │─── POST /api/v1/init (app_id, version) ──────────────>│
  │                                                       │ (Validates App & Version)
  │                                                       │ (Generates 256-bit Key & 128-bit IV)
  │<── 200 OK (session_token, session_key, session_iv) ───│
  │                                                       │
  │─── POST /api/v1/action ──────────────────────────────>│
  │    Header: X-Session-Token: <token>                   │ (Resolves Session)
  │    Body: { "data": "<AES-256-CBC Encrypted>" }        │ (Decrypts & Enforces Replay Check)
  │                                                       │ (Processes Auth / Licensing)
  │<── 200 OK { "data": "<Encrypted Response>" } ─────────│
```

### Encryption Scheme:
- **Algorithm:** AES-256-CBC
- **Padding:** PKCS7
- **Key:** 32-byte hexadecimal string negotiated on `/api/v1/init`
- **IV:** 16-byte hexadecimal string negotiated on `/api/v1/init`
- **Outer Transport:** Base64-encoded ciphertext wrapped in JSON `{ "data": "..." }`

---

## 2. API Endpoints

### 2.1 Initialization
- **Path:** `/api/v1/init`
- **Method:** `POST`
- **Headers:** `Content-Type: application/json`

**Request Payload:**
```json
{
  "app_id": "kawaii_demo_app",
  "version": "1.0",
  "client_hash": "optional_sha256_of_client_binary"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Initialized",
  "session_token": "1dacebe4-06c4-406f-92a0-d6338e1bcb20",
  "session_key": "2144fd60097ccd79a11a773786d327374a12145477f4399809ba32367551542a",
  "session_iv": "977626c584d778f1ac0a2a458ff2cd49",
  "app_name": "KawaiiDemo"
}
```

---

### 2.2 Encrypted Action Gateway
- **Path:** `/api/v1/action`
- **Method:** `POST`
- **Headers:**
  - `Content-Type: application/json`
  - `X-Session-Token: <session_token>`

**Outer Envelope:**
```json
{
  "data": "kZ8/21X9wF3mOQ..."
}
```

#### Action: `login` (Decrypted Inner JSON)
```json
{
  "action": "login",
  "username": "user1337",
  "password": "mypassword",
  "hwid": "VOL:1a2b3c;CPU:000806ea;NAME:DESKTOP-ABC",
  "timestamp": 1729160000
}
```
**Response (Decrypted Inner JSON):**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "username": "user1337",
    "expires_at": 1731752000,
    "level": 1,
    "hwid": "VOL:1a2b3c..."
  }
}
```

#### Action: `register` (Decrypted Inner JSON)
```json
{
  "action": "register",
  "username": "user1337",
  "password": "mypassword",
  "key": "KAWAII-ABCD-1234-EFGH",
  "hwid": "VOL:1a2b3c...",
  "timestamp": 1729160000
}
```

#### Action: `license_only` (Decrypted Inner JSON)
```json
{
  "action": "license_only",
  "key": "KAWAII-DEMO-KEY1",
  "hwid": "VOL:1a2b3c...",
  "timestamp": 1729160000
}
```

#### Action: `ping` (Heartbeat)
```json
{
  "action": "ping",
  "timestamp": 1729160000
}
```
**Response:**
```json
{
  "success": true,
  "message": "Pong",
  "timestamp": 1729160000
}
```

#### Action: `fetch_var` (Application Variable)
```json
{
  "action": "fetch_var",
  "var_key": "payload_offset",
  "timestamp": 1729160000
}
```
**Response:**
```json
{
  "success": true,
  "var_key": "payload_offset",
  "var_value": "0x1A4F0"
}
```

---

## 3. Admin Management Endpoints

All admin endpoints require the header `X-Admin-Key: <ADMIN_MASTER_KEY>`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/admin/apps` | List all registered applications and summary metrics |
| `POST` | `/api/admin/apps` | Create a new application |
| `POST` | `/api/admin/licenses/generate` | Batch generate license keys with duration and level |
| `GET` | `/api/admin/licenses?app_id=...` | List all licenses for target app |
| `GET` | `/api/admin/users?app_id=...` | List users, bound HWIDs, and ban states |
| `POST` | `/api/admin/users/reset-hwid` | Clear HWID lock for user |
| `POST` | `/api/admin/users/ban-toggle` | Set ban status and reason |
| `GET` | `/api/admin/variables?app_id=...` | List server-side stored variables |
| `POST` | `/api/admin/variables` | Set or update variable |
| `GET` | `/api/admin/logs?app_id=...` | Fetch audit and security telemetry logs |
