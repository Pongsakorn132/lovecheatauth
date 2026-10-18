# KawaiiAuth C++ Client SDK (Static Library & Header)

SDK สำหรับนักพัฒนา C++ เพื่อเชื่อมต่อกับระบบ **KawaiiAuth** อย่างง่ายดาย รองรับการคอมไพล์เป็นไฟล์ Static Library (`KawaiiAuth.lib`) และ Header (`KawaiiAuth.h`) ที่ออกแบบมาให้ **เพียงแค่ `#include "KawaiiAuth.h"` ก็พร้อมใช้งานได้ทันที** (มีระบบ Auto-Link ในตัวสำหรับ MSVC)

---

## 📁 โครงสร้างโปรเจกต์ (Project Structure)

```
client_sdk/
├── include/
│   └── KawaiiAuth.h          <-- Public Header สำหรับ include ในโปรเจกต์ของคุณ
├── src/
│   ├── KawaiiAuth.cpp        <-- SDK Implementation
│   ├── KawaiiAuth_impl.hpp   <-- Internal Networking, Crypto & Protocol
│   ├── security.cpp          <-- Anti-Debug & Evasion Gates
│   ├── security.hpp
│   ├── skCrypter.hpp         <-- Compile-time String Obfuscation
│   └── json.hpp              <-- Internal JSON engine (ไม่รั่วไหลไป header หลัก)
├── example/                  <-- โฟลเดอร์โปรเจกต์ตัวอย่างแบบ Standalone
│   ├── KawaiiAuth.h          <-- Header พร้อมใช้
│   ├── KawaiiAuth.lib        <-- Static Library พร้อมลิงก์
│   ├── example_main.cpp      <-- โค้ดตัวอย่างการเรียกใช้งานจริง
│   ├── CMakeLists.txt        <-- ตัวอย่าง CMake สำหรับโปรเจกต์ภายนอก
│   └── build.bat             <-- สคริปต์คลิกเดียวสำหรับ Build Example
├── dist/                     <-- โฟลเดอร์ผลลัพธ์หลัง Build (พร้อมแจกจ่าย/ใช้งาน)
│   ├── include/KawaiiAuth.h
│   └── lib/KawaiiAuth.lib
├── CMakeLists.txt            <-- CMake Build Script
├── build_lib.bat             <-- สคริปต์คลิกเดียวสำหรับ Build KawaiiAuth.lib & Example
└── README.md
```

---

## 🛠️ วิธีการ Build `KawaiiAuth.lib` และ `Example`

### วิธีที่ 1: ดับเบิลคลิกสคริปต์ (ง่ายที่สุด)
ดับเบิลคลิกที่ไฟล์ **`build_lib.bat`** 
สคริปต์จะทำการ:
1. กำหนดค่าผ่าน CMake (x64)
2. คอมไพล์ Static Library `KawaiiAuth.lib` (Release x64)
3. ส่งออกไฟล์ `KawaiiAuth.h` และ `KawaiiAuth.lib` ไปยังโฟลเดอร์ `dist/` และ `example/` โดยอัตโนมัติ
4. คอมไพล์โปรแกรมตัวอย่าง `KawaiiAuthExample.exe` ไปยังโฟลเดอร์ `example/` พร้อมทดสอบใช้งานทันที

### วิธีที่ 2: ใช้คำสั่งผ่าน Terminal / PowerShell
```powershell
# 1. สร้างโฟลเดอร์ build และกำหนดค่า
cmake -B build -S . -A x64

# 2. คอมไพล์ Static Library (.lib)
cmake --build build --config Release --target KawaiiAuth
```

---

## 🚀 วิธีนำไปใช้งานในโปรเจกต์ของคุณ (How to Use)

### ขั้นตอนที่ 1: นำไฟล์เข้าโปรเจกต์
1. คัดลอก `dist/include/KawaiiAuth.h` ไปวางในโฟลเดอร์โปรเจกต์ของคุณ
2. คัดลอก `dist/lib/KawaiiAuth.lib` ไปวางในโฟลเดอร์เดียวกับโปรเจกต์ หรือระบุใน Library Directories ของ Visual Studio

### ขั้นตอนที่ 2: เขียนโค้ดเรียกใช้งาน
ในโค้ด C++ ของคุณ ให้ `#include "KawaiiAuth.h"`:

```cpp
#include "KawaiiAuth.h"
#include <iostream>

int main() {
    // 1. ตรวจสอบความปลอดภัยเครื่องผู้ใช้ (Anti-Debug & Analysis Tool Detection)
    if (!KawaiiAuth::RunSecurityChecks()) {
        std::cout << "ตรวจพบเครื่องมือดักจับ/ดีบักเกอร์ ไม่อนุญาตให้ทำงาน!" << std::endl;
        return 1;
    }

    // 2. เริ่มต้นเชื่อมต่อเซิร์ฟเวอร์
    KawaiiAuth::Config config;
    config.app_id = "kawaii_demo_app";
    config.app_secret = "demo_app_secret";
    config.version = "1.0";
    config.api = "http://127.0.0.1:8080"; // ระบุ URL ได้ทั้ง http / https หรือ domain/IP ระบบจะตัดคำนวณ Port และ SSL ให้อัตโนมัติ

    if (!KawaiiAuth::Init(config)) {
        std::cout << "เชื่อมต่อเซิร์ฟเวอร์ไม่สำเร็จ: " << KawaiiAuth::GetLastError() << std::endl;
        return 1;
    }

    // 3. ยืนยันตัวตนด้วย License Key (แบบใช้งานคีย์เดี่ยว)
    std::string key = "KAWAII-DEMO-KEY1";
    auto result = KawaiiAuth::LicenseLogin(key);

    if (!result) {
        std::cout << "เข้าสู่ระบบไม่สำเร็จ: " << result.message << std::endl;
        return 1;
    }

    std::cout << "เข้าสู่ระบบสำเร็จ! สวัสดีคุณ " << result.user.username << std::endl;
    std::cout << "เวลาคงเหลือ: " << KawaiiAuth::GetFormattedTimeLeft() << std::endl;

    // 4. ตรวจสอบความถูกต้องของ Session ระหว่างทำงาน
    if (KawaiiAuth::CheckSession()) {
        std::cout << "Session กำลังทำงาน ปลอดภัยจากการ Replay Attack!" << std::endl;
    }

    // 5. ดึงตัวแปรลับจากเซิร์ฟเวอร์ (เช่น Offset หรือ Payload)
    std::string offset = KawaiiAuth::GetVariable("payload_offset");
    std::cout << "Offset จากเซิร์ฟเวอร์: " << offset << std::endl;

    return 0;
}
```

> **หมายเหตุ (Auto-Link)**: 
> ในหัวไฟล์ `KawaiiAuth.h` มีคำสั่ง `#pragma comment(lib, "KawaiiAuth.lib")` รวมถึง System Libraries ที่จำเป็น (`wininet.lib`, `bcrypt.lib`, `crypt32.lib`, `user32.lib`) รวมไว้แล้ว ผู้พัฒนาที่ใช้ Visual Studio จึงไม่ต้องเข้าไปตั้งค่า Linker ให้ยุ่งยาก

---

## 📚 สรุปฟังก์ชัน API หลัก (API Reference)

### 1. การเริ่มต้นระบบ (Initialization)
- `bool KawaiiAuth::Init(const Config& config)`: เริ่มต้นการทำงานด้วยการตั้งค่าแบบ Struct
- `bool KawaiiAuth::Init(app_id, app_secret, version, api)`: เริ่มต้นแบบพารามิเตอร์แบบย่อ (ระบุ URL เช่น "http://127.0.0.1:8080" หรือ "https://auth.domain.com")

### 2. การยืนยันตัวตน (Authentication)
- `AuthResult KawaiiAuth::LicenseLogin(const std::string& license_key)`: เข้าสู่ระบบด้วย License Key
- `AuthResult KawaiiAuth::Login(const std::string& username, const std::string& password)`: เข้าสู่ระบบด้วย Username & Password
- `AuthResult KawaiiAuth::Register(username, password, license_key)`: สมัครสมาชิกใหม่พร้อมผูกกับ License Key

### 3. สถานะ Session & ความปลอดภัย (Session & Security)
- `SessionInfo KawaiiAuth::CheckSession()`: ตรวจสอบความสมบูรณ์ของ Session กับเซิร์ฟเวอร์แบบ Real-time
- `bool KawaiiAuth::IsAuthed()`: ตรวจสอบว่าได้รับการยืนยันตัวตนแล้วหรือไม่
- `bool KawaiiAuth::Ping()`: ทดสอบการตอบสนองของเซิร์ฟเวอร์
- `bool KawaiiAuth::RunSecurityChecks()`: เรียกตรวจจับ Debugger, Hardware Breakpoint (DR0-DR3), โปรแกรมวิเคราะห์ย้อนกลับ (IDA, x64dbg, Cheat Engine, Process Hacker ฯลฯ)

### 4. การดึงข้อมูลและเนื้อหาจากเซิร์ฟเวอร์ (Assets & Variables)
- `std::string KawaiiAuth::GetVariable(const std::string& var_key)`: ดึงค่าตัวแปรปลอดภัยจากเซิร์ฟเวอร์
- `std::vector<uint8_t> KawaiiAuth::DownloadFile(const std::string& file_name)`: ดาวน์โหลดไฟล์ Binary จากเซิร์ฟเวอร์
- `ProtectedPayload KawaiiAuth::FetchProtectedPayload(const std::string& payload_name)`: สตรีม Protected Binary Payload พร้อมตรวจจับ SHA-256 Tampering ใน Memory และรับข้อความแจ้งเตือนสถานะละเอียด
- `bool KawaiiAuth::Log(const std::string& message)`: ส่งข้อความ Audit Log บันทึกลงเซิร์ฟเวอร์

### 5. ข้อมูลผู้ใช้ (User Information)
- `UserInfo KawaiiAuth::GetUser()`: ดึง Struct ข้อมูลผู้ใช้งานปัจจุบัน
- `std::string KawaiiAuth::GetHWID()`: ดึงค่า Hardware ID ของเครื่อง
- `std::string KawaiiAuth::GetSessionToken()`: ดึง Token เซสชันปัจจุบัน
- `uint64_t KawaiiAuth::GetSecondsLeft()`: เวลาที่เหลือก่อนสิทธิ์หมดอายุ (วินาที)
- `std::string KawaiiAuth::GetFormattedTimeLeft()`: เวลาคงเหลือในรูปแบบที่อ่านง่าย เช่น `29d 23h 50m 10s`
- `std::string KawaiiAuth::GetLastError()`: ข้อความแจ้งเตือนความผิดพลาดล่าสุด

---

## 🔒 ฟีเจอร์ความปลอดภัยภายใน (Built-in Security)

1. **Anti-Replay Attack**: ทุก Request มี Cryptographic Nonce 128-bit และ Sequence Number ป้องกันการดักจับ Response เดิมมาเล่นซ้ำ
2. **AES-256-CBC Session Encryption**: ข้อมูลการสนทนาทั้งหมดเข้ารหัสด้วย Session Key และ IV เฉพาะตัวที่สร้างใหม่ทุก Session
3. **RSA-2048 Server Signature Verification**: ทุก Response จากเซิร์ฟเวอร์ถูกตรวจสอบลายเซ็นดิจิทัลผ่าน Windows CryptoAPI ก่อนนำไปประมวลผล
4. **PIMPL Architecture**: Header ภายนอกไม่มีการเปิดเผยตัวแปรภายในหรือ Header ภายนอกอย่าง `json.hpp` ทำให้ไม่เกิด Symbol Collision และเข้ากันได้กับทุกโปรเจกต์
