#include "security.hpp"
#include "skCrypter.hpp"
#include <bcrypt.h>
#include <sstream>
#include <iomanip>
#include <iostream>

#pragma comment(lib, "bcrypt.lib")

namespace KawaiiSecurity {

    typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
        HANDLE ThreadHandle,
        ULONG ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
    );

    bool DetectDebugger() {
        // 1. Direct Win32
        if (IsDebuggerPresent()) return true;

        // 2. Remote Debugger
        BOOL remoteDebugger = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
            return true;
        }

        // 3. Hardware Breakpoints (DR0-DR3)
        if (DetectHardwareBreakpoints()) return true;

        // 4. Blacklisted Windows
        if (DetectBlacklistedWindows()) return true;

        return false;
    }

    bool DetectHardwareBreakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        HANDLE hThread = GetCurrentThread();
        if (GetThreadContext(hThread, &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                return true;
            }
        }
        return false;
    }

    bool DetectBlacklistedWindows() {
        const char* blacklisted[] = {
            skCrypt("x64dbg"),
            skCrypt("x32dbg"),
            skCrypt("IDA: Quick start"),
            skCrypt("Cheat Engine"),
            skCrypt("Process Hacker"),
            skCrypt("Wireshark"),
            skCrypt("HTTP Debugger Pro"),
            skCrypt("Fiddler Everywhere"),
            skCrypt("Scylla")
        };

        for (const char* title : blacklisted) {
            if (FindWindowA(nullptr, title) != nullptr) {
                return true;
            }
        }
        return false;
    }

    bool HideFromDebugger() {
        HMODULE hNtdll = GetModuleHandleA(skCrypt("ntdll.dll"));
        if (!hNtdll) return false;

        auto NtSetInformationThread = reinterpret_cast<pfnNtSetInformationThread>(
            GetProcAddress(hNtdll, skCrypt("NtSetInformationThread"))
        );

        if (!NtSetInformationThread) return false;

        // 0x11 = ThreadHideFromDebugger
        NTSTATUS status = NtSetInformationThread(GetCurrentThread(), 0x11, nullptr, 0);
        return (status == 0);
    }

    std::string ComputeTextSectionHash() {
        uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
        if (!base) return "";

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return "";

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return "";

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            // Find .text section
            if (strncmp(reinterpret_cast<const char*>(sectionHeader->Name), ".text", 5) == 0) {
                const uint8_t* textStart = reinterpret_cast<const uint8_t*>(base + sectionHeader->VirtualAddress);
                DWORD textSize = sectionHeader->Misc.VirtualSize;

                // Hash via BCrypt
                BCRYPT_ALG_HANDLE hAlg = nullptr;
                BCRYPT_HASH_HANDLE hHash = nullptr;
                std::string hashHex = "";

                if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
                    DWORD hashObjSize = 0, dataLen = 0;
                    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjSize, sizeof(DWORD), &dataLen, 0);
                    std::vector<uint8_t> hashObj(hashObjSize);
                    std::vector<uint8_t> hashVal(32);

                    if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0) == 0) {
                        BCryptHashData(hHash, (PUCHAR)textStart, textSize, 0);
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
        }
        return "";
    }

    bool ExecuteEvasionGates() {
        // 1. Thread hide
        HideFromDebugger();

        // 2. Detection check
        if (DetectDebugger()) {
            return false;
        }

        return true;
    }

}
