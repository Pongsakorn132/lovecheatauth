#pragma once

#include <string>
#include <vector>
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace KawaiiSecurity {

    // Anti-Debug checks
    bool DetectDebugger();
    bool DetectHardwareBreakpoints();
    bool DetectBlacklistedWindows();
    bool HideFromDebugger();

    // In-memory integrity hashing
    std::string ComputeTextSectionHash();

    // Master evasion gate
    bool ExecuteEvasionGates();

}
