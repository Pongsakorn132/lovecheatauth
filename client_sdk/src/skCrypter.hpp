#pragma once

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>

namespace KawaiiSecurity {

    constexpr uint64_t HashSeed(const char* str) {
        uint64_t hash = 14695981039346656037ULL;
        while (*str) {
            hash ^= static_cast<uint64_t>(*str++);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    constexpr uint8_t GenKey(size_t index) {
        uint64_t seed = HashSeed(__TIME__ __DATE__) + (index * 0x9E3779B97F4A7C15ULL);
        return static_cast<uint8_t>((seed ^ (seed >> 16)) & 0xFF);
    }

    template <size_t N>
    struct CryptString {
        std::array<char, N> data{};
        std::array<uint8_t, N> key{};

        consteval CryptString(const char(&str)[N]) {
            for (size_t i = 0; i < N; ++i) {
                key[i] = GenKey(i) | 0x01;
                data[i] = static_cast<char>(str[i] ^ key[i]);
            }
        }
    };

    template <size_t N>
    inline const char* DecryptStatic(const CryptString<N>& cs) {
        thread_local char buf[N];
        for (size_t i = 0; i < N; ++i) {
            buf[i] = static_cast<char>(cs.data[i] ^ cs.key[i]);
        }
        return buf;
    }

}

#define skCrypt(str) ([]() -> const char* { \
    static constexpr auto _crypt_storage = KawaiiSecurity::CryptString<sizeof(str)>(str); \
    return KawaiiSecurity::DecryptStatic(_crypt_storage); \
}())
