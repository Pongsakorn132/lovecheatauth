cmake_minimum_required(VERSION 3.16)
project(KawaiiAuthClient VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    include
)

set(SOURCES
    src/kawaii_auth.cpp
    src/security.cpp
    src/main.cpp
)

set(HEADERS
    include/kawaii_auth.hpp
    include/security.hpp
    include/skCrypter.hpp
    include/json.hpp
)

add_executable(KawaiiClient ${SOURCES} ${HEADERS})

# Link Windows Native Security & Network Libraries
target_link_libraries(KawaiiClient PRIVATE
    wininet
    bcrypt
    crypt32
    user32
)

if (MSVC)
    target_compile_options(KawaiiClient PRIVATE /W4 /EHsc /permissive-)
endif()
