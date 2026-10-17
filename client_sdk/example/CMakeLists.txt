cmake_minimum_required(VERSION 3.16)
project(KawaiiAuthExample VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include KawaiiAuth Header
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Link directories for KawaiiAuth.lib
link_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../dist/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../build/lib/Release
    ${CMAKE_CURRENT_SOURCE_DIR}/../build/lib
)

add_executable(KawaiiAuthExample example_main.cpp)

# Windows native libs
target_link_libraries(KawaiiAuthExample PRIVATE
    wininet
    bcrypt
    crypt32
    user32
)

if (MSVC)
    target_compile_options(KawaiiAuthExample PRIVATE /W4 /EHsc /permissive- /utf-8)
endif()
