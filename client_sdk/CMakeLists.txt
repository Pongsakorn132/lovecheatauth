cmake_minimum_required(VERSION 3.16)
project(KawaiiAuthSDK VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files for the Static Library (.lib)
set(SDK_SOURCES
    src/KawaiiAuth.cpp
    src/security.cpp
)

set(SDK_HEADERS
    include/KawaiiAuth.h
    src/KawaiiAuth_impl.hpp
    src/security.hpp
    src/skCrypter.hpp
    src/json.hpp
)

# Build STATIC library (.lib)
add_library(KawaiiAuth STATIC ${SDK_SOURCES} ${SDK_HEADERS})

target_include_directories(KawaiiAuth
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link Windows Native Security, Network, and Cryptography Libraries
target_link_libraries(KawaiiAuth PUBLIC
    wininet
    bcrypt
    crypt32
    user32
)

# MSVC specific compiler optimizations & warnings
if (MSVC)
    target_compile_options(KawaiiAuth PRIVATE /W4 /EHsc /permissive- /utf-8)
    
    # Set output name as KawaiiAuth.lib
    set_target_properties(KawaiiAuth PROPERTIES
        OUTPUT_NAME "KawaiiAuth"
        OUTPUT_NAME_DEBUG "KawaiiAuth_d"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib"
    )
endif()

# Dist & Example Package Target: copies header and .lib to dist/ and example/ folders
add_custom_command(TARGET KawaiiAuth POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/dist/include"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/dist/lib"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/include/KawaiiAuth.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/dist/include/KawaiiAuth.h"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:KawaiiAuth>"
        "${CMAKE_CURRENT_SOURCE_DIR}/dist/lib/$<TARGET_FILE_NAME:KawaiiAuth>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/include/KawaiiAuth.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/example/KawaiiAuth.h"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:KawaiiAuth>"
        "${CMAKE_CURRENT_SOURCE_DIR}/example/$<TARGET_FILE_NAME:KawaiiAuth>"
    COMMENT "[KawaiiAuth] Exporting KawaiiAuth.h and KawaiiAuth.lib to dist/ and example/..."
)

# Example executable
add_subdirectory(example)
