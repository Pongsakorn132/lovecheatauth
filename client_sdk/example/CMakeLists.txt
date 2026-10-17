cmake_minimum_required(VERSION 3.16)
project(KawaiiAuthExample VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(KawaiiAuthExample example_main.cpp)

if (TARGET KawaiiAuth)
    target_include_directories(KawaiiAuthExample PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    target_link_directories(KawaiiAuthExample PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(KawaiiAuthExample PRIVATE
        KawaiiAuth
        wininet
        bcrypt
        crypt32
        user32
    )
else()
    target_include_directories(KawaiiAuthExample PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../dist/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    target_link_directories(KawaiiAuthExample PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../dist/lib
    )
    target_link_libraries(KawaiiAuthExample PRIVATE
        KawaiiAuth
        wininet
        bcrypt
        crypt32
        user32
    )
endif()

if (MSVC)
    target_compile_options(KawaiiAuthExample PRIVATE /W4 /EHsc /permissive- /utf-8)
    set_target_properties(KawaiiAuthExample PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()
