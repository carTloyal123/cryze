cmake_minimum_required(VERSION 3.16)
project(bridge CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(LIBS_DIR ${CMAKE_SOURCE_DIR}/libs)
set(CMAKE_BUILD_RPATH "${LIBS_DIR}")
set(CMAKE_INSTALL_RPATH "${LIBS_DIR}")

add_compile_options(-Wall -Wextra -Wno-unused-parameter -g -O1)

add_library(android_stubs STATIC src/android_stubs.c)
target_compile_options(android_stubs PRIVATE -fPIC)

add_executable(bridge
    src/main.cpp
    src/sdk_loader.cpp
    src/wyze_auth.cpp
    src/callbacks.cpp)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

target_link_libraries(bridge PRIVATE
    -Wl,--whole-archive android_stubs -Wl,--no-whole-archive
    CURL::libcurl
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    uuid
    dl pthread)
target_link_options(bridge PRIVATE -rdynamic)
