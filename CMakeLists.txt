cmake_minimum_required(VERSION 3.16)
project(bridge CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(LIBS_DIR ${CMAKE_SOURCE_DIR}/libs)
set(CMAKE_BUILD_RPATH "${LIBS_DIR}")
set(CMAKE_INSTALL_RPATH "${LIBS_DIR}")

add_compile_options(-Wall -Wextra -Wno-unused-parameter -g -O1)

add_library(android_stubs STATIC src/bridge/android_stubs.c)
target_compile_options(android_stubs PRIVATE -fPIC)

set(BRIDGE_COMMON
    src/bridge/log.cpp
    src/bridge/sdk_loader.cpp
    src/bridge/wyze_auth.cpp
    src/bridge/callbacks.cpp
    src/bridge/broadcast.cpp
    src/bridge/session_key.cpp
    src/bridge/signal.cpp)

add_executable(bridge
    src/bridge/main.cpp
    ${BRIDGE_COMMON})

add_executable(bridge-daemon
    src/bridge/daemon.cpp
    ${BRIDGE_COMMON})

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

set(BRIDGE_LIBS
    -Wl,--whole-archive android_stubs -Wl,--no-whole-archive
    CURL::libcurl
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    uuid
    dl pthread)

target_link_libraries(bridge PRIVATE ${BRIDGE_LIBS})
target_link_options(bridge PRIVATE -rdynamic)

target_link_libraries(bridge-daemon PRIVATE ${BRIDGE_LIBS})
target_link_options(bridge-daemon PRIVATE -rdynamic)

add_library(bionic_interpose SHARED src/bridge/bionic_interpose.c)
target_compile_options(bionic_interpose PRIVATE -fPIC)
target_link_libraries(bionic_interpose PRIVATE dl pthread)
