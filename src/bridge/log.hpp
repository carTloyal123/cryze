// log.hpp — Structured logging with timestamps, levels, and component tags.
//
// Usage:
//   LOG_INFO("bridge", "SDK version: %d.%d", major, minor);
//   LOG_ERROR("auth", "login failed: %s", err.what());
//
// Output: 2026-05-17T14:23:01.123Z [INFO ] [bridge] SDK version: 1.0
//
// Env: LOG_FILE (file path), LOG_LEVEL (debug/info/warn/error)
#pragma once

#include <cstdio>
#include <cstdarg>
#include <cstdint>

namespace blog {

enum Level : int {
    DEBUG = 0,
    INFO  = 1,
    WARN  = 2,
    ERROR = 3,
};

void init();
void set_level(Level level);
void set_file(const char* path);
void emit(Level level, const char* component, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));

}  // namespace blog

#define LOG_DEBUG(comp, ...) blog::emit(blog::DEBUG, comp, __VA_ARGS__)
#define LOG_INFO(comp, ...)  blog::emit(blog::INFO,  comp, __VA_ARGS__)
#define LOG_WARN(comp, ...)  blog::emit(blog::WARN,  comp, __VA_ARGS__)
#define LOG_ERROR(comp, ...) blog::emit(blog::ERROR, comp, __VA_ARGS__)
