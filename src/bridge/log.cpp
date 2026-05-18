// log.cpp — Structured logging implementation.
#include "log.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>

namespace blog {

static Level    s_level = INFO;
static FILE*    s_file  = nullptr;
static std::mutex s_mutex;

static const char* level_str(Level l) {
    switch (l) {
        case DEBUG: return "DEBUG";
        case INFO:  return "INFO ";
        case WARN:  return "WARN ";
        case ERROR: return "ERROR";
    }
    return "?????";
}

static Level parse_level(const char* s) {
    if (!s) return INFO;
    if (strcasecmp(s, "debug") == 0) return DEBUG;
    if (strcasecmp(s, "warn")  == 0 || strcasecmp(s, "warning") == 0) return WARN;
    if (strcasecmp(s, "error") == 0) return ERROR;
    return INFO;
}

void init() {
    const char* level_env = std::getenv("LOG_LEVEL");
    if (level_env) s_level = parse_level(level_env);

    const char* file_env = std::getenv("LOG_FILE");
    if (file_env && file_env[0]) set_file(file_env);
}

void set_level(Level level) { s_level = level; }

void set_file(const char* path) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_file && s_file != stderr) std::fclose(s_file);
    s_file = std::fopen(path, "a");
    if (!s_file) {
        std::fprintf(stderr, "[log] failed to open %s, using stderr\n", path);
        s_file = nullptr;
    }
}

static void write_timestamp(FILE* out) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    auto tt = system_clock::to_time_t(now);
    struct tm tm{};
    gmtime_r(&tt, &tm);
    std::fprintf(out, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms);
}

void emit(Level level, const char* component, const char* fmt, ...) {
    if (level < s_level) return;

    std::lock_guard<std::mutex> lock(s_mutex);

    va_list ap;
    va_start(ap, fmt);

    write_timestamp(stderr);
    std::fprintf(stderr, " [%s] [%s] ", level_str(level), component);
    va_list ap2;
    va_copy(ap2, ap);
    std::vfprintf(stderr, fmt, ap2);
    va_end(ap2);
    std::fputc('\n', stderr);
    std::fflush(stderr);

    if (s_file) {
        write_timestamp(s_file);
        std::fprintf(s_file, " [%s] [%s] ", level_str(level), component);
        va_list ap3;
        va_copy(ap3, ap);
        std::vfprintf(s_file, fmt, ap3);
        va_end(ap3);
        std::fputc('\n', s_file);
        std::fflush(s_file);
    }

    va_end(ap);
}

}  // namespace blog
