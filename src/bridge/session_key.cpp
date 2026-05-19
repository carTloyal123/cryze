#include "session_key.hpp"
#include "log.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

using fn_get_key = int (*)(uint8_t*, size_t);

static fn_get_key resolve_getter() {
    auto fn = reinterpret_cast<fn_get_key>(dlsym(RTLD_DEFAULT, "interpose_get_session_key"));
    if (!fn)
        LOG_WARN("session_key", "interpose_get_session_key not found — hook not loaded?");
    return fn;
}

namespace session_key {

bool get(uint8_t* out) {
    static fn_get_key getter = resolve_getter();
    return getter && getter(out, 32) == 0;
}

bool wait_for(uint8_t* out, int timeout_sec) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (std::chrono::steady_clock::now() < deadline) {
        if (get(out)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return false;
}

bool write_to_file(const uint8_t* key, const char* path) {
    if (!path) {
        path = std::getenv("SESSION_KEY_PATH");
        if (!path) path = kDefaultPath;
    }
    int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_ERROR("session_key", "cannot write %s: %s", path, strerror(errno));
        return false;
    }
    ssize_t w = ::write(fd, key, 32);
    ::close(fd);
    if (w != 32) {
        LOG_ERROR("session_key", "short write to %s (%zd/32)", path, w);
        return false;
    }
    LOG_INFO("session_key", "written to %s", path);
    return true;
}

std::string to_hex(const uint8_t* key) {
    char buf[65];
    for (int i = 0; i < 32; ++i)
        std::snprintf(buf + i * 2, 3, "%02x", key[i]);
    buf[64] = '\0';
    return std::string(buf);
}

}  // namespace session_key
