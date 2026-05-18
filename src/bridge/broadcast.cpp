// broadcast.cpp — SDK broadcast list polling and LAN injection
#include "broadcast.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

namespace broadcast {

// SDK ELF offsets for broadcast manager globals
static constexpr uintptr_t kBcastMgrOff = 0x0f0438;
static constexpr uintptr_t kTermunitOff = 0x0f0430;

static uintptr_t get_bcast_mgr(const sdk::SdkSymbols& sdk) {
    uintptr_t base = reinterpret_cast<uintptr_t>(sdk.lib_base);
    return *reinterpret_cast<uintptr_t*>(base + kBcastMgrOff);
}

static uintptr_t get_termunit(const sdk::SdkSymbols& sdk) {
    uintptr_t base = reinterpret_cast<uintptr_t>(sdk.lib_base);
    return *reinterpret_cast<uintptr_t*>(base + kTermunitOff);
}

int64_t resolve_dst_id(const sdk::SdkSymbols& sdk, const std::string& device_mac) {
    uintptr_t termunit = get_termunit(sdk);
    if (!termunit || !sdk.find_dstid) return 0;
    std::string devid = "_@." + device_mac;
    int64_t id = sdk.find_dstid(reinterpret_cast<void*>(termunit), devid.c_str());
    std::fprintf(stderr, "  [LAN] resolved dst_id=%lld\n", (long long)id);
    return id;
}

PollResult poll(const sdk::SdkSymbols& sdk, int64_t dst_id,
                int max_wait_sec, std::atomic<bool>& shutdown) {
    PollResult result{};
    uintptr_t bcast_mgr = get_bcast_mgr(sdk);
    if (!bcast_mgr || max_wait_sec <= 0) return result;

    uintptr_t sentinel = bcast_mgr + 0x5c;
    auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + 0x1c);

    std::fprintf(stderr, "  [LAN] polling broadcast list (max %ds)...\n", max_wait_sec);

    for (int ms = 0; ms < max_wait_sec * 1000; ms += 500) {
        if (shutdown.load()) break;

        pthread_mutex_lock(mutex);
        uintptr_t* node = *reinterpret_cast<uintptr_t**>(sentinel);
        while (reinterpret_cast<uintptr_t>(node) != sentinel) {
            uint32_t ip = *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(node) + 0x2e);
            int64_t nid = *reinterpret_cast<int64_t*>(reinterpret_cast<uintptr_t>(node) + 0x1c);
            if (ip != 0 && (dst_id == 0 || nid == dst_id)) {
                result.found = true;
                result.dst_id = nid;
                result.ip = ip;
                result.port = *reinterpret_cast<uint16_t*>(reinterpret_cast<uintptr_t>(node) + 0x2c);
                result.wait_secs = ms / 1000.0;
                break;
            }
            node = *reinterpret_cast<uintptr_t**>(node);
        }
        pthread_mutex_unlock(mutex);

        if (result.found) {
            uint8_t* b = reinterpret_cast<uint8_t*>(&result.ip);
            std::fprintf(stderr, "  [LAN] doorbell found! dst_id=%lld ip=%u.%u.%u.%u:%u (%.1fs)\n",
                         (long long)result.dst_id, b[0], b[1], b[2], b[3], result.port, result.wait_secs);
            return result;
        }

        if (ms % 10000 == 9500)
            std::fprintf(stderr, "  [LAN] waiting... (%d/%ds)\n", (ms + 500) / 1000, max_wait_sec);

        usleep(500000);
    }

    std::fprintf(stderr, "  [LAN] no broadcast response after %ds\n", max_wait_sec);
    return result;
}

bool inject(const sdk::SdkSymbols& sdk, int64_t dst_id,
            const std::string& ip_str, uint16_t port,
            const std::string& device_mac) {
    uintptr_t bcast_mgr = get_bcast_mgr(sdk);
    if (!bcast_mgr || dst_id == 0) return false;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;

    std::fprintf(stderr, "  [LAN] injecting: dst_id=%lld ip=%s port=%u\n",
                 (long long)dst_id, ip_str.c_str(), port);

    // Broadcast list entry: 0x8e bytes (layout from Ghidra RE)
    void* entry = std::calloc(1, 0x8e);
    if (!entry) return false;

    auto e = reinterpret_cast<uintptr_t>(entry);
    uint32_t now = sdk.get_tick ? sdk.get_tick() : 0;
    *reinterpret_cast<uint32_t*>(e + 0x10) = now;
    *reinterpret_cast<uint32_t*>(e + 0x14) = now;
    *reinterpret_cast<int64_t*>(e + 0x1c)  = dst_id;
    *reinterpret_cast<uint32_t*>(e + 0x2e) = addr.s_addr;
    *reinterpret_cast<uint16_t*>(e + 0x2c) = port;
    *reinterpret_cast<uint8_t*>(e + 0x66)  = 1;
    std::strncpy(reinterpret_cast<char*>(e + 0x6a), device_mac.c_str(), 0x23);

    // Insert into doubly-linked list under mutex
    auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + 0x1c);
    uintptr_t sentinel_addr = bcast_mgr + 0x5c;
    auto** sentinel_prev = reinterpret_cast<uintptr_t**>(bcast_mgr + 0x64);

    pthread_mutex_lock(mutex);
    *reinterpret_cast<uintptr_t*>(e + 0x00) = sentinel_addr;
    *reinterpret_cast<uintptr_t*>(e + 0x08) = reinterpret_cast<uintptr_t>(*sentinel_prev);
    **sentinel_prev = reinterpret_cast<uintptr_t>(entry);
    *sentinel_prev = reinterpret_cast<uintptr_t*>(entry);
    pthread_mutex_unlock(mutex);

    std::fprintf(stderr, "  [LAN] entry injected\n");
    return true;
}

}  // namespace broadcast
