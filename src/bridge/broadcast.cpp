#include "broadcast.hpp"
#include "log.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

namespace broadcast {

static constexpr uintptr_t kBroadcastManagerOffset = 0x0f0438;
static constexpr uintptr_t kTerminalUnitOffset     = 0x0f0430;

namespace entry_offset {
    constexpr size_t timestamp_general = 0x10;
    constexpr size_t timestamp_ipv4    = 0x14;
    constexpr size_t device_id         = 0x1c;
    constexpr size_t port              = 0x2c;
    constexpr size_t ipv4_addr         = 0x2e;
    constexpr size_t lan_flag          = 0x66;
    constexpr size_t device_string     = 0x6a;
}
constexpr size_t kBroadcastEntrySize = 0x8e;

namespace mgr_offset {
    constexpr size_t mutex             = 0x1c;
    constexpr size_t list_head         = 0x5c;
    constexpr size_t list_tail         = 0x64;
}

static uintptr_t get_broadcast_manager(const sdk::SdkSymbols& sdk) {
    uintptr_t base = reinterpret_cast<uintptr_t>(sdk.lib_base);
    return *reinterpret_cast<uintptr_t*>(base + kBroadcastManagerOffset);
}

static uintptr_t get_terminal_unit(const sdk::SdkSymbols& sdk) {
    uintptr_t base = reinterpret_cast<uintptr_t>(sdk.lib_base);
    return *reinterpret_cast<uintptr_t*>(base + kTerminalUnitOffset);
}

int64_t resolve_dst_id(const sdk::SdkSymbols& sdk, const std::string& device_mac) {
    uintptr_t termunit = get_terminal_unit(sdk);
    if (!termunit || !sdk.find_device_id) return 0;
    std::string devid = "_@." + device_mac;
    int64_t id = sdk.find_device_id(reinterpret_cast<void*>(termunit), devid.c_str());
    LOG_INFO("lan", "resolved dst_id=%lld", (long long)id);
    return id;
}

PollResult poll(const sdk::SdkSymbols& sdk, int64_t dst_id,
                int max_wait_sec, std::atomic<bool>& shutdown) {
    PollResult result{};
    uintptr_t bcast_mgr = get_broadcast_manager(sdk);
    if (!bcast_mgr || max_wait_sec <= 0) return result;

    uintptr_t list_head_ptr = bcast_mgr + mgr_offset::list_head;
    auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + mgr_offset::mutex);

    LOG_INFO("lan", "polling broadcast list (max %ds)...", max_wait_sec);

    for (int ms = 0; ms < max_wait_sec * 1000; ms += 500) {
        if (shutdown.load()) break;

        pthread_mutex_lock(mutex);
        uintptr_t* current_entry = *reinterpret_cast<uintptr_t**>(list_head_ptr);
        while (reinterpret_cast<uintptr_t>(current_entry) != list_head_ptr) {
            uint32_t ipv4_addr = *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(current_entry) + entry_offset::ipv4_addr);
            int64_t entry_device_id = *reinterpret_cast<int64_t*>(reinterpret_cast<uintptr_t>(current_entry) + entry_offset::device_id);
            if (ipv4_addr != 0 && (dst_id == 0 || entry_device_id == dst_id)) {
                result.found = true;
                result.device_id = entry_device_id;
                result.ipv4_addr = ipv4_addr;
                result.port = *reinterpret_cast<uint16_t*>(reinterpret_cast<uintptr_t>(current_entry) + entry_offset::port);
                result.elapsed_seconds = ms / 1000.0;
                break;
            }
            current_entry = *reinterpret_cast<uintptr_t**>(current_entry);
        }
        pthread_mutex_unlock(mutex);

        if (result.found) {
            uint8_t* b = reinterpret_cast<uint8_t*>(&result.ipv4_addr);
            LOG_INFO("lan", "doorbell found! dst_id=%lld ip=%u.%u.%u.%u:%u (%.1fs)",
                     (long long)result.device_id, b[0], b[1], b[2], b[3], result.port, result.elapsed_seconds);
            return result;
        }

        if (ms % 10000 == 9500)
            LOG_DEBUG("lan", "waiting... (%d/%ds)", (ms + 500) / 1000, max_wait_sec);

        usleep(500000);
    }

    LOG_WARN("lan", "no broadcast response after %ds", max_wait_sec);
    return result;
}

bool inject(const sdk::SdkSymbols& sdk, int64_t dst_id,
            const std::string& ip_str, uint16_t port,
            const std::string& device_mac) {
    uintptr_t bcast_mgr = get_broadcast_manager(sdk);
    if (!bcast_mgr || dst_id == 0) return false;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;

    LOG_INFO("lan", "injecting: dst_id=%lld ip=%s port=%u",
             (long long)dst_id, ip_str.c_str(), port);

    void* entry = std::calloc(1, kBroadcastEntrySize);
    if (!entry) return false;

    auto entry_addr = reinterpret_cast<uintptr_t>(entry);
    uint32_t now = sdk.get_tick ? sdk.get_tick() : 0;
    *reinterpret_cast<uint32_t*>(entry_addr + entry_offset::timestamp_general) = now;
    *reinterpret_cast<uint32_t*>(entry_addr + entry_offset::timestamp_ipv4)    = now;
    *reinterpret_cast<int64_t*>(entry_addr + entry_offset::device_id)          = dst_id;
    *reinterpret_cast<uint32_t*>(entry_addr + entry_offset::ipv4_addr)         = addr.s_addr;
    *reinterpret_cast<uint16_t*>(entry_addr + entry_offset::port)              = port;
    *reinterpret_cast<uint8_t*>(entry_addr + entry_offset::lan_flag)           = 1;
    std::strncpy(reinterpret_cast<char*>(entry_addr + entry_offset::device_string), device_mac.c_str(), 0x23);

    auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + mgr_offset::mutex);
    uintptr_t list_head_addr = bcast_mgr + mgr_offset::list_head;
    auto** list_tail_ptr = reinterpret_cast<uintptr_t**>(bcast_mgr + mgr_offset::list_tail);

    pthread_mutex_lock(mutex);
    *reinterpret_cast<uintptr_t*>(entry_addr + 0x00) = list_head_addr;
    *reinterpret_cast<uintptr_t*>(entry_addr + 0x08) = reinterpret_cast<uintptr_t>(*list_tail_ptr);
    **list_tail_ptr = reinterpret_cast<uintptr_t>(entry);
    *list_tail_ptr = reinterpret_cast<uintptr_t*>(entry);
    pthread_mutex_unlock(mutex);

    LOG_INFO("lan", "entry injected");
    return true;
}

}  // namespace broadcast
