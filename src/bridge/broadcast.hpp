// broadcast.hpp — SDK broadcast list polling and LAN injection
#pragma once

#include "sdk_types.hpp"
#include <atomic>
#include <cstdint>
#include <string>

namespace broadcast {

struct PollResult {
    bool found = false;
    int64_t dst_id = 0;
    uint32_t ip = 0;      // network byte order
    uint16_t port = 0;
    double wait_secs = 0;
};

// Resolve the numeric dst_id for a device from the SDK's tid_key_map.
int64_t resolve_dst_id(const sdk::SdkSymbols& sdk, const std::string& device_mac);

// Poll the SDK's broadcast list for a doorbell response.
// Returns when an entry with a non-zero IPv4 matching dst_id is found, or timeout.
PollResult poll(const sdk::SdkSymbols& sdk, int64_t dst_id,
                int max_wait_sec, std::atomic<bool>& shutdown);

// Inject a synthetic broadcast list entry (fallback when doorbell doesn't respond).
bool inject(const sdk::SdkSymbols& sdk, int64_t dst_id,
            const std::string& ip_str, uint16_t port,
            const std::string& device_mac);

}  // namespace broadcast
