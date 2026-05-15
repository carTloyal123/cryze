// wyze_auth.hpp — Wyze cloud auth: login + device discovery + Mars token
//
// Supports caching Mars creds (7-day TTL) and Wyze login tokens to disk.
// Set CACHE_FILE env var to control cache path (default: cache/auth.json).
#pragma once

#include <string>
#include <cstdint>
#include <optional>
#include <vector>

namespace wyze {

struct DeviceInfo {
    std::string mac;
    std::string product_model;
    std::string product_type;
    std::string nickname;
};

struct StreamCreds {
    std::string device_mac;
    std::string product_model;
    std::string access_id;       // numeric string for IoTVideo SDK
    std::string access_token;    // Mars token (Base64, >= 128 bytes)
    int64_t     expire_time = 0;
    std::string user_id;         // Wyze user ID
};

// Full auth flow: checks cache first, does fresh auth if needed.
//   1. Try loading cached creds from CACHE_FILE (default: cache/auth.json)
//   2. If cache valid: use cached Mars creds + Wyze token for wakeup
//   3. If cache miss/expired: login → get_devices → register_mars_user → save cache
//   4. Send wakeup command to doorbell
// Returns ready-to-use StreamCreds. Throws on any failure.
StreamCreds bootstrap(const std::string& device_mac = "");

// Send wakeup command to a battery doorbell so it starts responding to P2P.
// Requires valid Wyze login tokens. Called automatically by bootstrap().
// Can also be called separately if you want to re-wake.
void wakeup(const std::string& device_mac, const std::string& product_model);

}  // namespace wyze
