// wyze_auth.hpp — Wyze cloud auth, device discovery, Mars token registration.
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
    std::string device_ip;       // LAN IP from GDM (e.g. "192.168.1.81")
};

StreamCreds bootstrap(const std::string& device_mac = "");

void wakeup(const std::string& device_mac, const std::string& product_model);

}  // namespace wyze
