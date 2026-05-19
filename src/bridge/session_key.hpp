#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace session_key {

bool get(uint8_t* out);

bool wait_for(uint8_t* out, int timeout_sec);

bool write_to_file(const uint8_t* key, const char* path = nullptr);

std::string to_hex(const uint8_t* key);

constexpr const char* kDefaultPath = "/cache/session_key_extracted.bin";

}  // namespace session_key
