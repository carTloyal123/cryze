// session_key.hpp — Session key extraction from the SDK's CERTIFY handshake.
//
// The LD_PRELOAD hook in bionic_interpose.c intercepts rc5_ctx_setkey() and
// captures the 32-byte session key when the SDK's GUTES certify response
// handler installs it.  This header provides the C++ interface to query
// and persist that key.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace session_key {

// Poll the interpose hook for a captured 32-byte session key.
// Returns true if a key was available and copied into |out|.
// |out| must point to at least 32 bytes.
bool get(uint8_t* out);

// Wait up to |timeout_sec| seconds for the session key to appear.
// Returns true if captured, false on timeout.
bool wait_for(uint8_t* out, int timeout_sec);

// Write 32 raw key bytes to |path|.  Returns true on success.
bool write_to_file(const uint8_t* key, const char* path = nullptr);

// Format 32 key bytes as a 64-char lowercase hex string.
std::string to_hex(const uint8_t* key);

// Default output path (overridden by SESSION_KEY_PATH env var).
constexpr const char* kDefaultPath = "/cache/session_key_extracted.bin";

}  // namespace session_key
