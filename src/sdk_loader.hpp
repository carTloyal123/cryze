// sdk_loader.hpp — dlopen wrapper for libiotp2pav.so
#pragma once

#include "sdk_types.hpp"
#include <string>

namespace sdk {

// Load libiotp2pav.so and resolve all required symbols.
// Returns populated SdkSymbols or throws std::runtime_error.
SdkSymbols load(const std::string& path = "libs/libiotp2pav.so");

}  // namespace sdk
