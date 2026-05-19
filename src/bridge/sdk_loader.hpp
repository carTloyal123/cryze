#pragma once

#include "sdk_types.hpp"
#include <string>

namespace sdk {

SdkSymbols load(const std::string& path = "/libs/libiotp2pav.so");

}  // namespace sdk
