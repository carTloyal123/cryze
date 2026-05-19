#pragma once

#include <atomic>

namespace sig {

void install(std::atomic<bool>& shutdown_flag);

void print_network_interfaces();

}  // namespace sig
