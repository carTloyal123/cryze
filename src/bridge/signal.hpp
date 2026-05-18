// signal.hpp — Signal handling and crash diagnostics
#pragma once

#include <atomic>

namespace sig {

// Install crash handlers (SIGSEGV/SIGBUS with backtrace) and SIGINT/SIGTERM.
// shutdown_flag is set to true on SIGINT/SIGTERM.
void install(std::atomic<bool>& shutdown_flag);

// Print network interfaces to stderr (for LAN debugging).
void print_network_interfaces();

}  // namespace sig
