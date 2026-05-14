// callbacks.hpp — SDK callback implementations
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace cb {

// --- State flags set by callbacks ---
extern std::atomic<bool>     g_app_online;       // slot 8 → state=1
extern std::atomic<bool>     g_sub_success;      // slot 12 → error=0
extern std::atomic<uint32_t> g_sub_error;        // slot 12 → error code
extern std::atomic<int>      g_video_frames;     // decode_video frame count
extern std::atomic<size_t>   g_video_bytes;      // decode_video total bytes
extern int                   g_output_fd;        // fd for H.264 output

// Get the array of 16 iv_access_init callback function pointers.
void** get_init_callbacks();

}  // namespace cb
