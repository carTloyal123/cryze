// callbacks.hpp — SDK callback implementations
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace cb {

extern std::atomic<bool>     g_app_online;
extern std::atomic<bool>     g_sub_success;
extern std::atomic<uint32_t> g_sub_error;
extern std::atomic<int>      g_video_frames;
extern std::atomic<size_t>   g_video_bytes;
extern int                   g_h264_output_fd;
extern int                   g_min_log_level;

// Get the array of iv_access_init callback function pointers.
void** get_init_callbacks();

}  // namespace cb
