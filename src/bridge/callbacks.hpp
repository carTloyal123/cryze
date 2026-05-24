#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace cb {

extern std::atomic<bool>     g_app_online;
extern std::atomic<bool>     g_sub_success;
extern std::atomic<uint32_t> g_sub_error;
extern std::atomic<int>      g_video_frames;
extern std::atomic<size_t>   g_video_bytes;
extern int                   g_h264_output_fd;
extern int                   g_min_log_level;
extern std::string           g_device_mac;  // set by main() before AV link starts

void** get_init_callbacks();

}  // namespace cb
