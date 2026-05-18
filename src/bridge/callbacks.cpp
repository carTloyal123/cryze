#include "callbacks.hpp"
#include "sdk_types.hpp"
#include "log.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace cb {

std::atomic<bool>     g_app_online{false};
std::atomic<bool>     g_sub_success{false};
std::atomic<uint32_t> g_sub_error{0};
std::atomic<int>      g_video_frames{0};
std::atomic<size_t>   g_video_bytes{0};
int                   g_h264_output_fd = -1;

// iv_access_init callbacks (16 slots)

static int64_t generic_cb(int slot, uint64_t a0, uint64_t a1) {
    LOG_DEBUG("sdk", "cb slot=%d a0=0x%" PRIx64 " a1=0x%" PRIx64, slot, a0, a1);
    return 0;
}

static int64_t cb_app_state(uint64_t link_state, uint64_t, uint64_t,
                            uint64_t, uint64_t, uint64_t) {
    int s = (int)link_state;
    const char* name = s == 1 ? "ONLINE" : s == 2 ? "OFFLINE" : s == 3 ? "TOKEN_ERROR" : "?";
    LOG_INFO("sdk", "APP_LINK_STATE=%d (%s)", s, name);
    if (s == sdk::kAppOnline)
        g_app_online.store(true);
    return 0;
}

// Slot 12: subscribe_with_devid_resp_cb
static int64_t cb_subscribe(uint64_t, uint64_t error_code, uint64_t,
                            uint64_t, uint64_t, uint64_t) {
    uint32_t err = (uint32_t)error_code;
    g_sub_error.store(err);
    if (err == 0) {
        g_sub_success.store(true);
        LOG_INFO("sdk", "subscribe OK");
    } else {
        LOG_WARN("sdk", "subscribe error=0x%x", err);
    }
    return 0;
}

// SDK cache read: always miss
static int64_t cb_cache_read(uint64_t key, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5) {
    return -1;
}

// SDK cache write: no-op
static int64_t cb_cache_write(uint64_t key, uint64_t a1, uint64_t a2,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    return 0;
}

#define SLOT_STUB(N)                                                          \
    static int64_t cb_slot_##N(uint64_t a0, uint64_t a1, uint64_t a2,         \
                               uint64_t a3, uint64_t a4, uint64_t a5) {       \
        return generic_cb(N, a0, a1);                                         \
    }

SLOT_STUB(0)  SLOT_STUB(1)  SLOT_STUB(2)  SLOT_STUB(3)
SLOT_STUB(4)  SLOT_STUB(5)  SLOT_STUB(6)
SLOT_STUB(9)  SLOT_STUB(11)
SLOT_STUB(15)

// Provides the host's LAN IP to the SDK for broadcast discovery and P2P addressing.
static int64_t cb_get_local_ip(uint64_t ipv4_out_ptr, uint64_t ipv6_out_ptr,
                               uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    auto* ipv4_out = reinterpret_cast<uint32_t*>(ipv4_out_ptr);
    auto* ipv6_out = reinterpret_cast<uint8_t*>(ipv6_out_ptr);

    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        LOG_ERROR("sdk", "getifaddrs failed: %s", strerror(errno));
        return 0;
    }

    uint32_t selected_ipv4 = 0;
    const char* selected_iface = nullptr;

    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        uint32_t ip = sin->sin_addr.s_addr;  // network byte order
        uint8_t first = ip & 0xFF;

        if (first == 172 || first == 169) continue;

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        LOG_DEBUG("sdk", "candidate: %s = %s", ifa->ifa_name, buf);

        if (selected_ipv4 == 0 || first == 192 || first == 10) {
            selected_ipv4 = ip;
            selected_iface = ifa->ifa_name;
        }
    }

    if (selected_ipv4 && ipv4_out) {
        *ipv4_out = selected_ipv4;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &selected_ipv4, buf, sizeof(buf));
        LOG_INFO("sdk", "local IP selected: %s = %s", selected_iface, buf);
    } else {
        LOG_WARN("sdk", "no suitable interface found");
    }

    if (ipv6_out) {
        for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6) continue;
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            if (sin6->sin6_addr.s6_addr[0] == 0xfe && sin6->sin6_addr.s6_addr[1] == 0x80) continue;
            std::memcpy(ipv6_out, &sin6->sin6_addr, 16);
            break;
        }
    }

    freeifaddrs(ifap);
    return 0;
}

// SDK log callback. Filtered by g_min_log_level.
int g_min_log_level = 5;

static int64_t cb_p2p_log(uint64_t level, uint64_t file_ptr, uint64_t fmt_ptr,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    int lvl = (int)level;
    const char* fmt = (const char*)fmt_ptr;
    if (lvl >= g_min_log_level && fmt) {
        char buf[512];
        int n = snprintf(buf, sizeof(buf), fmt, a3, a4, a5);
        if (n > 0) {
            if (n > 0 && buf[n-1] == '\n') buf[n-1] = 0;
            LOG_DEBUG("sdk", "[L%d] %s", lvl, buf);
        }
    }
    return 0;
}

static void* s_init_cbs[16] = {
    (void*)cb_slot_0,  (void*)cb_slot_1,  (void*)cb_slot_2,  (void*)cb_slot_3,
    (void*)cb_slot_4,  (void*)cb_slot_5,  (void*)cb_slot_6,  (void*)cb_p2p_log,
    (void*)cb_app_state,                                          // slot 8
    (void*)cb_slot_9,  (void*)cb_get_local_ip, (void*)cb_slot_11,
    (void*)cb_subscribe,                                          // slot 12
    (void*)cb_cache_read,                                         // slot 13
    (void*)cb_cache_write,                                        // slot 14
    (void*)cb_slot_15,
};

void** get_init_callbacks() { return s_init_cbs; }

// AV decoder callbacks (set in av_req for iv_start_av_link)
// These are extern "C" so libiotp2pav.so can call them directly.

constexpr int kDecoderToRingBufferOffset = 0x19b;
constexpr int kRingReadIndex  = 0x464;
constexpr int kRingWriteIndex = 0x465;

// SDK output ring buffer control — must advance read index to prevent stalls.
static uint32_t* s_ring_buffer_base = nullptr;

extern "C" {

int bridge_init_decoder(uint32_t chn, void* output_frame_ctx, void* decoder_ctx_out) {
    LOG_INFO("av", "init_decoder chn=%u output_ctx=%p decoder_out=%p",
             chn, output_frame_ctx, decoder_ctx_out);
    // Recover ring buffer base and set non-null sentinel for SDK.
    if (decoder_ctx_out)
        s_ring_buffer_base = reinterpret_cast<uint32_t*>(decoder_ctx_out) - kDecoderToRingBufferOffset;
    if (decoder_ctx_out)
        *reinterpret_cast<void**>(decoder_ctx_out) = reinterpret_cast<void*>(0xDEC0DE01);
    return 0;
}

void bridge_decode_audio(uint32_t chn, void* ctx, uint8_t* data,
                          uint32_t len, uint64_t pts, void* frame) {
}

int bridge_decode_video(uint32_t chn, void* ctx, uint8_t* h264_data,
                         uint32_t h264_len, uint64_t pts, void* frame) {
    if (!h264_data || h264_len == 0) return 0;

    int n = ++g_video_frames;
    g_video_bytes += h264_len;

    if (n == 1 && h264_len >= 5) {
        char nal_info[256] = {0};
        int nal_pos = 0;
        for (uint32_t i = 0; i + 4 < h264_len; ++i) {
            if (h264_data[i] == 0 && h264_data[i+1] == 0 &&
                ((h264_data[i+2] == 0 && h264_data[i+3] == 1) || h264_data[i+2] == 1)) {
                uint32_t off = (h264_data[i+2] == 1) ? i + 3 : i + 4;
                if (off < h264_len) {
                    uint8_t nal_type = h264_data[off] & 0x1F;
                    const char* name = nal_type == 7 ? "SPS" : nal_type == 8 ? "PPS" :
                                       nal_type == 5 ? "IDR" : nal_type == 6 ? "SEI" :
                                       nal_type == 1 ? "SLICE" : "?";
                    nal_pos += snprintf(nal_info + nal_pos, sizeof(nal_info) - nal_pos, " %s(%u)", name, nal_type);
                }
            }
        }
        LOG_INFO("av", "first frame: len=%u NALs:%s", h264_len, nal_info);
    }

    if (n <= 5 || n % 100 == 0)
        LOG_DEBUG("av", "frame #%d chn=%u len=%u pts=%" PRIu64, n, chn, h264_len, pts);

    if (g_h264_output_fd >= 0) {
        ssize_t w = ::write(g_h264_output_fd, h264_data, h264_len);
        if (w < 0 && n <= 3)
            LOG_ERROR("av", "write error: %s", strerror(errno));
    }

    if (s_ring_buffer_base)
        s_ring_buffer_base[kRingReadIndex] = s_ring_buffer_base[kRingWriteIndex];

    return 0;
}

void bridge_destroy_decoder(uint32_t chn, void* ctx) {
    LOG_INFO("av", "destroy_decoder chn=%u", chn);
}

void bridge_recv_av_data(uint32_t chn, void* ctx, void* av_data) {
    static int count = 0;
    if (++count <= 3)
        LOG_DEBUG("av", "recv_av_data #%d chn=%u", count, chn);
}

void bridge_recv_user_data(uint32_t chn, void* ctx, void* user_data) {
    static int count = 0;
    if (++count <= 3)
        LOG_DEBUG("av", "recv_user_data #%d chn=%u", count, chn);
}

void bridge_recv_avheader(uint32_t chn, void* ctx, void* av_header) {
    LOG_DEBUG("av", "recv_avheader chn=%u header=%p", chn, av_header);
}

}  // extern "C"

}  // namespace cb
