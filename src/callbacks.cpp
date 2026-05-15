// callbacks.cpp — SDK callback implementations
//
// Two sets of callbacks:
//   1. iv_access_init callbacks (16 slots) — SDK lifecycle events
//   2. AV decoder callbacks (7 slots in av_req) — frame delivery

#include "callbacks.hpp"
#include "sdk_types.hpp"

#include <chrono>
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

// --- Global state ---
std::atomic<bool>     g_app_online{false};
std::atomic<bool>     g_sub_success{false};
std::atomic<uint32_t> g_sub_error{0xFFFFFFFF};
std::atomic<int>      g_video_frames{0};
std::atomic<size_t>   g_video_bytes{0};
int                   g_output_fd = -1;

static auto g_start = std::chrono::steady_clock::now();

static int64_t elapsed_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - g_start).count();
}

// =========================================================================
// iv_access_init callbacks (16 slots)
// =========================================================================

// Generic stub for uninteresting slots
static int64_t generic_cb(int slot, uint64_t a0, uint64_t a1) {
    std::fprintf(stderr, "  [cb slot=%d t+%lldms] a0=0x%" PRIx64 " a1=0x%" PRIx64 "\n",
                 slot, (long long)elapsed_ms(), a0, a1);
    return 0;
}

// Slot 8: app_access_srv_callback — APP_ONLINE notification
static int64_t cb_app_state(uint64_t state, uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    int s = (int)state;
    const char* name = s == 1 ? "ONLINE" : s == 2 ? "OFFLINE" : s == 3 ? "TOKEN_ERROR" : "?";
    std::fprintf(stderr, "  [slot8 t+%lldms] APP_LINK_STATE=%d (%s)\n",
                 (long long)elapsed_ms(), s, name);
    if (s == sdk::kAppOnline)
        g_app_online.store(true);
    return 0;
}

// Slot 12: subscribe_with_devid_resp_cb
static int64_t cb_subscribe(uint64_t a0, uint64_t error_code, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    uint32_t err = (uint32_t)error_code;
    g_sub_error.store(err);
    if (err == 0) {
        g_sub_success.store(true);
        std::fprintf(stderr, "  [slot12 t+%lldms] subscribe OK\n", (long long)elapsed_ms());
    } else {
        std::fprintf(stderr, "  [slot12 t+%lldms] subscribe error=0x%x\n",
                     (long long)elapsed_ms(), err);
    }
    return 0;
}

// Slot 13: common_get_cb_sdk — must return -1 (no cache)
static int64_t cb_cache_read(uint64_t key, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5) {
    return -1;
}

// Slot 14: common_set_cb_sdk — cache write (ignore for now)
static int64_t cb_cache_write(uint64_t key, uint64_t a1, uint64_t a2,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    return 0;
}

// Macro-generated stubs for remaining slots
#define SLOT_STUB(N)                                                          \
    static int64_t cb_slot_##N(uint64_t a0, uint64_t a1, uint64_t a2,         \
                               uint64_t a3, uint64_t a4, uint64_t a5) {       \
        return generic_cb(N, a0, a1);                                         \
    }

SLOT_STUB(0)  SLOT_STUB(1)  SLOT_STUB(2)  SLOT_STUB(3)
SLOT_STUB(4)  SLOT_STUB(5)  SLOT_STUB(6)
SLOT_STUB(9)  SLOT_STUB(11)
SLOT_STUB(15)

// Slot 10: getCurrentLocalIp — SDK calls this FIRST before built-in get_local_ip().
// Signature: void(uint32_t* ipv4_out, uint8_t ipv6_out[16])
// Returns local LAN IPv4 in network byte order. Critical for:
//   - Broadcast discovery (correct subnet broadcast address)
//   - CALLING frame (tells peer our LAN address)
//   - Mars server LAN matching (peerlanip field)
static int64_t cb_get_local_ip(uint64_t ipv4_out_ptr, uint64_t ipv6_out_ptr,
                               uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    auto* ipv4_out = reinterpret_cast<uint32_t*>(ipv4_out_ptr);
    auto* ipv6_out = reinterpret_cast<uint8_t*>(ipv6_out_ptr);

    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        std::fprintf(stderr, "  [slot10] getifaddrs failed: %s\n", strerror(errno));
        return 0;
    }

    uint32_t best_ip = 0;
    const char* best_if = nullptr;

    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        uint32_t ip = sin->sin_addr.s_addr;  // network byte order
        uint8_t first = ip & 0xFF;

        // Skip Docker/container bridges (172.x) and link-local (169.254)
        if (first == 172 || first == 169) continue;

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        std::fprintf(stderr, "  [slot10] candidate: %s = %s\n", ifa->ifa_name, buf);

        // Prefer 192.168.x.x or 10.x.x.x (typical home networks)
        if (best_ip == 0 || first == 192 || first == 10) {
            best_ip = ip;
            best_if = ifa->ifa_name;
        }
    }

    if (best_ip && ipv4_out) {
        *ipv4_out = best_ip;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &best_ip, buf, sizeof(buf));
        std::fprintf(stderr, "  [slot10] selected: %s = %s\n", best_if, buf);
    } else {
        std::fprintf(stderr, "  [slot10] no suitable interface found\n");
    }

    // IPv6: first non-loopback, non-link-local global address
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

// Slot 7: p2p_log_callback — SDK internal logging
// Called as: callback(level, file_ptr, fmt_string, ...)
//
// Log verbosity controlled by g_sdk_log_level:
//   5 = all (very verbose, for LAN/P2P debugging)
//   6 = warn+ (default, cleaner output)
int g_sdk_log_level = 5;  // default: show all for debugging

static int64_t cb_p2p_log(uint64_t level, uint64_t file_ptr, uint64_t fmt_ptr,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    int lvl = (int)level;
    const char* fmt = (const char*)fmt_ptr;
    if (lvl >= g_sdk_log_level && fmt) {
        char buf[512];
        int n = snprintf(buf, sizeof(buf), fmt, a3, a4, a5);
        if (n > 0) {
            if (n > 0 && buf[n-1] == '\n') buf[n-1] = 0;
            std::fprintf(stderr, "  [sdk L%d] %s\n", lvl, buf);
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

// =========================================================================
// AV decoder callbacks (set in av_req for iv_start_av_link)
// These are extern "C" so libiotp2pav.so can call them directly.
// =========================================================================

// The output ring buffer read index at avctl[0x464] must be advanced
// by us since we're not using libiotvideo.so's render thread.
static uint32_t* s_avctl_base = nullptr;

extern "C" {

int bridge_init_decoder(uint32_t chn, void* output_frame_ctx, void* decoder_ctx_out) {
    std::fprintf(stderr, "[av] init_decoder chn=%u output_ctx=%p decoder_out=%p\n",
                 chn, output_frame_ctx, decoder_ctx_out);
    // Recover avctl base from decoder_ctx_out = avctl + 0x19b
    // We need this to advance the output ring buffer read index.
    if (decoder_ctx_out)
        s_avctl_base = reinterpret_cast<uint32_t*>(decoder_ctx_out) - 0x19b;
    // SDK checks *(void**)decoder_ctx_out != NULL before calling decode_video.
    if (decoder_ctx_out)
        *reinterpret_cast<void**>(decoder_ctx_out) = reinterpret_cast<void*>(0xDEC0DE01);
    return 0;
}

void bridge_decode_audio(uint32_t chn, void* ctx, uint8_t* data,
                          uint32_t len, uint64_t pts, void* frame) {
    // Ignore audio
}

int bridge_decode_video(uint32_t chn, void* ctx, uint8_t* h264_data,
                         uint32_t h264_len, uint64_t pts, void* frame) {
    if (!h264_data || h264_len == 0) return 0;

    int n = ++g_video_frames;
    g_video_bytes += h264_len;

    if (n <= 5 || n % 100 == 0)
        std::fprintf(stderr, "[av] frame #%d chn=%u len=%u pts=%" PRIu64 "\n",
                     n, chn, h264_len, pts);

    if (g_output_fd >= 0) {
        ssize_t w = ::write(g_output_fd, h264_data, h264_len);
        if (w < 0 && n <= 3)
            std::fprintf(stderr, "[av] write error: %s\n", strerror(errno));
    }
    // Advance output ring buffer read index to match write index.
    // Without this, the 8-slot output buffer fills up and decode stalls.
    // In Android, libiotvideo.so's render thread does this.
    if (s_avctl_base)
        s_avctl_base[0x464] = s_avctl_base[0x465];

    return 0;  // 0 = consumed, SDK advances ring buffer to next frame
}

void bridge_destroy_decoder(uint32_t chn, void* ctx) {
    std::fprintf(stderr, "[av] destroy_decoder chn=%u\n", chn);
}

void bridge_recv_av_data(uint32_t chn, void* ctx, void* av_data) {
    static int count = 0;
    if (++count <= 3)
        std::fprintf(stderr, "[av] recv_av_data #%d chn=%u\n", count, chn);
}

void bridge_recv_user_data(uint32_t chn, void* ctx, void* user_data) {
    static int count = 0;
    if (++count <= 3)
        std::fprintf(stderr, "[av] recv_user_data #%d chn=%u\n", count, chn);
}

void bridge_recv_avheader(uint32_t chn, void* ctx, void* av_header) {
    std::fprintf(stderr, "[av] recv_avheader chn=%u header=%p\n", chn, av_header);
}

}  // extern "C"

}  // namespace cb
