// daemon.cpp — Persistent bridge daemon for fast reconnect.
//
// Instead of cold-starting the entire SDK for each viewer connection,
// the daemon keeps the SDK initialized and subscribed. When a viewer
// connects (via stdin command), it only needs to call iv_start_av_link.
//
// Protocol (stdin/stdout):
//   Input commands (one per line):
//     "start"      → Begin streaming H.264 to the output pipe
//     "stop"       → Stop current stream (but keep SDK alive)
//     "quit"       → Shutdown daemon entirely
//
//   Output:
//     H.264 Annex B NALUs on stdout (when streaming)
//     Status messages on stderr
//
// Integration with go2rtc:
//   The daemon runs as a long-lived process. go2rtc connects to it
//   via a named pipe or exec with stdin commands.

#include "sdk_types.hpp"
#include "sdk_loader.hpp"
#include "wyze_auth.hpp"
#include "callbacks.hpp"

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <string>

// --- Globals ---
static std::atomic<bool> g_shutdown{false};
static std::atomic<bool> g_streaming{false};
static std::atomic<int>  g_channel_id{-1};
static sdk::SdkSymbols   g_sdk{};
static std::string        g_devid;  // "_@." + device_mac

// Declared in callbacks.cpp
extern "C" {
    int  bridge_init_decoder(uint32_t, void*, void*);
    void bridge_decode_audio(uint32_t, void*, uint8_t*, uint32_t, uint64_t, void*);
    int  bridge_decode_video(uint32_t, void*, uint8_t*, uint32_t, uint64_t, void*);
    void bridge_destroy_decoder(uint32_t, void*);
    void bridge_recv_av_data(uint32_t, void*, void*);
    void bridge_recv_user_data(uint32_t, void*, void*);
    void bridge_recv_avheader(uint32_t, void*, void*);
}

static void sighandler(int) { g_shutdown.store(true); }

static bool wait_for(std::atomic<bool>& flag, int timeout_sec, const char* label) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (!flag.load() && !g_shutdown.load()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::fprintf(stderr, "[daemon] %s timed out after %ds\n", label, timeout_sec);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return flag.load();
}

// Start AV link to doorbell — the fast path (skips init+subscribe)
static int start_stream() {
    if (g_streaming.load()) {
        std::fprintf(stderr, "[daemon] already streaming\n");
        return g_channel_id.load();
    }

    // Check if doorbell is in broadcast list (already awake from keepalive)
    uintptr_t base = reinterpret_cast<uintptr_t>(g_sdk.lib_base);
    uintptr_t bcast_mgr = *reinterpret_cast<uintptr_t*>(base + 0x0f0438);
    uintptr_t termunit = *reinterpret_cast<uintptr_t*>(base + 0x0f0430);

    int64_t dst_id = 0;
    if (termunit && g_sdk.find_dstid) {
        dst_id = g_sdk.find_dstid(reinterpret_cast<void*>(termunit), g_devid.c_str());
    }

    // Quick poll: check if doorbell is already in broadcast list (from keepalive)
    bool doorbell_ready = false;
    if (bcast_mgr) {
        uintptr_t sentinel = bcast_mgr + 0x5c;
        auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + 0x1c);

        pthread_mutex_lock(mutex);
        uintptr_t* node = *reinterpret_cast<uintptr_t**>(sentinel);
        while (reinterpret_cast<uintptr_t>(node) != sentinel) {
            uint32_t ip = *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(node) + 0x2e);
            int64_t nid = *reinterpret_cast<int64_t*>(reinterpret_cast<uintptr_t>(node) + 0x1c);
            if (ip != 0 && (dst_id == 0 || nid == dst_id)) {
                doorbell_ready = true;
                break;
            }
            node = *reinterpret_cast<uintptr_t**>(node);
        }
        pthread_mutex_unlock(mutex);
    }

    if (doorbell_ready) {
        std::fprintf(stderr, "[daemon] doorbell already in broadcast list — fast path\n");
    } else {
        // Wait briefly for broadcast response (doorbell should be awake from keepalive)
        std::fprintf(stderr, "[daemon] waiting for doorbell broadcast response (max 10s)...\n");
        auto t0 = std::chrono::steady_clock::now();
        while (!doorbell_ready && !g_shutdown.load()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - t0).count();
            if (elapsed >= 10) break;

            if (bcast_mgr) {
                uintptr_t sentinel = bcast_mgr + 0x5c;
                auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + 0x1c);
                pthread_mutex_lock(mutex);
                uintptr_t* node = *reinterpret_cast<uintptr_t**>(sentinel);
                while (reinterpret_cast<uintptr_t>(node) != sentinel) {
                    uint32_t ip = *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(node) + 0x2e);
                    int64_t nid = *reinterpret_cast<int64_t*>(reinterpret_cast<uintptr_t>(node) + 0x1c);
                    if (ip != 0 && (dst_id == 0 || nid == dst_id)) {
                        doorbell_ready = true;
                        break;
                    }
                    node = *reinterpret_cast<uintptr_t**>(node);
                }
                pthread_mutex_unlock(mutex);
            }
            if (!doorbell_ready)
                usleep(200000);  // 200ms
        }
    }

    // Inject doorbell IP if not found (fallback from env)
    if (!doorbell_ready) {
        const char* doorbell_ip_env = std::getenv("DOORBELL_IP");
        if (doorbell_ip_env && doorbell_ip_env[0] && dst_id != 0 && bcast_mgr) {
            struct in_addr addr;
            if (inet_pton(AF_INET, doorbell_ip_env, &addr) == 1) {
                const char* port_str = std::getenv("DOORBELL_PORT");
                uint16_t db_port = port_str ? (uint16_t)std::atoi(port_str) : 8899;
                std::fprintf(stderr, "[daemon] injecting doorbell %s:%u\n", doorbell_ip_env, db_port);

                void* entry = std::calloc(1, 0x8e);
                if (entry) {
                    auto e = reinterpret_cast<uintptr_t>(entry);
                    uint32_t now = g_sdk.get_tick ? g_sdk.get_tick() : 0;
                    *reinterpret_cast<uint32_t*>(e + 0x10) = now;
                    *reinterpret_cast<uint32_t*>(e + 0x14) = now;
                    *reinterpret_cast<int64_t*>(e + 0x1c) = dst_id;
                    *reinterpret_cast<uint32_t*>(e + 0x2e) = addr.s_addr;
                    *reinterpret_cast<uint16_t*>(e + 0x2c) = db_port;
                    *reinterpret_cast<uint8_t*>(e + 0x66) = 1;

                    auto* mutex = reinterpret_cast<pthread_mutex_t*>(bcast_mgr + 0x1c);
                    uintptr_t sentinel_addr = bcast_mgr + 0x5c;
                    auto** sentinel_prev = reinterpret_cast<uintptr_t**>(bcast_mgr + 0x64);

                    pthread_mutex_lock(mutex);
                    *reinterpret_cast<uintptr_t*>(e + 0x00) = sentinel_addr;
                    *reinterpret_cast<uintptr_t*>(e + 0x08) = reinterpret_cast<uintptr_t>(*sentinel_prev);
                    **sentinel_prev = reinterpret_cast<uintptr_t>(entry);
                    *sentinel_prev = reinterpret_cast<uintptr_t*>(entry);
                    pthread_mutex_unlock(mutex);
                }
            }
        }
    }

    // Build av_req struct
    static std::string s_user_id;  // Will be set during init
    static uint8_t s_fake_ctx[sdk::kFakeContextSize] = {0};
    alignas(8) static uint8_t av_req[sdk::kAvReqSize];
    std::memset(av_req, 0, sizeof(av_req));

    auto put_u32 = [](size_t off, uint32_t v) {
        *reinterpret_cast<uint32_t*>(av_req + off) = v;
    };
    auto put_u64 = [](size_t off, uint64_t v) {
        *reinterpret_cast<uint64_t*>(av_req + off) = v;
    };

    put_u64(sdk::av_off::dst_id_ptr, reinterpret_cast<uint64_t>(g_devid.c_str()));
    put_u32(sdk::av_off::call_type, 1);
    put_u32(sdk::av_off::state, 1);
    put_u32(sdk::av_off::user_data, 2);  // SD quality

    put_u64(sdk::av_off::init_decoder,    reinterpret_cast<uint64_t>(&bridge_init_decoder));
    put_u64(sdk::av_off::decode_audio,    reinterpret_cast<uint64_t>(&bridge_decode_audio));
    put_u64(sdk::av_off::decode_video,    reinterpret_cast<uint64_t>(&bridge_decode_video));
    put_u64(sdk::av_off::destroy_decoder, reinterpret_cast<uint64_t>(&bridge_destroy_decoder));
    put_u64(sdk::av_off::recv_av_data,    reinterpret_cast<uint64_t>(&bridge_recv_av_data));
    put_u64(sdk::av_off::cb_slot_5,       reinterpret_cast<uint64_t>(&bridge_recv_user_data));
    put_u64(sdk::av_off::recv_avheader,   reinterpret_cast<uint64_t>(&bridge_recv_avheader));
    put_u64(sdk::av_off::context_ptr, reinterpret_cast<uint64_t>(s_fake_ctx));

    if (!s_user_id.empty())
        put_u64(sdk::av_off::user_id_str_ptr, reinterpret_cast<uint64_t>(s_user_id.c_str()));

    int err_code = 0;
    std::fprintf(stderr, "[daemon] calling iv_start_av_link...\n");
    auto t0 = std::chrono::steady_clock::now();

    int av_rc = g_sdk.start_av_link(av_req, &err_code);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    std::fprintf(stderr, "[daemon] iv_start_av_link returned %d err=%d in %lldms\n",
                 av_rc, err_code, (long long)elapsed);

    if (av_rc < 0) {
        std::fprintf(stderr, "[daemon] AV link failed (err=0x%x)\n", err_code);
        return -1;
    }

    g_channel_id.store(av_rc);
    g_streaming.store(true);
    std::fprintf(stderr, "[daemon] streaming on channel %d\n", av_rc);
    return av_rc;
}

static void stop_stream() {
    int chn = g_channel_id.load();
    if (chn >= 0 && g_sdk.stop_av_link) {
        std::fprintf(stderr, "[daemon] stopping AV link (chn=%d)\n", chn);
        g_sdk.stop_av_link((uint32_t)chn, 0, 0);
    }
    g_channel_id.store(-1);
    g_streaming.store(false);
    cb::g_video_frames.store(0);
    cb::g_video_bytes.store(0);
    std::fprintf(stderr, "[daemon] stream stopped\n");
}

int main(int argc, char** argv) {
    // Parse args
    std::string device_mac;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--device" && i + 1 < argc) device_mac = argv[++i];
        else if (a == "--verbose" || a == "-v") cb::g_sdk_log_level = 5;
        else if (a == "--quiet" || a == "-q") cb::g_sdk_log_level = 7;
    }

    // Setup stdout for H.264 output (same as main.cpp --stdout)
    int h264_fd = ::dup(STDOUT_FILENO);
    ::dup2(STDERR_FILENO, STDOUT_FILENO);
    cb::g_output_fd = h264_fd;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    std::fprintf(stderr, "[daemon] starting persistent bridge daemon\n");

    // === Phase 0: Auth ===
    wyze::StreamCreds creds;
    try {
        creds = wyze::bootstrap(device_mac);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[daemon] auth failed: %s\n", e.what());
        return 1;
    }
    g_devid = "_@." + creds.device_mac;

    // === Phase 1: SDK Init ===
    try {
        g_sdk = sdk::load();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[daemon] SDK load failed: %s\n", e.what());
        return 1;
    }

    sdk::InitParamBlob param{};
    param.zero();

    uint64_t access_id_num = std::strtoull(creds.access_id.c_str(), nullptr, 10);
    static std::string s_token = creds.access_token;

    param.i32(sdk::init_off::marker_a)  = 2;
    param.i32(sdk::init_off::marker_b)  = 1;
    param.u64(sdk::init_off::access_id) = access_id_num;
    param.ptr(sdk::init_off::access_token_ptr) = const_cast<char*>(s_token.c_str());
    param.i32(sdk::init_off::access_token_len) = (int32_t)s_token.size();
    {
        const char* p2p_url = std::getenv("P2P_URL");
        if (!p2p_url) p2p_url = "|wyze-mars-asrv.wyzecam.com";
        std::strncpy(param.cstr(sdk::init_off::p2p_url_buf), p2p_url, 420);
    }
    param.i16(sdk::init_off::lang_code)     = 1;
    param.i16(sdk::init_off::dev_type)      = 3;
    param.i32(sdk::init_off::version)       = 0x0d000000;
    param.i32(sdk::init_off::p2p_port_type) = 0;
    {
        const char* pt = std::getenv("P2P_PORT_TYPE");
        if (pt) param.i32(sdk::init_off::p2p_port_type) = std::atoi(pt);
    }

    void** cbs = cb::get_init_callbacks();
    for (int i = 0; i < 16; ++i)
        param.ptr(sdk::init_off::cb[i]) = cbs[i];

    std::atomic<bool> init_done{false};
    std::atomic<int> init_rc{-99};
    std::thread init_thread([&] {
        init_rc.store(g_sdk.access_init(&param));
        init_done.store(true);
    });
    init_thread.detach();

    if (!wait_for(init_done, 35, "iv_access_init")) return 1;
    if (init_rc.load() != 0) {
        std::fprintf(stderr, "[daemon] init failed (rc=%d)\n", init_rc.load());
        return 1;
    }
    if (!wait_for(cb::g_app_online, 30, "APP_ONLINE")) return 1;
    std::fprintf(stderr, "[daemon] SDK online\n");

    // === Phase 2: Subscribe ===
    g_sdk.subscribe_dev(creds.access_token.c_str(), creds.device_mac.c_str(),
                        (uint32_t)creds.access_token.size());
    if (!wait_for(cb::g_sub_success, 20, "subscribe")) return 1;
    std::fprintf(stderr, "[daemon] subscribed OK\n");

    // === Phase 3: Command loop ===
    // The daemon is now warm — SDK initialized, subscribed, ready for av_link.
    // Read commands from a control pipe (or stdin if not a pipe).
    std::fprintf(stderr, "[daemon] READY — waiting for commands on stdin\n");
    std::fprintf(stderr, "[daemon] Commands: start | stop | quit\n");

    // Create control pipe at a well-known path for go2rtc integration
    const char* ctl_pipe = std::getenv("DAEMON_CTL_PIPE");
    std::string pipe_path = ctl_pipe ? ctl_pipe : "/tmp/bridge-daemon.ctl";

    // Use stdin for commands (simplest for exec integration)
    char cmd_buf[256];
    while (!g_shutdown.load()) {
        // Non-blocking read from stdin with timeout
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval tv = {1, 0};  // 1 second timeout

        int sel = select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        if (!fgets(cmd_buf, sizeof(cmd_buf), stdin)) {
            // stdin closed (go2rtc disconnected) — stop stream but keep running
            if (g_streaming.load()) {
                std::fprintf(stderr, "[daemon] stdin closed — stopping stream\n");
                stop_stream();
            }
            // Reopen stdin won't work; just wait for signal
            while (!g_shutdown.load())
                std::this_thread::sleep_for(std::chrono::seconds(1));
            break;
        }

        std::string cmd(cmd_buf);
        // Trim whitespace
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
            cmd.pop_back();

        if (cmd == "start") {
            int rc = start_stream();
            if (rc >= 0)
                std::fprintf(stderr, "[daemon] ACK start (chn=%d)\n", rc);
            else
                std::fprintf(stderr, "[daemon] NAK start (failed)\n");
        }
        else if (cmd == "stop") {
            stop_stream();
            std::fprintf(stderr, "[daemon] ACK stop\n");
        }
        else if (cmd == "quit" || cmd == "exit") {
            std::fprintf(stderr, "[daemon] quit requested\n");
            break;
        }
        else if (cmd == "status") {
            std::fprintf(stderr, "[daemon] streaming=%d chn=%d frames=%d bytes=%zu\n",
                         g_streaming.load(), g_channel_id.load(),
                         cb::g_video_frames.load(), cb::g_video_bytes.load());
        }
        else if (!cmd.empty()) {
            std::fprintf(stderr, "[daemon] unknown command: '%s'\n", cmd.c_str());
        }
    }

    // Shutdown
    if (g_streaming.load()) stop_stream();
    if (cb::g_output_fd >= 0 && cb::g_output_fd != STDOUT_FILENO)
        ::close(cb::g_output_fd);

    std::fprintf(stderr, "[daemon] exiting\n");
    _exit(0);
}
