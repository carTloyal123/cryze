// daemon.cpp — Persistent bridge daemon for fast reconnect
//
// Keeps the SDK initialized and subscribed. Accepts stdin commands
// to start/stop AV links without cold-starting the SDK.
//
// Commands: start | stop | quit | status

#include "sdk_types.hpp"
#include "sdk_loader.hpp"
#include "wyze_auth.hpp"
#include "callbacks.hpp"
#include "broadcast.hpp"
#include "signal.hpp"

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/select.h>
#include <thread>
#include <unistd.h>
#include <string>

extern "C" {
    int  bridge_init_decoder(uint32_t, void*, void*);
    void bridge_decode_audio(uint32_t, void*, uint8_t*, uint32_t, uint64_t, void*);
    int  bridge_decode_video(uint32_t, void*, uint8_t*, uint32_t, uint64_t, void*);
    void bridge_destroy_decoder(uint32_t, void*);
    void bridge_recv_av_data(uint32_t, void*, void*);
    void bridge_recv_user_data(uint32_t, void*, void*);
    void bridge_recv_avheader(uint32_t, void*, void*);
}

static std::atomic<bool> g_shutdown{false};
static std::atomic<bool> g_streaming{false};
static std::atomic<int>  g_channel_id{-1};
static sdk::SdkSymbols   g_sdk{};
static std::string        g_devid;

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

static int start_stream(const std::string& device_mac) {
    if (g_streaming.load()) {
        std::fprintf(stderr, "[daemon] already streaming\n");
        return g_channel_id.load();
    }

    int64_t dst_id = broadcast::resolve_dst_id(g_sdk, device_mac);

    // Quick poll — doorbell should be awake from keepalive
    auto result = broadcast::poll(g_sdk, dst_id, 10, g_shutdown);

    if (!result.found) {
        const char* db_ip = std::getenv("DOORBELL_IP");
        if (db_ip && db_ip[0] && dst_id != 0) {
            const char* ps = std::getenv("DOORBELL_PORT");
            uint16_t port = ps ? (uint16_t)std::atoi(ps) : 8899;
            broadcast::inject(g_sdk, dst_id, db_ip, port, device_mac);
        }
    }

    // Build av_req
    static std::string s_user_id;
    static uint8_t s_fake_ctx[sdk::kFakeContextSize] = {0};
    alignas(8) static uint8_t av_req[sdk::kAvReqSize];
    std::memset(av_req, 0, sizeof(av_req));

    auto put_u32 = [](size_t off, uint32_t v) { *reinterpret_cast<uint32_t*>(av_req + off) = v; };
    auto put_u64 = [](size_t off, uint64_t v) { *reinterpret_cast<uint64_t*>(av_req + off) = v; };

    put_u64(sdk::av_off::dst_id_ptr, reinterpret_cast<uint64_t>(g_devid.c_str()));
    put_u32(sdk::av_off::call_type, 1);
    put_u32(sdk::av_off::state, 1);
    put_u32(sdk::av_off::user_data, 2);
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
    int av_rc = g_sdk.start_av_link(av_req, &err_code);
    std::fprintf(stderr, "[daemon] iv_start_av_link returned %d err=%d\n", av_rc, err_code);

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
    if (chn >= 0 && g_sdk.stop_av_link)
        g_sdk.stop_av_link((uint32_t)chn, 0, 0);
    g_channel_id.store(-1);
    g_streaming.store(false);
    cb::g_video_frames.store(0);
    cb::g_video_bytes.store(0);
    std::fprintf(stderr, "[daemon] stream stopped\n");
}

int main(int argc, char** argv) {
    std::string device_mac;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--device" && i + 1 < argc) device_mac = argv[++i];
        else if (a == "--verbose" || a == "-v") cb::g_sdk_log_level = 5;
        else if (a == "--quiet" || a == "-q") cb::g_sdk_log_level = 7;
    }

    // H.264 on original stdout, logs on stderr
    int h264_fd = ::dup(STDOUT_FILENO);
    ::dup2(STDERR_FILENO, STDOUT_FILENO);
    cb::g_output_fd = h264_fd;

    sig::install(g_shutdown);
    std::fprintf(stderr, "[daemon] starting\n");

    // --- Auth ---
    wyze::StreamCreds creds;
    try { creds = wyze::bootstrap(device_mac); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "[daemon] auth failed: %s\n", e.what());
        return 1;
    }
    g_devid = "_@." + creds.device_mac;

    // --- SDK Init ---
    try { g_sdk = sdk::load(); }
    catch (const std::exception& e) {
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
    std::thread([&] { init_rc.store(g_sdk.access_init(&param)); init_done.store(true); }).detach();

    if (!wait_for(init_done, 35, "iv_access_init")) return 1;
    if (init_rc.load() != 0) return 1;
    if (!wait_for(cb::g_app_online, 30, "APP_ONLINE")) return 1;
    std::fprintf(stderr, "[daemon] SDK online\n");

    // --- Subscribe ---
    g_sdk.subscribe_dev(creds.access_token.c_str(), creds.device_mac.c_str(),
                        (uint32_t)creds.access_token.size());
    if (!wait_for(cb::g_sub_success, 20, "subscribe")) return 1;
    std::fprintf(stderr, "[daemon] subscribed — READY\n");
    std::fprintf(stderr, "[daemon] commands: start | stop | quit | status\n");

    // --- Command loop ---
    char cmd_buf[256];
    while (!g_shutdown.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval tv = {1, 0};

        int sel = select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        if (!fgets(cmd_buf, sizeof(cmd_buf), stdin)) {
            if (g_streaming.load()) stop_stream();
            while (!g_shutdown.load())
                std::this_thread::sleep_for(std::chrono::seconds(1));
            break;
        }

        std::string cmd(cmd_buf);
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
            cmd.pop_back();

        if (cmd == "start") {
            int rc = start_stream(creds.device_mac);
            std::fprintf(stderr, "[daemon] %s start (chn=%d)\n", rc >= 0 ? "ACK" : "NAK", rc);
        } else if (cmd == "stop") {
            stop_stream();
        } else if (cmd == "quit" || cmd == "exit") {
            break;
        } else if (cmd == "status") {
            std::fprintf(stderr, "[daemon] streaming=%d chn=%d frames=%d bytes=%zu\n",
                         g_streaming.load(), g_channel_id.load(),
                         cb::g_video_frames.load(), cb::g_video_bytes.load());
        } else if (!cmd.empty()) {
            std::fprintf(stderr, "[daemon] unknown: '%s'\n", cmd.c_str());
        }
    }

    if (g_streaming.load()) stop_stream();
    if (cb::g_output_fd >= 0 && cb::g_output_fd != STDOUT_FILENO)
        ::close(cb::g_output_fd);
    _exit(0);
}
