#include "sdk_types.hpp"
#include "sdk_loader.hpp"
#include "wyze_auth.hpp"
#include "callbacks.hpp"
#include "broadcast.hpp"
#include "signal.hpp"
#include "session_key.hpp"
#include "log.hpp"

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

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

static bool wait_for(std::atomic<bool>& flag, int timeout_sec, const char* label) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (!flag.load() && !g_shutdown.load()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            LOG_WARN("bridge", "%s timed out after %ds", label, timeout_sec);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return flag.load();
}

int main(int argc, char** argv) {
    std::string output_path = "logs/frames.h264";
    std::string device_mac;
    int duration = 60;
    bool use_stdout = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) { fprintf(stderr, "missing value for %s\n", a.c_str()); exit(2); }
            return argv[++i];
        };
        if      (a == "--device")   device_mac = next();
        else if (a == "--output")   output_path = next();
        else if (a == "--stdout")   use_stdout = true;
        else if (a == "--duration") duration = std::atoi(next());
        else if (a == "--verbose" || a == "-v") cb::g_min_log_level = 5;
        else if (a == "--quiet"   || a == "-q") cb::g_min_log_level = 7;
        else if (a == "--help" || a == "-h") {
            printf("Usage: bridge [--stdout] [--device MAC] [--output PATH] [--duration SECS] [-v|-q]\n");
            return 0;
        }
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }

    blog::init();

    if (use_stdout) {
        duration = 0;
        int h264_fd = ::dup(STDOUT_FILENO);
        if (h264_fd < 0) { LOG_ERROR("bridge", "dup(stdout) failed"); return 1; }
        ::dup2(STDERR_FILENO, STDOUT_FILENO);
        cb::g_h264_output_fd = h264_fd;
    }

    sig::install(g_shutdown);
    sig::print_network_interfaces();

    LOG_INFO("bridge", "authenticating...");
    wyze::StreamCreds creds;
    try {
        creds = wyze::bootstrap(device_mac);
    } catch (const std::exception& e) {
        LOG_ERROR("bridge", "auth failed: %s", e.what());
        return 1;
    }
    LOG_INFO("bridge", "device=%s access_id=%s",
             creds.device_mac.c_str(), creds.access_id.c_str());

    LOG_INFO("bridge", "initializing SDK...");
    sdk::SdkSymbols sdk;
    try { sdk = sdk::load(); }
    catch (const std::exception& e) {
        LOG_ERROR("bridge", "SDK load failed: %s", e.what());
        return 1;
    }

    if (sdk.get_version) {
        int v = sdk.get_version();
        LOG_INFO("bridge", "SDK version: %d.%d", v >> 8, v & 0xff);
    }

    sdk::InitParamBlob param{};
    param.zero();
    uint64_t access_id_num = std::strtoull(creds.access_id.c_str(), nullptr, 10);
    static std::string stored_token = creds.access_token;

    param.field_i32(sdk::init_off::sdk_mode)  = 2;
    param.field_i32(sdk::init_off::net_mode)  = 1;
    param.field_u64(sdk::init_off::access_id) = access_id_num;
    param.field_ptr(sdk::init_off::access_token_ptr) = const_cast<char*>(stored_token.c_str());
    param.field_i32(sdk::init_off::access_token_len) = (int32_t)stored_token.size();
    {
        const char* p2p_url = std::getenv("P2P_URL");
        if (!p2p_url) p2p_url = "|wyze-mars-asrv.wyzecam.com";
        std::strncpy(param.field_str(sdk::init_off::p2p_url_buf), p2p_url, 420);
        LOG_INFO("bridge", "p2p_url: %s", p2p_url);
    }
    param.field_i16(sdk::init_off::lang_code)     = 1;
    param.field_i16(sdk::init_off::dev_type)      = 3;
    param.field_i32(sdk::init_off::version)       = 0x0d000000;
    param.field_i32(sdk::init_off::p2p_port_type) = 0;
    {
        const char* pt = std::getenv("P2P_PORT_TYPE");
        if (pt) param.field_i32(sdk::init_off::p2p_port_type) = std::atoi(pt);
    }

    void** cbs = cb::get_init_callbacks();
    for (int i = 0; i < 16; ++i)
        param.field_ptr(sdk::init_off::callback_slots[i]) = cbs[i];

    std::atomic<bool> init_done{false};
    std::atomic<int> init_rc{-99};
    std::thread([&] { init_rc.store(sdk.access_init(&param)); init_done.store(true); }).detach();

    if (!wait_for(init_done, 35, "iv_access_init")) return 1;
    if (init_rc.load() != 0) { LOG_ERROR("bridge", "init failed (rc=%d)", init_rc.load()); return 1; }

    // Clear the subscribe-required flag so APP_ONLINE fires immediately
    {
        uintptr_t base = reinterpret_cast<uintptr_t>(sdk.lib_base);
        uintptr_t unit = *reinterpret_cast<uintptr_t*>(base + 0x0f0430);
        if (unit) {
            *reinterpret_cast<int32_t*>(unit + 0x3bc) = 0;
            *reinterpret_cast<int32_t*>(unit + 0x16f8) = 2;
            *reinterpret_cast<int8_t*>(unit + 0x1189) = 1;
            LOG_INFO("bridge", "cleared subscribe gate and set registered state");
        }
    }

    if (!wait_for(cb::g_app_online, 5, "APP_ONLINE (quick)")) {
        LOG_WARN("bridge", "APP_ONLINE not received, forcing via direct callback");
        uintptr_t base = reinterpret_cast<uintptr_t>(sdk.lib_base);
        uintptr_t unit = *reinterpret_cast<uintptr_t*>(base + 0x0f0430);
        if (unit) {
            auto* cb_ptr = reinterpret_cast<void(**)(int)>(unit + 0x1218);
            if (*cb_ptr) {
                (*cb_ptr)(1);  // APP_ONLINE = 1
            }
        }
    }
    if (!wait_for(cb::g_app_online, 5, "APP_ONLINE")) return 1;
    LOG_INFO("bridge", "SDK online!");

    {
        uint8_t sk[32];
        if (session_key::wait_for(sk, 5)) {
            LOG_INFO("bridge", "session key: %s", session_key::to_hex(sk).c_str());
            session_key::write_to_file(sk);
        } else {
            LOG_WARN("bridge", "session key not captured (hook may not have fired)");
        }
    }

    LOG_INFO("bridge", "subscribing...");
    sdk.subscribe_dev(creds.access_token.c_str(), creds.device_mac.c_str(),
                      (uint32_t)creds.access_token.size());
    {
        const char* sub_wait_env = std::getenv("SUBSCRIBE_WAIT");
        int sub_wait = sub_wait_env ? std::atoi(sub_wait_env) : 20;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(sub_wait);
        while (!cb::g_sub_success.load() && !g_shutdown.load()) {
            if (cb::g_sub_error.load() != 0) break;
            if (std::chrono::steady_clock::now() >= deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    if (cb::g_sub_success.load()) LOG_INFO("bridge", "subscribed OK");
    else LOG_WARN("bridge", "subscribe timed out (proceeding)");

    LOG_INFO("bridge", "starting AV link...");
    {
        int64_t dst_id = broadcast::resolve_dst_id(sdk, creds.device_mac);
        const char* lan_wait_env = std::getenv("LAN_WAIT");
        int max_wait = lan_wait_env ? std::atoi(lan_wait_env) : 90;
        auto result = broadcast::poll(sdk, dst_id, max_wait, g_shutdown);

        if (!result.found) {
            const char* doorbell_ip_env = std::getenv("DOORBELL_IP");
            std::string ip = (doorbell_ip_env && doorbell_ip_env[0]) ? std::string(doorbell_ip_env) : creds.device_ip;
            if (!ip.empty() && dst_id != 0) {
                const char* port_env = std::getenv("DOORBELL_PORT");
                uint16_t port = port_env ? (uint16_t)std::atoi(port_env) : 8899;
                broadcast::inject(sdk, dst_id, ip, port, creds.device_mac);
            }
        }
    }

    if (use_stdout) {
        LOG_INFO("bridge", "output: stdout pipe (fd=%d)", cb::g_h264_output_fd);
    } else {
        cb::g_h264_output_fd = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (cb::g_h264_output_fd < 0) {
            LOG_ERROR("bridge", "cannot open %s: %s", output_path.c_str(), strerror(errno));
            return 1;
        }
    }

    cb::g_device_mac = creds.device_mac;  // expose to avheader callback for metrics writes
    static std::string sdk_device_id = "_@." + creds.device_mac;
    static std::string user_id = creds.user_id;
    static uint8_t null_context[sdk::kFakeContextSize] = {0};
    alignas(8) static uint8_t av_req[sdk::kAvReqSize];
    std::memset(av_req, 0, sizeof(av_req));

    auto set_u32 = [](size_t off, uint32_t v) { *reinterpret_cast<uint32_t*>(av_req + off) = v; };
    auto set_u64 = [](size_t off, uint64_t v) { *reinterpret_cast<uint64_t*>(av_req + off) = v; };

    set_u64(sdk::av_off::dst_id_ptr, reinterpret_cast<uint64_t>(sdk_device_id.c_str()));
    set_u32(sdk::av_off::call_type, 1);
    set_u32(sdk::av_off::state, 1);
    set_u32(sdk::av_off::user_data, 2);
    set_u64(sdk::av_off::init_decoder,    reinterpret_cast<uint64_t>(&bridge_init_decoder));
    set_u64(sdk::av_off::decode_audio,    reinterpret_cast<uint64_t>(&bridge_decode_audio));
    set_u64(sdk::av_off::decode_video,    reinterpret_cast<uint64_t>(&bridge_decode_video));
    set_u64(sdk::av_off::destroy_decoder, reinterpret_cast<uint64_t>(&bridge_destroy_decoder));
    set_u64(sdk::av_off::recv_av_data,    reinterpret_cast<uint64_t>(&bridge_recv_av_data));
    set_u64(sdk::av_off::recv_user_data,  reinterpret_cast<uint64_t>(&bridge_recv_user_data));
    set_u64(sdk::av_off::recv_avheader,   reinterpret_cast<uint64_t>(&bridge_recv_avheader));
    set_u64(sdk::av_off::context_ptr, reinterpret_cast<uint64_t>(null_context));
    if (!user_id.empty())
        set_u64(sdk::av_off::user_id_str_ptr, reinterpret_cast<uint64_t>(user_id.c_str()));

    int err_code = 0;
    int av_rc = sdk.start_av_link(av_req, &err_code);
    LOG_INFO("bridge", "iv_start_av_link returned %d, err=%d", av_rc, err_code);
    if (av_rc < 0) {
        LOG_ERROR("bridge", "AV link failed (0x%x)", err_code);
        return 1;
    }
    int channel_id = av_rc;
    LOG_INFO("bridge", "streaming on channel %d", channel_id);

    if (duration > 0)
        LOG_INFO("bridge", "streaming for %ds", duration);
    else
        LOG_INFO("bridge", "streaming until SIGINT");

    auto start = std::chrono::steady_clock::now();
    while (!g_shutdown.load()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        if (duration > 0 && elapsed >= duration) break;
        if (elapsed > 0 && elapsed % 30 == 0) {
            static int64_t last = -1;
            if (elapsed != last) {
                last = elapsed;
                LOG_INFO("bridge", "[%llds] frames=%d bytes=%zu",
                         (long long)elapsed, cb::g_video_frames.load(), cb::g_video_bytes.load());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    LOG_INFO("bridge", "shutdown: %d frames, %zu bytes",
             cb::g_video_frames.load(), cb::g_video_bytes.load());
    if (cb::g_h264_output_fd >= 0 && cb::g_h264_output_fd != STDOUT_FILENO && cb::g_h264_output_fd != STDERR_FILENO)
        ::close(cb::g_h264_output_fd);
    if (sdk.stop_av_link && channel_id >= 0)
        sdk.stop_av_link((uint32_t)channel_id, 0, 0);
    _exit(cb::g_video_frames.load() > 0 ? 0 : 1);
}
