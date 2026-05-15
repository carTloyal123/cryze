// main.cpp — bridge: Wyze Doorbell H.264 stream bridge
//
// Linear flow: init SDK → subscribe → start AV link → receive frames → shutdown
// Uses only libiotp2pav.so — no Java, no JNI, no libiotvideo.so.
//
// Modes:
//   --stdout     Write raw H.264 Annex B to stdout (for go2rtc pipe transport)
//   --output F   Write to file F (default: logs/frames.h264)
//   --duration N Run for N seconds (0 = indefinite, until SIGINT)

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
#include <thread>
#include <unistd.h>

// --- Globals ---
static std::atomic<bool> g_shutdown{false};

// Declared in callbacks.cpp
extern "C" {
    int  bridge_init_decoder(uint32_t, void*, void*);
    void bridge_decode_audio(uint32_t, void*, uint8_t*, uint32_t, uint64_t, void*);
    int  bridge_decode_video(uint32_t, void*, uint8_t*, uint32_t, uint64_t, void*);
    void bridge_destroy_decoder(uint32_t, void*);
    void bridge_recv_av_data(uint32_t, void*, void*);
    void bridge_recv_user_data(uint32_t, void*, void*);  // slot 5 at 0x70 — MUST be non-null
    void bridge_recv_avheader(uint32_t, void*, void*);
}

// --- Signal handling ---
static void* s_lib_base = nullptr;

static void crash_handler(int sig, siginfo_t* si, void* ucv) {
    auto* uc = (ucontext_t*)ucv;
    void* pc = (void*)uc->uc_mcontext.pc;
    void* lr = (void*)uc->uc_mcontext.regs[30];
    fprintf(stderr, "\n=== SIGNAL %d ===\n  fault=%p pc=%p lr=%p\n",
            sig, si->si_addr, pc, lr);
    Dl_info di{};
    if (dladdr(pc, &di))
        fprintf(stderr, "  pc in: %s+0x%lx (%s)\n", di.dli_fname ?: "?",
                (unsigned long)((uintptr_t)pc - (uintptr_t)di.dli_fbase),
                di.dli_sname ?: "?");
    if (dladdr(lr, &di))
        fprintf(stderr, "  lr in: %s+0x%lx (%s)\n", di.dli_fname ?: "?",
                (unsigned long)((uintptr_t)lr - (uintptr_t)di.dli_fbase),
                di.dli_sname ?: "?");
    // Walk frame pointers
    void** fp = (void**)uc->uc_mcontext.regs[29];
    for (int d = 0; d < 15 && fp; ++d) {
        void* prev_lr = fp[1];
        if (!prev_lr) break;
        Dl_info d2{};
        if (dladdr(prev_lr, &d2))
            fprintf(stderr, "  #%d %s+0x%lx (%s)\n", d, d2.dli_fname ?: "?",
                    (unsigned long)((uintptr_t)prev_lr - (uintptr_t)d2.dli_fbase),
                    d2.dli_sname ?: "?");
        if (fp[0] <= (void*)fp) break;
        fp = (void**)fp[0];
    }
    _exit(128 + sig);
}

static void sigint_handler(int) { g_shutdown.store(true); }

// --- Helpers ---
static void print_network_interfaces() {
    std::fprintf(stderr, "\n=== Network Interfaces ===\n");
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        std::fprintf(stderr, "  getifaddrs failed: %s\n", strerror(errno));
        return;
    }
    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        char buf[INET6_ADDRSTRLEN];
        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            std::fprintf(stderr, "  %-8s IPv4 %-16s  flags=0x%x%s%s\n",
                         ifa->ifa_name, buf, ifa->ifa_flags,
                         (ifa->ifa_flags & IFF_LOOPBACK) ? " LO" : "",
                         (ifa->ifa_flags & IFF_BROADCAST) ? " BCAST" : "");
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
            std::fprintf(stderr, "  %-8s IPv6 %s\n", ifa->ifa_name, buf);
        }
    }
    freeifaddrs(ifap);
    std::fprintf(stderr, "\n");
}

static bool wait_for(std::atomic<bool>& flag, int timeout_sec, const char* label) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (!flag.load() && !g_shutdown.load()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::fprintf(stderr, "[wait] %s timed out after %ds\n", label, timeout_sec);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return flag.load();
}

// === MAIN ===
int main(int argc, char** argv) {
    // Parse args
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
        else if (a == "--verbose" || a == "-v") cb::g_sdk_log_level = 5;
        else if (a == "--quiet"   || a == "-q") cb::g_sdk_log_level = 7;
        else if (a == "--help" || a == "-h") {
            printf("Usage: bridge [--stdout] [--device MAC] [--output PATH] [--duration SECS] [-v|-q]\n");
            return 0;
        }
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }

    // --stdout mode: pipe H.264 to stdout for go2rtc, run indefinitely
    // Logs stay on stderr (safe — won't pollute the H.264 pipe) so they
    // are visible via `docker compose logs -f`.  Use -q to suppress.
    if (use_stdout) {
        duration = 0;                  // indefinite until SIGINT

        // The SDK internally uses printf/write(1,...) for some log messages.
        // To keep the stdout pipe clean for H.264 data only:
        //   1. dup stdout fd to a new fd (for H.264 output)
        //   2. redirect fd 1 to stderr (so SDK printf goes to stderr)
        int h264_fd = ::dup(STDOUT_FILENO);
        if (h264_fd < 0) {
            std::fprintf(stderr, "  dup(stdout) failed: %s\n", strerror(errno));
            return 1;
        }
        ::dup2(STDERR_FILENO, STDOUT_FILENO);  // fd 1 now points to stderr
        cb::g_output_fd = h264_fd;              // H.264 goes to the original stdout
        std::fprintf(stderr, "  stdout redirected: H.264→fd%d, printf→stderr\n", h264_fd);
    }

    // Signal handlers
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE — go2rtc may close stdout pipe
    struct sigaction sa{};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // Print network topology for LAN/P2P debugging
    print_network_interfaces();

    // ================================================================
    // Phase 0: Fresh auth from env vars
    // ================================================================
    std::fprintf(stderr, "\n=== Phase 0: Auth ===\n");
    wyze::StreamCreds creds;
    try {
        creds = wyze::bootstrap(device_mac);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "  auth failed: %s\n", e.what());
        return 1;
    }

    std::fprintf(stderr, "  device=%s access_id=%s token=%zu bytes\n",
                 creds.device_mac.c_str(), creds.access_id.c_str(), creds.access_token.size());

    // ================================================================
    // Phase 1: SDK Init — iv_access_init → wait for APP_ONLINE
    // ================================================================
    std::fprintf(stderr, "\n=== Phase 1: SDK Init ===\n");

    sdk::SdkSymbols sdk;
    try {
        sdk = sdk::load();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "  SDK load failed: %s\n", e.what());
        return 1;
    }
    s_lib_base = sdk.lib_base;

    if (sdk.get_version) {
        int v = sdk.get_version();
        std::fprintf(stderr, "  SDK version: %d.%d\n", v >> 8, v & 0xff);
    }

    // Build 0x1c0 param blob
    sdk::InitParamBlob param{};
    param.zero();

    uint64_t access_id_num = std::strtoull(creds.access_id.c_str(), nullptr, 10);
    static std::string s_token = creds.access_token;  // static storage for pointer stability

    param.i32(sdk::init_off::marker_a)  = 2;
    param.i32(sdk::init_off::marker_b)  = 1;
    param.u64(sdk::init_off::access_id) = access_id_num;
    param.ptr(sdk::init_off::access_token_ptr) = const_cast<char*>(s_token.c_str());
    param.i32(sdk::init_off::access_token_len) = (int32_t)s_token.size();
    std::strncpy(param.cstr(sdk::init_off::p2p_url_buf), "|wyze-mars-asrv.wyzecam.com", 420);
    param.i16(sdk::init_off::lang_code)     = 1;
    param.i16(sdk::init_off::dev_type)      = 3;
    param.i32(sdk::init_off::version)       = 0x0d000000;
    param.i32(sdk::init_off::p2p_port_type) = 0;

    // Log LAN-relevant config for diagnostics
    std::fprintf(stderr, "  LAN config: marker_b=%d dev_type=%d p2p_port_type=%d\n",
                 param.i32(sdk::init_off::marker_b),
                 param.i16(sdk::init_off::dev_type),
                 param.i32(sdk::init_off::p2p_port_type));
    std::fprintf(stderr, "  Broadcast discovery: port 8899/8900 (UDP)\n");

    // Install callbacks
    void** cbs = cb::get_init_callbacks();
    for (int i = 0; i < 16; ++i)
        param.ptr(sdk::init_off::cb[i]) = cbs[i];

    std::fprintf(stderr, "  calling iv_access_init...\n");

    std::atomic<bool> init_done{false};
    std::atomic<int> init_rc{-99};
    std::thread init_thread([&] {
        init_rc.store(sdk.access_init(&param));
        init_done.store(true);
    });
    init_thread.detach();

    // Wait for return
    if (!wait_for(init_done, 35, "iv_access_init")) {
        std::fprintf(stderr, "  iv_access_init hung — check network to wyze-mars-asrv\n");
        return 1;
    }
    std::fprintf(stderr, "  iv_access_init returned %d\n", init_rc.load());
    if (init_rc.load() != 0) {
        std::fprintf(stderr, "  init failed (token too short? %zu bytes)\n", s_token.size());
        return 1;
    }

    // Wait for APP_ONLINE
    if (!wait_for(cb::g_app_online, 30, "APP_ONLINE")) {
        std::fprintf(stderr, "  SDK did not come online\n");
        return 1;
    }
    std::fprintf(stderr, "  SDK online!\n");

    // ================================================================
    // Phase 2: Subscribe — iv_subscribe_dev → wait for success
    // ================================================================
    std::fprintf(stderr, "\n=== Phase 2: Subscribe ===\n");

    uint32_t msg_id = sdk.subscribe_dev(
        creds.access_token.c_str(), creds.device_mac.c_str(), (uint32_t)creds.access_token.size());
    std::fprintf(stderr, "  iv_subscribe_dev returned msg_id=%u\n", msg_id);

    if (!wait_for(cb::g_sub_success, 20, "subscribe")) {
        uint32_t err = cb::g_sub_error.load();
        std::fprintf(stderr, "  subscribe failed: error=0x%x\n", err);
        return 1;
    }
    std::fprintf(stderr, "  subscribed OK!\n");

    // ================================================================
    // Phase 3: AV Link — iv_start_av_link with corrected struct
    // ================================================================
    std::fprintf(stderr, "\n=== Phase 3: AV Link ===\n");

    // Pre-AV-link LAN check: is the device visible via broadcast?
    if (sdk.lan_connectable) {
        int lan = sdk.lan_connectable(s_devid.c_str());
        std::fprintf(stderr, "  [LAN] pre-link: iv_lan_device_connectable(%s) = %d\n",
                     s_devid.c_str(), lan);
    }

    // Open output — stdout pipe (already set up above) or file
    if (use_stdout) {
        // g_output_fd already set during --stdout setup (dup'd fd)
        std::fprintf(stderr, "  output: stdout pipe (fd=%d)\n", cb::g_output_fd);
    } else {
        cb::g_output_fd = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (cb::g_output_fd < 0) {
            std::fprintf(stderr, "  cannot open %s: %s\n", output_path.c_str(), strerror(errno));
            return 1;
        }
        std::fprintf(stderr, "  output: %s (fd=%d)\n", output_path.c_str(), cb::g_output_fd);
    }

    // Device ID with third-party prefix
    static std::string s_devid = "_@." + creds.device_mac;
    static std::string s_user_id = creds.user_id;

    // Fake context struct (8KB zeroed) — SDK dereferences context_ptr but
    // checks for NULL at each level, so all-zeros is safe.
    static uint8_t s_fake_ctx[sdk::kFakeContextSize] = {0};

    // Build the 192-byte av_req
    alignas(8) static uint8_t av_req[sdk::kAvReqSize];
    std::memset(av_req, 0, sizeof(av_req));

    auto put_u32 = [](size_t off, uint32_t v) {
        *reinterpret_cast<uint32_t*>(av_req + off) = v;
    };
    auto put_u64 = [](size_t off, uint64_t v) {
        *reinterpret_cast<uint64_t*>(av_req + off) = v;
    };

    // dst_id: pointer to device ID string
    put_u64(sdk::av_off::dst_id_ptr, reinterpret_cast<uint64_t>(s_devid.c_str()));

    // callType = 1 (live monitor)
    put_u32(sdk::av_off::call_type, 1);

    // state = 1 (play)
    put_u32(sdk::av_off::state, 1);

    // PlayerUserData: definition = 2 (SD quality, matches cryze-android)
    // The definition field is at the start of user_data (offset 0x14)
    put_u32(sdk::av_off::user_data, 2);

    // Decoder callbacks
    put_u64(sdk::av_off::init_decoder,    reinterpret_cast<uint64_t>(&bridge_init_decoder));
    put_u64(sdk::av_off::decode_audio,    reinterpret_cast<uint64_t>(&bridge_decode_audio));
    put_u64(sdk::av_off::decode_video,    reinterpret_cast<uint64_t>(&bridge_decode_video));
    put_u64(sdk::av_off::destroy_decoder, reinterpret_cast<uint64_t>(&bridge_destroy_decoder));
    put_u64(sdk::av_off::recv_av_data,    reinterpret_cast<uint64_t>(&bridge_recv_av_data));
    put_u64(sdk::av_off::cb_slot_5,       reinterpret_cast<uint64_t>(&bridge_recv_user_data));
    put_u64(sdk::av_off::recv_avheader,   reinterpret_cast<uint64_t>(&bridge_recv_avheader));

    // ★ CRITICAL: context pointer — must be non-NULL valid memory
    put_u64(sdk::av_off::context_ptr, reinterpret_cast<uint64_t>(s_fake_ctx));

    // user_id string (optional but helpful for session auth)
    if (!s_user_id.empty())
        put_u64(sdk::av_off::user_id_str_ptr, reinterpret_cast<uint64_t>(s_user_id.c_str()));

    int err_code = 0;
    std::fprintf(stderr, "  calling iv_start_av_link(dst=%s)...\n", s_devid.c_str());

    int av_rc = sdk.start_av_link(av_req, &err_code);
    std::fprintf(stderr, "  iv_start_av_link returned %d, err_code=%d (0x%x)\n",
                 av_rc, err_code, (unsigned)err_code);

    if (av_rc < 0) {
        std::fprintf(stderr, "  AV link failed. Error 0x%x meanings:\n", err_code);
        std::fprintf(stderr, "    0x4e29 = device not in tid_key_map (subscribe failed?)\n");
        std::fprintf(stderr, "    0x4e25 = timeout (device offline/asleep?)\n");
        std::fprintf(stderr, "    0x4e2f = SDK not initialized\n");
        std::fprintf(stderr, "    0x4e30 = LAN call not allowed\n");
        std::fprintf(stderr, "    0x4e31 = server call not allowed\n");
        std::fprintf(stderr, "    0x4e32 = device not subscribed\n");

        if (sdk.access_destroy) sdk.access_destroy();
        return 1;
    }

    int chn_id = av_rc;
    std::fprintf(stderr, "  AV link established! channel=%d\n", chn_id);

    // --- LAN diagnostics ---
    if (sdk.lan_connectable) {
        int lan = sdk.lan_connectable(s_devid.c_str());
        std::fprintf(stderr, "  [LAN] iv_lan_device_connectable(%s) = %d (%s)\n",
                     s_devid.c_str(), lan, lan ? "FOUND on LAN" : "not on LAN");
    }
    if (sdk.get_connect_mode) {
        uint32_t mode = 0, sub_mode = 0;
        int cm_rc = sdk.get_connect_mode((uint32_t)chn_id, &mode, &sub_mode);
        const char* mode_name = mode == 0 ? "UNKNOWN" : mode == 1 ? "RELAY" :
                                mode == 2 ? "LAN" : mode == 3 ? "NAT" : "OTHER";
        std::fprintf(stderr, "  [LAN] connect_mode: rc=%d mode=%u (%s) sub=%u\n",
                     cm_rc, mode, mode_name, sub_mode);
    }

    // ================================================================
    // Phase 4: Wait for frames
    // ================================================================
    if (duration > 0)
        std::fprintf(stderr, "\n=== Phase 4: Receiving frames (%ds) ===\n", duration);
    else
        std::fprintf(stderr, "\n=== Phase 4: Streaming (until SIGINT) ===\n");

    auto start = std::chrono::steady_clock::now();
    while (!g_shutdown.load()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        if (duration > 0 && elapsed >= duration) break;

        // Progress report every 30s (less noisy for long/indefinite runs)
        if (elapsed > 0 && elapsed % 30 == 0) {
            static int64_t last_report = -1;
            if (elapsed != last_report) {
                last_report = elapsed;
                std::fprintf(stderr, "  [%llds] frames=%d bytes=%zu\n",
                             (long long)elapsed,
                             cb::g_video_frames.load(),
                             cb::g_video_bytes.load());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // ================================================================
    // Shutdown
    // ================================================================
    std::fprintf(stderr, "\n=== Shutdown ===\n");
    std::fprintf(stderr, "  total frames: %d\n", cb::g_video_frames.load());
    std::fprintf(stderr, "  total bytes:  %zu\n", cb::g_video_bytes.load());

    // Close output fd (don't close STDOUT/STDERR — let go2rtc detect EOF)
    if (cb::g_output_fd >= 0 && cb::g_output_fd != STDOUT_FILENO && cb::g_output_fd != STDERR_FILENO) {
        ::close(cb::g_output_fd);
    }
    cb::g_output_fd = -1;

    if (sdk.stop_av_link && chn_id >= 0) {
        std::fprintf(stderr, "  stopping AV link (chn=%d)...\n", chn_id);
        sdk.stop_av_link((uint32_t)chn_id, 0, 0);
    }

    // Skip iv_access_destroy — it crashes on cleanup due to internal
    // thread/timer teardown assumptions. Since we're exiting anyway,
    // let the OS reclaim resources via _exit.
    std::fprintf(stderr, "  skipping SDK destroy (known crash), using _exit\n");
    if (cb::g_video_frames.load() > 0) {
        std::fprintf(stderr, "  H.264 frames written to %s\n",
                     use_stdout ? "stdout" : output_path.c_str());
    } else {
        std::fprintf(stderr, "  No frames received. Possible issues:\n");
        std::fprintf(stderr, "    - Device may be asleep (battery doorbell needs wake-up)\n");
        std::fprintf(stderr, "    - P2P connection may not have completed\n");
        std::fprintf(stderr, "    - Check stderr output for SDK logs\n");
    }

    _exit(cb::g_video_frames.load() > 0 ? 0 : 1);
}
