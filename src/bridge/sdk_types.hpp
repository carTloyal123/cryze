#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace sdk {

// iv_access_init param blob (0x1c0 = 448 bytes)

constexpr size_t kInitParamSize = 0x1c0;

struct InitParamBlob {
    uint8_t bytes[kInitParamSize];

    void zero()                { std::memset(bytes, 0, sizeof(bytes)); }
    int32_t& field_i32(size_t off)   { return *reinterpret_cast<int32_t*>(bytes + off); }
    int16_t& field_i16(size_t off)   { return *reinterpret_cast<int16_t*>(bytes + off); }
    uint64_t& field_u64(size_t off)  { return *reinterpret_cast<uint64_t*>(bytes + off); }
    void*& field_ptr(size_t off)     { return *reinterpret_cast<void**>(bytes + off); }
    char* field_str(size_t off)     { return reinterpret_cast<char*>(bytes + off); }
};

// Field offsets within InitParamBlob.
namespace init_off {
    constexpr size_t sdk_mode         = 0x000;  // int32 = 2
    constexpr size_t net_mode         = 0x004;  // int32 = 1
    constexpr size_t access_id        = 0x008;  // uint64
    constexpr size_t access_token_ptr = 0x010;  // const char*
    constexpr size_t access_token_len = 0x018;  // int32
    constexpr size_t p2p_url_buf      = 0x01c;  // char[~256]
    constexpr size_t lang_code        = 0x11c;  // int16
    constexpr size_t dev_type         = 0x11e;  // int16
    constexpr size_t version          = 0x120;  // int32
    constexpr size_t p2p_port_type    = 0x1ac;  // int32
    constexpr size_t user_ctx_a       = 0x1b0;  // void*
    constexpr size_t user_ctx_b       = 0x1b8;  // void*

    // 16 callback slots (8 bytes each, gap at 0x15c skipped)
    constexpr size_t callback_slots[16] = {
        0x124, 0x12c, 0x134, 0x13c, 0x144, 0x14c, 0x154, 0x164,
        0x16c, 0x174, 0x17c, 0x184, 0x18c, 0x194, 0x19c, 0x1a4,
    };

    constexpr const char* callback_names[16] = {
        "iv_discon_av_link",              // 0
        "set_mode_callback",              // 1
        "event_callback",                 // 2
        "send_server_callback",           // 3
        "send_pass_through_msg_callback", // 4
        "send_pass_through_ack_callback", // 5
        "get_mode_callback",              // 6
        "p2p_log_callback",               // 7
        "app_access_srv_callback",              // 8  APP_ONLINE
        "onlmesg_callback",               // 9
        "getCurrentLocalIp",              // 10
        "rcv_speed_test_result",          // 11
        "subscribe_with_devid_resp_cb",   // 12
        "common_get_cb_sdk",              // 13 must return -1
        "common_set_cb_sdk",              // 14
        "iv_notify_connect_state_cb",     // 15
    };
}

// AppLink states (from callback slot 8)
constexpr int kAppOnline           = 1;
constexpr int kAppOffline          = 2;
constexpr int kAccessTokenError    = 3;

// av_req struct for iv_start_av_link (0xc0 = 192 bytes)

constexpr size_t kAvReqSize = 0xc0;

namespace av_off {
    constexpr size_t dst_id_ptr       = 0x00;  // const char* — device ID "_@.GW_..."
    // 0x08: padding/flags
    constexpr size_t call_type        = 0x0c;  // int32 — 1=live, 6=playback, 7=download
    constexpr size_t state            = 0x10;  // int32 — 1=play, 2=prepare
    constexpr size_t user_data        = 0x14;  // 32 bytes — PlayerUserData
    constexpr size_t init_decoder     = 0x48;  // fn(chn, ctx, av_header) -> int
    constexpr size_t decode_audio     = 0x50;  // fn(chn, ctx, data, len, pts, frame)
    constexpr size_t decode_video     = 0x58;  // fn(chn, ctx, data, len, pts, frame)
    constexpr size_t destroy_decoder  = 0x60;  // fn(chn, ctx)
    constexpr size_t recv_av_data     = 0x68;  // fn(chn, ctx, av_data)
    constexpr size_t recv_user_data   = 0x70;  // fn(chn, ctx, user_data)
    constexpr size_t recv_avheader    = 0x78;  // fn(chn, ctx, av_header)
    constexpr size_t encoder_slot_7   = 0x80;  // (unused for receive)

    // Must be non-NULL valid memory
    constexpr size_t context_ptr      = 0xa8;  // void*
    constexpr size_t definition       = 0xb0;  // int32 — video definition config
    constexpr size_t user_id_str_ptr  = 0xb4;  // const char* — user ID string (optional)
    constexpr size_t flags            = 0xbc;  // byte — additional flags
}

constexpr size_t kFakeContextSize = 0x2000;

using fn_iv_access_init       = int  (*)(void* param);
using fn_iv_access_destroy    = void (*)(void);
using fn_iv_set_access_token  = int  (*)(const char* token);
using fn_iv_subscribe_dev     = uint32_t (*)(const char* token, const char* dev_id, uint32_t token_len);
using fn_iv_start_av_link     = int  (*)(void* av_req, int* out_err);
using fn_iv_stop_av_link      = int  (*)(uint32_t chn_id, int reason, uint16_t flags);
using fn_get_sdk_version      = int  (*)(void);
using fn_iv_get_connect_mode  = int  (*)(uint32_t chn_id, uint32_t* mode, uint32_t* sub_mode);
using fn_iv_lan_connectable   = int  (*)(const char* dev_id);
using fn_find_device_id       = int64_t (*)(void* termunit, const char* dev_id);
using fn_get_tick_count       = uint32_t (*)(void);

struct SdkSymbols {
    fn_iv_access_init       access_init;
    fn_iv_access_destroy    access_destroy;
    fn_iv_set_access_token  set_access_token;
    fn_iv_subscribe_dev     subscribe_dev;
    fn_iv_start_av_link     start_av_link;
    fn_iv_stop_av_link      stop_av_link;
    fn_get_sdk_version      get_version;
    fn_iv_get_connect_mode  get_connect_mode;
    fn_iv_lan_connectable   lan_connectable;
    fn_find_device_id       find_device_id;
    fn_get_tick_count       get_tick;
    void*                   lib_handle;
    void*                   lib_base;
};

}  // namespace sdk
