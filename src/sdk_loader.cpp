// sdk_loader.cpp — dlopen wrapper for libiotp2pav.so
#include "sdk_loader.hpp"
#include <dlfcn.h>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>

namespace sdk {

SdkSymbols load(const std::string& path) {
    // Ensure shim libs and APK libs are findable
    setenv("LD_LIBRARY_PATH", "/work/libs:/apk/xapk_contents/arm64_libs/lib/arm64-v8a", 1);

    void* lib = dlopen(path.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (!lib)
        throw std::runtime_error(std::string("dlopen failed: ") + dlerror());

    auto resolve = [&](const char* name) -> void* {
        void* sym = dlsym(lib, name);
        if (!sym)
            std::fprintf(stderr, "  warn: %s not found\n", name);
        return sym;
    };

    SdkSymbols s{};
    s.lib_handle     = lib;
    s.access_init    = (fn_iv_access_init)      resolve("iv_access_init");
    s.access_destroy = (fn_iv_access_destroy)   resolve("iv_access_destroy");
    s.set_access_token = (fn_iv_set_access_token) resolve("iv_set_access_token");
    s.subscribe_dev  = (fn_iv_subscribe_dev)    resolve("iv_subscribe_dev");
    s.start_av_link  = (fn_iv_start_av_link)    resolve("iv_start_av_link");
    s.stop_av_link   = (fn_iv_stop_av_link)     resolve("iv_stop_av_link");
    s.get_version    = (fn_get_sdk_version)     resolve("get_sdk_version");
    s.get_connect_mode = (fn_iv_get_connect_mode) resolve("iv_get_connect_mode_link_chn");
    s.lan_connectable  = (fn_iv_lan_connectable)  resolve("iv_lan_device_connectable");
    s.find_dstid       = (fn_iv_find_dstid)       resolve("iv_find_dstid_from_tid_key_map");

    // Get base address for crash offset reporting
    Dl_info dli{};
    if (s.access_init && dladdr((void*)s.access_init, &dli))
        s.lib_base = dli.dli_fbase;

    if (!s.access_init || !s.subscribe_dev || !s.start_av_link)
        throw std::runtime_error("missing critical SDK symbols");

    std::fprintf(stderr, "[sdk] loaded %s base=%p\n", path.c_str(), s.lib_base);
    return s;
}

}  // namespace sdk
