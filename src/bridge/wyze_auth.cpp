// wyze_auth.cpp — Wyze cloud auth with token caching.
//
// Flow: try_cache → (login → get_devices → register_mars_user → save_cache) → wakeup

#include "wyze_auth.hpp"

#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <uuid/uuid.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>
#include <thread>

namespace wyze {

namespace {

// Endpoints
constexpr const char* kAuthBase = "https://auth-prod.api.wyze.com";
constexpr const char* kAppBase  = "https://app.wyzecam.com";
constexpr const char* kMarsBase = "https://wyze-mars-service.wyzecam.com";

constexpr const char* kPathLogin      = "/api/user/login";
constexpr const char* kPathGetDevices = "/app/v2/home_page/get_object_list";

// Signing constants
constexpr const char* kSc             = "9f275790cab94a72bd206c8876429f3c";
constexpr const char* kSvGetObjList   = "c86fa16fc99d4d6580f4efeae8b4b13c";
constexpr const char* kIotAppId       = "9319141212m2ik";
constexpr const char* kIotSecret      = "wyze_app_secret_key_132";

// DMS (Device Management Service) for run_action_batch
constexpr const char* kDmsBase            = "https://devicemgmt-service.wyze.com";
constexpr const char* kPathRunActionBatch = "/device-management/api/action/run_action_batch";

// App identity
constexpr const char* kAppName    = "com.hualai";
constexpr const char* kAppVer     = "com.hualai___3.13.0.784";
constexpr const char* kAppVersion = "3.13.0.784";
constexpr const char* kPhoneSys   = "1";
constexpr const char* kUserAgent  = "wyze_android_3.13.0";

// --- helpers ---

std::string md5_hex(const std::string& data) {
    unsigned char d[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(data.data()), data.size(), d);
    char hex[33];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) std::snprintf(hex + 2*i, 3, "%02x", d[i]);
    return {hex, 32};
}

std::string scramble_password(const std::string& pw) {
    return md5_hex(md5_hex(md5_hex(pw)));
}

std::string hmac_md5_hex(const std::string& key, const std::string& msg) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_md5(), key.data(), (int)key.size(),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest, &len);
    char hex[65];
    for (unsigned i = 0; i < len; i++) std::snprintf(hex + 2*i, 3, "%02x", digest[i]);
    return {hex, 2 * len};
}

std::string signature2(const std::string& access_token, const std::string& body) {
    return hmac_md5_hex(md5_hex(access_token + kIotSecret), body);
}

std::string new_uuid() {
    uuid_t u; uuid_generate(u);
    char buf[37]; uuid_unparse_lower(u, buf);
    return {buf};
}

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

size_t curl_write_cb(void* p, size_t sz, size_t n, void* ud) {
    static_cast<std::string*>(ud)->append(static_cast<char*>(p), sz * n);
    return sz * n;
}

std::string env_required(const char* name) {
    const char* v = std::getenv(name);
    if (!v || !*v) throw std::runtime_error(std::string("missing env var: ") + name);
    return v;
}

// --- HTTP ---

struct Http {
    CURL* c;
    std::string phone_id;

    Http() : c(curl_easy_init()), phone_id(new_uuid()) {
        if (!c) throw std::runtime_error("curl_easy_init failed");
    }
    ~Http() { if (c) curl_easy_cleanup(c); }

    nlohmann::json post(const std::string& url, const std::string& body,
                        const std::vector<std::string>& hdrs) {
        curl_easy_reset(c);
        std::string resp;
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(c, CURLOPT_USERAGENT, kUserAgent);

        struct curl_slist* sl = nullptr;
        sl = curl_slist_append(sl, "Content-Type: application/json");
        for (auto& h : hdrs) sl = curl_slist_append(sl, h.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, sl);

        CURLcode rc = curl_easy_perform(c);
        long status = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
        curl_slist_free_all(sl);

        if (rc != CURLE_OK)
            throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(rc));
        if (status < 200 || status >= 300)
            throw std::runtime_error("HTTP " + std::to_string(status) + ": " + resp.substr(0, 500));

        return nlohmann::json::parse(resp);
    }
};

// Module-level state (populated by bootstrap, used by wakeup)
static std::string s_access_token;
static std::string s_user_id;
static std::string s_phone_id;

// --- Cache ---

static std::string cache_path() {
    const char* p = std::getenv("CACHE_FILE");
    return p && *p ? std::string(p) : "cache/auth.json";
}

static void ensure_parent_dir(const std::string& path) {
    auto slash = path.rfind('/');
    if (slash != std::string::npos) {
        std::string dir = path.substr(0, slash);
        mkdir(dir.c_str(), 0755);
    }
}

// Save all auth state to disk as JSON.
static void save_cache(const StreamCreds& creds) {
    std::string path = cache_path();
    ensure_parent_dir(path);

    nlohmann::json j = {
        {"version", 1},
        {"device_mac", creds.device_mac},
        {"product_model", creds.product_model},
        {"mars_access_id", creds.access_id},
        {"mars_access_token", creds.access_token},
        {"mars_expire_time", creds.expire_time},
        {"user_id", creds.user_id},
        {"device_ip", creds.device_ip},
        {"wyze_access_token", s_access_token},
        {"phone_id", s_phone_id},
        {"saved_at", now_ms() / 1000},
    };

    std::ofstream f(path);
    if (!f) {
        std::fprintf(stderr, "[cache] failed to write %s\n", path.c_str());
        return;
    }
    f << j.dump(2) << std::endl;
    std::fprintf(stderr, "[cache] saved to %s (expires %lld)\n",
                 path.c_str(), (long long)creds.expire_time);
}

// Load cached creds. Returns nullopt if cache missing, corrupted, or expired.
static std::optional<StreamCreds> load_cache(const std::string& target_mac) {
    std::string path = cache_path();
    std::ifstream f(path);
    if (!f) return std::nullopt;

    nlohmann::json j;
    try {
        f >> j;
    } catch (...) {
        std::fprintf(stderr, "[cache] corrupt cache file %s\n", path.c_str());
        return std::nullopt;
    }

    if (!j.contains("version") || j["version"] != 1) return std::nullopt;

    // Check device MAC matches (if specified)
    std::string cached_mac = j.value("device_mac", std::string{});
    if (!target_mac.empty() && cached_mac != target_mac) {
        std::fprintf(stderr, "[cache] MAC mismatch: cached=%s target=%s\n",
                     cached_mac.c_str(), target_mac.c_str());
        return std::nullopt;
    }

    // Check Mars token expiry (with 1-hour safety margin)
    int64_t expire = j.value("mars_expire_time", (int64_t)0);
    int64_t now_s = now_ms() / 1000;
    int64_t margin = 3600; // 1 hour
    if (expire > 0 && now_s >= (expire - margin)) {
        int64_t hours_ago = (now_s - expire) / 3600;
        std::fprintf(stderr, "[cache] Mars token expired %lld hours ago\n", hours_ago);
        return std::nullopt;
    }

    // Validate required fields
    std::string mars_id = j.value("mars_access_id", std::string{});
    std::string mars_token = j.value("mars_access_token", std::string{});
    if (mars_id.empty() || mars_token.empty()) {
        std::fprintf(stderr, "[cache] missing Mars creds in cache\n");
        return std::nullopt;
    }

    // Restore module-level state for wakeup
    s_access_token = j.value("wyze_access_token", std::string{});
    s_user_id = j.value("user_id", std::string{});
    s_phone_id = j.value("phone_id", std::string{});

    StreamCreds creds;
    creds.device_mac = cached_mac;
    creds.product_model = j.value("product_model", std::string{});
    creds.access_id = mars_id;
    creds.access_token = mars_token;
    creds.expire_time = expire;
    creds.user_id = s_user_id;
    creds.device_ip = j.value("device_ip", std::string{});

    int64_t remaining_h = (expire - now_s) / 3600;
    std::fprintf(stderr, "[cache] loaded from %s (%lld hours remaining)\n",
                 path.c_str(), remaining_h);

    return creds;
}

// --- run_action_batch helper ---

void do_run_action_batch(Http& http, const std::string& device_id,
                         const std::string& product_model,
                         const std::string& capability_name,
                         const std::string& function_name,
                         const nlohmann::json& in_params) {
    nlohmann::json function = {
        {"name",      function_name},
        {"separator", "::"},
        {"in",        in_params.is_null() ? nlohmann::json::object() : in_params},
    };
    nlohmann::json capability = {
        {"iid",       ""},
        {"name",      capability_name},
        {"functions", nlohmann::json::array({function})},
    };
    nlohmann::json target = {
        {"capabilities", nlohmann::json::array({capability})},
        {"targetInfo",   {{"id", device_id},
                          {"productModel", product_model},
                          {"type", "DEVICE"}}},
        {"userId",       s_user_id},
    };
    nlohmann::json body = {
        {"nonce",         std::to_string(now_ms())},
        {"targetDevices", nlohmann::json::array({target})},
        {"userId",        s_user_id},
    };
    std::string body_str = body.dump();
    std::string sig2 = signature2(s_access_token, body_str);

    auto resp = http.post(
        std::string(kDmsBase) + kPathRunActionBatch,
        body_str,
        {"appid: " + std::string(kIotAppId),
         "access_token: " + s_access_token,
         "Authorization: " + s_access_token,
         "appinfo: " + std::string(kAppName) + "_android_" + kAppVersion,
         "app_version: android_" + std::string(kAppVersion),
         "phoneid: " + http.phone_id,
         "requestid: " + md5_hex(md5_hex(std::to_string(now_ms()))),
         "Signature2: " + sig2});

    std::fprintf(stderr, "[auth] run_action_batch(%s/%s): %s\n",
                 capability_name.c_str(), function_name.c_str(),
                 resp.dump().substr(0, 200).c_str());
}

}  // namespace

// --- public API ---

StreamCreds bootstrap(const std::string& target_mac) {
    // --- Try cache first ---
    auto cached = load_cache(target_mac);
    if (cached) {
        std::fprintf(stderr, "[auth] using cached Mars creds (access_id=%s)\n",
                     cached->access_id.c_str());

        // Wakeup still needed — doorbell sleeps between sessions.
        // Skip if SKIP_WAKEUP=1 (doorbell connected to local relay via keepalive).
        const char* skip_wakeup = std::getenv("SKIP_WAKEUP");
        if (skip_wakeup && (std::string(skip_wakeup) == "1" || std::string(skip_wakeup) == "true")) {
            std::fprintf(stderr, "[auth] SKIP_WAKEUP=1 — skipping cloud wakeup (doorbell on local relay)\n");
        } else {
        // Try with cached Wyze token; if it fails, wakeup is non-fatal.
        try {
            wakeup(cached->device_mac, cached->product_model);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[auth] cached wakeup failed: %s\n", e.what());
            std::fprintf(stderr, "[auth] Wyze token may be expired — doing fresh login for wakeup\n");

            // Re-login just for wakeup token
            try {
                auto email    = env_required("WYZE_EMAIL");
                auto password = env_required("WYZE_PASSWORD");
                auto key_id   = env_required("WYZE_KEY_ID");
                auto api_key  = env_required("WYZE_API_KEY");

                Http http;
                nlohmann::json login_body = {
                    {"email",    email},
                    {"password", scramble_password(password)},
                    {"nonce",    std::to_string(now_ms())},
                };
                auto login_resp = http.post(
                    std::string(kAuthBase) + kPathLogin,
                    login_body.dump(),
                    {"keyid: " + key_id, "apikey: " + api_key,
                     "phone-id: " + http.phone_id, "requestid: " + new_uuid()});

                s_access_token = login_resp.value("access_token", std::string{});
                s_user_id = login_resp.value("user_id", std::string{});
                s_phone_id = http.phone_id;

                // Update cache with fresh Wyze token
                save_cache(*cached);

                wakeup(cached->device_mac, cached->product_model);
            } catch (const std::exception& e2) {
                std::fprintf(stderr, "[auth] fresh wakeup also failed (non-fatal): %s\n", e2.what());
            }
        }
        }  // end else (wakeup not skipped)

        return *cached;
    }

    // --- Full fresh auth ---
    std::fprintf(stderr, "[auth] no valid cache — doing fresh auth\n");
    auto email    = env_required("WYZE_EMAIL");
    auto password = env_required("WYZE_PASSWORD");
    auto key_id   = env_required("WYZE_KEY_ID");
    auto api_key  = env_required("WYZE_API_KEY");

    Http http;
    std::fprintf(stderr, "[auth] logging in as %s...\n", email.c_str());

    // 1. Login
    nlohmann::json login_body = {
        {"email",    email},
        {"password", scramble_password(password)},
        {"nonce",    std::to_string(now_ms())},
    };
    auto login_resp = http.post(
        std::string(kAuthBase) + kPathLogin,
        login_body.dump(),
        {"keyid: " + key_id, "apikey: " + api_key,
         "phone-id: " + http.phone_id, "requestid: " + new_uuid()});

    s_access_token = login_resp.value("access_token", std::string{});
    s_user_id       = login_resp.value("user_id", std::string{});
    s_phone_id      = http.phone_id;
    if (s_access_token.empty())
        throw std::runtime_error("login failed: no access_token in response");
    std::fprintf(stderr, "[auth] login OK, user_id=%s\n", s_user_id.c_str());

    // 2. Get devices
    nlohmann::json dev_body = {
        {"access_token", s_access_token},
        {"app_name",     kAppName},
        {"app_ver",      kAppVer},
        {"app_version",  kAppVersion},
        {"phone_id",     http.phone_id},
        {"phone_system_type", kPhoneSys},
        {"sc",           kSc},
        {"sv",           kSvGetObjList},
        {"ts",           now_ms()},
    };
    auto dev_resp = http.post(
        std::string(kAppBase) + kPathGetDevices,
        dev_body.dump(),
        {"phone-id: " + http.phone_id, "requestid: " + new_uuid()});

    // Find target device
    std::string device_mac, product_model;
    const auto& dev_list = dev_resp["data"]["device_list"];
    std::string device_ip;
    for (const auto& d : dev_list) {
        std::string mac   = d.value("mac", std::string{});
        std::string model = d.value("product_model", std::string{});
        std::string type  = d.value("product_type", std::string{});
        std::string name  = d.value("nickname", std::string{});
        std::string ip    = d.value("ip", std::string{});
        std::fprintf(stderr, "[auth] device: %s (%s, model=%s, type=%s, ip=%s)\n",
                     mac.c_str(), name.c_str(), model.c_str(), type.c_str(), ip.c_str());
        if (type != "Camera" || model.rfind("GW_", 0) != 0) continue;
        if (!target_mac.empty() && mac != target_mac) continue;
        device_mac    = mac;
        product_model = model;
        device_ip     = ip;
    }
    if (device_mac.empty())
        throw std::runtime_error("no matching GW_ camera found on account");
    std::fprintf(stderr, "[auth] selected device: %s (%s)\n",
                 device_mac.c_str(), product_model.c_str());

    // 3. Register Mars user
    nlohmann::json mars_body = {
        {"ttl_minutes", 10080},
        {"nonce",       std::to_string(now_ms())},
        {"unique_id",   http.phone_id},
    };
    std::string mars_body_str = mars_body.dump();
    std::string sig2 = signature2(s_access_token, mars_body_str);

    auto mars_resp = http.post(
        std::string(kMarsBase) + "/plugin/mars/v2/regist_gw_user/" + device_mac,
        mars_body_str,
        {"appid: " + std::string(kIotAppId),
         "access_token: " + s_access_token,
         "appinfo: " + std::string(kAppName) + "_android_" + kAppVersion,
         "phoneid: " + http.phone_id,
         "requestid: " + md5_hex(md5_hex(std::to_string(now_ms()))),
         "Signature2: " + sig2});

    if (mars_resp.contains("code")) {
        int code = mars_resp["code"].is_number()
            ? mars_resp["code"].get<int>()
            : std::atoi(mars_resp["code"].get<std::string>().c_str());
        if (code != 1)
            throw std::runtime_error("register_mars_user failed: " + mars_resp.dump().substr(0, 500));
    }

    const auto& data = mars_resp["data"];
    auto pick = [&](const char* s, const char* c) -> std::string {
        for (auto k : {s, c}) {
            if (data.contains(k)) {
                auto& v = data[k];
                if (v.is_string()) return v.get<std::string>();
                if (v.is_number()) return std::to_string(v.get<int64_t>());
            }
        }
        return {};
    };

    StreamCreds creds;
    creds.device_mac    = device_mac;
    creds.product_model = product_model;
    creds.access_id     = pick("access_id", "accessId");
    creds.access_token  = pick("access_token", "accessToken");
    creds.user_id       = s_user_id;
    creds.device_ip     = device_ip;

    if (data.contains("expire_time")) {
        auto& et = data["expire_time"];
        creds.expire_time = et.is_number() ? et.get<int64_t>() : std::atoll(et.get<std::string>().c_str());
    } else if (data.contains("expireTime")) {
        auto& et = data["expireTime"];
        creds.expire_time = et.is_number() ? et.get<int64_t>() : std::atoll(et.get<std::string>().c_str());
    }

    if (creds.access_id.empty() || creds.access_token.empty())
        throw std::runtime_error("register_mars_user: no creds in response: " + mars_resp.dump().substr(0, 500));

    std::fprintf(stderr, "[auth] Mars creds OK: access_id=%s\n", creds.access_id.c_str());

    // 4. Save cache
    save_cache(creds);

    // 5. Wakeup doorbell
    wakeup(device_mac, product_model);

    return creds;
}

void wakeup(const std::string& device_mac, const std::string& product_model) {
    if (s_access_token.empty())
        throw std::runtime_error("wakeup: not logged in (call bootstrap first)");

    Http http;
    http.phone_id = s_phone_id;

    std::fprintf(stderr, "[auth] sending wakeup to %s...\n", device_mac.c_str());
    try {
        do_run_action_batch(http, device_mac, product_model,
                            "iot-device", "wakeup",
                            {{"wakeup-live-view", 1}});
        std::fprintf(stderr, "[auth] wakeup sent (doorbell wakes async while SDK initializes)\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[auth] wakeup failed (non-fatal): %s\n", e.what());
    }
}

}  // namespace wyze
