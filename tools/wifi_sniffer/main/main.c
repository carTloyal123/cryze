/**
 * WiFi Promiscuous Sniffer for ESP32-C6
 * Target: Wyze "wzap" protocol discovery
 *
 * Pure ESP-IDF (no Arduino). Captures all 802.11 frames in promiscuous mode,
 * highlights anything related to wzap/wyze, and logs beacon/probe activity.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "driver/gpio.h"

static const char *TAG = "SNIFF";

/* ── Stats ─────────────────────────────────────────────────────────── */

static uint32_t stat_total   = 0;
static uint32_t stat_mgmt    = 0;
static uint32_t stat_data    = 0;
static uint32_t stat_ctrl    = 0;
static uint32_t stat_beacons = 0;

#define MAX_SSIDS 32

typedef struct {
    char    ssid[33];
    uint8_t bssid[6];
    uint32_t count;
} ssid_entry_t;

static ssid_entry_t ssid_table[MAX_SSIDS];
static int ssid_count = 0;

/* ── Channel hop state ─────────────────────────────────────────────── */

static volatile int  current_channel = 1;
static volatile bool auto_hop = true;

/* ── Helpers ───────────────────────────────────────────────────────── */

static void mac_to_str(const uint8_t *mac, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static float timestamp_sec(void)
{
    return (float)(esp_timer_get_time() / 1000) / 1000.0f;
}

/** Case-insensitive substring search */
static bool contains_ci(const char *haystack, const char *needle)
{
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen) return false;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        bool match = true;
        for (size_t j = 0; j < nlen; j++) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

static bool is_wzap_ssid(const char *ssid)
{
    return contains_ci(ssid, "wzap") ||
           contains_ci(ssid, "wyze") ||
           contains_ci(ssid, "wz");
}

/** Returns index in ssid_table, or -1 if new (and inserts it). */
static int ssid_lookup_or_add(const char *ssid, const uint8_t *bssid)
{
    for (int i = 0; i < ssid_count; i++) {
        if (strcmp(ssid_table[i].ssid, ssid) == 0 &&
            memcmp(ssid_table[i].bssid, bssid, 6) == 0) {
            ssid_table[i].count++;
            return i;
        }
    }
    /* New entry */
    if (ssid_count < MAX_SSIDS) {
        strncpy(ssid_table[ssid_count].ssid, ssid, 32);
        ssid_table[ssid_count].ssid[32] = '\0';
        memcpy(ssid_table[ssid_count].bssid, bssid, 6);
        ssid_table[ssid_count].count = 1;
        ssid_count++;
        return -1; /* first time */
    }
    return -2; /* table full, treat as seen */
}

static void print_hex_dump(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            /* pad remaining */
            int pad = 15 - (i % 16);
            for (int p = 0; p < pad; p++) printf("   ");
            printf(" |");
            int start = i - (i % 16);
            for (int j = start; j <= i; j++) {
                printf("%c", isprint(data[j]) ? data[j] : '.');
            }
            printf("|\n");
        }
    }
}

static void print_wzap_banner(const char *ssid, const uint8_t *src,
                               const uint8_t *bssid, int rssi, int channel,
                               const uint8_t *payload, int payload_len)
{
    char src_s[18], bssid_s[18];
    mac_to_str(src, src_s);
    mac_to_str(bssid, bssid_s);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  *** WZAP TARGET DETECTED ***                              ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  SSID    : %-48s║\n", ssid);
    printf("║  SRC     : %-48s║\n", src_s);
    printf("║  BSSID   : %-48s║\n", bssid_s);
    printf("║  RSSI    : %-48d║\n", rssi);
    printf("║  Channel : %-48d║\n", channel);
    printf("║  Time    : %-48.3f║\n", timestamp_sec());
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    if (payload && payload_len > 0) {
        printf("  Full frame hex dump (%d bytes):\n", payload_len);
        print_hex_dump(payload, payload_len > 512 ? 512 : payload_len);
    }
    printf("\n");
}

static void print_stats(void)
{
    printf("\n--- Sniffer Stats ---\n");
    printf("  Total frames : %lu\n", (unsigned long)stat_total);
    printf("  Mgmt frames  : %lu\n", (unsigned long)stat_mgmt);
    printf("  Data frames  : %lu\n", (unsigned long)stat_data);
    printf("  Ctrl frames  : %lu\n", (unsigned long)stat_ctrl);
    printf("  Beacons      : %lu\n", (unsigned long)stat_beacons);
    printf("  Unique SSIDs : %d / %d\n", ssid_count, MAX_SSIDS);
    for (int i = 0; i < ssid_count; i++) {
        char b[18];
        mac_to_str(ssid_table[i].bssid, b);
        printf("    [%2d] %-32s  %s  (x%lu)\n",
               i, ssid_table[i].ssid, b, (unsigned long)ssid_table[i].count);
    }
    printf("---------------------\n\n");
}

/* ── Sniffer callback ──────────────────────────────────────────────── */

static void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    int rssi = pkt->rx_ctrl.rssi;
    int channel = pkt->rx_ctrl.channel;

    stat_total++;

    /* Debug: print every 100th frame to confirm callback is alive */
    if (stat_total <= 5 || stat_total % 100 == 0) {
        printf("[CB] frame #%lu type=%d len=%d rssi=%d ch=%d\n",
               (unsigned long)stat_total, type, len, rssi, channel);
    }

    if (len < 24) return; /* too short for any useful 802.11 header */

    /* Parse frame control */
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t frame_type    = (fc >> 2) & 0x3;
    uint8_t frame_subtype = (fc >> 4) & 0xF;

    const uint8_t *addr1 = payload + 4;   /* destination / receiver */
    const uint8_t *addr2 = payload + 10;  /* source / transmitter */
    const uint8_t *addr3 = payload + 16;  /* BSSID (usually) */

    char src_str[18], bssid_str[18];

    switch (frame_type) {
    case 0: stat_mgmt++; break;
    case 1: stat_ctrl++; return; /* don't process ctrl frames further */
    case 2: stat_data++; break;
    default: return;
    }

    /* ── Management frames ─────────────────────────────────────────── */
    if (frame_type == 0) {
        bool is_beacon       = (frame_subtype == 8);
        bool is_probe_resp   = (frame_subtype == 5);
        bool is_probe_req    = (frame_subtype == 4);

        if (is_beacon) stat_beacons++;

        /* Extract SSID from tagged parameters */
        char ssid[33] = {0};
        bool hidden_ssid = false;
        int ie_offset = -1;

        if (is_beacon || is_probe_resp) {
            /* 24 byte MAC header + 12 bytes fixed params (timestamp, interval, cap) */
            ie_offset = 36;
        } else if (is_probe_req) {
            /* 24 byte MAC header, IEs start immediately */
            ie_offset = 24;
        }

        if (ie_offset > 0 && ie_offset < len) {
            int pos = ie_offset;
            while (pos + 2 <= len) {
                uint8_t tag_id  = payload[pos];
                uint8_t tag_len = payload[pos + 1];
                if (pos + 2 + tag_len > len) break;

                if (tag_id == 0) { /* SSID */
                    if (tag_len == 0) {
                        hidden_ssid = true;
                        strcpy(ssid, "<hidden>");
                    } else {
                        int cplen = tag_len > 32 ? 32 : tag_len;
                        memcpy(ssid, payload + pos + 2, cplen);
                        ssid[cplen] = '\0';
                        /* Check for zero-filled SSID (also hidden) */
                        bool all_zero = true;
                        for (int z = 0; z < cplen; z++) {
                            if (ssid[z] != '\0') { all_zero = false; break; }
                        }
                        if (all_zero) {
                            hidden_ssid = true;
                            strcpy(ssid, "<hidden>");
                        }
                    }
                    break;
                }
                pos += 2 + tag_len;
            }
        }

        mac_to_str(addr2, src_str);
        mac_to_str(addr3, bssid_str);

        bool wzap_match = is_wzap_ssid(ssid);

        /* ── WZAP match: full banner ──────────────────────────────── */
        if (wzap_match) {
            print_wzap_banner(ssid, addr2, addr3, rssi, channel,
                              payload, len);
            /* Still deduplicate in the table */
            ssid_lookup_or_add(ssid, addr3);
            return;
        }

        /* ── Hidden SSID beacon: always print (could be wzap hiding) */
        if (hidden_ssid && is_beacon) {
            printf("[%8.3f] CH:%02d R:%-4d Beacon  SRC:%s BSSID:%s SSID:\"<HIDDEN>\" ***\n",
                   timestamp_sec(), channel, rssi, src_str, bssid_str);
            ssid_lookup_or_add(ssid, addr3);
            return;
        }

        /* ── Probe requests: always print ─────────────────────────── */
        if (is_probe_req) {
            printf("[%8.3f] CH:%02d R:%-4d ProbeReq SRC:%s SSID:\"%s\"\n",
                   timestamp_sec(), channel, rssi, src_str,
                   ssid[0] ? ssid : "<broadcast>");
            return;
        }

        /* ── Beacons / probe responses: print first-seen only ─────── */
        if ((is_beacon || is_probe_resp) && ssid[0]) {
            int idx = ssid_lookup_or_add(ssid, addr3);
            if (idx == -1) { /* first time */
                const char *ftype = is_beacon ? "Beacon " : "ProbeRsp";
                printf("[%8.3f] CH:%02d R:%-4d %s SRC:%s BSSID:%s SSID:\"%s\"\n",
                       timestamp_sec(), channel, rssi, ftype,
                       src_str, bssid_str, ssid);
            }
        }
        return;
    }

    /* ── Data frames: only if wzap-related MAC ─────────────────────── */
    /* For data frames we could check MACs against known wzap BSSIDs,
       but for now we just count them silently. */
    (void)addr1;
}

/* ── Channel hopping task ──────────────────────────────────────────── */

static void channel_hop_task(void *param)
{
    (void)param;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(500));
        if (!auto_hop) continue;

        current_channel++;
        if (current_channel > 13) current_channel = 1;
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    }
}

/* ── Main ──────────────────────────────────────────────────────────── */

void app_main(void)
{
    ESP_LOGI(TAG, "======================================");
    ESP_LOGI(TAG, "  WiFi Sniffer - wzap hunter");
    ESP_LOGI(TAG, "  ESP32-C6 promiscuous mode");
    ESP_LOGI(TAG, "======================================");

    /* ── NVS ────────────────────────────────────────────────────────── */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* ── Network / event init ───────────────────────────────────────── */
    esp_netif_init();
    esp_event_loop_create_default();

    /* ── XIAO ESP32-C6 RF switch: GPIO3 LOW activates antenna ────────── */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << 3) | (1ULL << 14),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&io_conf);
    gpio_set_level(3, 0);   /* Enable RF switch */
    gpio_set_level(14, 0);  /* Select onboard antenna */
    vTaskDelay(pdMS_TO_TICKS(100));

    /* ── WiFi init ──────────────────────────────────────────────────── */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    /* ── Test scan first to verify radio works ─────────────────────── */
    ESP_LOGI(TAG, "Running test WiFi scan...");
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } }
    };
    esp_err_t scan_err = esp_wifi_scan_start(&scan_cfg, true);
    ESP_LOGI(TAG, "Scan start result: %s", esp_err_to_name(scan_err));
    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    ESP_LOGI(TAG, "Found %d APs", ap_num);
    if (ap_num > 0) {
        wifi_ap_record_t *recs = malloc(ap_num * sizeof(wifi_ap_record_t));
        if (recs) {
            esp_wifi_scan_get_ap_records(&ap_num, recs);
            for (int i = 0; i < ap_num && i < 15; i++) {
                ESP_LOGI(TAG, "  AP[%d]: \"%s\" CH:%d RSSI:%d", i, recs[i].ssid, recs[i].primary, recs[i].rssi);
            }
            free(recs);
        }
    }
    esp_wifi_scan_stop();

    /* ── Promiscuous mode (register callback BEFORE enabling!) ─────── */
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(sniffer_callback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

    ESP_LOGI(TAG, "Promiscuous mode active on channel 1");
    ESP_LOGI(TAG, "Commands: m=mark  s=stats  c<N>=lock ch  a=auto-hop");

    /* ── Channel hop task ───────────────────────────────────────────── */
    xTaskCreate(channel_hop_task, "ch_hop", 2048, NULL, 5, NULL);

    /* ── UART command loop (app_main must not return) ───────────────── */
    while (1) {
        int c = getchar();
        if (c != EOF) {
            switch (c) {
            case 'm':
            case 'M':
                printf("\n===== MARK @ %.3f  CH:%d =====\n\n",
                       timestamp_sec(), current_channel);
                break;

            case 's':
            case 'S':
                print_stats();
                break;

            case 'c':
            case 'C': {
                /* Read channel number (1-2 digits) */
                vTaskDelay(pdMS_TO_TICKS(50));
                int ch = 0;
                for (int i = 0; i < 2; i++) {
                    int d = getchar();
                    if (d >= '0' && d <= '9') {
                        ch = ch * 10 + (d - '0');
                    } else {
                        break;
                    }
                }
                if (ch >= 1 && ch <= 13) {
                    auto_hop = false;
                    current_channel = ch;
                    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                    ESP_LOGI(TAG, "Locked to channel %d", ch);
                } else {
                    ESP_LOGI(TAG, "Invalid channel (use 1-13)");
                }
                break;
            }

            case 'a':
            case 'A':
                auto_hop = true;
                ESP_LOGI(TAG, "Auto channel hop resumed");
                break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
