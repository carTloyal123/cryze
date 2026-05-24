// sniffer_wifi.h - WiFi AP Scanner for Seeed XIAO ESP32-C6
// Uses Arduino WiFi scan API (which actually works on C6) to find 'wzap'
// and monitor when it appears/disappears during doorbell events.
#pragma once

#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "esp_wifi.h"
}

size_t getArduinoLoopTaskStackSize(void) { return 16384; }

#define SERIAL_BAUD 115200
#define SCAN_INTERVAL_MS 3000  // Scan every 3 seconds
#define MAX_TRACKED 64

struct APEntry {
    char ssid[33];
    uint8_t bssid[6];
    int32_t rssi;
    uint8_t channel;
    uint8_t encType;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint32_t count;
    bool isWzap;
    bool inBaseline;
};

static APEntry g_aps[MAX_TRACKED];
static int g_apCount = 0;
static uint32_t g_scanCount = 0;
static uint32_t g_startMs = 0;
static uint32_t g_markCount = 0;
static bool g_filterMode = false;  // true = only show new/wzap

// Forward declarations
void handleSerial();
int findAP(const char *ssid, const uint8_t *bssid);
int addAP(const char *ssid, const uint8_t *bssid, int32_t rssi, uint8_t ch, uint8_t enc, uint32_t now);
bool isWzapSSID(const char *ssid);
void printMAC(const uint8_t *mac);
float elapsed();

float elapsed() {
    return (millis() - g_startMs) / 1000.0f;
}

bool isWzapSSID(const char *ssid) {
    if (!ssid || ssid[0] == '\0') return false;
    // Case-insensitive search
    char lower[33];
    int i;
    for (i = 0; ssid[i] && i < 32; i++) {
        lower[i] = tolower(ssid[i]);
    }
    lower[i] = '\0';
    return (strstr(lower, "wzap") || strstr(lower, "wyze") ||
            (lower[0] == 'w' && lower[1] == 'z'));
}

void printMAC(const uint8_t *mac) {
    Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int findAP(const char *ssid, const uint8_t *bssid) {
    for (int i = 0; i < g_apCount; i++) {
        if (memcmp(g_aps[i].bssid, bssid, 6) == 0 &&
            strcmp(g_aps[i].ssid, ssid) == 0) {
            return i;
        }
    }
    return -1;
}

int addAP(const char *ssid, const uint8_t *bssid, int32_t rssi, uint8_t ch, uint8_t enc, uint32_t now) {
    if (g_apCount >= MAX_TRACKED) return -1;
    int idx = g_apCount++;
    strncpy(g_aps[idx].ssid, ssid, 32);
    g_aps[idx].ssid[32] = '\0';
    memcpy(g_aps[idx].bssid, bssid, 6);
    g_aps[idx].rssi = rssi;
    g_aps[idx].channel = ch;
    g_aps[idx].encType = enc;
    g_aps[idx].firstSeen = now;
    g_aps[idx].lastSeen = now;
    g_aps[idx].count = 1;
    g_aps[idx].isWzap = isWzapSSID(ssid);
    g_aps[idx].inBaseline = false;
    return idx;
}

void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(2000);

    Serial.println(F("\n================================================"));
    Serial.println(F("  WiFi AP Scanner - Seeed XIAO ESP32-C6"));
    Serial.println(F("  Hunting for 'wzap' Wyze soft-AP"));
    Serial.println(F("================================================"));
    Serial.println(F("Commands: [c]lear baseline  [f]ilter  [m]ark"));
    Serial.println(F("          [s]tats  [r]eset  [q]uit scan"));
    Serial.println(F("Scans every 3s, shows new APs and wzap always"));
    Serial.println(F("================================================\n"));

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    // CRITICAL: XIAO ESP32-C6 needs GPIO3 LOW to activate RF switch!
    pinMode(3, OUTPUT);
    digitalWrite(3, LOW);   // Enable RF switch
    pinMode(14, OUTPUT);
    digitalWrite(14, LOW);  // Select onboard antenna
    delay(500);

    g_startMs = millis();
    Serial.printf("[%8.2f] Starting WiFi scanner...\n", 0.0);

    // Do first scan using raw ESP-IDF API
    Serial.println(F("Running initial scan (ESP-IDF direct)..."));
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } }
    };
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);  // blocking
    Serial.printf("Scan start: %s\n", esp_err_to_name(err));

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    Serial.printf("Found %d APs via ESP-IDF\n\n", ap_count);
    if (ap_count > 0) {
        wifi_ap_record_t *records = (wifi_ap_record_t *)malloc(ap_count * sizeof(wifi_ap_record_t));
        if (records) {
            esp_wifi_scan_get_ap_records(&ap_count, records);
            for (int i = 0; i < ap_count && i < 20; i++) {
                Serial.printf("  [%d] \"%s\" CH:%d RSSI:%d\n",
                    i, records[i].ssid, records[i].primary, records[i].rssi);
            }
            free(records);
        }
        Serial.println();
    }
}

void loop() {
    handleSerial();

    // Run synchronous scan every cycle (simpler, more reliable on C6)
    int n = WiFi.scanNetworks(false, true, false, 200);  // sync, show_hidden
        // Scan complete - process results
        g_scanCount++;
        uint32_t now = millis();

        int newCount = 0;
        int wzapCount = 0;

        for (int i = 0; i < n; i++) {
            String ssidStr = WiFi.SSID(i);
            const char *ssid = ssidStr.c_str();
            uint8_t *bssid = WiFi.BSSID(i);
            int32_t rssi = WiFi.RSSI(i);
            uint8_t ch = WiFi.channel(i);
            uint8_t enc = WiFi.encryptionType(i);

            // Handle hidden SSIDs
            char ssidBuf[33];
            if (ssid[0] == '\0') {
                snprintf(ssidBuf, sizeof(ssidBuf), "<hidden>");
                ssid = ssidBuf;
            }

            bool isWzap = isWzapSSID(ssid);
            if (isWzap) wzapCount++;

            int idx = findAP(ssid, bssid);
            if (idx >= 0) {
                // Known AP - update
                g_aps[idx].rssi = rssi;
                g_aps[idx].channel = ch;
                g_aps[idx].lastSeen = now;
                g_aps[idx].count++;

                // Always print wzap
                if (g_aps[idx].isWzap) {
                    Serial.println(F("!!!!!!!!!!!!!! WZAP DETECTED !!!!!!!!!!!!!!"));
                    Serial.printf("[%8.2f] WZAP SSID:\"%s\" BSSID:", elapsed(), g_aps[idx].ssid);
                    printMAC(g_aps[idx].bssid);
                    Serial.printf(" CH:%d RSSI:%d ENC:%d cnt:%lu\n",
                        ch, rssi, enc, (unsigned long)g_aps[idx].count);
                    Serial.println(F("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
                }
            } else {
                // New AP
                idx = addAP(ssid, bssid, rssi, ch, enc, now);
                if (idx < 0) continue;
                newCount++;

                bool shouldPrint = true;
                if (g_filterMode && !isWzap) shouldPrint = false;

                if (shouldPrint) {
                    if (isWzap) {
                        Serial.println(F("!!!!!!!!!!!!!! WZAP FOUND !!!!!!!!!!!!!!"));
                    }

                    Serial.printf("[%8.2f] >>> NEW AP: \"%s\" BSSID:", elapsed(), ssid);
                    printMAC(bssid);
                    Serial.printf(" CH:%d RSSI:%d ENC:%d\n", ch, rssi, enc);

                    if (isWzap) {
                        Serial.println(F("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
                    }
                }
            }
        }

        // Scan summary line
        Serial.printf("[%8.2f] --- scan #%lu: %d APs found, %d total tracked, %d new",
            elapsed(), (unsigned long)g_scanCount, n, g_apCount, newCount);
        if (wzapCount > 0) Serial.printf(", %d WZAP!", wzapCount);
        Serial.println(" ---");

        // Delete scan results
        WiFi.scanDelete();
        delay(SCAN_INTERVAL_MS);

    delay(100);
}

void handleSerial() {
    while (Serial.available()) {
        char cmd = Serial.read();

        switch (cmd) {
            case 'c':
                for (int i = 0; i < g_apCount; i++) {
                    g_aps[i].inBaseline = true;
                }
                Serial.printf("\n[%8.2f] BASELINE SET: %d APs marked as known\n\n", elapsed(), g_apCount);
                break;

            case 'f':
                g_filterMode = !g_filterMode;
                Serial.printf("\n[%8.2f] FILTER: %s\n\n", elapsed(), g_filterMode ? "ON (new/wzap only)" : "OFF");
                break;

            case 'm':
                g_markCount++;
                Serial.printf("\n[%8.2f] ===== MARK #%lu =====\n\n", elapsed(), (unsigned long)g_markCount);
                break;

            case 'r':
                g_apCount = 0;
                g_scanCount = 0;
                g_startMs = millis();
                Serial.println(F("\n[    0.00] RESET\n"));
                break;

            case 's': {
                Serial.printf("\n[%8.2f] === STATS ===\n", elapsed());
                Serial.printf("  Scans: %lu  APs tracked: %d  Filter: %s\n",
                    (unsigned long)g_scanCount, g_apCount, g_filterMode ? "ON" : "OFF");
                Serial.println(F("  --- All APs ---"));
                for (int i = 0; i < g_apCount; i++) {
                    APEntry &a = g_aps[i];
                    Serial.printf("  %s%s%-20s BSSID:", a.isWzap ? ">>>" : "   ",
                        a.inBaseline ? " " : "*", a.ssid);
                    printMAC(a.bssid);
                    Serial.printf(" CH:%-2d R:%-4d cnt:%-4lu %s\n",
                        a.channel, a.rssi, (unsigned long)a.count,
                        a.isWzap ? " <<<< WZAP" : "");
                }
                Serial.println(F("  ===============\n"));
                break;
            }
        }
    }
}
