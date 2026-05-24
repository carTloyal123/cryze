// DGLP Brute Force - try all 256 message types on both FFE1 and FFE9
// Boot -> scan -> connect -> baseline -> send type 0x00-0xFF on FFE9, then FFE1
// Log any response that differs from normal heartbeat pattern
#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>

size_t getArduinoLoopTaskStackSize(void) { return 32768; }

static const char* TARGET_PREFIX = "WOUTDOOR";
static NimBLEClient* gClient = nullptr;
static NimBLEAddress gTargetAddr;
static NimBLERemoteCharacteristic* gFFE1 = nullptr;
static NimBLERemoteCharacteristic* gFFE9 = nullptr;
static NimBLERemoteCharacteristic* gFFEA = nullptr;
static bool gFound = false;
static bool gReady = false;
static bool gDisconnected = false;
static uint32_t gStart = 0;
static bool gScanActive = true;

// Track notifications for detecting responses to our commands
static volatile uint32_t gFFE1NotifyCount = 0;
static volatile uint32_t gFFEANonStdCount = 0;
static volatile bool gGotFFE1Response = false;
static volatile uint32_t gLastFFE1NotifyTime = 0;

static float ts() { return (millis() - gStart) / 1000.0f; }
static void hexDump(const uint8_t* d, size_t len) {
    for (size_t i = 0; i < len; i++) Serial.printf("%02X ", d[i]);
}

static void onFFE1Notify(NimBLERemoteCharacteristic* chr, uint8_t* data, size_t len, bool isNotify) {
    gFFE1NotifyCount++;
    gGotFFE1Response = true;
    gLastFFE1NotifyTime = millis();
    Serial.printf("\n  !!! FFE1 RESPONSE len=%d: ", (int)len);
    hexDump(data, len);
    Serial.println();
}

static void onFFEANotify(NimBLERemoteCharacteristic* chr, uint8_t* data, size_t len, bool isNotify) {
    // Only log non-standard messages (not the regular type 0x27 heartbeat)
    if (len != 30 || (len >= 8 && data[7] != 0x27)) {
        gFFEANonStdCount++;
        Serial.printf("  [FFEA non-std len=%d type=0x%02X]: ", (int)len, len >= 8 ? data[7] : 0);
        hexDump(data, len > 20 ? 20 : len);
        if (len > 20) Serial.print("...");
        Serial.println();
    }
}

class ClientCB : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient* c) override {}
    void onDisconnect(NimBLEClient* c, int reason) override {
        gDisconnected = true;
        gReady = false;
        Serial.printf("\n[%8.2f] DISCONNECTED (reason=%d)\n", ts(), reason);
    }
};
static ClientCB gCB;

class ScanCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        std::string name = dev->getName();
        if (name.length() > 0 && name.find(TARGET_PREFIX) == 0) {
            Serial.printf("\n*** TARGET FOUND: %s ***\n\n", name.c_str());
            gTargetAddr = dev->getAddress();
            gFound = true;
            NimBLEDevice::getScan()->stop();
        }
    }
    void onScanEnd(const NimBLEScanResults& r, int reason) override {}
};
static ScanCB gScanCB;

// Build minimal DGLP packet
static size_t buildDGLP(uint8_t* buf, uint8_t msgType, uint8_t seq) {
    // Minimal: header(8) + seq_field(8) = 16 bytes
    memset(buf, 0, 16);
    buf[0] = 0x96;
    buf[2] = 0x01;
    buf[3] = 0x44; buf[4] = 0x47; buf[5] = 0x4C; buf[6] = 0x50;
    buf[7] = msgType;
    buf[15] = seq;  // sequence at offset 15 (matching observed format)
    // Checksum
    uint8_t cksum = 0;
    for (int i = 2; i < 16; i++) cksum ^= buf[i];
    buf[1] = cksum;
    return 16;
}

// Run brute force on one characteristic
static void bruteForce(NimBLERemoteCharacteristic* chr, const char* name) {
    Serial.println("\n================================================================");
    Serial.printf("  BRUTE FORCE: All 256 types on %s\n", name);
    Serial.println("  Watching for FFE1 responses and FFEA non-standard messages");
    Serial.println("================================================================\n");

    uint8_t buf[16];
    uint32_t responsiveTypes = 0;

    for (int type = 0; type < 256; type++) {
        if (!gClient || !gClient->isConnected()) {
            Serial.println("\n*** DISCONNECTED during brute force! ***");
            return;
        }

        size_t len = buildDGLP(buf, (uint8_t)type, (uint8_t)type);

        // Reset response tracking
        gGotFFE1Response = false;
        uint32_t prevNonStd = gFFEANonStdCount;

        // Send
        bool ok = chr->writeValue(buf, len, false);

        // Brief wait for response
        delay(200);

        // Check for any response
        bool gotResponse = gGotFFE1Response || (gFFEANonStdCount > prevNonStd);

        if (gotResponse) {
            responsiveTypes++;
            Serial.printf(">>> TYPE 0x%02X (%3d) on %s: RESPONDED! ffe1_notify=%s ffea_nonstd=%s\n",
                type, type, name,
                gGotFFE1Response ? "YES" : "no",
                (gFFEANonStdCount > prevNonStd) ? "YES" : "no");
        } else if (type % 32 == 0) {
            // Progress indicator every 32 types
            Serial.printf("[%8.2f] Testing types 0x%02X-0x%02X on %s...\n",
                ts(), type, type + 31 < 256 ? type + 31 : 255, name);
        }

        // Don't send too fast
        if (type % 16 == 15) delay(300);  // Extra pause every 16
    }

    Serial.printf("\n  %s complete: %lu types got responses\n\n",
        name, (unsigned long)responsiveTypes);
}

void setup() {
    Serial.begin(115200);
    delay(2000);
    gStart = millis();

    Serial.println("\n========================================");
    Serial.println("  DGLP Brute Force - All 256 Types");
    Serial.println("  Scan -> Connect -> Test every type");
    Serial.println("========================================\n");

    NimBLEDevice::init("WyzeBridge");
    NimBLEDevice::setSecurityAuth(false, false, false);

    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&gScanCB, false);
    scan->setActiveScan(true);
    scan->setInterval(40);
    scan->setWindow(30);
    scan->setMaxResults(0);
    scan->setDuplicateFilter(false);

    Serial.printf("[%8.2f] Scanning for 30 seconds...\n", ts());
    Serial.println("  Boot the doorbell NOW (chime must be OFF)\n");
    scan->start(0);
}

void loop() {
    // Countdown
    static uint32_t lastPrint = 0;
    if (gScanActive && !gFound && millis() - lastPrint > 3000) {
        lastPrint = millis();
        int rem = 30 - (int)ts();
        if (rem > 0) Serial.printf("[%8.2f] Scanning... %ds remaining\n", ts(), rem);
    }

    if (gScanActive && !gFound && ts() > 30.0f) {
        gScanActive = false;
        NimBLEDevice::getScan()->stop();
        Serial.println("Scan timeout. Reboot ESP32 and doorbell to retry.");
    }

    // Connect and run brute force
    if (gFound && !gReady && !gClient) {
        gFound = false;
        gScanActive = false;
        NimBLEDevice::getScan()->stop();

        Serial.printf("[%8.2f] Connecting...\n", ts());
        gClient = NimBLEDevice::createClient();
        gClient->setClientCallbacks(&gCB, false);

        if (!gClient->connect(gTargetAddr, false)) {
            Serial.println("CONNECTION FAILED");
            gClient = nullptr;
            return;
        }
        Serial.printf("[%8.2f] CONNECTED! MTU=%d\n", ts(), gClient->getMTU());

        NimBLERemoteService* svc = gClient->getService(NimBLEUUID("0000e0ff-3c17-d293-8e48-14fe2e4da212"));
        if (!svc) { Serial.println("Service not found!"); return; }

        gFFE1 = svc->getCharacteristic(NimBLEUUID((uint16_t)0xFFE1));
        gFFE9 = svc->getCharacteristic(NimBLEUUID((uint16_t)0xFFE9));
        gFFEA = svc->getCharacteristic(NimBLEUUID((uint16_t)0xFFEA));

        if (!gFFE1 || !gFFE9 || !gFFEA) { Serial.println("Missing chars!"); return; }

        gFFE1->subscribe(true, onFFE1Notify);
        gFFEA->subscribe(true, onFFEANotify);
        Serial.println("  Subscribed. Collecting 5s baseline...\n");
        delay(5000);

        gReady = true;

        // Phase 1: Brute force FFE9 (write-only channel)
        bruteForce(gFFE9, "FFE9");

        // Phase 2: Brute force FFE1 (command channel)
        if (gClient && gClient->isConnected()) {
            bruteForce(gFFE1, "FFE1");
        }

        Serial.println("\n========================================");
        Serial.println("  BRUTE FORCE COMPLETE");
        Serial.printf("  FFE1 notify count: %lu\n", (unsigned long)gFFE1NotifyCount);
        Serial.printf("  FFEA non-std count: %lu\n", (unsigned long)gFFEANonStdCount);
        Serial.println("========================================\n");
    }

    if (gDisconnected) {
        gDisconnected = false;
        Serial.println("\n*** Disconnected. Did you hear the shutter? ***");
    }

    static uint32_t lastHB = 0;
    if (gReady && gClient && gClient->isConnected() && millis() - lastHB > 30000) {
        lastHB = millis();
        Serial.printf("[%8.2f] Still connected, monitoring...\n", ts());
    }

    delay(10);
}
