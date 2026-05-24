#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include <set>
#include <map>
#include <vector>

// Override default loop task stack size (default 8192 is too small for BLE)
size_t getArduinoLoopTaskStackSize(void) { return 16384; }

// ============================================================================
// Configuration
// ============================================================================

static const uint32_t SCAN_DURATION_SEC = 5;
static const uint32_t SERIAL_BAUD       = 115200;

// ============================================================================
// Data structures
// ============================================================================

struct ADEntry {
  uint8_t type;
  std::vector<uint8_t> data;
};

struct MACInfo {
  String     mac;
  String     name;
  int        rssi;
  int        addrType;
  int        seenCount;
  uint32_t   firstSeen;
  uint32_t   lastSeen;
  bool       isBaseline;
  std::vector<ADEntry> adStructures;
  uint16_t   companyId;
  bool       hasManufData;
  String     rawPayloadHex;
};

// ============================================================================
// Globals
// ============================================================================

static BLEScan*                     pScan        = nullptr;
static std::set<String>             baselineMACs;
static std::map<String, MACInfo>    allDevices;
static bool                         filterBaseline = false;
static bool                         verboseMode    = false;
static uint32_t                     scanCount      = 0;
static uint32_t                     totalAdverts   = 0;
static uint32_t                     markTimestamp   = 0;

// ============================================================================
// Forward declarations
// ============================================================================

void        parseADStructures(const uint8_t* payload, size_t len, std::vector<ADEntry>& out);
String      adTypeToString(uint8_t type);
String      bytesToHex(const uint8_t* data, size_t len);
uint16_t    parseCompanyId(const ADEntry& entry);
void        printDeviceInfo(const MACInfo& info, bool isNew);
void        printADStructures(const std::vector<ADEntry>& ads);
void        handleSerialCommand(char cmd);
void        printStats();
void        printHelp();
void        clearBaseline();
void        resetAll();
void        toggleFilter();
void        toggleVerbose();
void        setMark();
void        processResults(BLEScanResults* results);

// ============================================================================
// AD type parser
// ============================================================================

String adTypeToString(uint8_t type) {
  switch (type) {
    case 0x01: return "Flags";
    case 0x02: return "Inc16UUID";
    case 0x03: return "Cmp16UUID";
    case 0x04: return "Inc32UUID";
    case 0x05: return "Cmp32UUID";
    case 0x06: return "Inc128UUID";
    case 0x07: return "Cmp128UUID";
    case 0x08: return "ShortName";
    case 0x09: return "CmpName";
    case 0x0A: return "TxPower";
    case 0x0D: return "ClassOfDev";
    case 0x0E: return "SSP_Hash";
    case 0x0F: return "SSP_Rand";
    case 0x10: return "TK_Value";
    case 0x11: return "SecMgrOOB";
    case 0x12: return "PeriphConn";
    case 0x14: return "Solicit16";
    case 0x15: return "Solicit128";
    case 0x16: return "SvcData16";
    case 0x17: return "PubTgtAddr";
    case 0x18: return "RndTgtAddr";
    case 0x19: return "Appearance";
    case 0x1A: return "AdvIntv";
    case 0x1B: return "LEBTAddr";
    case 0x1C: return "LERole";
    case 0x20: return "SvcData32";
    case 0x21: return "SvcData128";
    case 0xFF: return "MfgData";
    default: {
      char buf[12];
      snprintf(buf, sizeof(buf), "0x%02X", type);
      return String(buf);
    }
  }
}

// ============================================================================
// Utility functions
// ============================================================================

String bytesToHex(const uint8_t* data, size_t len) {
  String out;
  out.reserve(len * 3);
  for (size_t i = 0; i < len; i++) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%02X ", data[i]);
    out += buf;
  }
  out.trim();
  return out;
}

uint16_t parseCompanyId(const ADEntry& entry) {
  if (entry.type == 0xFF && entry.data.size() >= 2) {
    return (uint16_t)entry.data[0] | ((uint16_t)entry.data[1] << 8);
  }
  return 0;
}

// ============================================================================
// Parse raw advertisement payload into AD structures
// ============================================================================

void parseADStructures(const uint8_t* payload, size_t len, std::vector<ADEntry>& out) {
  out.clear();
  size_t offset = 0;
  while (offset < len) {
    uint8_t fieldLen = payload[offset];
    if (fieldLen == 0) break;
    if (offset + 1 + fieldLen > len) break;

    ADEntry entry;
    entry.type = payload[offset + 1];
    for (size_t i = 0; i < (size_t)(fieldLen - 1); i++) {
      entry.data.push_back(payload[offset + 2 + i]);
    }
    out.push_back(entry);
    offset += 1 + fieldLen;
  }
}

// ============================================================================
// Print helpers
// ============================================================================

void printADStructures(const std::vector<ADEntry>& ads) {
  for (size_t i = 0; i < ads.size(); i++) {
    const ADEntry& ad = ads[i];
    Serial.printf("    AD[%d] type=0x%02X (%s) len=%d: %s\n",
                  (int)i, ad.type, adTypeToString(ad.type).c_str(),
                  (int)ad.data.size(),
                  bytesToHex(ad.data.data(), ad.data.size()).c_str());

    // Extra detail for manufacturer data
    if (ad.type == 0xFF && ad.data.size() >= 2) {
      uint16_t cid = parseCompanyId(ad);
      Serial.printf("         Company ID: 0x%04X", cid);
      // Common company IDs
      if (cid == 0x004C) Serial.print(" (Apple)");
      else if (cid == 0x0006) Serial.print(" (Microsoft)");
      else if (cid == 0x0075) Serial.print(" (Samsung)");
      else if (cid == 0x00E0) Serial.print(" (Google)");
      else if (cid == 0x0059) Serial.print(" (Nordic)");
      else if (cid == 0x02AC) Serial.print(" (Wyze)");
      Serial.println();
      if (ad.data.size() > 2) {
        Serial.printf("         Payload:    %s\n",
                      bytesToHex(ad.data.data() + 2, ad.data.size() - 2).c_str());
      }
    }

    // Flags decode
    if (ad.type == 0x01 && ad.data.size() >= 1) {
      uint8_t flags = ad.data[0];
      Serial.printf("         Flags: %s%s%s%s%s\n",
                     (flags & 0x01) ? "LE_LIMITED " : "",
                     (flags & 0x02) ? "LE_GENERAL " : "",
                     (flags & 0x04) ? "NO_BREDR " : "",
                     (flags & 0x08) ? "LE+BREDR_CTRL " : "",
                     (flags & 0x10) ? "LE+BREDR_HOST " : "");
    }

    // Service data decode
    if ((ad.type == 0x16) && ad.data.size() >= 2) {
      uint16_t svcUUID = (uint16_t)ad.data[0] | ((uint16_t)ad.data[1] << 8);
      Serial.printf("         Svc UUID: 0x%04X\n", svcUUID);
      if (ad.data.size() > 2) {
        Serial.printf("         Svc Data: %s\n",
                      bytesToHex(ad.data.data() + 2, ad.data.size() - 2).c_str());
      }
    }
  }
}

void printDeviceInfo(const MACInfo& info, bool isNew) {
  uint32_t now = millis();
  uint32_t age = (now - info.firstSeen) / 1000;

  const char* tag = isNew ? ">>> NEW" : "   seen";
  const char* baseTag = info.isBaseline ? " [BASE]" : "";

  Serial.printf("%s | %s | RSSI:%4d | Type:%d | cnt:%d | age:%us%s",
                tag, info.mac.c_str(), info.rssi, info.addrType,
                info.seenCount, age, baseTag);

  if (info.name.length() > 0) {
    Serial.printf(" | name:\"%s\"", info.name.c_str());
  }
  if (info.hasManufData) {
    Serial.printf(" | mfg:0x%04X", info.companyId);
  }
  if (markTimestamp > 0 && info.firstSeen >= markTimestamp) {
    Serial.print(" [AFTER-MARK]");
  }
  Serial.println();

  if (verboseMode || isNew) {
    printADStructures(info.adStructures);
    if (info.rawPayloadHex.length() > 0) {
      Serial.printf("    RAW: %s\n", info.rawPayloadHex.c_str());
    }
  }
}

// ============================================================================
// Process scan results (blocking batch mode)
// ============================================================================

void processResults(BLEScanResults* results) {
  if (results == nullptr) return;

  int count = results->getCount();
  if (count == 0) return;

  uint32_t now = millis();

  for (int i = 0; i < count; i++) {
    BLEAdvertisedDevice dev = results->getDevice(i);
    totalAdverts++;

    String mac = String(dev.getAddress().toString().c_str());
    mac.toUpperCase();

    bool isNew = (allDevices.find(mac) == allDevices.end());

    MACInfo& info = allDevices[mac];

    if (isNew) {
      info.mac       = mac;
      info.firstSeen = now;
      info.seenCount = 0;
      info.isBaseline = false;
      info.hasManufData = false;
      info.companyId = 0;
    }

    info.rssi      = dev.getRSSI();
    info.addrType  = dev.getAddressType();
    info.lastSeen  = now;
    info.seenCount++;

    if (dev.haveName()) {
      info.name = String(dev.getName().c_str());
    }

    // Parse raw payload for AD structures
    uint8_t* payload = dev.getPayload();
    size_t payloadLen = dev.getPayloadLength();

    if (payload != nullptr && payloadLen > 0) {
      parseADStructures(payload, payloadLen, info.adStructures);
      info.rawPayloadHex = bytesToHex(payload, payloadLen);

      // Check for manufacturer data
      for (size_t a = 0; a < info.adStructures.size(); a++) {
        if (info.adStructures[a].type == 0xFF && info.adStructures[a].data.size() >= 2) {
          info.hasManufData = true;
          info.companyId = parseCompanyId(info.adStructures[a]);
        }
      }
    }

    // Apply filter
    if (filterBaseline && info.isBaseline) continue;

    printDeviceInfo(info, isNew);
  }
}

// ============================================================================
// Serial command handlers
// ============================================================================

void printHelp() {
  Serial.println();
  Serial.println("=== BLE Sniffer Commands ===");
  Serial.println("  c - Capture current devices as baseline (mark as known)");
  Serial.println("  r - Reset everything (clear all devices + baseline)");
  Serial.println("  s - Print statistics");
  Serial.println("  f - Toggle baseline filter (hide known devices)");
  Serial.println("  v - Toggle verbose mode (show AD details for all)");
  Serial.println("  m - Set time mark (highlight devices seen after this point)");
  Serial.println("  h - This help");
  Serial.println("============================");
  Serial.println();
}

void clearBaseline() {
  baselineMACs.clear();
  uint32_t count = 0;
  for (auto& kv : allDevices) {
    baselineMACs.insert(kv.first);
    kv.second.isBaseline = true;
    count++;
  }
  Serial.printf("\n*** BASELINE SET: %u devices marked as known ***\n\n", count);
}

void resetAll() {
  allDevices.clear();
  baselineMACs.clear();
  scanCount = 0;
  totalAdverts = 0;
  markTimestamp = 0;
  Serial.println("\n*** FULL RESET: all data cleared ***\n");
}

void toggleFilter() {
  filterBaseline = !filterBaseline;
  Serial.printf("\n*** Baseline filter: %s ***\n\n",
                filterBaseline ? "ON (hiding known)" : "OFF (showing all)");
}

void toggleVerbose() {
  verboseMode = !verboseMode;
  Serial.printf("\n*** Verbose mode: %s ***\n\n",
                verboseMode ? "ON" : "OFF");
}

void setMark() {
  markTimestamp = millis();
  Serial.printf("\n*** MARK set at %u ms uptime ***\n\n", markTimestamp);
}

void printStats() {
  Serial.println();
  Serial.println("========== STATISTICS ==========");
  Serial.printf("  Uptime:          %u s\n", millis() / 1000);
  Serial.printf("  Scan cycles:     %u\n", scanCount);
  Serial.printf("  Total adverts:   %u\n", totalAdverts);
  Serial.printf("  Unique MACs:     %u\n", (unsigned)allDevices.size());
  Serial.printf("  Baseline MACs:   %u\n", (unsigned)baselineMACs.size());
  Serial.printf("  Filter:          %s\n", filterBaseline ? "ON" : "OFF");
  Serial.printf("  Verbose:         %s\n", verboseMode ? "ON" : "OFF");
  Serial.printf("  Mark:            %s\n", markTimestamp > 0 ? "SET" : "not set");
  Serial.println();

  // Count by company ID
  std::map<uint16_t, int> companyCounts;
  int noMfgCount = 0;
  for (auto& kv : allDevices) {
    if (kv.second.hasManufData) {
      companyCounts[kv.second.companyId]++;
    } else {
      noMfgCount++;
    }
  }
  Serial.println("  Devices by manufacturer:");
  for (auto& cc : companyCounts) {
    Serial.printf("    CID 0x%04X: %d devices\n", cc.first, cc.second);
  }
  if (noMfgCount > 0) {
    Serial.printf("    No mfg data: %d devices\n", noMfgCount);
  }

  // Show non-baseline devices
  int newCount = 0;
  for (auto& kv : allDevices) {
    if (!kv.second.isBaseline) newCount++;
  }
  Serial.printf("\n  Non-baseline (new) devices: %d\n", newCount);

  if (newCount > 0) {
    Serial.println("  --- New devices ---");
    for (auto& kv : allDevices) {
      if (!kv.second.isBaseline) {
        printDeviceInfo(kv.second, false);
      }
    }
  }

  Serial.println("================================");
  Serial.println();
}

void handleSerialCommand(char cmd) {
  switch (cmd) {
    case 'c': case 'C': clearBaseline(); break;
    case 'r': case 'R': resetAll();      break;
    case 's': case 'S': printStats();    break;
    case 'f': case 'F': toggleFilter();  break;
    case 'v': case 'V': toggleVerbose(); break;
    case 'm': case 'M': setMark();       break;
    case 'h': case 'H': case '?': printHelp(); break;
    default: break;
  }
}

// ============================================================================
// Arduino setup & loop
// ============================================================================

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(2000);  // Let serial settle on USB-C

  Serial.println();
  Serial.println("=============================================");
  Serial.println("  BLE Sniffer - Seeed XIAO ESP32-C6");
  Serial.println("  Wyze Chime/Doorbell Wake Analysis");
  Serial.println("=============================================");
  Serial.println();

  BLEDevice::init("");

  pScan = BLEDevice::getScan();
  pScan->setActiveScan(false);       // Passive scan - don't send SCAN_REQ
  pScan->setInterval(40);            // 25ms interval (units of 0.625ms)
  pScan->setWindow(40);              // 100% duty cycle
  pScan->setDuplicateFilter(false);  // We want ALL advertisements

  Serial.printf("Scan config: passive, interval=%d, window=%d, duration=%ds\n",
                40, 40, SCAN_DURATION_SEC);
  Serial.println("Duplicate filter: OFF (capturing all adverts)");
  Serial.println();
  printHelp();

  Serial.println("Starting scan loop...\n");
}

void loop() {
  // Check for serial commands
  while (Serial.available()) {
    char c = Serial.read();
    if (c >= ' ') {
      handleSerialCommand(c);
    }
  }

  // Run blocking scan
  scanCount++;
  Serial.printf("--- Scan #%u (t=%us) ---\n", scanCount, millis() / 1000);

  BLEScanResults* results = pScan->start(SCAN_DURATION_SEC, false);

  if (results != nullptr) {
    int count = results->getCount();
    Serial.printf("--- Got %d advertisements ---\n", count);
    processResults(results);
  } else {
    Serial.println("--- Scan returned null ---");
  }

  pScan->clearResults();

  Serial.println();
  delay(100);  // Brief pause between scans
}
