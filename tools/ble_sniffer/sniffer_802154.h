// sniffer_802154.h - IEEE 802.15.4 (Thread/Zigbee) Sniffer for Seeed XIAO ESP32-C6
// Included from ble_sniffer.ino to bypass Arduino's broken preprocessor.
//
// The ESP32-C6 has native 802.15.4 radio support. This sniffer captures
// raw frames in promiscuous mode across channels 11-26, parses MAC headers,
// and logs everything over serial. Useful for sniffing Thread, Zigbee, and
// any other 802.15.4 traffic in the vicinity.

#pragma once

#include <Arduino.h>

extern "C" {
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
#define CHANNEL_MIN          11
#define CHANNEL_MAX          26
#define NUM_CHANNELS         (CHANNEL_MAX - CHANNEL_MIN + 1)  // 16
#define HOP_INTERVAL_MS      2000   // 2 seconds per channel in auto-hop
#define SERIAL_BAUD          115200

// Ring-buffer queue for ISR -> main-loop handoff
#define FRAME_QUEUE_SIZE     32
#define MAX_FRAME_LEN        128    // 802.15.4 max PHY payload is 127

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t  data[MAX_FRAME_LEN];
    uint8_t  len;           // first byte of frame = PHY length
    uint8_t  channel;
    int8_t   rssi;
    uint32_t timestamp_ms;
} queued_frame_t;

// 802.15.4 frame types
enum frame_type_t : uint8_t {
    FRAME_BEACON  = 0,
    FRAME_DATA    = 1,
    FRAME_ACK     = 2,
    FRAME_CMD     = 3,
    FRAME_UNKNOWN = 7
};

// Addressing modes
enum addr_mode_t : uint8_t {
    ADDR_NONE     = 0,
    ADDR_SHORT    = 2,   // 16-bit
    ADDR_EXTENDED = 3    // 64-bit (EUI-64)
};

// Parsed MAC header
typedef struct {
    frame_type_t frame_type;
    bool         security_enabled;
    bool         frame_pending;
    bool         ack_request;
    bool         pan_id_compress;
    uint8_t      seq_num;
    addr_mode_t  dst_addr_mode;
    addr_mode_t  src_addr_mode;
    uint16_t     dst_pan_id;
    uint16_t     src_pan_id;
    uint8_t      dst_addr[8];  // short=2B, extended=8B
    uint8_t      src_addr[8];
    uint8_t      header_len;   // total MHR length consumed
} mac_header_t;

// Tracking entry for unique addresses
#define MAX_TRACKED_ADDRS    128
#define MAX_TRACKED_PANIDS   32

typedef struct {
    uint8_t  addr[8];
    uint8_t  addr_len;      // 2 or 8
    uint16_t pan_id;
    uint8_t  last_channel;
    int8_t   best_rssi;
    uint32_t frame_count;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
} tracked_addr_t;

typedef struct {
    uint16_t pan_id;
    uint32_t frame_count;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
} tracked_panid_t;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static volatile queued_frame_t g_frame_queue[FRAME_QUEUE_SIZE];
static volatile uint8_t        g_queue_head = 0;   // ISR writes here
static volatile uint8_t        g_queue_tail = 0;   // main loop reads here
static volatile uint32_t       g_dropped_frames = 0;

static uint8_t  g_current_channel = CHANNEL_MIN;
static bool     g_auto_hop = true;
static uint32_t g_last_hop_ms = 0;

// Stats
static uint32_t g_total_frames = 0;
static uint32_t g_frames_per_channel[NUM_CHANNELS] = {0};
static uint32_t g_frames_per_type[8] = {0};  // indexed by frame_type_t
static uint32_t g_start_time_ms = 0;

// Tracked addresses and PAN IDs
static tracked_addr_t  g_addrs[MAX_TRACKED_ADDRS];
static uint8_t         g_addr_count = 0;
static tracked_panid_t g_panids[MAX_TRACKED_PANIDS];
static uint8_t         g_panid_count = 0;

// Mark counter for user annotations
static uint32_t g_mark_counter = 0;

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
size_t getArduinoLoopTaskStackSize(void);

// Queue helpers
static inline bool     queue_full(void);
static inline bool     queue_empty(void);
static inline uint8_t  queue_next(uint8_t idx);

// 802.15.4 control
static void     init_802154(void);
static void     set_channel(uint8_t ch);
static void     hop_channel(void);

// Frame parsing
static bool     parse_mac_header(const uint8_t *frame, uint8_t frame_len, mac_header_t *hdr);
static const char *frame_type_str(frame_type_t ft);
static uint8_t  addr_mode_len(addr_mode_t mode);

// Logging
static void     log_frame(const queued_frame_t *qf);
static void     print_hex(const uint8_t *data, uint8_t len);
static void     print_addr(const uint8_t *addr, uint8_t len);

// Tracking
static void     track_address(const uint8_t *addr, uint8_t addr_len, uint16_t pan_id,
                               uint8_t channel, int8_t rssi, uint32_t now);
static void     track_panid(uint16_t pan_id, uint32_t now);

// Serial commands
static void     handle_serial(void);
static void     print_help(void);
static void     print_stats(void);
static void     reset_stats(void);
static void     print_mark(void);

// ---------------------------------------------------------------------------
// Arduino loop task stack override - need extra room for printf/parsing
// ---------------------------------------------------------------------------
size_t getArduinoLoopTaskStackSize(void) { return 16384; }

// ---------------------------------------------------------------------------
// ISR callback - called from radio ISR when a frame is received
// ---------------------------------------------------------------------------
extern "C" void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
    // frame[0] = length byte, frame[1..length] = MPDU (no FCS - replaced by RSSI/LQI)
    uint8_t frame_len = frame[0];
    if (frame_len == 0 || frame_len > MAX_FRAME_LEN - 1) {
        esp_ieee802154_receive_handle_done(frame);
        esp_ieee802154_receive();
        return;
    }

    if (queue_full()) {
        g_dropped_frames++;
        esp_ieee802154_receive_handle_done(frame);
        esp_ieee802154_receive();
        return;
    }

    // Copy into queue slot
    volatile queued_frame_t *slot = &g_frame_queue[g_queue_head];
    slot->len = frame_len;
    slot->channel = g_current_channel;
    slot->rssi = esp_ieee802154_get_recent_rssi();
    slot->timestamp_ms = millis();
    memcpy((void *)slot->data, frame + 1, frame_len);  // skip length byte

    // Advance head
    g_queue_head = queue_next(g_queue_head);

    // Re-arm receiver
    esp_ieee802154_receive_handle_done(frame);
    esp_ieee802154_receive();
}

// Other 802.15.4 callbacks we must define (can be empty stubs)
extern "C" void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack,
                                              esp_ieee802154_frame_info_t *ack_frame_info) {
    (void)frame; (void)ack; (void)ack_frame_info;
}

extern "C" void esp_ieee802154_transmit_failed(const uint8_t *frame,
                                                esp_ieee802154_tx_error_t error) {
    (void)frame; (void)error;
}

extern "C" void esp_ieee802154_energy_detect_done(int8_t power) {
    (void)power;
}

extern "C" void esp_ieee802154_receive_sfd_done(void) {}

extern "C" void esp_ieee802154_transmit_sfd_done(uint8_t *frame) {
    (void)frame;
}

// ---------------------------------------------------------------------------
// Queue helpers
// ---------------------------------------------------------------------------
static inline uint8_t queue_next(uint8_t idx) {
    return (idx + 1) % FRAME_QUEUE_SIZE;
}

static inline bool queue_full(void) {
    return queue_next(g_queue_head) == g_queue_tail;
}

static inline bool queue_empty(void) {
    return g_queue_head == g_queue_tail;
}

// ---------------------------------------------------------------------------
// 802.15.4 initialization
// ---------------------------------------------------------------------------
static void init_802154(void) {
    esp_ieee802154_enable();
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_panid(0xFFFF);           // accept all PAN IDs
    esp_ieee802154_set_short_address(0xFFFF);    // accept all destinations
    esp_ieee802154_set_rx_when_idle(true);

    set_channel(g_current_channel);

    Serial.println(F("802.15.4 radio initialized in promiscuous mode"));
}

// ---------------------------------------------------------------------------
// Channel control
// ---------------------------------------------------------------------------
static void set_channel(uint8_t ch) {
    if (ch < CHANNEL_MIN) ch = CHANNEL_MIN;
    if (ch > CHANNEL_MAX) ch = CHANNEL_MAX;
    g_current_channel = ch;
    esp_ieee802154_set_channel(ch);
    esp_ieee802154_receive();  // start/restart RX on new channel
}

static void hop_channel(void) {
    uint8_t next = g_current_channel + 1;
    if (next > CHANNEL_MAX) next = CHANNEL_MIN;
    set_channel(next);
}

// ---------------------------------------------------------------------------
// MAC header parsing
// ---------------------------------------------------------------------------
static uint8_t addr_mode_len(addr_mode_t mode) {
    switch (mode) {
        case ADDR_SHORT:    return 2;
        case ADDR_EXTENDED: return 8;
        default:            return 0;
    }
}

static const char *frame_type_str(frame_type_t ft) {
    switch (ft) {
        case FRAME_BEACON:  return "BEACON";
        case FRAME_DATA:    return "DATA";
        case FRAME_ACK:     return "ACK";
        case FRAME_CMD:     return "CMD";
        default:            return "UNKNOWN";
    }
}

static bool parse_mac_header(const uint8_t *frame, uint8_t frame_len, mac_header_t *hdr) {
    memset(hdr, 0, sizeof(mac_header_t));

    if (frame_len < 2) return false;  // need at least FCF

    // Frame Control Field (2 bytes, little-endian)
    uint16_t fcf = frame[0] | (frame[1] << 8);

    hdr->frame_type       = (frame_type_t)(fcf & 0x07);
    hdr->security_enabled = (fcf >> 3) & 0x01;
    hdr->frame_pending    = (fcf >> 4) & 0x01;
    hdr->ack_request      = (fcf >> 5) & 0x01;
    hdr->pan_id_compress  = (fcf >> 6) & 0x01;
    hdr->dst_addr_mode    = (addr_mode_t)((fcf >> 10) & 0x03);
    hdr->src_addr_mode    = (addr_mode_t)((fcf >> 14) & 0x03);

    uint8_t pos = 2;  // past FCF

    // Sequence number (ACK frames may omit in 802.15.4e, but classic always has it)
    if (frame_len < pos + 1) return false;
    hdr->seq_num = frame[pos++];

    // Destination PAN ID + address
    if (hdr->dst_addr_mode != ADDR_NONE) {
        if (frame_len < pos + 2) return false;
        hdr->dst_pan_id = frame[pos] | (frame[pos + 1] << 8);
        pos += 2;

        uint8_t dst_len = addr_mode_len(hdr->dst_addr_mode);
        if (frame_len < pos + dst_len) return false;
        memcpy(hdr->dst_addr, frame + pos, dst_len);
        pos += dst_len;
    }

    // Source PAN ID + address
    if (hdr->src_addr_mode != ADDR_NONE) {
        if (!hdr->pan_id_compress) {
            if (frame_len < pos + 2) return false;
            hdr->src_pan_id = frame[pos] | (frame[pos + 1] << 8);
            pos += 2;
        } else {
            // PAN ID compression: src PAN == dst PAN
            hdr->src_pan_id = hdr->dst_pan_id;
        }

        uint8_t src_len = addr_mode_len(hdr->src_addr_mode);
        if (frame_len < pos + src_len) return false;
        memcpy(hdr->src_addr, frame + pos, src_len);
        pos += src_len;
    }

    hdr->header_len = pos;
    return true;
}

// ---------------------------------------------------------------------------
// Hex / address printing
// ---------------------------------------------------------------------------
static void print_hex(const uint8_t *data, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        if (data[i] < 0x10) Serial.print('0');
        Serial.print(data[i], HEX);
    }
}

static void print_addr(const uint8_t *addr, uint8_t len) {
    if (len == 2) {
        // Short address: print as 0xHHHH (little-endian in frame)
        Serial.printf("0x%02X%02X", addr[1], addr[0]);
    } else if (len == 8) {
        // EUI-64: print colon-separated, reversed to big-endian
        for (int i = 7; i >= 0; i--) {
            if (i < 7) Serial.print(':');
            if (addr[i] < 0x10) Serial.print('0');
            Serial.print(addr[i], HEX);
        }
    } else {
        Serial.print("none");
    }
}

// ---------------------------------------------------------------------------
// Address and PAN ID tracking
// ---------------------------------------------------------------------------
static void track_panid(uint16_t pan_id, uint32_t now) {
    if (pan_id == 0x0000 || pan_id == 0xFFFF) return;  // skip broadcast/unset

    for (uint8_t i = 0; i < g_panid_count; i++) {
        if (g_panids[i].pan_id == pan_id) {
            g_panids[i].frame_count++;
            g_panids[i].last_seen_ms = now;
            return;
        }
    }
    if (g_panid_count < MAX_TRACKED_PANIDS) {
        tracked_panid_t *p = &g_panids[g_panid_count++];
        p->pan_id = pan_id;
        p->frame_count = 1;
        p->first_seen_ms = now;
        p->last_seen_ms = now;
    }
}

static void track_address(const uint8_t *addr, uint8_t addr_len, uint16_t pan_id,
                           uint8_t channel, int8_t rssi, uint32_t now) {
    if (addr_len == 0) return;

    for (uint8_t i = 0; i < g_addr_count; i++) {
        if (g_addrs[i].addr_len == addr_len &&
            memcmp(g_addrs[i].addr, addr, addr_len) == 0) {
            // Update existing
            g_addrs[i].frame_count++;
            g_addrs[i].last_seen_ms = now;
            g_addrs[i].last_channel = channel;
            if (rssi > g_addrs[i].best_rssi) g_addrs[i].best_rssi = rssi;
            return;
        }
    }
    if (g_addr_count < MAX_TRACKED_ADDRS) {
        tracked_addr_t *a = &g_addrs[g_addr_count++];
        memcpy(a->addr, addr, addr_len);
        a->addr_len = addr_len;
        a->pan_id = pan_id;
        a->last_channel = channel;
        a->best_rssi = rssi;
        a->frame_count = 1;
        a->first_seen_ms = now;
        a->last_seen_ms = now;
    }
}

// ---------------------------------------------------------------------------
// Frame logging
// ---------------------------------------------------------------------------
static void log_frame(const queued_frame_t *qf) {
    mac_header_t hdr;
    bool parsed = parse_mac_header(qf->data, qf->len, &hdr);

    // Update stats
    g_total_frames++;
    if (qf->channel >= CHANNEL_MIN && qf->channel <= CHANNEL_MAX) {
        g_frames_per_channel[qf->channel - CHANNEL_MIN]++;
    }
    if (parsed) {
        g_frames_per_type[hdr.frame_type & 0x07]++;
    }

    // Timestamp and basic info
    uint32_t t = qf->timestamp_ms;
    Serial.printf("[%02lu:%02lu:%02lu.%03lu] CH:%d RSSI:%d ",
                  (t / 3600000) % 24, (t / 60000) % 60,
                  (t / 1000) % 60, t % 1000,
                  qf->channel, qf->rssi);

    if (!parsed) {
        Serial.printf("LEN:%d UNPARSEABLE RAW:", qf->len);
        print_hex(qf->data, qf->len);
        Serial.println();
        return;
    }

    // Frame type and sequence
    Serial.printf("%-6s SEQ:%3d ", frame_type_str(hdr.frame_type), hdr.seq_num);

    // PAN ID(s)
    if (hdr.dst_addr_mode != ADDR_NONE) {
        Serial.printf("PAN:0x%04X ", hdr.dst_pan_id);
    }

    // Destination address
    Serial.print("DST:");
    if (hdr.dst_addr_mode != ADDR_NONE) {
        print_addr(hdr.dst_addr, addr_mode_len(hdr.dst_addr_mode));
    } else {
        Serial.print("none");
    }

    // Source address
    Serial.print(" SRC:");
    if (hdr.src_addr_mode != ADDR_NONE) {
        print_addr(hdr.src_addr, addr_mode_len(hdr.src_addr_mode));
    } else {
        Serial.print("none");
    }

    // Payload hex (after MAC header)
    if (hdr.header_len < qf->len) {
        uint8_t payload_len = qf->len - hdr.header_len;
        Serial.printf(" [%dB] ", payload_len);
        print_hex(qf->data + hdr.header_len, payload_len);
    }

    Serial.println();

    // Track addresses and PAN IDs
    uint32_t now = qf->timestamp_ms;
    if (hdr.dst_addr_mode != ADDR_NONE) {
        track_panid(hdr.dst_pan_id, now);
        track_address(hdr.dst_addr, addr_mode_len(hdr.dst_addr_mode),
                      hdr.dst_pan_id, qf->channel, qf->rssi, now);
    }
    if (hdr.src_addr_mode != ADDR_NONE) {
        track_panid(hdr.src_pan_id, now);
        track_address(hdr.src_addr, addr_mode_len(hdr.src_addr_mode),
                      hdr.src_pan_id, qf->channel, qf->rssi, now);
    }
}

// ---------------------------------------------------------------------------
// Serial command handling
// ---------------------------------------------------------------------------
static void print_help(void) {
    Serial.println(F("\n=== 802.15.4 Sniffer Commands ==="));
    Serial.println(F("  c<N>  - Set channel (11-26), e.g. 'c15'"));
    Serial.println(F("  a     - Auto-hop all channels (2s each)"));
    Serial.println(F("  s     - Show statistics"));
    Serial.println(F("  r     - Reset statistics"));
    Serial.println(F("  m     - Place a mark/annotation in log"));
    Serial.println(F("  h     - Show this help"));
    Serial.println();
}

static void print_stats(void) {
    uint32_t uptime_s = (millis() - g_start_time_ms) / 1000;

    Serial.println(F("\n=== 802.15.4 Sniffer Statistics ==="));
    Serial.printf("Uptime: %lu:%02lu:%02lu\n",
                  uptime_s / 3600, (uptime_s / 60) % 60, uptime_s % 60);
    Serial.printf("Mode: %s  Current CH: %d\n",
                  g_auto_hop ? "AUTO-HOP" : "FIXED", g_current_channel);
    Serial.printf("Total frames: %lu  Dropped (queue full): %lu\n",
                  g_total_frames, g_dropped_frames);

    Serial.println(F("\n--- Frames by Type ---"));
    const char *type_names[] = {"Beacon", "Data", "Ack", "Command"};
    for (int i = 0; i < 4; i++) {
        if (g_frames_per_type[i] > 0) {
            Serial.printf("  %-8s: %lu\n", type_names[i], g_frames_per_type[i]);
        }
    }

    Serial.println(F("\n--- Frames by Channel ---"));
    for (int i = 0; i < NUM_CHANNELS; i++) {
        if (g_frames_per_channel[i] > 0) {
            Serial.printf("  CH %2d: %lu\n", CHANNEL_MIN + i, g_frames_per_channel[i]);
        }
    }

    if (g_panid_count > 0) {
        Serial.println(F("\n--- Unique PAN IDs ---"));
        for (uint8_t i = 0; i < g_panid_count; i++) {
            uint32_t age = (millis() - g_panids[i].first_seen_ms) / 1000;
            Serial.printf("  0x%04X  frames:%-5lu  age:%lus\n",
                          g_panids[i].pan_id, g_panids[i].frame_count, age);
        }
    }

    if (g_addr_count > 0) {
        Serial.println(F("\n--- Unique Addresses ---"));
        for (uint8_t i = 0; i < g_addr_count; i++) {
            Serial.print("  ");
            print_addr(g_addrs[i].addr, g_addrs[i].addr_len);
            Serial.printf("  PAN:0x%04X  CH:%d  RSSI:%d  frames:%-5lu\n",
                          g_addrs[i].pan_id, g_addrs[i].last_channel,
                          g_addrs[i].best_rssi, g_addrs[i].frame_count);
        }
    }
    Serial.println();
}

static void reset_stats(void) {
    g_total_frames = 0;
    g_dropped_frames = 0;
    memset(g_frames_per_channel, 0, sizeof(g_frames_per_channel));
    memset(g_frames_per_type, 0, sizeof(g_frames_per_type));
    g_addr_count = 0;
    g_panid_count = 0;
    g_start_time_ms = millis();
    Serial.println(F("--- Statistics reset ---"));
}

static void print_mark(void) {
    g_mark_counter++;
    uint32_t t = millis();
    Serial.printf("\n>>>>>> MARK #%lu at [%02lu:%02lu:%02lu.%03lu] CH:%d <<<<<<\n\n",
                  g_mark_counter,
                  (t / 3600000) % 24, (t / 60000) % 60,
                  (t / 1000) % 60, t % 1000,
                  g_current_channel);
}

static void handle_serial(void) {
    if (!Serial.available()) return;

    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() == 0) return;

    char cmd = input.charAt(0);

    switch (cmd) {
        case 'c':
        case 'C': {
            int ch = input.substring(1).toInt();
            if (ch >= CHANNEL_MIN && ch <= CHANNEL_MAX) {
                g_auto_hop = false;
                set_channel((uint8_t)ch);
                Serial.printf("Fixed on channel %d (auto-hop OFF)\n", ch);
            } else {
                Serial.printf("Invalid channel. Use %d-%d\n", CHANNEL_MIN, CHANNEL_MAX);
            }
            break;
        }
        case 'a':
        case 'A':
            g_auto_hop = true;
            g_last_hop_ms = millis();
            Serial.println(F("Auto-hop enabled (2s/channel, 32s sweep)"));
            break;
        case 's':
        case 'S':
            print_stats();
            break;
        case 'r':
        case 'R':
            reset_stats();
            break;
        case 'm':
        case 'M':
            print_mark();
            break;
        case 'h':
        case 'H':
        case '?':
            print_help();
            break;
        default:
            Serial.printf("Unknown command '%c'. Press 'h' for help.\n", cmd);
            break;
    }
}

// ---------------------------------------------------------------------------
// setup() / loop() - called from .ino
// ---------------------------------------------------------------------------
void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(1000);  // let serial settle

    Serial.println(F("\n========================================"));
    Serial.println(F("  802.15.4 Sniffer - ESP32-C6"));
    Serial.println(F("  Thread / Zigbee / 802.15.4 capture"));
    Serial.println(F("========================================"));
    Serial.printf("Channels: %d-%d  Hop interval: %d ms\n",
                  CHANNEL_MIN, CHANNEL_MAX, HOP_INTERVAL_MS);
    Serial.println(F("Default: auto-hop mode (32s full sweep)"));
    print_help();

    g_start_time_ms = millis();
    g_last_hop_ms = millis();

    init_802154();

    Serial.println(F("Listening...\n"));
}

void loop() {
    // Process queued frames
    while (!queue_empty()) {
        volatile queued_frame_t *slot = &g_frame_queue[g_queue_tail];

        // Copy out of volatile queue into local
        queued_frame_t local;
        memcpy(&local, (const void *)slot, sizeof(queued_frame_t));

        g_queue_tail = queue_next(g_queue_tail);

        log_frame(&local);
    }

    // Channel hopping
    if (g_auto_hop && (millis() - g_last_hop_ms >= HOP_INTERVAL_MS)) {
        g_last_hop_ms = millis();
        hop_channel();
    }

    // Serial commands
    handle_serial();

    // Small yield to avoid watchdog
    delay(1);
}
