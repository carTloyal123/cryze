"""GUTES protocol constants — frame types, header size, and type name map."""

# Frame type codes (from giot_on_rcvpkt dispatch table)
TYPE_DETECT_REQ = 0x01
TYPE_DETECT_RESP = 0x02
TYPE_CERTIFY_REQ = 0x0C
TYPE_CERTIFY_RESP = 0x0D
TYPE_LIST_REQ = 0x15
TYPE_LIST_RESP = 0x16
TYPE_KEEPALIVE = 0x17
TYPE_SUBSCRIBE = 0xA0
TYPE_SUBSCRIBE_RESP = 0xA1
TYPE_MTP_RES_RESPONSE = 0xA2
TYPE_CALLING_REQ = 0xA4
TYPE_INIT_INFO_MSG = 0xA6
TYPE_GDM_PUSH = 0xA7
TYPE_CALLING_ERR = 0xAA
TYPE_MTP_RES_RESP_A3 = 0xA3  # MTP resource response (relay server list)
TYPE_SESSION_CTL = 0xB0
TYPE_SESSION_CTL_RESP = 0xB1
TYPE_ONLINE_MSG = 0xB4
TYPE_WAKEUP = 0xBB  # WakeUp frame — sent by Mars to wake sleeping devices
TYPE_PASSTHROUGH = 0xBD
TYPE_MTP_DATA = 0xCA  # MTP media data over TCP relay

# Human-readable frame type names
FRAME_TYPES = {
    0x01: "DETECT_REQ", 0x02: "DETECT_RESP",
    0x0C: "CERTIFY", 0x0D: "CERTIFY_RESP",
    0x15: "LIST_REQ", 0x16: "LIST_RESP",
    0x17: "KEEPALIVE",
    0xA0: "SUBSCRIBE", 0xA1: "SUBSCRIBE_RESP",
    0xA2: "MTP_RES_RESP", 0xA3: "MTP_RES_RESP_A3",
    0xA4: "CALLING_REQ",
    0xBB: "WAKEUP",
    0xA6: "INIT_INFO", 0xA7: "GDM_PUSH",
    0xAA: "CALLING_ERR/GDM", 0xB0: "SESSION_CTL",
    0xB1: "SESSION_CTL_RESP", 0xB4: "ONLINE_MSG",
    0xBD: "PASSTHROUGH", 0xCA: "MTP_DATA",
}

# Header size in bytes (0x1C = 28)
HEADER_SIZE = 0x1C
