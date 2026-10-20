/*
 * WPSplinter vulnerability detector (Broadcom WPS fingerprinting).
 *
 * Passive on-device port of the Broadcom WPS fingerprint logic from the
 * broadcom-wps research tool. Beacons and probe responses are parsed for
 * the Broadcom proprietary vendor IE, the WPS IE, and Broadcom default
 * WPS identity attributes; APs are classified following the reference
 * scheme (see wpsplinter_scan.h).
 *
 * Architecture mirrors airspace_monitor.c: heap-backed tables guarded by
 * a portMUX, channel hopping driven by an esp_timer, and SD exports
 * using the manager's JIT mount pattern.
 */

#include "scans/wifi/wpsplinter_scan.h"

#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "managers/sd_card_manager.h"
#include "scans/wifi/hop_profile.h"
#include "scans/wifi/wifi_channels.h"
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "WPSplinter";

/* Reference dwell time (broadcom_fingerprint.py DEFAULT_DWELL 0.45s). */
#define WPSPLINTER_DEFAULT_HOP_MS 450U
#define WPSPLINTER_MIN_HOP_MS 100U
#define WPSPLINTER_MAX_HOP_MS 5000U

/* Fingerprint constants ported verbatim from the reference tool. */
static const uint8_t BROADCOM_IE_PREFIX[4] = {0x00, 0x10, 0x18, 0x02};
static const uint8_t WPS_IE_PREFIX[4] = {0x00, 0x50, 0xF2, 0x04};
static const uint8_t FIXED_WPS_UUID[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xBB};

/* WPS information attribute IDs (reference: _parse_wps_attributes). */
#define WPS_ATTR_DEVICE_NAME   0x1011
#define WPS_ATTR_VENDOR        0x1021
#define WPS_ATTR_MODEL         0x1023
#define WPS_ATTR_MODEL_NUMBER  0x1024
#define WPS_ATTR_SERIAL        0x1042
#define WPS_ATTR_UUID_E        0x1047
#define WPS_ATTR_UUID_R        0x1048

/* Frame geometry: 24-byte 802.11 header, then 12 bytes of fixed fields
 * (timestamp 8, interval 2, capability 2) => IEs start at byte 36. */
#define MGMT_IE_OFFSET 36

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static wpsplinter_ap_t *s_aps = NULL;
static uint8_t *s_channels = NULL;
static esp_timer_handle_t s_hop_timer = NULL;
static bool s_active = false;
static uint8_t s_channel_count = 0;
static uint8_t s_channel_idx = 0;
static int8_t s_current_channel = 1;
static uint32_t s_hop_interval_ms = WPSPLINTER_DEFAULT_HOP_MS;

static uint32_t s_frames_seen = 0;
static uint32_t s_beacons_seen = 0;
static uint32_t s_probe_responses_seen = 0;
static uint16_t s_aps_seen = 0;

static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static bool allocate_buffers(void) {
    if (s_aps != NULL && s_channels != NULL) {
        return true;
    }

    if (s_aps == NULL) {
        s_aps = heap_caps_calloc(WPSPLINTER_MAX_APS, sizeof(*s_aps),
                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_aps) {
            s_aps = heap_caps_calloc(WPSPLINTER_MAX_APS, sizeof(*s_aps),
                                     MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        }
    }
    if (s_channels == NULL) {
        s_channels = heap_caps_calloc(WIFI_CHANNELS_MAX, sizeof(*s_channels),
                                      MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_channels) {
            s_channels = heap_caps_calloc(WIFI_CHANNELS_MAX, sizeof(*s_channels),
                                          MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        }
    }

    if (s_aps == NULL || s_channels == NULL) {
        free(s_aps);
        free(s_channels);
        s_aps = NULL;
        s_channels = NULL;
        ESP_LOGE(TAG, "heap allocation failed");
        return false;
    }
    return true;
}

/* WPS text attributes are UTF-8; keep printable bytes and always
 * NUL-terminate (reference decodes with errors ignored). */
static void copy_wps_text(char *dst, size_t dst_len, const uint8_t *src, size_t len) {
    if (dst_len == 0) {
        return;
    }
    size_t n = len < (dst_len - 1) ? len : (dst_len - 1);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    dst[n] = '\0';
}

/* Case-insensitive ASCII compare (reference uses casefold comparisons). */
static bool ascii_case_equal(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* WPS identity attributes observed in a single frame. */
typedef struct {
    bool present;
    char vendor[24];
    char model[24];
    char model_number[16];
    char device_name[24];
    char serial_number[20];
} wps_identity_t;

/* Walk the WPS IE payload (TLV: 2-byte BE type, 2-byte BE length). Sets
 * the fixed Broadcom WPS UUID evidence when UUID-E/UUID-R matches the
 * reference constant. Mirrors _parse_wps_attributes. */
static void parse_wps_attributes(const uint8_t *data, size_t len, wps_identity_t *identity,
                                 bool *fixed_wps_uuid) {
    size_t offset = 0;
    while (offset + 4 <= len) {
        uint16_t kind = (uint16_t)((data[offset] << 8) | data[offset + 1]);
        uint16_t vlen = (uint16_t)((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
        if (vlen > len - offset) {
            break;
        }
        const uint8_t *value = data + offset;

        switch (kind) {
        case WPS_ATTR_DEVICE_NAME:
            copy_wps_text(identity->device_name, sizeof(identity->device_name), value, vlen);
            identity->present = true;
            break;
        case WPS_ATTR_VENDOR:
            copy_wps_text(identity->vendor, sizeof(identity->vendor), value, vlen);
            identity->present = true;
            break;
        case WPS_ATTR_MODEL:
            copy_wps_text(identity->model, sizeof(identity->model), value, vlen);
            identity->present = true;
            break;
        case WPS_ATTR_MODEL_NUMBER:
            copy_wps_text(identity->model_number, sizeof(identity->model_number), value, vlen);
            identity->present = true;
            break;
        case WPS_ATTR_SERIAL:
            copy_wps_text(identity->serial_number, sizeof(identity->serial_number), value, vlen);
            break;
        case WPS_ATTR_UUID_E:
        case WPS_ATTR_UUID_R:
            if (vlen == sizeof(FIXED_WPS_UUID) &&
                memcmp(value, FIXED_WPS_UUID, sizeof(FIXED_WPS_UUID)) == 0) {
                *fixed_wps_uuid = true;
            }
            break;
        default:
            break;
        }
        offset += vlen;
    }
}

/* Two or more Broadcom default identity characteristics fingerprint an
 * unmodified Broadcom WPS implementation (reference heuristic). */
static bool has_broadcom_identity_defaults(const wps_identity_t *id) {
    if (!id->present) {
        return false;
    }
    uint8_t matches = 0;
    if (ascii_case_equal(id->vendor, "broadcom")) {
        matches++;
    }
    if (ascii_case_equal(id->model, "broadcom") ||
        ascii_case_equal(id->model, "broadcomap")) {
        matches++;
    }
    if (ascii_case_equal(id->model_number, "1234") ||
        ascii_case_equal(id->model_number, "123456")) {
        matches++;
    }
    if (ascii_case_equal(id->device_name, "broadcomap")) {
        matches++;
    }
    return matches >= 2;
}

static bool is_zero_or_broadcast(const uint8_t mac[6]) {
    bool all_zero = true;
    bool all_ff = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) all_zero = false;
        if (mac[i] != 0xff) all_ff = false;
    }
    return all_zero || all_ff || ((mac[0] & 0x01) != 0);
}

/* Fill first-empty fields only, so the earliest observed value per
 * attribute is preserved across frames of the same AP. */
static void merge_identity_fields(wpsplinter_ap_t *ap, const wps_identity_t *id) {
    if (id->present) {
        if (ap->vendor[0] == '\0') strlcpy(ap->vendor, id->vendor, sizeof(ap->vendor));
        if (ap->model[0] == '\0') strlcpy(ap->model, id->model, sizeof(ap->model));
        if (ap->model_number[0] == '\0') strlcpy(ap->model_number, id->model_number, sizeof(ap->model_number));
        if (ap->device_name[0] == '\0') strlcpy(ap->device_name, id->device_name, sizeof(ap->device_name));
    }
    if (ap->serial_number[0] == '\0') {
        strlcpy(ap->serial_number, id->serial_number, sizeof(ap->serial_number));
    }
}

static wpsplinter_assessment_t assess_ap(bool wps_advertised, uint8_t evidence) {
    if (!wps_advertised) {
        return WPSPLINTER_ASSESSMENT_INCONCLUSIVE;
    }
    if (evidence != 0) {
        return WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE;
    }
    return WPSPLINTER_ASSESSMENT_NO_BROADCOM_FINGERPRINT;
}

/* Update the AP table for one observed beacon/probe response. Runs under
 * s_lock from the promiscuous callback. */
static void ap_track_locked(const uint8_t bssid[6], const uint8_t *ssid, uint8_t ssid_len,
                            int8_t channel, int8_t rssi, bool is_probe_response,
                            bool wps_advertised, uint8_t evidence,
                            const wps_identity_t *identity, uint32_t now) {
    if (s_aps == NULL) {
        return;
    }

    /* A slot is in use once any frame has been counted for it. */
    int slot = -1;
    int free_slot = -1;
    for (int i = 0; i < WPSPLINTER_MAX_APS; i++) {
        wpsplinter_ap_t *ap = &s_aps[i];
        if (ap->beacons_seen == 0 && ap->probe_responses_seen == 0) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        if (memcmp(ap->bssid, bssid, 6) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (free_slot < 0) {
            /* Table full: LRU eviction of the stalest entry. */
            int oldest = 0;
            int64_t oldest_seen = INT64_MAX;
            for (int i = 0; i < WPSPLINTER_MAX_APS; i++) {
                if (s_aps[i].last_seen_ms < oldest_seen) {
                    oldest_seen = s_aps[i].last_seen_ms;
                    oldest = i;
                }
            }
            slot = oldest;
        } else {
            slot = free_slot;
        }
        memset(&s_aps[slot], 0, sizeof(s_aps[slot]));
        memcpy(s_aps[slot].bssid, bssid, 6);
        s_aps_seen++;
    }

    wpsplinter_ap_t *ap = &s_aps[slot];
    ap->wps_advertised = ap->wps_advertised || wps_advertised;
    ap->evidence |= evidence;
    if (ssid_len > 0 && ap->ssid[0] == '\0') {
        size_t n = ssid_len < sizeof(ap->ssid) - 1 ? ssid_len : sizeof(ap->ssid) - 1;
        memcpy(ap->ssid, ssid, n);
        ap->ssid[n] = '\0';
    }
    if (channel > 0) {
        ap->channel = channel;
    }
    ap->rssi = rssi;
    if (is_probe_response) {
        ap->probe_responses_seen++;
    } else {
        ap->beacons_seen++;
    }
    ap->last_seen_ms = (int64_t)now;
    merge_identity_fields(ap, identity);
    ap->assessment = assess_ap(ap->wps_advertised, ap->evidence);
}

/* Parse one beacon/probe response. Walks the bounded IE TLV list (same
 * approach as airspace parse_mgmt_ssid: valid frames need not keep the
 * SSID-first order). */
static void process_frame_locked(const uint8_t *frame, int len, int8_t rx_channel,
                                 int8_t rssi, bool is_probe_response, uint32_t now) {
    if (len < MGMT_IE_OFFSET + 2) {
        return;
    }

    const uint8_t *bssid = frame + 16; /* Addr3 */
    if (is_zero_or_broadcast(bssid)) {
        bssid = frame + 10; /* Addr2: the transmitting AP */
        if (is_zero_or_broadcast(bssid)) {
            return;
        }
    }

    const uint8_t *ssid = NULL;
    uint8_t ssid_len = 0;
    int8_t channel = 0;
    bool wps_advertised = false;
    bool fixed_wps_uuid = false;
    bool broadcom_proprietary_ie = false;
    wps_identity_t identity = {0};

    int offset = MGMT_IE_OFFSET;
    while (offset + 2 <= len) {
        uint8_t id = frame[offset];
        uint8_t ie_len = frame[offset + 1];
        offset += 2;
        if (offset + ie_len > len) {
            break;
        }
        const uint8_t *ie = frame + offset;

        if (id == 0) { /* SSID */
            if (ie_len <= 32) {
                ssid = ie;
                ssid_len = ie_len;
            }
        } else if (id == 3) { /* DS Parameter Set */
            if (ie_len >= 1) {
                channel = (int8_t)ie[0];
            }
        } else if (id == 61) { /* HT Operation: primary channel */
            if (ie_len >= 1 && channel == 0) {
                channel = (int8_t)ie[0];
            }
        } else if (id == 221) { /* Vendor Specific */
            if (ie_len >= sizeof(BROADCOM_IE_PREFIX) &&
                memcmp(ie, BROADCOM_IE_PREFIX, sizeof(BROADCOM_IE_PREFIX)) == 0) {
                /* Broadcom proprietary IE (reference: contents length 9). */
                broadcom_proprietary_ie = true;
            } else if (ie_len >= sizeof(WPS_IE_PREFIX) + 1 &&
                       memcmp(ie, WPS_IE_PREFIX, sizeof(WPS_IE_PREFIX)) == 0) {
                /* WPS IE advertised; parse its attributes. */
                wps_advertised = true;
                parse_wps_attributes(ie + sizeof(WPS_IE_PREFIX),
                                     (size_t)ie_len - sizeof(WPS_IE_PREFIX),
                                     &identity, &fixed_wps_uuid);
            }
        }
        offset += ie_len;
    }

    uint8_t evidence = 0;
    if (broadcom_proprietary_ie) {
        evidence |= WPSPLINTER_EVIDENCE_BROADCOM_PROPRIETARY_IE;
    }
    if (fixed_wps_uuid) {
        evidence |= WPSPLINTER_EVIDENCE_BROADCOM_FIXED_WPS_UUID;
    }
    if (has_broadcom_identity_defaults(&identity)) {
        evidence |= WPSPLINTER_EVIDENCE_WPS_IDENTITY_DEFAULTS;
    }

    ap_track_locked(bssid, ssid, ssid_len, channel > 0 ? channel : rx_channel,
                    rssi, is_probe_response, wps_advertised, evidence, &identity, now);
}

void wifi_wpsplinter_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!s_active || !buf || s_aps == NULL || type == WIFI_PKT_MISC) {
        return;
    }

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 2) {
        return;
    }

    const uint8_t *frame = pkt->payload;
    uint8_t frame_type = (frame[0] & 0x0C) >> 2;
    uint8_t subtype = (frame[0] & 0xF0) >> 4;
    if (frame_type != 0) {
        return; /* management frames only */
    }
    if (subtype != 0x08 && subtype != 0x05) {
        return; /* beacons and probe responses only */
    }

    uint32_t now = now_ms();
    portENTER_CRITICAL(&s_lock);
    s_frames_seen++;
    if (subtype == 0x08) {
        s_beacons_seen++;
    } else {
        s_probe_responses_seen++;
    }
    process_frame_locked(frame, len, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi,
                         subtype == 0x05, now);
    portEXIT_CRITICAL(&s_lock);
}

static void build_channel_list(int8_t lock_channel) {
    if (s_channels == NULL) {
        s_channel_count = 0;
        return;
    }

    if (lock_channel > 0) {
        if (wifi_channels_is_monitor_channel(lock_channel) &&
            esp_wifi_set_channel((uint8_t)lock_channel, WIFI_SECOND_CHAN_NONE) == ESP_OK) {
            s_channels[0] = (uint8_t)lock_channel;
            s_channel_count = 1;
            s_channel_idx = 0;
            s_current_channel = lock_channel;
            return;
        }
        ESP_LOGW(TAG, "channel %d not available, falling back to hopping",
                 (int)lock_channel);
    }

    /* User hop profile takes priority; otherwise build the country list
     * (same resolution order as the airspace monitor). */
    uint8_t candidates[WIFI_CHANNELS_MAX] = {0};
    size_t profile_count = 0;
    hop_profile_resolve_monitor(candidates, WIFI_CHANNELS_MAX, &profile_count);
    uint8_t candidate_count;
    if (profile_count > 0) {
        candidate_count = (uint8_t)profile_count;
    } else {
        candidate_count = wifi_channels_build_country_list(candidates, WIFI_CHANNELS_MAX);
        if (candidate_count == 0) {
            candidates[0] = 1;
            candidate_count = 1;
        }
    }

    uint8_t accepted_count = 0;
    for (uint8_t i = 0; i < candidate_count && accepted_count < WIFI_CHANNELS_MAX; i++) {
        uint8_t ch = candidates[i];
        bool duplicate = false;
        for (uint8_t j = 0; j < accepted_count; j++) {
            if (s_channels[j] == ch) {
                duplicate = true;
                break;
            }
        }
        if (duplicate || !wifi_channels_is_monitor_channel(ch)) {
            continue;
        }
        if (esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE) == ESP_OK) {
            s_channels[accepted_count++] = ch;
        }
    }

    if (accepted_count == 0) {
        s_channels[0] = 1;
        accepted_count = 1;
        (void)esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    }

    s_channel_count = accepted_count;
    s_channel_idx = 0;
    s_current_channel = (int8_t)s_channels[0];
    ESP_LOGI(TAG, "channel plan: %u channels", (unsigned)accepted_count);
}

static void hop_timer_cb(void *arg) {
    (void)arg;

    if (s_channel_count <= 1) {
        return; /* locked to a single channel */
    }

    portENTER_CRITICAL(&s_lock);
    if (!s_active || s_channels == NULL || s_channel_count == 0) {
        portEXIT_CRITICAL(&s_lock);
        return;
    }
    s_channel_idx = (uint8_t)((s_channel_idx + 1) % s_channel_count);
    uint8_t channel = s_channels[s_channel_idx];
    portEXIT_CRITICAL(&s_lock);

    if (!wifi_channels_is_monitor_channel(channel)) {
        return;
    }

    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err == ESP_OK) {
        s_current_channel = (int8_t)channel;
    } else {
        ESP_LOGD(TAG, "hop to channel %u failed: %s", (unsigned)channel,
                 esp_err_to_name(err));
    }
}

static void reset_tables_locked(void) {
    if (s_aps != NULL) {
        memset(s_aps, 0, WPSPLINTER_MAX_APS * sizeof(*s_aps));
    }
    s_frames_seen = 0;
    s_beacons_seen = 0;
    s_probe_responses_seen = 0;
    s_aps_seen = 0;
    s_channel_idx = 0;
}

esp_err_t wpsplinter_scan_start(uint32_t hop_interval_ms, int8_t lock_channel) {
    if (s_active) {
        return ESP_OK;
    }

    if (hop_interval_ms != 0) {
        if (hop_interval_ms < WPSPLINTER_MIN_HOP_MS) {
            hop_interval_ms = WPSPLINTER_MIN_HOP_MS;
        }
        if (hop_interval_ms > WPSPLINTER_MAX_HOP_MS) {
            hop_interval_ms = WPSPLINTER_MAX_HOP_MS;
        }
        s_hop_interval_ms = hop_interval_ms;
    } else {
        s_hop_interval_ms = WPSPLINTER_DEFAULT_HOP_MS;
    }

    if (!allocate_buffers()) {
        return ESP_ERR_NO_MEM;
    }

    build_channel_list(lock_channel);

    portENTER_CRITICAL(&s_lock);
    reset_tables_locked();
    portEXIT_CRITICAL(&s_lock);

    s_active = true;
    (void)esp_wifi_set_channel((uint8_t)s_current_channel, WIFI_SECOND_CHAN_NONE);

    if (s_hop_timer == NULL) {
        const esp_timer_create_args_t args = {
            .callback = hop_timer_cb,
            .name = "wpsplinter_hop"
        };
        esp_err_t err = esp_timer_create(&args, &s_hop_timer);
        if (err != ESP_OK) {
            s_active = false;
            return err;
        }
    }

    esp_err_t err = esp_timer_start_periodic(s_hop_timer, s_hop_interval_ms * 1000ULL);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        s_active = false;
        return err;
    }

    ESP_LOGI(TAG, "started (%u channels, %ums hop)",
             (unsigned)s_channel_count, (unsigned)s_hop_interval_ms);
    return ESP_OK;
}

void wpsplinter_scan_stop(void) {
    s_active = false;
    if (s_hop_timer != NULL) {
        (void)esp_timer_stop(s_hop_timer);
        esp_timer_delete(s_hop_timer);
        s_hop_timer = NULL;
    }

    portENTER_CRITICAL(&s_lock);
    wpsplinter_ap_t *aps = s_aps;
    uint8_t *channels = s_channels;
    s_aps = NULL;
    s_channels = NULL;
    s_channel_count = 0;
    s_channel_idx = 0;
    portEXIT_CRITICAL(&s_lock);

    free(aps);
    free(channels);
    ESP_LOGI(TAG, "stopped");
}

void wpsplinter_scan_reset(void) {
    wpsplinter_scan_stop();
    portENTER_CRITICAL(&s_lock);
    reset_tables_locked(); /* counters only; tables were freed */
    portEXIT_CRITICAL(&s_lock);
}

bool wpsplinter_scan_is_active(void) {
    return s_active;
}

esp_err_t wpsplinter_scan_get_snapshot(wpsplinter_snapshot_t *out) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    portENTER_CRITICAL(&s_lock);
    bool active = s_active;
    out->active = active;
    out->current_channel = s_current_channel;
    out->channel_count = s_channel_count;
    out->hop_interval_ms = s_hop_interval_ms;
    out->frames_seen = s_frames_seen;
    out->beacons_seen = s_beacons_seen;
    out->probe_responses_seen = s_probe_responses_seen;
    if (s_aps != NULL) {
        uint16_t aps_seen = 0;
        uint16_t with_wps = 0;
        uint16_t vulnerable = 0;
        for (int i = 0; i < WPSPLINTER_MAX_APS; i++) {
            const wpsplinter_ap_t *ap = &s_aps[i];
            if (ap->beacons_seen == 0 && ap->probe_responses_seen == 0) {
                continue;
            }
            aps_seen++;
            if (ap->wps_advertised) {
                with_wps++;
            }
            if (ap->assessment == WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE) {
                vulnerable++;
            }
        }
        out->aps_seen = aps_seen;
        out->aps_with_wps = with_wps;
        out->aps_likely_vulnerable = vulnerable;
    }
    portEXIT_CRITICAL(&s_lock);

    return active ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static uint8_t assessment_rank(wpsplinter_assessment_t a) {
    switch (a) {
    case WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE:
        return 3;
    case WPSPLINTER_ASSESSMENT_PATCHED_HOSTAPD:
        return 2;
    case WPSPLINTER_ASSESSMENT_NO_BROADCOM_FINGERPRINT:
        return 1;
    default:
        return 0;
    }
}

uint16_t wpsplinter_scan_get_aps(wpsplinter_ap_t *out, uint16_t max) {
    if (out == NULL || max == 0) {
        return 0;
    }

    uint16_t count = 0;
    portENTER_CRITICAL(&s_lock);
    if (s_aps != NULL) {
        for (int i = 0; i < WPSPLINTER_MAX_APS && count < max; i++) {
            if (s_aps[i].beacons_seen != 0 || s_aps[i].probe_responses_seen != 0) {
                out[count++] = s_aps[i];
            }
        }
    }
    portEXIT_CRITICAL(&s_lock);

    /* Insertion sort: most severe assessment first, strongest signal
     * within the same severity. */
    for (uint16_t i = 1; i < count; i++) {
        wpsplinter_ap_t key = out[i];
        uint8_t key_rank = assessment_rank(key.assessment);
        int16_t j = (int16_t)i - 1;
        while (j >= 0) {
            uint8_t cur_rank = assessment_rank(out[j].assessment);
            bool swap = false;
            if (cur_rank < key_rank) {
                swap = true;
            } else if (cur_rank == key_rank && out[j].rssi < key.rssi) {
                swap = true;
            }
            if (!swap) {
                break;
            }
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = key;
    }
    return count;
}

const char *wpsplinter_assessment_label(wpsplinter_assessment_t a) {
    switch (a) {
    case WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE:
        return "LIKELY_VULNERABLE";
    case WPSPLINTER_ASSESSMENT_PATCHED_HOSTAPD:
        return "PATCHED_HOSTAPD";
    case WPSPLINTER_ASSESSMENT_NO_BROADCOM_FINGERPRINT:
        return "NO_BROADCOM_FINGERPRINT";
    default:
        return "INCONCLUSIVE";
    }
}

/* Comma-separated evidence names using the reference naming, or "none". */
static void evidence_string(uint8_t evidence, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (evidence & WPSPLINTER_EVIDENCE_BROADCOM_PROPRIETARY_IE) {
        strlcat(out, "broadcom_proprietary_ie", out_len);
    }
    if (evidence & WPSPLINTER_EVIDENCE_BROADCOM_FIXED_WPS_UUID) {
        if (out[0] != '\0') strlcat(out, ",", out_len);
        strlcat(out, "broadcom_fixed_wps_uuid", out_len);
    }
    if (evidence & WPSPLINTER_EVIDENCE_WPS_IDENTITY_DEFAULTS) {
        if (out[0] != '\0') strlcat(out, ",", out_len);
        strlcat(out, "broadcom_wps_identity_defaults", out_len);
    }
    if (out[0] == '\0') {
        strlcpy(out, "none", out_len);
    }
}

/* Sweep-style CSV field escaping. */
static void csv_write_escaped(FILE *f, const char *str) {
    bool needs_quote = false;
    for (const char *p = str; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n') {
            needs_quote = true;
            break;
        }
    }
    if (!needs_quote) {
        fputs(str, f);
        return;
    }
    fputc('"', f);
    for (const char *p = str; *p; p++) {
        if (*p == '"') {
            fputc('"', f);
        }
        fputc(*p, f);
    }
    fputc('"', f);
}

static int next_export_index(const char *ext) {
    char path[96];
    int next = 0;
    while (next < 9999) {
        snprintf(path, sizeof(path), SD_DIR_SCANS "/wpsplinter_%d.%s", next, ext);
        FILE *f = fopen(path, "r");
        if (!f) {
            break;
        }
        fclose(f);
        next++;
    }
    return next;
}

esp_err_t wpsplinter_scan_export_csv(char *out_path, size_t out_path_len) {
    if (out_path != NULL && out_path_len > 0) {
        out_path[0] = '\0';
    }

    wpsplinter_ap_t aps[WPSPLINTER_MAX_APS];
    uint16_t count = wpsplinter_scan_get_aps(aps, WPSPLINTER_MAX_APS);
    if (count == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    bool suspended = false;
    if (!sd_card_jit_begin(&suspended, true)) {
        return ESP_FAIL;
    }

    (void)sd_card_create_directory(SD_DIR_SCANS);
    int idx = next_export_index("csv");
    char path[96];
    snprintf(path, sizeof(path), SD_DIR_SCANS "/wpsplinter_%d.csv", idx);

    esp_err_t result = ESP_OK;
    FILE *f = fopen(path, "w");
    if (!f) {
        result = ESP_FAIL;
    } else {
        fputs("bssid,ssid,channel,rssi,wps_advertised,assessment,evidence,"
              "vendor,model,model_number,device_name,serial_number,"
              "beacons_seen,probe_responses_seen\n",
              f);
        for (uint16_t i = 0; i < count; i++) {
            const wpsplinter_ap_t *ap = &aps[i];
            char evidence[80];
            evidence_string(ap->evidence, evidence, sizeof(evidence));

            fprintf(f, "%02X:%02X:%02X:%02X:%02X:%02X,",
                    ap->bssid[0], ap->bssid[1], ap->bssid[2],
                    ap->bssid[3], ap->bssid[4], ap->bssid[5]);
            csv_write_escaped(f, ap->ssid[0] ? ap->ssid : "<hidden>");
            fprintf(f, ",%d,%d,%s,%s,",
                    ap->channel, ap->rssi,
                    ap->wps_advertised ? "true" : "false",
                    wpsplinter_assessment_label(ap->assessment));
            csv_write_escaped(f, evidence);
            fputc(',', f);
            csv_write_escaped(f, ap->vendor);
            fputc(',', f);
            csv_write_escaped(f, ap->model);
            fputc(',', f);
            csv_write_escaped(f, ap->model_number);
            fputc(',', f);
            csv_write_escaped(f, ap->device_name);
            fputc(',', f);
            csv_write_escaped(f, ap->serial_number);
            fprintf(f, ",%u,%u\n",
                    (unsigned)ap->beacons_seen,
                    (unsigned)ap->probe_responses_seen);
        }
        fclose(f);
    }
    sd_card_jit_end(suspended);

    if (result == ESP_OK) {
        ESP_LOGI(TAG, "exported %u APs to %s", (unsigned)count, path);
        if (out_path != NULL && out_path_len > 0) {
            snprintf(out_path, out_path_len, "%s", path);
        }
    }
    return result;
}

esp_err_t wpsplinter_scan_export_json(char *out_path, size_t out_path_len) {
    if (out_path != NULL && out_path_len > 0) {
        out_path[0] = '\0';
    }

    wpsplinter_ap_t aps[WPSPLINTER_MAX_APS];
    uint16_t count = wpsplinter_scan_get_aps(aps, WPSPLINTER_MAX_APS);
    if (count == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    char timestamp[24] = {0};
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info && tm_info->tm_year >= 120) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *ap_array = cJSON_CreateArray();
    if (root == NULL || ap_array == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(ap_array);
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "module", "wpsplinter");
    cJSON_AddNumberToObject(root, "schema", 1);
    cJSON_AddBoolToObject(root, "passive", true);
    if (timestamp[0] != '\0') {
        cJSON_AddStringToObject(root, "timestamp", timestamp);
    }
    cJSON_AddItemToObject(root, "aps", ap_array);

    for (uint16_t i = 0; i < count; i++) {
        const wpsplinter_ap_t *ap = &aps[i];
        cJSON *obj = cJSON_CreateObject();
        if (obj == NULL) {
            continue;
        }
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        cJSON_AddStringToObject(obj, "bssid", mac);
        cJSON_AddStringToObject(obj, "ssid", ap->ssid[0] ? ap->ssid : "<hidden>");
        cJSON_AddNumberToObject(obj, "channel", ap->channel);
        cJSON_AddNumberToObject(obj, "rssi", ap->rssi);
        cJSON_AddBoolToObject(obj, "wps_advertised", ap->wps_advertised);
        cJSON_AddStringToObject(obj, "assessment",
                                wpsplinter_assessment_label(ap->assessment));

        /* Evidence list using the reference evidence names. */
        cJSON *ev_list = cJSON_CreateArray();
        if (ev_list != NULL) {
            if (ap->evidence & WPSPLINTER_EVIDENCE_BROADCOM_PROPRIETARY_IE) {
                cJSON_AddItemToArray(ev_list, cJSON_CreateString("broadcom_proprietary_ie"));
            }
            if (ap->evidence & WPSPLINTER_EVIDENCE_BROADCOM_FIXED_WPS_UUID) {
                cJSON_AddItemToArray(ev_list, cJSON_CreateString("broadcom_fixed_wps_uuid"));
            }
            if (ap->evidence & WPSPLINTER_EVIDENCE_WPS_IDENTITY_DEFAULTS) {
                cJSON_AddItemToArray(ev_list, cJSON_CreateString("broadcom_wps_identity_defaults"));
            }
            cJSON_AddItemToObject(obj, "evidence", ev_list);
        }

        cJSON_AddStringToObject(obj, "vendor", ap->vendor);
        cJSON_AddStringToObject(obj, "model", ap->model);
        cJSON_AddStringToObject(obj, "model_number", ap->model_number);
        cJSON_AddStringToObject(obj, "device_name", ap->device_name);
        cJSON_AddStringToObject(obj, "serial_number", ap->serial_number);
        cJSON_AddNumberToObject(obj, "beacons_seen", ap->beacons_seen);
        cJSON_AddNumberToObject(obj, "probe_responses_seen", ap->probe_responses_seen);
        cJSON_AddItemToArray(ap_array, obj);
    }

    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    if (json == NULL) {
        return ESP_ERR_NO_MEM;
    }

    bool suspended = false;
    esp_err_t result = ESP_OK;
    if (!sd_card_jit_begin(&suspended, true)) {
        cJSON_free(json);
        return ESP_FAIL;
    }

    (void)sd_card_create_directory(SD_DIR_SCANS);
    int idx = next_export_index("json");
    char path[96];
    snprintf(path, sizeof(path), SD_DIR_SCANS "/wpsplinter_%d.json", idx);

    FILE *f = fopen(path, "w");
    if (!f) {
        result = ESP_FAIL;
    } else {
        size_t len = strlen(json);
        size_t wrote = fwrite(json, 1, len, f);
        fputc('\n', f);
        fclose(f);
        if (wrote != len) {
            result = ESP_FAIL;
        }
    }
    sd_card_jit_end(suspended);
    cJSON_free(json);

    if (result == ESP_OK) {
        ESP_LOGI(TAG, "exported %u APs to %s", (unsigned)count, path);
        if (out_path != NULL && out_path_len > 0) {
            snprintf(out_path, out_path_len, "%s", path);
        }
    }
    return result;
}






