/**
 * WPSplinter vulnerability detector (Broadcom WPS fingerprinting).
 *
 * Passive on-device port of the Broadcom WPS fingerprint logic from the
 * broadcom-wps research tool (WPSplinter). 802.11 beacons and probe
 * responses are inspected for:
 *   - the Broadcom proprietary vendor IE (OUI 00:10:18, type 0x02)
 *   - a WPS IE (OUI 00:50:F2, type 0x04) whose UUID-E/UUID-R attribute is
 *     the well-known fixed Broadcom WPS UUID (00 01 .. 0e bb)
 *   - WPS identity attributes left at Broadcom defaults (vendor/model/
 *     model_number/device_name), two or more of which fingerprint an
 *     unmodified Broadcom WPS implementation
 *
 * Based on the reference classification:
 *   - LIKELY_VULNERABLE         : WPS advertised and Broadcom fingerprints
 *                                 present (passive assessment; active
 *                                 confirmation is not performed on-device)
 *   - NO_BROADCOM_FINGERPRINT   : WPS advertised, no Broadcom fingerprints
 *   - INCONCLUSIVE              : WPS not advertised in observed frames
 *   - PATCHED_HOSTAPD           : only reachable with the active
 *                                 zero-fragment differential probe, which
 *                                 the passive detector does not perform
 *
 * The module follows the airspace monitor architecture: results are
 * collected by a promiscuous-mode callback, channel hopping is driven by
 * an esp_timer, and exports are written to the microSD scans directory.
 */

#ifndef WPSPLINTER_SCAN_H
#define WPSPLINTER_SCAN_H

#include "esp_err.h"
#include "esp_wifi_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WPSPLINTER_MAX_APS 24

/* Broadcom WPS fingerprint evidence flags (reference evidence names are
 * used verbatim in CSV/JSON exports). */
#define WPSPLINTER_EVIDENCE_BROADCOM_PROPRIETARY_IE 0x01u /* broadcom_proprietary_ie */
#define WPSPLINTER_EVIDENCE_BROADCOM_FIXED_WPS_UUID 0x02u /* broadcom_fixed_wps_uuid */
#define WPSPLINTER_EVIDENCE_WPS_IDENTITY_DEFAULTS   0x04u /* broadcom_wps_identity_defaults */

typedef enum {
    WPSPLINTER_ASSESSMENT_INCONCLUSIVE = 0,
    WPSPLINTER_ASSESSMENT_NO_BROADCOM_FINGERPRINT,
    WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE,
    WPSPLINTER_ASSESSMENT_PATCHED_HOSTAPD, /* reserved: active differential */
} wpsplinter_assessment_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t channel;
    int8_t rssi;
    bool wps_advertised;
    uint8_t evidence;
    wpsplinter_assessment_t assessment;
    /* WPS identity attributes observed in beacon/probe response IEs. */
    char vendor[24];
    char model[24];
    char model_number[16];
    char device_name[24];
    char serial_number[20];
    uint32_t beacons_seen;
    uint32_t probe_responses_seen;
    int64_t last_seen_ms;
} wpsplinter_ap_t;

typedef struct {
    bool active;
    int8_t current_channel;
    uint8_t channel_count;
    uint32_t hop_interval_ms;
    uint32_t frames_seen;
    uint32_t beacons_seen;
    uint32_t probe_responses_seen;
    uint16_t aps_seen;
    uint16_t aps_with_wps;
    uint16_t aps_likely_vulnerable;
} wpsplinter_snapshot_t;

/**
 * Start the passive detector.
 *
 * @param hop_interval_ms channel hop/dwell interval in milliseconds
 *                        (100..5000, reference default 450)
 * @param lock_channel    0 to hop across all monitor channels for the
 *                        active country, otherwise a single channel to
 *                        lock onto (valid monitor channel only)
 *
 * @return ESP_OK on success (also when already active), error otherwise.
 */
esp_err_t wpsplinter_scan_start(uint32_t hop_interval_ms, int8_t lock_channel);

/** Stop the detector and free its buffers. */
void wpsplinter_scan_stop(void);

/** Stop and clear all collected results. */
void wpsplinter_scan_reset(void);

/** True while the detector is running. */
bool wpsplinter_scan_is_active(void);

/**
 * Fill a snapshot of counters/state under the internal lock.
 * @return ESP_OK, or ESP_ERR_INVALID_STATE when not active.
 */
esp_err_t wpsplinter_scan_get_snapshot(wpsplinter_snapshot_t *out);

/**
 * Copy the collected APs into out (up to max entries), sorted by
 * assessment severity (most interesting first) and then strongest signal.
 * @return number of entries copied.
 */
uint16_t wpsplinter_scan_get_aps(wpsplinter_ap_t *out, uint16_t max);

/** Human readable assessment label (reference naming). */
const char *wpsplinter_assessment_label(wpsplinter_assessment_t a);

/**
 * Export collected APs to "<SD_DIR_SCANS>/wpsplinter_N.csv".
 * Uses the SD JIT mount pattern so it is safe regardless of the active
 * build profile.
 * @return ESP_OK on success, error otherwise (path stored in out_path).
 */
esp_err_t wpsplinter_scan_export_csv(char *out_path, size_t out_path_len);

/**
 * Export collected APs to "<SD_DIR_SCANS>/wpsplinter_N.json".
 * @return ESP_OK on success, error otherwise.
 */
esp_err_t wpsplinter_scan_export_json(char *out_path, size_t out_path_len);

/**
 * Promiscuous-mode results callback (MGMT frames). Registered via
 * wifi_manager_start_monitor_mode(); same contract as
 * wifi_airspace_monitor_callback.
 */
void wifi_wpsplinter_callback(void *buf, wifi_promiscuous_pkt_type_t type);

#endif /* WPSPLINTER_SCAN_H */