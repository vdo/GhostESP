// cmd_wpsplinter.c
// WPSplinter (Broadcom WPS fingerprint) vulnerability detector commands.
//
// Passive scan of beacons/probe responses for Broadcom WPS fingerprints
// (port of the broadcom-wps research tool logic; see wpsplinter_scan.c).

#include "core/commands.h"
#include "core/glog.h"
#include "managers/status_display_manager.h"
#include "managers/wifi_manager.h"
#include "scans/wifi/wpsplinter_scan.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WPSPLINTER_TIMED_MIN_SECONDS 5
#define WPSPLINTER_TIMED_MAX_SECONDS 600

static bool s_timed_task_running = false;
static struct {
    int seconds;
    char fmt[8]; /* "", "csv" or "json": auto-export at timed end */
} s_timed_cfg = {0, ""};

static void print_usage(void) {
    glog("WPSplinter: passive Broadcom WPS vulnerability detector\n\n");
    glog("Usage: wpsplinter [options]\n");
    glog("       wpsplinter stop\n");
    glog("       wpsplinter list\n");
    glog("       wpsplinter export [csv|json]\n\n");
    glog("Options:\n");
    glog("    (none)        start continuous scan, hopping all channels\n");
    glog("    -c <channel>  lock onto a single channel\n");
    glog("    -d <ms>       channel dwell/hop interval (100-5000, default 450)\n");
    glog("    -t <seconds>  timed scan, stops and summarizes when done (5-600)\n");
    glog("    -e <format>   auto-export at end of timed scan: csv or json\n\n");
}

static void print_ap(const wpsplinter_ap_t *ap) {
    char evidence[80];
    const char *label = wpsplinter_assessment_label(ap->assessment);
    evidence[0] = '\0';
    if (ap->evidence & WPSPLINTER_EVIDENCE_BROADCOM_PROPRIETARY_IE) {
        strlcat(evidence, "broadcom_proprietary_ie", sizeof(evidence));
    }
    if (ap->evidence & WPSPLINTER_EVIDENCE_BROADCOM_FIXED_WPS_UUID) {
        if (evidence[0]) strlcat(evidence, ",", sizeof(evidence));
        strlcat(evidence, "broadcom_fixed_wps_uuid", sizeof(evidence));
    }
    if (ap->evidence & WPSPLINTER_EVIDENCE_WPS_IDENTITY_DEFAULTS) {
        if (evidence[0]) strlcat(evidence, ",", sizeof(evidence));
        strlcat(evidence, "broadcom_wps_identity_defaults", sizeof(evidence));
    }
    if (!evidence[0]) {
        strlcpy(evidence, "none", sizeof(evidence));
    }

    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);

    glog("%s  ch%-3d %4d dBm  WPS:%-3s  %s\n", bssid, ap->channel, ap->rssi,
         ap->wps_advertised ? "yes" : "no", label);
    glog("    SSID: %s | evidence: %s\n",
         ap->ssid[0] ? ap->ssid : "<hidden>", evidence);
    if (ap->vendor[0] || ap->model[0] || ap->model_number[0] || ap->device_name[0]) {
        glog("    %s / %s / %s / %s\n",
             ap->vendor[0] ? ap->vendor : "?",
             ap->model[0] ? ap->model : "?",
             ap->model_number[0] ? ap->model_number : "?",
             ap->device_name[0] ? ap->device_name : "?");
    }
}

static void print_summary(void) {
    wpsplinter_snapshot_t snap;
    wpsplinter_scan_get_snapshot(&snap);
    glog("--- WPSplinter summary ---\n");
    glog("APs seen: %u | WPS advertised: %u | likely vulnerable: %u\n",
         (unsigned)snap.aps_seen, (unsigned)snap.aps_with_wps,
         (unsigned)snap.aps_likely_vulnerable);

    wpsplinter_ap_t aps[WPSPLINTER_MAX_APS];
    uint16_t count = wpsplinter_scan_get_aps(aps, WPSPLINTER_MAX_APS);
    for (uint16_t i = 0; i < count; i++) {
        if (aps[i].assessment == WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE) {
            print_ap(&aps[i]);
        }
    }
}

static void print_list(void) {
    wpsplinter_snapshot_t snap;
    wpsplinter_scan_get_snapshot(&snap);
    glog("WPSplinter results (%u APs, %u with WPS, %u likely vulnerable)\n\n",
         (unsigned)snap.aps_seen, (unsigned)snap.aps_with_wps,
         (unsigned)snap.aps_likely_vulnerable);

    wpsplinter_ap_t aps[WPSPLINTER_MAX_APS];
    uint16_t count = wpsplinter_scan_get_aps(aps, WPSPLINTER_MAX_APS);
    if (count == 0) {
        glog("No APs collected yet.\n");
        return;
    }
    for (uint16_t i = 0; i < count; i++) {
        print_ap(&aps[i]);
    }
}

static void run_export(const char *fmt) {
    char path[96];
    if (strcmp(fmt, "json") == 0) {
        esp_err_t err = wpsplinter_scan_export_json(path, sizeof(path));
        if (err == ESP_OK) {
            glog("Exported JSON results to %s\n", path);
            status_display_show_status("WPSplinter Exp");
        } else {
            glog("JSON export failed: %s\n", esp_err_to_name(err));
            status_display_show_status("Export Fail");
        }
        return;
    }
    esp_err_t err = wpsplinter_scan_export_csv(path, sizeof(path));
    if (err == ESP_OK) {
        glog("Exported CSV results to %s\n", path);
        status_display_show_status("WPSplinter Exp");
    } else {
        glog("CSV export failed: %s\n", esp_err_to_name(err));
        status_display_show_status("Export Fail");
    }
}

/* Timed scan worker: reports newly classified likely-vulnerable APs,
 * then stops the scan, summarizes and optionally auto-exports. */
static void wpsplinter_timed_task(void *arg) {
    (void)arg;
    int seconds = s_timed_cfg.seconds;
    uint8_t reported[WPSPLINTER_MAX_APS][6];
    memset(reported, 0, sizeof(reported));

    for (int elapsed = 0; elapsed < seconds; elapsed++) {
        if (!wpsplinter_scan_is_active()) {
            s_timed_task_running = false;
            vTaskDelete(NULL);
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));

        wpsplinter_ap_t aps[WPSPLINTER_MAX_APS];
        uint16_t count = wpsplinter_scan_get_aps(aps, WPSPLINTER_MAX_APS);
        for (uint16_t i = 0; i < count; i++) {
            if (aps[i].assessment != WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE) {
                continue;
            }
            bool already = false;
            for (uint16_t j = 0; j < WPSPLINTER_MAX_APS; j++) {
                if (memcmp(reported[j], aps[i].bssid, 6) == 0) {
                    already = true;
                    break;
                }
            }
            if (already) {
                continue;
            }
            for (uint16_t j = 0; j < WPSPLINTER_MAX_APS; j++) {
                bool empty = true;
                for (int b = 0; b < 6; b++) {
                    if (reported[j][b] != 0) {
                        empty = false;
                        break;
                    }
                }
                if (empty) {
                    memcpy(reported[j], aps[i].bssid, 6);
                    break;
                }
            }
            glog("[WPSplinter] Likely vulnerable AP detected:\n");
            print_ap(&aps[i]);
        }
    }

    if (wpsplinter_scan_is_active()) {
        wifi_manager_stop_monitor_mode(); /* also stops the detector */
        print_summary();
        if (s_timed_cfg.fmt[0] != '\0') {
            run_export(s_timed_cfg.fmt);
        }
    }
    s_timed_task_running = false;
    vTaskDelete(NULL);
}

void handle_wpsplinter_cmd(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        if (!wpsplinter_scan_is_active()) {
            glog("WPSplinter scan is not running.\n");
            status_display_show_status("WPSplinter Off");
            return;
        }
        glog("Stopping WPSplinter scan...\n");
        wifi_manager_stop_monitor_mode(); /* also stops the detector */
        print_summary();
        status_display_show_status("WPSplinter Stop");
        return;
    }

    if (argc > 1 && strcmp(argv[1], "list") == 0) {
        print_list();
        return;
    }

    if (argc > 1 && strcmp(argv[1], "export") == 0) {
        const char *fmt = (argc > 2) ? argv[2] : "csv";
        if (strcmp(fmt, "csv") != 0 && strcmp(fmt, "json") != 0) {
            glog("Usage: wpsplinter export [csv|json]\n");
            return;
        }
        run_export(fmt);
        return;
    }

    if (argc > 1 && argv[1][0] != '-') {
        print_usage();
        return;
    }

    int8_t lock_channel = 0;
    uint32_t dwell_ms = 0;
    int seconds = 0;
    const char *export_fmt = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            int channel = atoi(argv[++i]);
            if (channel < 1 || channel > 200) {
                glog("Invalid channel. Usage: wpsplinter -c <channel>\n");
                return;
            }
            lock_channel = (int8_t)channel;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            dwell_ms = (uint32_t)atoi(argv[++i]);
            if (dwell_ms < 100 || dwell_ms > 5000) {
                glog("Invalid dwell time (100-5000 ms).\n");
                return;
            }
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
            if (seconds < WPSPLINTER_TIMED_MIN_SECONDS ||
                seconds > WPSPLINTER_TIMED_MAX_SECONDS) {
                glog("Invalid duration (5-600 seconds).\n");
                return;
            }
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            export_fmt = argv[++i];
            if (strcmp(export_fmt, "csv") != 0 && strcmp(export_fmt, "json") != 0) {
                glog("Invalid export format. Use: -e csv or -e json\n");
                return;
            }
        } else {
            print_usage();
            return;
        }
    }

    if (wpsplinter_scan_is_active()) {
        glog("WPSplinter scan already running. Use 'wpsplinter stop' first.\n");
        return;
    }

    glog("Starting WPSplinter passive Broadcom WPS scan...\n");
    status_display_show_status("WPSplinter Start");

    wifi_manager_start_monitor_mode(wifi_wpsplinter_callback);
    esp_err_t err = wpsplinter_scan_start(dwell_ms, lock_channel);
    if (err != ESP_OK) {
        glog("Failed to start WPSplinter scan: %s\n", esp_err_to_name(err));
        wifi_manager_stop_monitor_mode();
        status_display_show_status("WPSplinter Err");
        return;
    }

    if (lock_channel > 0) {
        glog("Locked to channel %d%s...\n", (int)lock_channel,
             seconds > 0 ? " (timed)" : "");
    } else {
        glog("Hopping all channels%s...\n", seconds > 0 ? " (timed)" : "");
    }

    if (seconds > 0) {
        if (export_fmt != NULL) {
            strlcpy(s_timed_cfg.fmt, export_fmt, sizeof(s_timed_cfg.fmt));
        } else {
            s_timed_cfg.fmt[0] = '\0';
        }
        s_timed_cfg.seconds = seconds;

        if (s_timed_task_running) {
            glog("A timed scan task is already running.\n");
            return;
        }
        s_timed_task_running = true;
        if (xTaskCreate(wpsplinter_timed_task, "wpsplinter_cli", 8192, NULL,
                        tskIDLE_PRIORITY + 2, NULL) != pdPASS) {
            s_timed_task_running = false;
            glog("Failed to create timed scan task; running continuous.\n");
            return;
        }
        glog("Timed scan: %d seconds%s%s\n", seconds,
             s_timed_cfg.fmt[0] ? ", auto-export " : "",
             s_timed_cfg.fmt[0] ? s_timed_cfg.fmt : "");
    } else {
        glog("Use 'wpsplinter list' to view results, 'wpsplinter stop' to stop.\n");
    }
}


