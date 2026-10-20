#include "managers/views/wpsplinter_screen.h"
#include "core/callbacks.h"
#include "core/utils.h"
#include "gui/accessibility_fonts.h"
#include "gui/lvgl_safe.h"
#include "gui/screen_layout.h"
#include "gui/theme_palette_api.h"
#include "managers/display_manager.h"
#include "managers/settings_manager.h"
#include "managers/views/main_menu_screen.h"
#include "managers/wifi_manager.h"
#include "scans/wifi/wpsplinter_scan.h"
#include "lvgl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WPSPLINTER_GUI_SLOTS 6

static lv_obj_t *root_container = NULL;
static lv_timer_t *update_timer = NULL;
static lv_obj_t *lbl_channel = NULL;
static lv_obj_t *lbl_counts = NULL;
static lv_obj_t *ap_cards[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap_mac[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap_assess[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap_evidence[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap_detail[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *content_scroller = NULL;

static uint32_t accent_color = 0x00FFFF;
static uint32_t bg_color = 0x0A0A0A;
static uint32_t card_color = 0x1A1A1A;
static uint32_t text_color = 0xFFFFFF;
static uint32_t dim_color = 0x888888;
static uint32_t warn_color = 0xFFAA00;
static uint32_t error_color = 0xFF4444;
static uint32_t good_color = 0x00FF00;

static bool touch_active = false;
static bool touch_moved = false;
static int16_t touch_last_y = 0;
static touch_drag_t s_touch_drag = {0};

static bool compact_layout(void) {
    return LV_VER_RES <= 320;
}

static bool tiny_layout(void) {
    return LV_VER_RES <= 160;
}

/* Project-wide accessibility tiers: they scale with the Settings font-size
 * selection the same way every other view does, instead of pinning an 8px
 * body font on short displays. */
static const lv_font_t *body_font(void) {
    return accessibility_get_font_body();
}

static const lv_font_t *title_font(void) {
    return accessibility_get_font_title();
}

static lv_obj_t *create_card(lv_obj_t *parent, int width_pct) {
    lv_obj_t *card = lv_obj_create(parent);
    int padding = tiny_layout() ? 2 : (compact_layout() ? 4 : 8);
    lv_obj_set_size(card, LV_PCT(width_pct), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(card, lv_color_hex(card_color), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(card, lv_color_hex(accent_color), 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_border_side(card, LV_BORDER_SIDE_LEFT, 0);
    lv_obj_set_style_radius(card, 0, 0);
    lv_obj_set_style_pad_all(card, padding, 0);
    lv_obj_set_style_text_color(card, lv_color_hex(text_color), 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(card, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(card, tiny_layout() ? 0 : (compact_layout() ? 1 : 2), 0);
    return card;
}

static lv_obj_t *create_card_title(lv_obj_t *card, const char *text) {
    lv_obj_t *label = lv_label_create(card);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, body_font(), 0);
    lv_obj_set_style_text_color(label, lv_color_hex(dim_color), 0);
    return label;
}

static void format_mac(const uint8_t mac[6], char *out, size_t out_size) {
    snprintf(out, out_size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    privacy_redact_mac(out);  /* display only */
}

static uint32_t color_for_assessment(wpsplinter_assessment_t a) {
    switch (a) {
        case WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE: return error_color;
        case WPSPLINTER_ASSESSMENT_PATCHED_HOSTAPD: return good_color;
        case WPSPLINTER_ASSESSMENT_NO_BROADCOM_FINGERPRINT:
        default: return text_color;
    }
}

/* Human-readable matched fingerprints, so each flagged AP can be confirmed
 * on-screen: only the criteria that actually matched are listed. */
static void build_evidence(uint8_t evidence, char *out, size_t out_size) {
    out[0] = '\0';
    if (evidence & WPSPLINTER_EVIDENCE_BROADCOM_PROPRIETARY_IE) {
        strlcat(out, "Broadcom proprietary IE", out_size);
    }
    if (evidence & WPSPLINTER_EVIDENCE_BROADCOM_FIXED_WPS_UUID) {
        if (out[0]) strlcat(out, " + ", out_size);
        strlcat(out, "fixed Broadcom WPS UUID", out_size);
    }
    if (evidence & WPSPLINTER_EVIDENCE_WPS_IDENTITY_DEFAULTS) {
        if (out[0]) strlcat(out, " + ", out_size);
        strlcat(out, "identity at Broadcom defaults (2+)", out_size);
    }
    if (!out[0]) {
        strlcpy(out, "no Broadcom fingerprints", out_size);
    }
}

static void append_field(char *out, size_t out_size, const char *key, const char *val) {
    if (!val[0]) {
        return;
    }
    if (out[0]) {
        strlcat(out, "  ", out_size);
    }
    strlcat(out, key, out_size);
    strlcat(out, val, out_size);
}

/* WPS identity attributes observed in the wild, so a flagged AP can be
 * confirmed against the raw beacon/probe-response values. */
static void build_identity(const wpsplinter_ap_t *ap, char *out, size_t out_size) {
    out[0] = '\0';
    append_field(out, out_size, "V:", ap->vendor);
    append_field(out, out_size, "M:", ap->model);
    append_field(out, out_size, "#:", ap->model_number);
    append_field(out, out_size, "DN:", ap->device_name);
    append_field(out, out_size, "S:", ap->serial_number);
}

static void scroll_wpsplinter(int dir) {
    if (!content_scroller) return;
    lv_coord_t step = lv_obj_get_height(content_scroller) / 2;
    if (step < 24) step = 24;
    lv_obj_scroll_by_bounded(content_scroller, 0, dir > 0 ? -step : step, LV_ANIM_OFF);
}

static void update_display_cb(lv_timer_t *timer) {
    (void)timer;

    wpsplinter_snapshot_t snap = {0};
    wpsplinter_scan_get_snapshot(&snap);

    if (lbl_channel) {
        const char *band = snap.current_channel > 14 ? "5G" : "2G";
        lv_label_set_text_fmt(lbl_channel, "Ch %u %s  plan %u  dwell %lums",
                              (unsigned)snap.current_channel,
                              band,
                              (unsigned)snap.channel_count,
                              (unsigned long)snap.hop_interval_ms);
    }
    if (lbl_counts) {
        lv_label_set_text_fmt(lbl_counts, "APs %u  WPS %u  likely vuln %u",
                              (unsigned)snap.aps_seen,
                              (unsigned)snap.aps_with_wps,
                              (unsigned)snap.aps_likely_vulnerable);
        lv_obj_set_style_text_color(lbl_counts,
                                    lv_color_hex(snap.aps_likely_vulnerable > 0 ? warn_color : text_color),
                                    0);
    }

    /* Top APs are severity-then-RSSI sorted; only render the leading slots
     * (bounded stack use in the LVGL timer task). */
    wpsplinter_ap_t aps[WPSPLINTER_GUI_SLOTS];
    uint16_t count = wpsplinter_scan_get_aps(aps, WPSPLINTER_GUI_SLOTS);

    for (uint8_t i = 0; i < WPSPLINTER_GUI_SLOTS; i++) {
        if (!ap_cards[i]) continue;

        if (i >= count) {
            if (i == 0 && count == 0) {
                lv_obj_clear_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
                if (lbl_ap[i]) lv_label_set_text(lbl_ap[i], "Scanning for WPS APs");
                if (lbl_ap_mac[i]) lv_label_set_text(lbl_ap_mac[i], "");
                if (lbl_ap_assess[i]) lv_label_set_text(lbl_ap_assess[i], "");
                if (lbl_ap_evidence[i]) lv_label_set_text(lbl_ap_evidence[i], "");
                if (lbl_ap_detail[i]) lv_label_set_text(lbl_ap_detail[i], "Passive channel hopping");
            } else {
                lv_obj_add_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
            }
            continue;
        }

        const wpsplinter_ap_t *ap = &aps[i];
        char mac[18] = {0};
        char evidence[96];
        char identity[128];
        format_mac(ap->bssid, mac, sizeof(mac));
        build_evidence(ap->evidence, evidence, sizeof(evidence));
        build_identity(ap, identity, sizeof(identity));

        lv_obj_clear_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
        if (lbl_ap[i]) {
            lv_label_set_text_fmt(lbl_ap[i], "#%u %s",
                                  (unsigned)(i + 1),
                                  ap->ssid[0] ? ap->ssid : "<hidden>");
            lv_obj_set_style_text_color(lbl_ap[i],
                                        lv_color_hex(color_for_assessment(ap->assessment)),
                                        0);
        }
        if (lbl_ap_mac[i]) {
            lv_label_set_text_fmt(lbl_ap_mac[i], "%s  ch%u  %ddBm  b:%lu p:%lu",
                                  mac,
                                  (unsigned)ap->channel,
                                  (int)ap->rssi,
                                  (unsigned long)ap->beacons_seen,
                                  (unsigned long)ap->probe_responses_seen);
        }
        if (lbl_ap_assess[i]) {
            lv_label_set_text_fmt(lbl_ap_assess[i], "%s%s",
                                  wpsplinter_assessment_label(ap->assessment),
                                  ap->wps_advertised ? "" : " (no WPS)");
            lv_obj_set_style_text_color(lbl_ap_assess[i],
                                        lv_color_hex(color_for_assessment(ap->assessment)),
                                        0);
        }
        if (lbl_ap_evidence[i]) {
            lv_label_set_text(lbl_ap_evidence[i], evidence);
            lv_obj_set_style_text_color(lbl_ap_evidence[i],
                                        lv_color_hex(ap->evidence ? good_color : dim_color),
                                        0);
        }
        if (lbl_ap_detail[i]) {
            lv_label_set_text(lbl_ap_detail[i], identity);
        }
    }
}

static void wpsplinter_input_callback(InputEvent *event) {
    if (!event) return;
    if (event->type == INPUT_TYPE_TOUCH) {
        lv_indev_data_t *data = &event->data.touch_data;
        int16_t y = data->point.y;
        if (data->state == LV_INDEV_STATE_PR) {
            if (!s_touch_drag.started) {
                touch_drag_begin(&s_touch_drag, data);
                touch_active = true;
                touch_moved = false;
                touch_last_y = y;
            } else if (content_scroller) {
                touch_drag_update(&s_touch_drag, data, content_scroller);
                touch_last_y = y;
                touch_moved = true;
            }
        } else if (data->state == LV_INDEV_STATE_REL) {
            touch_active = false;
            if (touch_drag_release(&s_touch_drag, data)) {
                return;
            }
            if (!touch_moved) {
                display_manager_go_back();
            }
        }
    } else if (event->type == INPUT_TYPE_JOYSTICK || event->type == INPUT_TYPE_KEYBOARD) {
        if (event->type == INPUT_TYPE_JOYSTICK) {
            int button = event->data.joystick_index;
            if (button == 2) scroll_wpsplinter(-1);
            else if (button == 4) scroll_wpsplinter(1);
            else if (button == 0 || button == 1 || button == 3) display_manager_go_back();
            return;
        }

        int key = event->data.key_value;
        if (key == LV_KEY_UP || key == 'k' || key == ';') {
            scroll_wpsplinter(-1);
        } else if (key == LV_KEY_DOWN || key == 'j' || key == '.') {
            scroll_wpsplinter(1);
        } else if (key == LV_KEY_ESC || key == 27 || key == 29 || key == '`' || key == 'q' || key == 'Q') {
            display_manager_go_back();
        }
    } else if (event->type == INPUT_TYPE_ENCODER) {
        if (event->data.encoder.button) {
            display_manager_go_back();
        } else if (event->data.encoder.direction > 0) {
            scroll_wpsplinter(1);
        } else if (event->data.encoder.direction < 0) {
            scroll_wpsplinter(-1);
        }
    } else if (event->type == INPUT_TYPE_EXIT_BUTTON) {
        display_manager_go_back();
    }
}

void wpsplinter_view_create(void) {
    if (wpsplinter_view.root != NULL) {
        return;
    }

    uint8_t theme = settings_get_menu_theme(&G_Settings);
    accent_color = theme_palette_get_accent(theme);
    bg_color = theme_palette_get_background(theme);
    card_color = theme_palette_get_surface_alt(theme);
    text_color = theme_palette_get_text(theme);
    dim_color = theme_palette_get_text_muted(theme);

    wpsplinter_scan_reset();
    wifi_manager_start_monitor_mode(wifi_wpsplinter_callback);
    (void)wpsplinter_scan_start(0, 0);

    display_manager_fill_screen(lv_color_hex(bg_color));
    root_container = gui_screen_create_root(NULL, "WPSplinter", lv_color_hex(bg_color), LV_OPA_COVER);
    wpsplinter_view.root = root_container;

    lv_obj_t *content = gui_screen_create_content(root_container, GUI_STATUS_BAR_HEIGHT);
    content_scroller = content;
    lv_obj_set_style_text_color(content, lv_color_hex(text_color), 0);
    lv_obj_set_style_pad_all(content, tiny_layout() ? 1 : (compact_layout() ? 2 : 4), 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(content, tiny_layout() ? 1 : (compact_layout() ? 2 : 4), 0);
    lv_obj_add_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(content, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(content, LV_SCROLLBAR_MODE_AUTO);

    lv_obj_t *status_card = create_card(content, 100);
    if (!compact_layout()) {
        create_card_title(status_card, "Broadcom WPS Fingerprint");
    }
    lbl_channel = lv_label_create(status_card);
    lv_obj_set_style_text_font(lbl_channel, body_font(), 0);
    lv_obj_set_style_text_color(lbl_channel, lv_color_hex(accent_color), 0);
    lv_obj_set_width(lbl_channel, LV_PCT(100));
    lv_label_set_long_mode(lbl_channel, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lbl_counts = lv_label_create(status_card);
    lv_obj_set_style_text_font(lbl_counts, title_font(), 0);
    lv_obj_set_width(lbl_counts, LV_PCT(100));
    lv_label_set_long_mode(lbl_counts, LV_LABEL_LONG_SCROLL_CIRCULAR);

    for (uint8_t i = 0; i < WPSPLINTER_GUI_SLOTS; i++) {
        ap_cards[i] = create_card(content, 100);
        if (!compact_layout()) {
            char title[16] = {0};
            snprintf(title, sizeof(title), "AP %u", (unsigned)(i + 1));
            create_card_title(ap_cards[i], title);
        }
        lbl_ap[i] = lv_label_create(ap_cards[i]);
        lv_obj_set_style_text_font(lbl_ap[i], title_font(), 0);
        lv_obj_set_width(lbl_ap[i], LV_PCT(100));
        lv_label_set_long_mode(lbl_ap[i], LV_LABEL_LONG_WRAP);
        lbl_ap_mac[i] = lv_label_create(ap_cards[i]);
        lv_obj_set_style_text_font(lbl_ap_mac[i], body_font(), 0);
        lv_obj_set_style_text_color(lbl_ap_mac[i], lv_color_hex(dim_color), 0);
        lv_obj_set_width(lbl_ap_mac[i], LV_PCT(100));
        lv_label_set_long_mode(lbl_ap_mac[i], LV_LABEL_LONG_WRAP);
        lbl_ap_assess[i] = lv_label_create(ap_cards[i]);
        lv_obj_set_style_text_font(lbl_ap_assess[i], body_font(), 0);
        lv_obj_set_width(lbl_ap_assess[i], LV_PCT(100));
        lv_label_set_long_mode(lbl_ap_assess[i], LV_LABEL_LONG_WRAP);
        lbl_ap_evidence[i] = lv_label_create(ap_cards[i]);
        lv_obj_set_style_text_font(lbl_ap_evidence[i], body_font(), 0);
        lv_obj_set_style_text_color(lbl_ap_evidence[i], lv_color_hex(dim_color), 0);
        lv_obj_set_width(lbl_ap_evidence[i], LV_PCT(100));
        lv_label_set_long_mode(lbl_ap_evidence[i], LV_LABEL_LONG_WRAP);
        lbl_ap_detail[i] = lv_label_create(ap_cards[i]);
        lv_obj_set_style_text_font(lbl_ap_detail[i], body_font(), 0);
        lv_obj_set_style_text_color(lbl_ap_detail[i], lv_color_hex(dim_color), 0);
        lv_obj_set_width(lbl_ap_detail[i], LV_PCT(100));
        lv_label_set_long_mode(lbl_ap_detail[i], LV_LABEL_LONG_WRAP);
        if (i > 0) {
            lv_obj_add_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
        }
    }

    display_manager_add_status_bar("WPSplinter");
    update_timer = lv_timer_create(update_display_cb, 250, NULL);
    update_display_cb(NULL);
}

void wpsplinter_view_destroy(void) {
    if (update_timer) {
        lv_timer_del(update_timer);
        update_timer = NULL;
    }

    wifi_manager_stop_monitor_mode(); /* also stops the detector */
    wpsplinter_scan_stop();

    if (root_container) {
        lv_obj_del(root_container);
        root_container = NULL;
        wpsplinter_view.root = NULL;
    }

    lbl_channel = NULL;
    lbl_counts = NULL;
    for (uint8_t i = 0; i < WPSPLINTER_GUI_SLOTS; i++) {
        ap_cards[i] = NULL;
        lbl_ap[i] = NULL;
        lbl_ap_mac[i] = NULL;
        lbl_ap_assess[i] = NULL;
        lbl_ap_evidence[i] = NULL;
        lbl_ap_detail[i] = NULL;
    }
    content_scroller = NULL;
    touch_active = false;
    touch_moved = false;
}

static void get_wpsplinter_callback(void **callback) {
    if (callback) {
        *callback = (void *)wpsplinter_input_callback;
    }
}

View wpsplinter_view = {
    .root = NULL,
    .create = wpsplinter_view_create,
    .destroy = wpsplinter_view_destroy,
    .input_callback = wpsplinter_input_callback,
    .name = "WPSplinterView",
    .get_hardwareinput_callback = get_wpsplinter_callback
};


