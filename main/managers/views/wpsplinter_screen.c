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

#define WPSPLINTER_GUI_SLOTS WPSPLINTER_MAX_APS
#define DETAIL_LABELS_MAX 16

static lv_obj_t *root_container = NULL;
static lv_timer_t *update_timer = NULL;
static lv_obj_t *lbl_channel = NULL;
static lv_obj_t *lbl_counts = NULL;
static lv_obj_t *ap_cards[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *lbl_ap_mac[WPSPLINTER_GUI_SLOTS] = {0};
static lv_obj_t *content_scroller = NULL;

/* Detail overlay: created when a card is selected, deleted on close. */
static lv_obj_t *detail_panel = NULL;
static lv_obj_t *lbl_detail[DETAIL_LABELS_MAX] = {0};
static uint8_t lbl_detail_n = 0;
static bool s_detail_open = false;
static wpsplinter_ap_t s_detail_ap;

/* Result mirror used by the LVGL timer task (bounded stack) and the
 * vulnerable-only list state: s_vuln_idx maps list rows to s_aps entries. */
static wpsplinter_ap_t s_aps[WPSPLINTER_MAX_APS];
static uint8_t s_vuln_idx[WPSPLINTER_MAX_APS];
static uint16_t s_total = 0;
static uint8_t s_list_count = 0;
static uint8_t s_selected = 0;

static uint32_t accent_color = 0x00FFFF;
static uint32_t bg_color = 0x0A0A0A;
static uint32_t card_color = 0x1A1A1A;
static uint32_t surface_color = 0x2A2A2A;
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

/* Reference criteria names shown per matched fingerprint in the detail view. */
static const char *const s_evidence_names[3] = {
    "Broadcom proprietary IE (OUI 00:10:18)",
    "fixed Broadcom WPS UUID",
    "identity attributes at Broadcom defaults (2+)",
};

static lv_obj_t *detail_label(const char *text, const lv_font_t *font, uint32_t color) {
    lv_obj_t *label = lv_label_create(detail_panel);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_color(label, lv_color_hex(color), 0);
    lv_obj_set_width(label, LV_PCT(100));
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_label_set_text(label, text);
    return label;
}

static void add_detail_label(const char *text, const lv_font_t *font, uint32_t color) {
    if (!detail_panel || lbl_detail_n >= DETAIL_LABELS_MAX) {
        return;
    }
    lbl_detail[lbl_detail_n++] = detail_label(text, font, color);
}

static void close_detail(void) {
    if (detail_panel) {
        lv_obj_del(detail_panel);
        detail_panel = NULL;
    }
    for (uint8_t k = 0; k < DETAIL_LABELS_MAX; k++) {
        lbl_detail[k] = NULL;
    }
    lbl_detail_n = 0;
    s_detail_open = false;
}

/* Full-evidence overlay for one selected AP: assessment, every fingerprint
 * criterion that matched, and the raw WPS identity strings observed. */
static void open_detail(uint8_t i) {
    if (s_detail_open || !root_container || i >= s_list_count) {
        return;
    }
    s_selected = i;
    s_detail_ap = s_aps[s_vuln_idx[i]];

    detail_panel = lv_obj_create(root_container);
    if (!detail_panel) {
        return;
    }
    lv_coord_t content_h = gui_screen_content_height(GUI_STATUS_BAR_HEIGHT, 0);
    lv_obj_set_pos(detail_panel, 0, GUI_STATUS_BAR_HEIGHT);
    lv_obj_set_size(detail_panel, LV_PCT(100), content_h > 80 ? content_h : 80);
    lv_obj_set_style_bg_color(detail_panel, lv_color_hex(bg_color), 0);
    lv_obj_set_style_bg_opa(detail_panel, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(detail_panel, lv_color_hex(accent_color), 0);
    lv_obj_set_style_border_width(detail_panel, 1, 0);
    lv_obj_set_style_border_side(detail_panel, LV_BORDER_SIDE_FULL, 0);
    lv_obj_set_style_radius(detail_panel, 0, 0);
    lv_obj_set_style_pad_all(detail_panel, tiny_layout() ? 2 : (compact_layout() ? 4 : 8), 0);
    lv_obj_set_style_text_color(detail_panel, lv_color_hex(text_color), 0);
    lv_obj_set_flex_flow(detail_panel, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(detail_panel, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(detail_panel, tiny_layout() ? 1 : (compact_layout() ? 2 : 4), 0);
    lv_obj_set_scroll_dir(detail_panel, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(detail_panel, LV_SCROLLBAR_MODE_AUTO);
    lbl_detail_n = 0;

    char line[64];
    char stats[128];
    add_detail_label(s_detail_ap.ssid[0] ? s_detail_ap.ssid : "<hidden>",
                     title_font(), error_color);

    format_mac(s_detail_ap.bssid, line, sizeof(line));
    snprintf(stats, sizeof(stats), "%s  ch%u  %ddBm  b:%lu p:%lu",
             line,
             (unsigned)s_detail_ap.channel,
             (int)s_detail_ap.rssi,
             (unsigned long)s_detail_ap.beacons_seen,
             (unsigned long)s_detail_ap.probe_responses_seen);
    add_detail_label(stats, body_font(), dim_color);

    snprintf(line, sizeof(line), "%s (passive assessment)",
             wpsplinter_assessment_label(s_detail_ap.assessment));
    add_detail_label(line, title_font(), color_for_assessment(s_detail_ap.assessment));

    add_detail_label("matched fingerprints:", body_font(), dim_color);
    uint8_t shown = 0;
    for (uint8_t b = 0; b < 3; b++) {
        if (s_detail_ap.evidence & (uint8_t)(1u << b)) {
            snprintf(line, sizeof(line), "+ %s", s_evidence_names[b]);
            add_detail_label(line, body_font(), good_color);
            shown++;
        }
    }
    if (shown == 0) {
        add_detail_label("none", body_font(), dim_color);
    }

    add_detail_label("observed WPS identity:", body_font(), dim_color);
    static const char *const keys[5] = {"Vendor", "Model", "Model #", "Device name", "Serial"};
    const char *vals[5] = {
        s_detail_ap.vendor, s_detail_ap.model, s_detail_ap.model_number,
        s_detail_ap.device_name, s_detail_ap.serial_number
    };
    for (uint8_t f = 0; f < 5; f++) {
        if (vals[f][0]) {
            snprintf(line, sizeof(line), "%s: %s", keys[f], vals[f]);
            add_detail_label(line, body_font(), text_color);
        }
    }

    add_detail_label("enter/tap: close", body_font(), dim_color);
    s_detail_open = true;
}

static void scroll_wpsplinter(int dir) {
    lv_obj_t *target = (s_detail_open && detail_panel) ? detail_panel : content_scroller;
    if (!target) {
        return;
    }
    lv_coord_t step = lv_obj_get_height(target) / 2;
    if (step < 24) step = 24;
    lv_obj_scroll_by_bounded(target, 0, dir > 0 ? -step : step, LV_ANIM_OFF);
}

/* Cards are created lazily so the number of LVGL objects tracks the number
 * of flagged APs instead of pinning a fixed pool. */
static void ensure_card(uint8_t i) {
    if (i >= WPSPLINTER_GUI_SLOTS || ap_cards[i] || !content_scroller) {
        return;
    }
    ap_cards[i] = create_card(content_scroller, 100);
    lbl_ap[i] = lv_label_create(ap_cards[i]);
    lv_obj_set_style_text_font(lbl_ap[i], title_font(), 0);
    lv_obj_set_width(lbl_ap[i], LV_PCT(100));
    lv_label_set_long_mode(lbl_ap[i], LV_LABEL_LONG_WRAP);
    lbl_ap_mac[i] = lv_label_create(ap_cards[i]);
    lv_obj_set_style_text_font(lbl_ap_mac[i], body_font(), 0);
    lv_obj_set_style_text_color(lbl_ap_mac[i], lv_color_hex(dim_color), 0);
    lv_obj_set_width(lbl_ap_mac[i], LV_PCT(100));
    lv_label_set_long_mode(lbl_ap_mac[i], LV_LABEL_LONG_WRAP);
    lv_obj_add_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
}

/* Vulnerable-only list: one compact card per flagged AP; the selected row
 * is highlighted (brighter surface + "> " marker) and scrolls into view. */
static void render_list(void) {
    if (!content_scroller) {
        return;
    }
    for (uint8_t i = 0; i < WPSPLINTER_GUI_SLOTS; i++) {
        if (i >= s_list_count) {
            if (i == 0) {
                ensure_card(0);
                lv_obj_clear_flag(ap_cards[0], LV_OBJ_FLAG_HIDDEN);
                lv_obj_set_style_bg_color(ap_cards[0], lv_color_hex(card_color), 0);
                if (lbl_ap[0]) {
                    lv_label_set_text(lbl_ap[0],
                                      s_total ? "No likely-vulnerable APs yet"
                                              : "Scanning for WPS APs");
                    lv_obj_set_style_text_color(lbl_ap[0], lv_color_hex(text_color), 0);
                }
                if (lbl_ap_mac[0]) {
                    lv_label_set_text(lbl_ap_mac[0],
                                      "Only flagged APs are listed; enter opens details");
                }
            } else if (ap_cards[i]) {
                lv_obj_add_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
            }
            continue;
        }

        ensure_card(i);
        const wpsplinter_ap_t *ap = &s_aps[s_vuln_idx[i]];
        char mac[18] = {0};
        format_mac(ap->bssid, mac, sizeof(mac));

        lv_obj_clear_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_style_bg_color(ap_cards[i],
                                  lv_color_hex(i == s_selected ? surface_color : card_color),
                                  0);
        if (lbl_ap[i]) {
            lv_label_set_text_fmt(lbl_ap[i], "%s#%u %s",
                                  i == s_selected ? "> " : "",
                                  (unsigned)(i + 1),
                                  ap->ssid[0] ? ap->ssid : "<hidden>");
            lv_obj_set_style_text_color(lbl_ap[i], lv_color_hex(error_color), 0);
        }
        if (lbl_ap_mac[i]) {
            lv_label_set_text_fmt(lbl_ap_mac[i], "%s  ch%u  %ddBm  b:%lu p:%lu",
                                  mac,
                                  (unsigned)ap->channel,
                                  (int)ap->rssi,
                                  (unsigned long)ap->beacons_seen,
                                  (unsigned long)ap->probe_responses_seen);
        }
    }
}

static void move_selection(int delta) {
    if (s_list_count == 0) {
        return;
    }
    int next = (int)s_selected + delta;
    if (next < 0) next = 0;
    if (next >= (int)s_list_count) next = (int)s_list_count - 1;
    if (next == (int)s_selected) {
        return;
    }
    s_selected = (uint8_t)next;
    if (ap_cards[s_selected]) {
        lv_obj_scroll_to_view(ap_cards[s_selected], LV_ANIM_ON);
    }
    render_list();
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

    /* Mirror the full result set into the static buffer (bounded LVGL timer
     * task stack), then keep only likely-vulnerable APs in the list view. */
    s_total = wpsplinter_scan_get_aps(s_aps, WPSPLINTER_MAX_APS);
    s_list_count = 0;
    for (uint16_t n = 0; n < s_total; n++) {
        if (s_aps[n].assessment == WPSPLINTER_ASSESSMENT_LIKELY_VULNERABLE) {
            s_vuln_idx[s_list_count++] = (uint8_t)n;
        }
    }
    if (s_selected >= s_list_count) {
        s_selected = s_list_count > 0 ? (uint8_t)(s_list_count - 1) : 0;
    }
    render_list();
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
            } else {
                lv_obj_t *target = (s_detail_open && detail_panel) ? detail_panel : content_scroller;
                if (target) {
                    touch_drag_update(&s_touch_drag, data, target);
                }
                touch_last_y = y;
                touch_moved = true;
            }
        } else if (data->state == LV_INDEV_STATE_REL) {
            touch_active = false;
            if (touch_drag_release(&s_touch_drag, data)) {
                return;
            }
            if (!touch_moved) {
                if (s_detail_open) {
                    close_detail();
                    return;
                }
                /* Tap on a list card selects it and opens the detail view. */
                int16_t x = data->point.x;
                for (uint8_t i = 0; i < s_list_count && i < WPSPLINTER_GUI_SLOTS; i++) {
                    if (!ap_cards[i] || lv_obj_has_flag(ap_cards[i], LV_OBJ_FLAG_HIDDEN)) {
                        continue;
                    }
                    lv_area_t coords;
                    lv_obj_get_coords(ap_cards[i], &coords);
                    if (x >= coords.x1 && x <= coords.x2 && y >= coords.y1 && y <= coords.y2) {
                        open_detail(i);
                        return;
                    }
                }
                display_manager_go_back();
            }
        }
    } else if (event->type == INPUT_TYPE_JOYSTICK || event->type == INPUT_TYPE_KEYBOARD) {
        if (event->type == INPUT_TYPE_JOYSTICK) {
            int button = event->data.joystick_index;
            if (button == 2) {
                if (s_detail_open) scroll_wpsplinter(-1);
                else move_selection(-1);
            } else if (button == 4) {
                if (s_detail_open) scroll_wpsplinter(1);
                else move_selection(1);
            } else if (button == 0 || button == 1 || button == 3) {
                if (s_detail_open) close_detail();
                else display_manager_go_back();
            }
            return;
        }

        int key = event->data.key_value;
        bool is_back = (key == LV_KEY_ESC || key == 27 || key == 29 || key == '`' ||
                        key == 'q' || key == 'Q');
        bool is_enter = (key == LV_KEY_ENTER || key == 13 || key == ' ');
        if (s_detail_open) {
            if (is_back || is_enter) {
                close_detail();
            } else if (key == LV_KEY_UP || key == 'k' || key == ';') {
                scroll_wpsplinter(-1);
            } else if (key == LV_KEY_DOWN || key == 'j' || key == '.') {
                scroll_wpsplinter(1);
            }
            return;
        }
        if (key == LV_KEY_UP || key == 'k' || key == ';') {
            move_selection(-1);
        } else if (key == LV_KEY_DOWN || key == 'j' || key == '.') {
            move_selection(1);
        } else if (is_enter) {
            if (s_list_count > 0) {
                open_detail(s_selected);
            }
        } else if (is_back) {
            display_manager_go_back();
        }
    } else if (event->type == INPUT_TYPE_ENCODER) {
        if (event->data.encoder.button) {
            if (s_detail_open) close_detail();
            else display_manager_go_back();
        } else if (event->data.encoder.direction > 0) {
            scroll_wpsplinter(1);
        } else if (event->data.encoder.direction < 0) {
            scroll_wpsplinter(-1);
        }
    } else if (event->type == INPUT_TYPE_EXIT_BUTTON) {
        if (s_detail_open) close_detail();
        else display_manager_go_back();
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
    surface_color = theme_palette_get_surface(theme);
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

    /* AP cards are created lazily by render_list() as flagged APs appear. */

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
    close_detail(); /* detail panel is a child of root_container */

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
    }
    content_scroller = NULL;
    s_total = 0;
    s_list_count = 0;
    s_selected = 0;
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


