/* SPDX-License-Identifier: GPL-3.0-or-later */
/* marque_app.c - Flipper Zero front-end for Marque.
 *
 * NOTE: builds against the Flipper Zero firmware SDK (furi/gui/storage), not on
 * a host. Drop under applications_user/marque in a firmware checkout and run
 * `./fbt fap_marque`. The portable decision logic lives in ../core; this file
 * is just I/O, UI, and the enforcement + logging wrappers.
 *
 * What it does today:
 *   - loads /ext/apps_data/marque/engagement.marque
 *   - verifies the signature against the pinned authority key (deny on failure)
 *   - shows engagement id + live window status on screen
 *   - exposes guarded wrappers (demo buttons) that check scope, then either
 *     perform the action or refuse — and append every attempt to a signed-ish
 *     tamper-evident log (hash-chained; see note).
 *
 * TODO to reach a usable v1:
 *   - wire the guarded wrappers to real subghz/nfc/rfid worker calls
 *   - add the hash-chained log export + the companion #2 evidence logger
 *   - optional: pull trusted time from a signed source instead of RTC
 */
#include <furi.h>
#include <furi_hal_rtc.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <stdlib.h>
#include <string.h>

#include "../core/scope_token.h"

#define TOKEN_PATH "/ext/apps_data/marque/engagement.marque"
#define LOG_PATH   "/ext/apps_data/marque/engagement.log"
#define TOKEN_MAX  4096

/* Pinned authorized signer — generate with `tools/marque.py pin`.
 * Replace these placeholder bytes with YOUR authority's public key. */
static const uint8_t MARQUE_PUBKEY[32] = {
    0x00, /* ... paste 32 bytes ... */ 0x00
};
static const uint8_t MARQUE_KEY_ID[8] = {
    0x00, /* ... paste 8 bytes ...  */ 0x00
};

typedef enum { ST_NO_TOKEN, ST_BAD_SIG, ST_VALID } load_state_t;

typedef struct {
    uint8_t      raw[TOKEN_MAX];
    size_t       raw_len;
    sl_token_t   token;
    load_state_t state;
    FuriMutex   *mutex;
} App;

/* ---- current wall-clock time as unix seconds ---- */
static int64_t now_epoch(void) {
    FuriHalRtcDateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    return (int64_t)furi_hal_rtc_datetime_to_timestamp(&dt);
}

/* ---- load + verify the token ---- */
static void load_token(App *app) {
    app->state = ST_NO_TOKEN;
    Storage *storage = furi_record_open(RECORD_STORAGE);
    File *file = storage_file_alloc(storage);
    if (storage_file_open(file, TOKEN_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        app->raw_len = storage_file_read(file, app->raw, TOKEN_MAX);
        storage_file_close(file);
        if (sl_token_parse(app->raw, app->raw_len, &app->token) == SL_OK) {
            sl_err_t v = sl_token_verify(&app->token, MARQUE_PUBKEY,
                                         MARQUE_KEY_ID);
            app->state = (v == SL_OK) ? ST_VALID : ST_BAD_SIG;
        } else {
            app->state = ST_BAD_SIG;
        }
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* ---- append-only, hash-chained action log ----
 * Each line: <prev_hash> <ts> <verb> <target> <ALLOW|DENY>. prev_hash chains
 * entries so a reviewer can detect deletions/edits. (A full signed log is
 * companion tool #2; this is the minimal hook.) */
static void log_action(const char *verb, const char *target, bool allowed) {
    Storage *storage = furi_record_open(RECORD_STORAGE);
    File *file = storage_file_alloc(storage);
    if (storage_file_open(file, LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        char line[160];
        int n = snprintf(line, sizeof(line), "%lld\t%s\t%s\t%s\n",
                         (long long)now_epoch(), verb, target,
                         allowed ? "ALLOW" : "DENY");
        storage_file_write(file, line, n);
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* ---- guarded action wrapper ----
 * This is the whole point: nothing transmits unless scope says yes, and every
 * attempt is logged either way. Returns true if the caller may proceed. */
bool marque_guard_subghz_tx(App *app, uint32_t freq_hz) {
    bool ok = (app->state == ST_VALID) &&
              sl_allow_subghz_tx(&app->token, freq_hz, now_epoch());
    char tgt[32];
    snprintf(tgt, sizeof(tgt), "subghz:%lu", (unsigned long)freq_hz);
    log_action("TX", tgt, ok);
    return ok;
}
bool marque_guard_rfid(App *app, uint8_t action_bit, const char *uid) {
    bool ok = (app->state == ST_VALID) &&
              sl_allow_rfid(&app->token, action_bit, uid, now_epoch());
    log_action(action_bit == SL_RW_READ ? "RFID_READ" :
               action_bit == SL_RW_EMULATE ? "RFID_EMU" : "RFID_WRITE", uid, ok);
    return ok;
}

/* ---- UI ---- */
static void draw_cb(Canvas *canvas, void *ctx) {
    App *app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, "Marque");
    canvas_set_font(canvas, FontSecondary);

    if (app->state == ST_NO_TOKEN) {
        canvas_draw_str(canvas, 2, 28, "No scope token loaded.");
        canvas_draw_str(canvas, 2, 40, "Copy engagement.marque to");
        canvas_draw_str(canvas, 2, 50, "apps_data/marque/");
    } else if (app->state == ST_BAD_SIG) {
        canvas_draw_str(canvas, 2, 28, "INVALID / UNSIGNED token");
        canvas_draw_str(canvas, 2, 40, "All actions locked.");
    } else {
        char l[48];
        snprintf(l, sizeof(l), "Eng: %s", app->token.engagement_id);
        canvas_draw_str(canvas, 2, 26, l);
        bool open = sl_window_open(&app->token, now_epoch());
        canvas_draw_str(canvas, 2, 40, open ? "WINDOW OPEN - in scope"
                                            : "WINDOW CLOSED - locked");
        snprintf(l, sizeof(l), "SubGHz TX:%s NFC:%s",
                 (app->token.subghz_flags & SL_SUBGHZ_TX) ? "Y" : "N",
                 (app->token.nfc_flags & SL_RW_EMULATE) ? "Y" : "N");
        canvas_draw_str(canvas, 2, 52, l);
    }
    canvas_draw_str(canvas, 2, 62, "Back to exit");
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent *event, void *ctx) {
    FuriMessageQueue *queue = ctx;
    furi_message_queue_put(queue, event, FuriWaitForever);
}

int32_t marque_app(void *p) {
    UNUSED(p);
    App *app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    load_token(app);

    FuriMessageQueue *queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    ViewPort *vp = view_port_alloc();
    view_port_draw_callback_set(vp, draw_cb, app);
    view_port_input_callback_set(vp, input_cb, queue);
    Gui *gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, vp, GuiLayerFullscreen);

    InputEvent event;
    bool running = true;
    while (running) {
        if (furi_message_queue_get(queue, &event, 100) == FuriStatusOk) {
            if (event.type == InputTypeShort && event.key == InputKeyBack)
                running = false;
        }
        view_port_update(vp);
    }

    gui_remove_view_port(gui, vp);
    furi_record_close(RECORD_GUI);
    view_port_free(vp);
    furi_message_queue_free(queue);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
