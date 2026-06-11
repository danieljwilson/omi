#include "offline_rec.h"

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include "rtc.h"
#include "sd_card.h"

LOG_MODULE_REGISTER(offline_rec, CONFIG_LOG_DEFAULT_LEVEL);

/* Headroom thresholds against the 480 MB usable cap (MAX_STORAGE_BYTES). */
#define LOW_WATER_BYTES (400UL * 1024 * 1024)   /* warn below ~80 MB headroom */
#define EVICT_WATER_BYTES (460UL * 1024 * 1024) /* start deleting oldest files */
#define EVICT_TARGET_BYTES (450UL * 1024 * 1024)
#define EVICT_MAX_PER_PASS 4
/* Also evict when the file count nears MAX_AUDIO_FILES — files beyond the
 * list cap would be invisible to the sync protocol. */
#define EVICT_FILE_COUNT_WATER (MAX_AUDIO_FILES - 4)

#define HOUSEKEEP_INTERVAL_MS (30 * 1000)

/* Default ON: the device's whole purpose is all-day capture; after a watchdog
 * reboot or battery swap it must resume without a button press. */
static bool rec_enabled = true;

static uint8_t storage_state = OFFLINE_REC_STORAGE_OK;
static uint64_t used_bytes_cached = 0;

static uint32_t markers[OFFLINE_REC_MAX_MARKERS];
static uint8_t marker_count = 0;

/* Boot forensics (2026-06-11 field freeze): which reset brought us up, how
 * many boots total, and whether the previous run powered off cleanly. */
static uint8_t last_reset_code = 0;
static uint16_t boot_count = 0;
static bool prev_shutdown_clean = false;

/* ------------------------------------------------------------------ */
/* Persistence: dedicated "pairent" settings subtree                   */
/* ------------------------------------------------------------------ */

static int pairent_settings_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
    const char *next;

    if (settings_name_steq(name, "rec_en", &next) && !next) {
        uint8_t val = 1;
        if (len != sizeof(val)) {
            return -EINVAL;
        }
        if (read_cb(cb_arg, &val, sizeof(val)) < 0) {
            return -EIO;
        }
        rec_enabled = (val != 0);
        return 0;
    }

    if (settings_name_steq(name, "markers", &next) && !next) {
        uint8_t blob[1 + sizeof(markers)];
        if (len < 1 || len > sizeof(blob)) {
            return -EINVAL;
        }
        ssize_t rd = read_cb(cb_arg, blob, len);
        if (rd < 1) {
            return -EIO;
        }
        uint8_t count = blob[0];
        if (count > OFFLINE_REC_MAX_MARKERS || (size_t) (1 + count * 4) > (size_t) rd) {
            count = 0;
        }
        marker_count = count;
        memcpy(markers, blob + 1, count * 4);
        return 0;
    }

    if (settings_name_steq(name, "boot_cnt", &next) && !next) {
        uint16_t val = 0;
        if (len != sizeof(val)) {
            return -EINVAL;
        }
        if (read_cb(cb_arg, &val, sizeof(val)) < 0) {
            return -EIO;
        }
        boot_count = val;
        return 0;
    }

    if (settings_name_steq(name, "clean_sd", &next) && !next) {
        uint8_t val = 0;
        if (len != sizeof(val)) {
            return -EINVAL;
        }
        if (read_cb(cb_arg, &val, sizeof(val)) < 0) {
            return -EIO;
        }
        prev_shutdown_clean = (val != 0);
        return 0;
    }

    return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(pairent_settings, "pairent", NULL, pairent_settings_set, NULL, NULL);

static void persist_rec_enabled(void)
{
    uint8_t val = rec_enabled ? 1 : 0;
    int err = settings_save_one("pairent/rec_en", &val, sizeof(val));
    if (err) {
        LOG_ERR("Failed to persist rec_en: %d", err);
    }
}

static void persist_markers(void)
{
    uint8_t blob[1 + sizeof(markers)];
    blob[0] = marker_count;
    memcpy(blob + 1, markers, marker_count * 4);
    int err = settings_save_one("pairent/markers", blob, 1 + marker_count * 4);
    if (err) {
        LOG_ERR("Failed to persist markers: %d", err);
    }
}

/* ------------------------------------------------------------------ */
/* Recording state                                                     */
/* ------------------------------------------------------------------ */

int offline_rec_init(uint8_t reset_code)
{
    last_reset_code = reset_code;

    boot_count++;
    uint16_t bc = boot_count;
    int err = settings_save_one("pairent/boot_cnt", &bc, sizeof(bc));
    if (err) {
        LOG_ERR("Failed to persist boot_cnt: %d", err);
    }

    /* The flag on flash describes how the PREVIOUS run ended (set only by
     * the power-off path). Consume and clear it so a freeze or battery
     * death before the next clean power-off reads as unclean. */
    uint8_t zero = 0;
    (void) settings_save_one("pairent/clean_sd", &zero, sizeof(zero));

    LOG_INF("Offline recording: %s, %u marker(s); boot #%u, reset code %u, prev shutdown %s",
            rec_enabled ? "ENABLED" : "standby",
            marker_count,
            boot_count,
            reset_code,
            prev_shutdown_clean ? "clean" : "UNCLEAN");
    return 0;
}

void offline_rec_mark_clean_shutdown(void)
{
    uint8_t one = 1;
    (void) settings_save_one("pairent/clean_sd", &one, sizeof(one));
}

bool offline_rec_enabled(void)
{
    return rec_enabled;
}

void offline_rec_set_enabled(bool enabled)
{
    if (rec_enabled == enabled) {
        return;
    }
    rec_enabled = enabled;
    persist_rec_enabled();
    LOG_INF("Offline recording %s", enabled ? "STARTED" : "STOPPED");
    transport_notify_offline_status();
}

void offline_rec_toggle(void)
{
    offline_rec_set_enabled(!rec_enabled);
}

/* ------------------------------------------------------------------ */
/* Markers                                                             */
/* ------------------------------------------------------------------ */

void offline_rec_add_marker(void)
{
    uint32_t value = get_utc_time();
    if (value == 0) {
        /* Clock unsynced: store uptime seconds with the high bit set so the
         * phone can reconstruct wall-clock time after a later time sync. */
        value = 0x80000000u | (uint32_t) (k_uptime_get() / 1000);
    }

    if (marker_count >= OFFLINE_REC_MAX_MARKERS) {
        memmove(&markers[0], &markers[1], (OFFLINE_REC_MAX_MARKERS - 1) * 4);
        marker_count = OFFLINE_REC_MAX_MARKERS - 1;
        LOG_WRN("Marker buffer full, dropped oldest");
    }

    markers[marker_count++] = value;
    persist_markers();
    LOG_INF("Marker %u recorded: 0x%08X", marker_count, value);
    transport_notify_offline_status();
}

uint8_t offline_rec_marker_count(void)
{
    return marker_count;
}

int offline_rec_read_markers(uint8_t *buf, size_t buf_len)
{
    size_t needed = 1 + (size_t) marker_count * 4;
    if (buf_len < needed) {
        return -EINVAL;
    }
    buf[0] = marker_count;
    memcpy(buf + 1, markers, marker_count * 4);
    return (int) needed;
}

void offline_rec_clear_markers(void)
{
    if (marker_count == 0) {
        return;
    }
    marker_count = 0;
    persist_markers();
    LOG_INF("Markers cleared");
}

/* ------------------------------------------------------------------ */
/* Status + storage housekeeping                                       */
/* ------------------------------------------------------------------ */

uint8_t offline_rec_storage_state(void)
{
    return storage_state;
}

static void put_le32(uint8_t *out, uint32_t v)
{
    out[0] = v & 0xFF;
    out[1] = (v >> 8) & 0xFF;
    out[2] = (v >> 16) & 0xFF;
    out[3] = (v >> 24) & 0xFF;
}

void offline_rec_get_status(uint8_t out[OFFLINE_REC_STATUS_LEN])
{
    uint32_t used = (used_bytes_cached > UINT32_MAX) ? UINT32_MAX : (uint32_t) used_bytes_cached;
    uint32_t free_bytes = (used < MAX_STORAGE_BYTES) ? (MAX_STORAGE_BYTES - used) : 0;

    out[0] = 2; /* protocol version */
    out[1] = rec_enabled ? 1 : 0;
    out[2] = storage_state;
    out[3] = marker_count;
    put_le32(out + 4, used);
    put_le32(out + 8, free_bytes);
    put_le32(out + 12, get_utc_time());
    out[16] = last_reset_code;
    out[17] = boot_count & 0xFF;
    out[18] = (boot_count >> 8) & 0xFF;
    out[19] = prev_shutdown_clean ? 0x01 : 0x00;
}

static void evict_oldest_files(void)
{
    char filenames[MAX_AUDIO_FILES][MAX_FILENAME_LEN];
    uint32_t sizes[MAX_AUDIO_FILES];
    int count = 0;

    if (get_audio_file_list_with_sizes(filenames, sizes, MAX_AUDIO_FILES, &count) < 0 || count <= 1) {
        return;
    }

    char current[MAX_FILENAME_LEN] = {0};
    (void) get_current_filename(current, sizeof(current));

    int evicted = 0;
    uint64_t freed = 0;
    for (int i = 0; i < count && evicted < EVICT_MAX_PER_PASS; i++) {
        if (current[0] != '\0' && strncmp(filenames[i], current, MAX_FILENAME_LEN) == 0) {
            continue; /* never evict the file being written */
        }
        if (used_bytes_cached - freed <= EVICT_TARGET_BYTES) {
            break;
        }
        if (delete_audio_file(filenames[i]) == 0) {
            freed += sizes[i];
            evicted++;
            LOG_WRN("Evicted oldest file %s (%u bytes) — un-synced audio lost", filenames[i], sizes[i]);
        }
    }

    if (freed > 0 && used_bytes_cached >= freed) {
        used_bytes_cached -= freed;
    }
}

void offline_rec_housekeep(void)
{
    static int64_t next_run_ms = 0;

    int64_t now = k_uptime_get();
    if (now < next_run_ms) {
        return;
    }
    next_run_ms = now + HOUSEKEEP_INTERVAL_MS;

    if (!is_sd_on()) {
        return;
    }

    uint32_t file_count = 0;
    uint64_t total_size = 0;
    if (get_audio_file_stats(&file_count, &total_size) != 0) {
        return;
    }
    used_bytes_cached = total_size;

    uint8_t prev_state = storage_state;
    if (total_size >= EVICT_WATER_BYTES || file_count >= EVICT_FILE_COUNT_WATER) {
        storage_state = OFFLINE_REC_STORAGE_EVICTING;
        evict_oldest_files();
    } else if (total_size >= LOW_WATER_BYTES) {
        storage_state = OFFLINE_REC_STORAGE_LOW;
    } else {
        storage_state = OFFLINE_REC_STORAGE_OK;
    }

    if (storage_state != prev_state) {
        LOG_INF("Storage state %u -> %u (used=%llu, files=%u)",
                prev_state,
                storage_state,
                (unsigned long long) total_size,
                file_count);
    }

    /* Doubles as the data-ready signal for the phone (status includes
     * used bytes; non-zero used = files pending sync). */
    transport_notify_offline_status();
}
