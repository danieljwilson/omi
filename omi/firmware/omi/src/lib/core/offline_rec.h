#ifndef OFFLINE_REC_H
#define OFFLINE_REC_H

/*
 * Pairent custom module: always-on offline recording control.
 *
 * Upstream firmware records to SD only while BLE is disconnected. This module
 * makes SD the primary recording target ("SD-primary"): when enabled, encoder
 * output is written to SD regardless of connection state. The phone drains
 * files opportunistically via the stock storage sync protocol (30295780).
 *
 * Also owns: flag markers (single-tap), storage eviction (oldest file is
 * deleted when the 480 MB cap nears, instead of upstream's silent drop), and
 * persistence of both via a dedicated "pairent" settings subtree.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "forensics.h"

/* v2 prefix (self-contained, served alone on pre-MTU-exchange notifies) +
 * the pairent.4 wedge-forensics appendix. */
#define OFFLINE_REC_STATUS_V2_LEN 20
#define OFFLINE_REC_STATUS_LEN (OFFLINE_REC_STATUS_V2_LEN + FORENSICS_STATUS_APPENDIX_LEN)
#define OFFLINE_REC_MAX_MARKERS 120

/* Storage states reported in the status payload */
#define OFFLINE_REC_STORAGE_OK 0
#define OFFLINE_REC_STORAGE_LOW 1      /* < ~80 MB headroom left */
#define OFFLINE_REC_STORAGE_EVICTING 2 /* at cap; oldest files being deleted */

/**
 * @brief Initialize module state (after settings + SD init).
 *
 * Persisted state (enabled flag, markers, boot count) is restored by the
 * settings subsystem during settings_load(). Increments the persisted boot
 * counter, records this boot's reset-reason code for the status payload,
 * and consumes the previous run's clean-shutdown flag.
 *
 * @param reset_code Compact reset-reason code from print_reset_reason()
 *                   (0=power-on, 1=pin, 2=watchdog, 3=lockup, 4=soft,
 *                   5=other, 6=NFC, 7=wake from System OFF).
 */
int offline_rec_init(uint8_t reset_code);

/**
 * @brief Mark the current shutdown as clean (call from the power-off path).
 *
 * If the next boot does NOT see this flag, the previous run ended uncleanly
 * (freeze, battery death, crash) — surfaced in the status payload.
 */
void offline_rec_mark_clean_shutdown(void);

/** @brief Whether SD-primary recording is currently enabled. */
bool offline_rec_enabled(void);

/** @brief Enable/disable SD-primary recording; persists across reboots. */
void offline_rec_set_enabled(bool enabled);

/** @brief Toggle recording state (double-tap handler). */
void offline_rec_toggle(void);

/**
 * @brief Record a flag marker (single-tap handler).
 *
 * Stores current UTC epoch seconds. If the clock is not yet synced, stores
 * (0x80000000 | uptime_seconds) so the phone can reconstruct the wall-clock
 * time after a later time sync. Markers persist across reboots.
 */
void offline_rec_add_marker(void);

/** @brief Number of stored markers (0..OFFLINE_REC_MAX_MARKERS). */
uint8_t offline_rec_marker_count(void);

/**
 * @brief Serialize markers as [count:u8][epoch:u32 LE]*count.
 *
 * @return number of bytes written to buf, or negative errno.
 */
int offline_rec_read_markers(uint8_t *buf, size_t buf_len);

/** @brief Clear all markers (phone calls this after reading them). */
void offline_rec_clear_markers(void);

/** @brief Current storage state (OFFLINE_REC_STORAGE_*). */
uint8_t offline_rec_storage_state(void);

/**
 * @brief Fill the 34-byte status payload (little-endian):
 *   [0]      protocol version (3)
 *   [1]      recording enabled (0/1)
 *   [2]      storage state (OFFLINE_REC_STORAGE_*)
 *   [3]      marker count
 *   [4..7]   used bytes (u32)
 *   [8..11]  free bytes vs 480 MB cap (u32)
 *   [12..15] device UTC epoch seconds, 0 if unsynced (u32)
 *   [16]     reset-reason code of the current boot (see offline_rec_init)
 *   [17..18] boot count (u16, persisted; monotonic across reboots)
 *   [19]     flags: bit0 = previous shutdown was clean
 *   [20..33] wedge-forensics appendix (see forensics.h)
 */
void offline_rec_get_status(uint8_t out[OFFLINE_REC_STATUS_LEN]);

/**
 * @brief Periodic housekeeping; call from the storage thread loop.
 *
 * Self-throttled to one pass per 30 s. Refreshes the used-bytes cache,
 * updates storage state, evicts oldest files when near the cap, and sends
 * a status notification when the phone is subscribed.
 */
void offline_rec_housekeep(void);

/**
 * @brief Notify the subscribed phone of current status via BLE.
 *
 * Implemented in transport.c (owns the GATT attributes). Safe to call from
 * any thread; no-op when not connected/subscribed.
 */
void transport_notify_offline_status(void);

#endif // OFFLINE_REC_H
