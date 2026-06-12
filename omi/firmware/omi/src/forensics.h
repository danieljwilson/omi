#ifndef _FORENSICS_H_
#define _FORENSICS_H_

#include <stdbool.h>
#include <stdint.h>

/* Wedge forensics + supervision (ISSUES #92, fw 3.0.19+pairent.4).
 *
 * Per-subsystem liveness heartbeats in __noinit RAM, an HCI liveness probe
 * for the network core, and an ISR-context supervisor that reboots with an
 * attributed cause when a monitored subsystem wedges. The previous life's
 * summary is served as the v3 appendix of the 19B10007 status payload
 * (bytes 20..33, see forensics_fill_status).
 */

/* Heartbeat slots. Each holds the k_uptime_get_32() of the subsystem's last
 * sign of life. Order is wire format: bit N of the v3 stale bitmap. */
enum forensics_slot {
    FB_MAIN_LOOP = 0, /* main.c while(1), ~1 s */
    FB_SYSWORKQ,      /* wdog_facade sysworkq feed, 2 s */
    FB_BUTTON_FSM,    /* button.c check_button_level, 40 ms */
    FB_MIC,           /* mic_handler: PDM buffer delivered (AAD may still drop it) */
    FB_CODEC_IN,      /* PCM frame passed the AAD/VAD gate into the codec */
    FB_CODEC,         /* codec_handler: encoded frame emitted */
    FB_PUSHER,        /* transport.c pusher: frame consumed from tx queue */
    FB_SD_WORKER,     /* sd_card.c worker loop iteration */
    FB_STORAGE,       /* storage.c drain/housekeeping thread loop iteration */
    FB_HCI_PROBE,     /* last completed HCI round-trip to the netcore */
    FB_SLOT_COUNT
};

/* v3 status payload appendix, appended after the 20-byte v2 prefix:
 * [0..3]  prev_uptime_ms  LE32  uptime at previous death (0 = cold/unknown)
 * [4]     prev_cause      u8    enum forensics_cause
 * [5..6]  prev_stale_map  LE16  bit per forensics_slot stale at death
 * [7]     prev_probe      u8    0 BT never ready, 1 ok, 2 in flight
 * [8]     prev_flags      u8    bit0 recording, bit1 connected, bit2 noinit valid
 * [9]     prev_button     u8    bit7 last polled pin level, bits0..6 ISR edge count
 * [10..13] prev_fatal_pc  LE32  PC at fatal error (0 = none)
 */
#define FORENSICS_STATUS_APPENDIX_LEN 14

/* Why the previous life ended (cause 0 with reset code 4/SREQ = a reset we
 * did not attribute: mcumgr/DFU, or a fatal before pairent.4 forensics). */
enum forensics_cause {
    FCAUSE_NONE = 0,
    FCAUSE_PROBE_STUCK = 1,          /* supervisor: no HCI round-trip > 75 s */
    FCAUSE_PUSHER_STALL = 2,         /* supervisor: codec alive, pusher frozen */
    FCAUSE_CODEC_STALL = 3,          /* supervisor: mic alive, codec frozen */
    FCAUSE_SD_STALL = 4,             /* supervisor: sd_worker loop frozen */
    FCAUSE_FATAL_PROBE_INFLIGHT = 5, /* fatal error with HCI probe in flight
                                      * = netcore HCI unresponsive (the
                                      * bt_hci_cmd_send_sync 10 s assert) */
    FCAUSE_FATAL_OTHER = 6,          /* fatal error elsewhere (see fatal PC) */
    FCAUSE_FATAL_PROBE_SYSWQ_STALL = 7, /* probe was in flight but the system
                                      * workqueue heartbeat was already stale
                                      * at fatal time: HCI command TX runs on
                                      * the syswq (Zephyr 3.7), so blame the
                                      * app-core syswq stall, not the netcore */
};

/* Consume the previous life's noinit state and re-arm for this life.
 * Must run before any forensics_beat() and after print_reset_reason(). */
void forensics_boot(uint8_t reset_code);

/* Start the HCI probe thread and the supervisor timer (end of main init). */
void forensics_start(void);

/* Called by transport once bt_enable() has succeeded; gates the probe. */
void forensics_bt_ready(void);

void forensics_beat(enum forensics_slot slot);

/* Button path is instrumented at both levels: the GPIO edge ISR (counter —
 * event-driven, never required to advance) and the polled FSM (level). */
void forensics_button_edge(bool pressed);
void forensics_button_level(bool pressed);

/* Write the FORENSICS_STATUS_APPENDIX_LEN summary bytes of the previous
 * life into out (the v3 payload appendix). */
void forensics_fill_status(uint8_t *out);

#endif /* _FORENSICS_H_ */
