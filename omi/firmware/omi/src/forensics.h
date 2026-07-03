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
 *
 * pairent.10 append-only extension — CURRENT-life health, not previous-life
 * (the app alarms on these live; after a reboot the story is already carried
 * by prev_cause + prev_stale_map). Existing bytes 0..13 are untouched; the
 * app parser reads the appendix append-only and tolerates extra bytes.
 * [14]    health_flags    u8    FHEALTH_* bits set this boot
 * [15]    heal_counts     u8    low nibble: button-FSM re-kicks this boot,
 *                               high nibble: advertising re-arms this boot
 *                               (each saturates at 15)
 */
#define FORENSICS_STATUS_APPENDIX_LEN 16

/* Current-life degraded-health bits (payload appendix byte [14]). Sticky for
 * the boot; the app treats any nonzero byte as alarm-worthy. */
#define FHEALTH_WDT_DEGRADED 0x01  /* watchdog init/channel install failed after retry */
#define FHEALTH_GPIO_FAULT 0x02    /* button GPIO reads hard-failing (>= ~10 s consecutive) */
#define FHEALTH_ADV_HEALED 0x04    /* connectability audit found advertising dead, revived it */
#define FHEALTH_BUTTON_HEALED 0x08 /* supervisor re-kicked a stale button FSM */
#define FHEALTH_GHOST_CONN 0x10    /* ghost-connection teardown attempted */
#define FHEALTH_BT_CYCLED 0x20     /* audit escalated to a bt_disable/bt_enable cycle */
#define FHEALTH_PRODUCT_DEAD 0x40  /* last-resort dog-starve latch armed (expect DOG0 next) */

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
    /* pairent.10 — appended only (the app parser tolerates new values). */
    FCAUSE_BUTTON_FSM = 8,  /* supervisor: button FSM stale, self-heal kicks exhausted */
    FCAUSE_GPIO_FAULT = 9,  /* button FSM: gpio_pin_get_dt hard-failing for ~10 s */
    FCAUSE_ADV_DEAD = 10,   /* connectability audit: adv restart failing repeatedly,
                             * even after a bt_disable/bt_enable cycle */
    FCAUSE_PRODUCT_DEAD = 11, /* dog-starve backstop latched: a prior attributed
                             * sys_reboot did not take AND button FSM + BLE
                             * connectability are both gone (write-ahead; the
                             * actual reset arrives as DOG0 once feeds stop) */
};

/* Consume the previous life's noinit state and re-arm for this life.
 * Must run before any forensics_beat() and after print_reset_reason(). */
void forensics_boot(uint8_t reset_code);

/* Start the HCI probe thread and the supervisor timer (end of main init). */
void forensics_start(void);

/* Called by transport once bt_enable() has succeeded; gates the probe. */
void forensics_bt_ready(void);

/* Pause the HCI probe (and the PROBE_STUCK supervisor check) around a
 * deliberate bt_disable/bt_enable cycle, so the probe never races a closed
 * HCI transport. Resume with forensics_bt_ready() once the host is back. */
void forensics_bt_suspend(void);

void forensics_beat(enum forensics_slot slot);

/* OR a FHEALTH_* bit into the current life's health flags (noinit-backed,
 * surfaced live in the status payload appendix byte [14]). Any context. */
void forensics_health_flag(uint8_t mask);

/* Ask the ISR-context supervisor to perform an attributed reboot on its next
 * tick (<= 5 s). First request wins; used by contexts that must not reboot
 * inline (button FSM on the sysworkq, connectability audit thread). */
void forensics_request_reboot(uint8_t cause);

/* Count an advertising resurrection (audit found adv dead, restart worked):
 * noinit counter for the payload heal nibble + FHEALTH_ADV_HEALED. */
void forensics_adv_healed(void);

/* Last-resort dog-starve latch (item: the supervisor's own sys_reboot path is
 * dead). When true, BOTH hardware WDT feeders stop feeding so the SoC resets
 * via DOG0 within CONFIG_OMI_WATCHDOG_TIMEOUT_MS. ISR-safe (atomic read). */
bool forensics_product_dead(void);

/* Button path is instrumented at both levels: the GPIO edge ISR (counter —
 * event-driven, never required to advance) and the polled FSM (level). */
void forensics_button_edge(bool pressed);
void forensics_button_level(bool pressed);

/* Write the FORENSICS_STATUS_APPENDIX_LEN summary bytes of the previous
 * life into out (the v3 payload appendix). */
void forensics_fill_status(uint8_t *out);

#endif /* _FORENSICS_H_ */
