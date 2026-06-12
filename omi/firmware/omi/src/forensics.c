/* Wedge forensics + supervision (ISSUES #92, fw 3.0.19+pairent.4).
 *
 * The 2026-06-12 field freezes wedge BLE + audio + SD while the main loop
 * and system workqueue keep running, so neither hardware watchdog channel
 * fires (85 min with no reset). Code-verified failure modes and how this
 * module observes each:
 *
 * - Netcore wedge with HCI traffic in flight: bt_hci_cmd_send_sync has no
 *   error return on timeout — it asserts after 10 s (Zephyr 3.7
 *   hci_core.c) and the fatal handler below reboots (SREQ). The handler
 *   records the faulting PC and the probe's write-ahead breadcrumb, so the
 *   next boot can attribute the reset instead of guessing.
 *
 * - Netcore wedge while idle: no HCI traffic flows, nothing notices. The
 *   probe thread issues a no-op HCI command every PROBE_INTERVAL_S, so an
 *   idle wedge becomes the assert-reboot above within ~25 s, attributed by
 *   probe_state == IN_FLIGHT. The probe must NOT run on the system
 *   workqueue (hci_core.c has a separate inline-drain assert branch for
 *   syswq callers, and it would stall the HCI TX processor).
 *
 * - BLE TX-completion loss with HCI alive (partial netcore wedge, or host
 *   conn-state corruption): the pusher parks forever in push_to_gatt on
 *   audio_tx_sem (K_FOREVER) and SD capture stops with it — the single
 *   pusher thread serializes SD-then-BLE per frame. The supervisor compares
 *   the codec and pusher heartbeats.
 *
 * - GPIO/ISR-level death (buttons dead while the FSM work item provably
 *   runs): edge-counter vs polled-level forensics discriminate; no reboot,
 *   the FSM now polls the pin so buttons keep working.
 *
 * All state lives in __noinit RAM: retained across SREQ / watchdog / lockup
 * / pin resets, lost at power-on or System OFF — the magic pair detects
 * that. The supervisor runs from a k_timer (ISR context) so it survives
 * every thread and workqueue wedge; its own death is covered by the
 * existing hardware WDT channels.
 */

#include "forensics.h"

#include <string.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/fatal.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>

#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
#include "offline_rec.h"
#endif
#include "sd_card.h"

LOG_MODULE_REGISTER(forensics, CONFIG_LOG_DEFAULT_LEVEL);

/* Implemented per-SoC; no public header declares it (zephyr lib/os/reboot.c
 * and sdk-nrf lib/fatal_error/fatal_error.c both carry this same extern). */
extern void sys_arch_reboot(int type);

extern bool is_off;
extern bool is_connected;

#define FORENSICS_MAGIC 0x50524E34u /* "PRN4" */

#define PROBE_INTERVAL_S 15
/* Probe interval + the host's 10 s HCI command timeout + worst-case 15 s
 * rpmsg vring-full sleep + margin. Normally the HCI assert reboots us long
 * before this trips; it covers the residual non-asserting path (probe stuck
 * in bt_hci_cmd_create's K_FOREVER buffer allocation). */
#define PROBE_STUCK_MS 75000u
/* Codec emitted frames this recently = the audio pipeline is active now.
 * AAD legitimately suspends PDM in quiet rooms, so mic/codec staleness
 * alone must never reboot — every check is gated on upstream freshness. */
#define UPSTREAM_FRESH_MS 30000u
/* Codec kept producing for this long after the pusher's last consumed
 * frame = pusher is parked (the 85-min wedge signature). */
#define PUSHER_LAG_MS 45000u
#define CODEC_STALL_MS 120000u
#define SD_STALL_MS 120000u
#define SUPERVISOR_PERIOD_S 5
#define SUPERVISOR_BOOT_GRACE_S 120
/* A subsystem this much older than the death uptime is reported stale. */
#define STALE_BITMAP_MS 60000u

enum probe_state {
    FPROBE_BT_NOT_READY = 0,
    FPROBE_OK = 1,
    FPROBE_IN_FLIGHT = 2,
};

struct forensics_noinit {
    uint32_t magic;
    uint32_t magic_inv;
    uint32_t stamps[FB_SLOT_COUNT];
    uint32_t sup_stamp;     /* supervisor tick = uptime-at-death recorder */
    uint32_t button_edges;  /* GPIO edge ISR invocation counter */
    uint32_t fatal_pc;
    uint8_t pin_level;      /* last FSM-polled button level */
    uint8_t probe_state;    /* enum probe_state, write-ahead breadcrumb */
    uint8_t cause;          /* enum forensics_cause, written before reboot */
    uint8_t flags;          /* bit0 recording, bit1 connected */
    uint8_t fatal_flag;
};

static struct forensics_noinit ni __noinit;

/* Previous life, summarized at boot for the v3 payload appendix. */
static uint32_t prev_uptime_ms;
static uint8_t prev_cause;
static uint16_t prev_stale_map;
static uint8_t prev_probe_state;
static uint8_t prev_flags;
static uint8_t prev_button;
static uint32_t prev_fatal_pc;

static atomic_t bt_ready;

K_THREAD_STACK_DEFINE(probe_stack, 2048);
static struct k_thread probe_thread_data;

static inline uint32_t elapsed(uint32_t later, uint32_t earlier)
{
    return later - earlier; /* wrap-safe for monotonic u32 uptime */
}

void forensics_beat(enum forensics_slot slot)
{
    ni.stamps[slot] = k_uptime_get_32();
}

void forensics_button_edge(bool pressed)
{
    ARG_UNUSED(pressed);
    ni.button_edges++;
}

void forensics_button_level(bool pressed)
{
    ni.pin_level = pressed ? 1 : 0;
}

void forensics_bt_ready(void)
{
    ni.stamps[FB_HCI_PROBE] = k_uptime_get_32();
    ni.probe_state = FPROBE_OK;
    atomic_set(&bt_ready, 1);
}

/* Replaces sdk-nrf's CONFIG_RESET_ON_FATAL_ERROR handler (omi.conf sets it
 * =n): identical reset behavior, plus the noinit breadcrumb that lets the
 * next boot attribute the reset (the HCI "Controller unresponsive" assert
 * leaves no other trace). */
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf)
{
    ARG_UNUSED(reason);
    ni.fatal_flag = 1;
    ni.fatal_pc = (esf != NULL) ? esf->basic.pc : 0;
    ni.sup_stamp = k_uptime_get_32();
    LOG_PANIC();
    LOG_ERR("Resetting system");
    sys_arch_reboot(0);
    CODE_UNREACHABLE;
}

static void supervisor_tick(struct k_timer *timer)
{
    ARG_UNUSED(timer);

    if (is_off) {
        return; /* power-off in progress: stand down */
    }

    uint32_t now = k_uptime_get_32();

    ni.sup_stamp = now;
    bool recording = false;
#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
    recording = offline_rec_enabled();
#endif
    ni.flags = (recording ? 0x01 : 0x00) | (is_connected ? 0x02 : 0x00);

    uint8_t cause = FCAUSE_NONE;

    if (atomic_get(&bt_ready) && elapsed(now, ni.stamps[FB_HCI_PROBE]) > PROBE_STUCK_MS) {
        cause = FCAUSE_PROBE_STUCK;
    } else if (elapsed(now, ni.stamps[FB_CODEC]) < UPSTREAM_FRESH_MS &&
               /* Signed: the pusher stamp normally leads the codec stamp by
                * a few ms, so an unsigned difference would wrap. */
               (int32_t) (ni.stamps[FB_CODEC] - ni.stamps[FB_PUSHER]) > (int32_t) PUSHER_LAG_MS) {
        cause = FCAUSE_PUSHER_STALL;
    } else if (elapsed(now, ni.stamps[FB_CODEC_IN]) < UPSTREAM_FRESH_MS &&
               elapsed(now, ni.stamps[FB_CODEC]) > CODEC_STALL_MS) {
        /* Gated on FB_CODEC_IN (post-AAD), NOT FB_MIC: with
         * CONFIG_OMI_ENABLE_T5838_AAD the VAD drops frames inside the mic
         * callback during silence, so PDM delivery alone does not imply
         * the codec has anything to emit. */
        cause = FCAUSE_CODEC_STALL;
    }
#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
    /* Armed only after SD boot init: mount + cleanup + the lfs_fs_gc
     * allocator pre-warm legitimately run minutes on a near-full card,
     * and the worker's first loop heartbeat comes after all of it. */
    else if (is_sd_on() && sd_is_boot_ready() &&
             elapsed(now, ni.stamps[FB_SD_WORKER]) > SD_STALL_MS) {
        cause = FCAUSE_SD_STALL;
    }
#endif

    if (cause != FCAUSE_NONE) {
        ni.cause = cause;
        sys_reboot(SYS_REBOOT_COLD);
    }
}

K_TIMER_DEFINE(supervisor_timer, supervisor_tick, NULL);

static void probe_thread_fn(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (!atomic_get(&bt_ready)) {
        k_sleep(K_SECONDS(1));
    }

    for (;;) {
        k_sleep(K_SECONDS(PROBE_INTERVAL_S));
        if (is_off) {
            continue; /* transport_off may be running bt_disable */
        }
        /* Write-ahead: if the netcore is unresponsive this call never
         * returns — it asserts at +10 s and the fatal handler reboots.
         * IN_FLIGHT at next boot is the attribution. */
        ni.probe_state = FPROBE_IN_FLIGHT;
        (void) bt_hci_cmd_send_sync(BT_HCI_OP_READ_BD_ADDR, NULL, NULL);
        /* Any return — even an error status — proves the controller is
         * servicing HCI. */
        ni.probe_state = FPROBE_OK;
        ni.stamps[FB_HCI_PROBE] = k_uptime_get_32();
    }
}

void forensics_boot(uint8_t reset_code)
{
    bool valid = (ni.magic == FORENSICS_MAGIC) && (ni.magic_inv == ~FORENSICS_MAGIC);

    if (valid) {
        uint32_t death = ni.sup_stamp;
        for (int i = 0; i < FB_SLOT_COUNT; i++) {
            if ((int32_t) (ni.stamps[i] - death) > 0) {
                death = ni.stamps[i];
            }
        }

        prev_uptime_ms = death;
        prev_cause = ni.cause;
        if (prev_cause == FCAUSE_NONE && ni.fatal_flag) {
            if (ni.probe_state == FPROBE_IN_FLIGHT) {
                /* HCI command TX is processed on the system workqueue in
                 * Zephyr 3.7, so a >=10 s syswq stall with a probe pending
                 * hits the same "Controller unresponsive" assert. The
                 * syswq feed runs every 2 s; an age beyond 8 s at fatal
                 * time means the syswq was stalled — blame the app core,
                 * not the netcore. (ni.sup_stamp is the fatal handler's
                 * own timestamp.) */
                uint32_t syswq_age = elapsed(ni.sup_stamp, ni.stamps[FB_SYSWORKQ]);
                prev_cause = (syswq_age > 8000u) ? FCAUSE_FATAL_PROBE_SYSWQ_STALL
                                                 : FCAUSE_FATAL_PROBE_INFLIGHT;
            } else {
                prev_cause = FCAUSE_FATAL_OTHER;
            }
        }

        prev_stale_map = 0;
        for (int i = 0; i < FB_SLOT_COUNT; i++) {
            if (elapsed(death, ni.stamps[i]) > STALE_BITMAP_MS) {
                prev_stale_map |= (uint16_t) (1u << i);
            }
        }

        prev_probe_state = ni.probe_state;
        prev_flags = (uint8_t) (ni.flags | 0x04); /* bit2 = noinit was valid */
        prev_button = (uint8_t) ((ni.pin_level ? 0x80 : 0x00) | (ni.button_edges & 0x7F));
        prev_fatal_pc = ni.fatal_flag ? ni.fatal_pc : 0;
    } else {
        prev_uptime_ms = 0;
        prev_cause = FCAUSE_NONE;
        prev_stale_map = 0;
        prev_probe_state = FPROBE_BT_NOT_READY;
        prev_flags = 0;
        prev_button = 0;
        prev_fatal_pc = 0;
    }

    LOG_INF("Forensics: reset code %u, prev life %s (uptime %u ms, cause %u, stale 0x%04x, "
            "probe %u, fatal_pc 0x%08x)",
            reset_code,
            valid ? "recovered" : "lost (cold boot)",
            prev_uptime_ms,
            prev_cause,
            prev_stale_map,
            prev_probe_state,
            prev_fatal_pc);

    /* Re-arm for this life. */
    memset(&ni, 0, sizeof(ni));
    ni.magic = FORENSICS_MAGIC;
    ni.magic_inv = ~FORENSICS_MAGIC;
    uint32_t now = k_uptime_get_32();
    for (int i = 0; i < FB_SLOT_COUNT; i++) {
        ni.stamps[i] = now;
    }
    ni.sup_stamp = now;
}

void forensics_start(void)
{
    k_tid_t tid = k_thread_create(&probe_thread_data,
                                  probe_stack,
                                  K_THREAD_STACK_SIZEOF(probe_stack),
                                  probe_thread_fn,
                                  NULL,
                                  NULL,
                                  NULL,
                                  K_PRIO_PREEMPT(12),
                                  0,
                                  K_NO_WAIT);
    k_thread_name_set(tid, "hci_probe");

    k_timer_start(&supervisor_timer, K_SECONDS(SUPERVISOR_BOOT_GRACE_S), K_SECONDS(SUPERVISOR_PERIOD_S));

    LOG_INF("Forensics supervision armed (probe %u s, grace %u s)",
            (unsigned int) PROBE_INTERVAL_S,
            (unsigned int) SUPERVISOR_BOOT_GRACE_S);
}

static void put_le32(uint8_t *out, uint32_t v)
{
    out[0] = v & 0xFF;
    out[1] = (v >> 8) & 0xFF;
    out[2] = (v >> 16) & 0xFF;
    out[3] = (v >> 24) & 0xFF;
}

void forensics_fill_status(uint8_t *out)
{
    put_le32(out, prev_uptime_ms);
    out[4] = prev_cause;
    out[5] = prev_stale_map & 0xFF;
    out[6] = (prev_stale_map >> 8) & 0xFF;
    out[7] = prev_probe_state;
    out[8] = prev_flags;
    out[9] = prev_button;
    put_le32(out + 10, prev_fatal_pc);
}
