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
#include "button.h"
#include "sd_card.h"
#include "transport.h"

LOG_MODULE_REGISTER(forensics, CONFIG_LOG_DEFAULT_LEVEL);

/* Implemented per-SoC; no public header declares it (zephyr lib/os/reboot.c
 * and sdk-nrf lib/fatal_error/fatal_error.c both carry this same extern). */
extern void sys_arch_reboot(int type);

extern bool is_off;
extern bool is_connected;

/* Bumped PRN4 -> PRN5 in pairent.10: struct forensics_noinit grew (heal
 * counters, reboot-attempt counter, health flags). The magic must change with
 * the layout, or the first boot after a DFU would parse the previous life's
 * OLD-layout bytes as the new layout and report garbage. A mismatch reads as
 * a cold boot — the correct degradation. */
#define FORENSICS_MAGIC 0x50524E35u /* "PRN5" */

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

/* Button-FSM supervision ladder (pairent.10). The 2026-07-01 incident proved
 * the 40 ms check_button_level chain can die while the sysworkq itself stays
 * alive (both WDT channels fed, FB_SYSWORKQ fresh) — the self-reschedule was
 * simply lost. That stall is usually recoverable by re-submitting the work,
 * so the ladder heals first and reboots only when healing demonstrably
 * failed: stale > 60 s -> ISR-safe re-kick (30 s apart, budget 2 per boot);
 * still stale > 150 s with the budget spent -> attributed reboot. The budget
 * is per boot, not per episode: an FSM that keeps dying after two revivals
 * has an underlying fault a reboot handles better than endless kicking. */
#define BUTTON_FSM_STALE_MS 60000u
#define BUTTON_FSM_HEAL_SPACING_MS 30000u
#define BUTTON_FSM_REBOOT_MS 150000u
#define BUTTON_FSM_MAX_HEALS 2u

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
    /* pairent.10 (magic bump PRN5). All are this-life state, zeroed by
     * forensics_boot; kept in noinit so they survive a sys_reboot that
     * half-fires and are readable in the post-DOG0 breadcrumb. */
    uint8_t button_heals;    /* supervisor re-kicks of the button FSM */
    uint8_t adv_heals;       /* audit resurrections of dead advertising */
    uint8_t reboot_attempts; /* write-ahead count of attributed sys_reboot
                              * calls; nonzero on a LATER tick means the
                              * reboot path itself is dead (backstop gate) */
    uint8_t health_flags;    /* FHEALTH_* bits (noinit mirror of the atomic
                              * health word; see health_flags below) */
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

/* First-wins reboot cause requested by a context that must not reboot inline
 * (button FSM on the sysworkq, connectability audit thread). The supervisor
 * executes it on its next tick, so all attributed reboots leave from one
 * place with the same write-ahead discipline. */
static atomic_t reboot_request;

/* Dog-starve backstop latch — read by both WDT feeders (wdog_facade.c). */
static atomic_t product_dead;

/* Probe quiesce handshake (pairent.10 review fix): set before the probe's
 * bt_hci_cmd_send_sync, cleared after it returns. ni.probe_state carries the
 * same information for POST-MORTEM attribution, but it is a plain noinit u8
 * with no ordering guarantees — this atomic is the LIVE synchronization
 * point the conn-audit escalation polls before bt_disable, so the disable
 * never runs concurrently with an in-flight sync HCI command. The probe
 * sets it BEFORE re-checking bt_ready, so once a suspender has observed
 * bt_ready==0 AND probe_hci_in_flight==0, the probe is provably parked and
 * cannot start another send until forensics_bt_ready(). */
static atomic_t probe_hci_in_flight;

/* Live health-flag word (pairent.10 review fix). ni.health_flags is set from
 * FOUR contexts (supervisor k_timer ISR, sysworkq via the button FSM, the
 * conn-audit thread, boot/main via wdog_facade), and `|=` on a plain u8 is a
 * non-atomic read-modify-write — an ISR set landing between another
 * context's load and store would silently drop a bit, and these bits are
 * the primary field-alarm surface. All writers OR into this atomic; the
 * supervisor tick, the fatal handler, and forensics_fill_status mirror it
 * into ni.health_flags so noinit persistence across a reset is preserved
 * (the mirror is a plain full-word store, not an RMW, and every reboot path
 * runs through one of those three mirror points first). */
static atomic_t health_flags;

/* Heal-spacing timestamp; plain static (within-life state only). */
static uint32_t last_button_kick_ms;

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

void forensics_bt_suspend(void)
{
    /* Clearing bt_ready both (a) makes the probe loop skip its HCI no-op
     * (bt_hci_cmd_send_sync against a closed transport is undefined-ish
     * territory we must not enter) and (b) disarms the PROBE_STUCK check,
     * which is gated on bt_ready — so a slow bt_disable/bt_enable cycle
     * cannot be misattributed as a netcore wedge. */
    atomic_set(&bt_ready, 0);
}

bool forensics_probe_in_flight(void)
{
    return atomic_get(&probe_hci_in_flight) != 0;
}

void forensics_health_flag(uint8_t mask)
{
    atomic_or(&health_flags, mask);
}

void forensics_request_reboot(uint8_t cause)
{
    (void) atomic_cas(&reboot_request, 0, cause);
}

void forensics_adv_healed(void)
{
    if (ni.adv_heals < UINT8_MAX) {
        ni.adv_heals++; /* single writer (conn-audit thread): plain RMW is fine */
    }
    atomic_or(&health_flags, FHEALTH_ADV_HEALED);
}

bool forensics_product_dead(void)
{
    return atomic_get(&product_dead) != 0;
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
    ni.health_flags = (uint8_t) atomic_get(&health_flags); /* mirror before reset */
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
    /* Mirror the atomic health word into noinit every tick (and therefore
     * ahead of every attributed reboot below, which leaves from this tick). */
    ni.health_flags = (uint8_t) atomic_get(&health_flags);

#ifdef CONFIG_OMI_ENABLE_BUTTON
    /* Button-FSM self-heal rung, run before the cause chain because it is a
     * side effect (a kick), not a verdict. k_work_reschedule is in the
     * ISR-safe subset of the k_work API, so calling button_kick() from this
     * k_timer context is legal. No logging here: this runs in ISR context
     * and the tick has always been log-free by design — the noinit heal
     * counter + FHEALTH_BUTTON_HEALED surface the event instead. */
    uint32_t btn_age = elapsed(now, ni.stamps[FB_BUTTON_FSM]);
    if (btn_age > BUTTON_FSM_STALE_MS && ni.button_heals < BUTTON_FSM_MAX_HEALS &&
        elapsed(now, last_button_kick_ms) >= BUTTON_FSM_HEAL_SPACING_MS) {
        ni.button_heals++;
        atomic_or(&health_flags, FHEALTH_BUTTON_HEALED);
        last_button_kick_ms = now;
        button_kick();
    }
#endif

    /* Deferred requests (GPIO fault, adv-dead escalation) outrank the
     * heartbeat heuristics: they are direct observations, not inferences. */
    uint8_t cause = (uint8_t) atomic_get(&reboot_request);

    if (cause != FCAUSE_NONE) {
        /* fall through to the reboot below */
    } else if (atomic_get(&bt_ready) && elapsed(now, ni.stamps[FB_HCI_PROBE]) > PROBE_STUCK_MS) {
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

#ifdef CONFIG_OMI_ENABLE_BUTTON
    /* Reboot rung of the button ladder: only after the heal budget is spent
     * AND the FSM stayed stale well past the last kick (60 s stale + kicks
     * at ~60/90 s + 60 s post-heal grace = 150 s). */
    if (cause == FCAUSE_NONE && btn_age > BUTTON_FSM_REBOOT_MS &&
        ni.button_heals >= BUTTON_FSM_MAX_HEALS) {
        cause = FCAUSE_BUTTON_FSM;
    }
#endif

#if defined(CONFIG_OMI_PRODUCT_DEAD_BACKSTOP) && defined(CONFIG_OMI_ENABLE_BUTTON)
    /* Last-resort dog-starve rung: everything below fires only when
     *   (a) an attributed sys_reboot was ALREADY attempted this boot
     *       (ni.reboot_attempts is written ahead of every sys_reboot below;
     *       observing it nonzero on a later tick proves the reboot path
     *       itself is dead), AND
     *   (b) the button FSM is stale with its heal budget spent, AND
     *   (c) the connectability audit is in its failing state
     * — i.e. the user can neither press a button nor connect a phone and we
     * demonstrably cannot soft-reset. Breadcrumb goes to noinit FIRST, then
     * the latch flips and both WDT feeders (wdog_facade.c) stop feeding, so
     * the SoC hard-resets via DOG0 within CONFIG_OMI_WATCHDOG_TIMEOUT_MS.
     * The reset arrives as reset code 2 (watchdog); forensics_boot sees the
     * surviving FHEALTH_PRODUCT_DEAD bit in noinit and reports
     * FCAUSE_PRODUCT_DEAD as the previous life's cause. */
    if (!atomic_get(&product_dead) && ni.reboot_attempts > 0 &&
        btn_age > BUTTON_FSM_REBOOT_MS && ni.button_heals >= BUTTON_FSM_MAX_HEALS &&
        transport_conn_audit_failing()) {
        atomic_or(&health_flags, FHEALTH_PRODUCT_DEAD);
        ni.health_flags = (uint8_t) atomic_get(&health_flags);
        ni.sup_stamp = now;
        atomic_set(&product_dead, 1);
    }
#endif

    /* Once the backstop is latched the feeds are already stopped and DOG0 is
     * on its way; sys_reboot provably failed on this boot already (that is a
     * latch precondition), so further attempts would only churn the
     * ni.cause/reboot_attempts breadcrumbs the post-mortem needs intact. */
    if (atomic_get(&product_dead)) {
        return;
    }

    if (cause != FCAUSE_NONE) {
        ni.cause = cause;
        /* Write-ahead: if this sys_reboot works, forensics_boot zeroes the
         * counter next life; if we are still ticking afterwards, the nonzero
         * counter arms the dog-starve backstop above. Saturate, never wrap:
         * a wrap back to 0 would silently disarm the backstop. */
        if (ni.reboot_attempts < UINT8_MAX) {
            ni.reboot_attempts++;
        }
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
        /* Publish in-flight intent BEFORE the gate check: a suspender that
         * clears bt_ready and then sees probe_hci_in_flight==0 must be able
         * to conclude the probe is parked. If this thread is preempted right
         * here, the suspender waits on the in-flight bit; when we resume,
         * the re-check below sees bt_ready==0 and backs out. Either
         * interleaving keeps bt_disable and the sync HCI send exclusive
         * (Zephyr atomics are full barriers, and this SoC is single-core). */
        atomic_set(&probe_hci_in_flight, 1);
        if (is_off || !atomic_get(&bt_ready)) {
            /* is_off: transport_off may be running bt_disable.
             * !bt_ready: the connectability audit is mid bt_disable/enable
             * cycle (forensics_bt_suspend) — probing a closed HCI transport
             * would fault, and the PROBE_STUCK check is disarmed anyway. */
            atomic_clear(&probe_hci_in_flight);
            continue;
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
        atomic_clear(&probe_hci_in_flight);
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
        if (ni.health_flags & FHEALTH_PRODUCT_DEAD) {
            /* The dog-starve backstop latched last life: the DOG0 reset that
             * followed is otherwise indistinguishable from a natural starve,
             * and ni.cause still holds whichever attributed sys_reboot
             * FAILED before the latch armed. The surviving health bit is the
             * only trace — fold it into the cause here, before the memset
             * below destroys it, so the reserved enum value actually
             * reaches the payload. Outranks the fatal-PC refinement: a latch
             * means the fatal path (if any) was part of the same death. */
            prev_cause = FCAUSE_PRODUCT_DEAD;
        } else if (prev_cause == FCAUSE_NONE && ni.fatal_flag) {
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
    /* pairent.10 append-only: CURRENT-life health (bytes 0..13 above are the
     * previous life; these two are this boot — the app alarms on them
     * without waiting for a reboot). Read from the atomic, which is always
     * current; ni.health_flags is only its noinit mirror. Mirror here too so
     * a reset arriving between supervisor ticks carries the freshest word. */
    ni.health_flags = (uint8_t) atomic_get(&health_flags);
    out[14] = ni.health_flags;
    out[15] = (uint8_t) (MIN(ni.button_heals, 15u) | (MIN(ni.adv_heals, 15u) << 4));
}
