/* Watchdog bench self-test (THROWAWAY image, fw/wdt-selftest branch only).
 *
 * Why this exists: the two hardware WDT channels (wdog_facade.c — channel 0
 * fed by the main loop, channel 1 fed every 2 s from the system workqueue)
 * have never been observed firing on real hardware. The ISR-timer supervisor
 * path is field-proven (two attributed pusher_stall self-resets 2026-07-01);
 * the hardware dog is not. This module deliberately wedges the device twice,
 * in escalating severity, so the founder can watch the dog bite.
 *
 * PHASE 0 — hang ONLY the system workqueue. This reproduces the 2026-06-11
 * wedge class: buttons dead (the button FSM is a sysworkq delayable), the
 * sysworkq feed work never runs again, but the main loop stays alive and
 * keeps feeding channel 0 and painting the LED. A reset can therefore ONLY
 * come from the sysworkq channel — if channel 1 were broken or never
 * installed, the device would sit there forever with a live LED and dead
 * buttons, which is exactly the negative result we want to be able to see.
 *
 *   Implementation note — pend, don't spin: the task sketch said "k_busy_wait
 *   forever", but the system workqueue runs at priority -1 (cooperative;
 *   CONFIG_SYSTEM_WORKQUEUE_PRIORITY is not overridden anywhere in this
 *   build). A busy-spin in a cooperative thread on this single-core app CPU
 *   starves EVERY thread including the main loop, so both channels would
 *   starve and the test could false-pass on channel 0 alone. Pending on a
 *   never-given semaphore parks the sysworkq thread without consuming CPU —
 *   which is also the true signature of the field wedge (a workqueue parked
 *   on something that never completes, cf. push_to_gatt / audio_tx_sem).
 *
 * PHASE 1 — irq_lock() + nop loop. No thread runs, no ISR runs, nothing can
 * feed either channel and even the k_timer supervisor is dead. The nRF5340
 * WDT counts on its own low-frequency clock and its reset does not need the
 * CPU to service anything, so DOG0 must still fire within the 30 s window.
 * This is the last-resort backstop property.
 *
 * PHASE 2 — nothing. Normal firmware, app connectable, forensics readable.
 * The verdict (reset code observed at each phase boundary) is logged at boot
 * and each code should be 2 (watchdog).
 *
 * State lives in its own magic-validated __noinit struct, mirroring the
 * forensics pattern — the forensics struct itself is never touched. RAM is
 * retained across watchdog/soft/lockup resets and lost at power-on or System
 * OFF, so a long-press power-off + power-on restarts the test from phase 0.
 */

#include "wdt_selftest.h"

#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(wdt_selftest, CONFIG_LOG_DEFAULT_LEVEL);

extern bool is_off;

#define WDT_SELFTEST_MAGIC 0x57445431u /* "WDT1" */

/* Long enough for boot + BLE bring-up to settle and for a bench observer to
 * see the device running normally before the wedge; well past nothing —
 * deliberately WITHIN the 120 s supervisor boot grace so the ISR supervisor
 * cannot steal the reset from the watchdog (hang at T+60, dog bites by T+90,
 * supervisor arms at T+120; its thresholds are >=45 s anyway). */
#define WDT_SELFTEST_TRIGGER_S 60

enum wdt_selftest_phase {
    PHASE_HANG_SYSWORKQ = 0, /* first boot after flash / power-on */
    PHASE_HANG_EVERYTHING = 1,
    PHASE_DONE = 2,
};

struct wdt_selftest_noinit {
    uint32_t magic;
    uint32_t magic_inv;
    uint8_t phase;
    /* Reset code (main.c print_reset_reason) observed at the boot that
     * ENDED each hang phase; 0xFF = not reached yet. Both must read 2
     * (watchdog) for a pass. Survives to phase 2 so the verdict can be
     * logged after the whole sequence, not just per-boot. */
    uint8_t reset_code_after_phase0;
    uint8_t reset_code_after_phase1;
};

static struct wdt_selftest_noinit sni __noinit;

/* Never given: pending on it parks the system workqueue forever (phase 0). */
K_SEM_DEFINE(selftest_hang_sem, 0, 1);

static bool probe_quiesced;

bool wdt_selftest_probe_quiesced(void)
{
    return probe_quiesced;
}

static void selftest_trigger_handler(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(selftest_trigger_work, selftest_trigger_handler);

/* Runs ON the system workqueue at T+60 s. For phase 0 the handler itself is
 * the hang; for phase 1 it is merely the context that locks IRQs. */
static void selftest_trigger_handler(struct k_work *work)
{
    ARG_UNUSED(work);

    if (is_off) {
        /* Power-off raced the trigger: stand down without advancing the
         * phase. System OFF loses noinit RAM, so the next power-on restarts
         * cleanly at phase 0 either way. */
        LOG_WRN("WDT SELFTEST: device powering off, trigger skipped");
        return;
    }

    if (sni.phase == PHASE_HANG_SYSWORKQ) {
        LOG_ERR("WDT SELFTEST PHASE 0: hanging the SYSTEM WORKQUEUE now. "
                "Buttons will die, LED keeps painting, main loop keeps "
                "feeding channel 0. EXPECT hardware reset (DOG0) within %u ms",
                (unsigned int) CONFIG_OMI_WATCHDOG_TIMEOUT_MS);
        probe_quiesced = true;
        /* Let the deferred-log thread drain the announcement while other
         * threads still run, then advance the phase BEFORE wedging so the
         * next boot proceeds regardless of what resets us. */
        k_sleep(K_MSEC(250));
        sni.phase = PHASE_HANG_EVERYTHING;
        for (;;) {
            /* Never given and K_FOREVER never times out; the loop is belt
             * and braces against a spurious wake. */
            k_sem_take(&selftest_hang_sem, K_FOREVER);
        }
    }

    if (sni.phase == PHASE_HANG_EVERYTHING) {
        LOG_ERR("WDT SELFTEST PHASE 1: irq_lock + spin — hanging EVERYTHING "
                "(no threads, no ISRs, LED frozen). EXPECT hardware reset "
                "(DOG0) within %u ms — the WDT needs no CPU service",
                (unsigned int) CONFIG_OMI_WATCHDOG_TIMEOUT_MS);
        probe_quiesced = true;
        k_sleep(K_MSEC(250)); /* drain the log before the lights go out */
        sni.phase = PHASE_DONE; /* write-ahead: next boot is normal */
        (void) irq_lock();
        for (;;) {
            /* Empty infinite loops are UB the compiler may elide; a nop is a
             * side effect it must keep. k_busy_wait would also work but touches
             * the timer driver with IRQs locked — keep it primitive. */
            __asm__ volatile("nop");
        }
        CODE_UNREACHABLE;
    }

    LOG_INF("WDT SELFTEST: phase 2 — test sequence complete, normal operation");
}

void wdt_selftest_boot(uint8_t reset_code)
{
    bool valid = (sni.magic == WDT_SELFTEST_MAGIC) &&
                 (sni.magic_inv == ~WDT_SELFTEST_MAGIC) &&
                 (sni.phase <= PHASE_DONE);

    if (!valid) {
        /* Fresh flash, power-on or garbage: arm the whole sequence. */
        sni.magic = WDT_SELFTEST_MAGIC;
        sni.magic_inv = ~WDT_SELFTEST_MAGIC;
        sni.phase = PHASE_HANG_SYSWORKQ;
        sni.reset_code_after_phase0 = 0xFF;
        sni.reset_code_after_phase1 = 0xFF;
    } else if (sni.phase == PHASE_HANG_EVERYTHING) {
        /* This boot ended phase 0. */
        sni.reset_code_after_phase0 = reset_code;
    } else if (sni.phase == PHASE_DONE && sni.reset_code_after_phase1 == 0xFF) {
        /* This boot ended phase 1 (only record it once — phase 2 persists
         * across later soft resets, e.g. DFU of the next image). */
        sni.reset_code_after_phase1 = reset_code;
    }

    LOG_WRN("WDT SELFTEST image: boot in phase %u (reset code %u, state %s)",
            sni.phase,
            reset_code,
            valid ? "retained" : "fresh");

    if (sni.phase == PHASE_DONE) {
        bool p0 = (sni.reset_code_after_phase0 == 2);
        bool p1 = (sni.reset_code_after_phase1 == 2);
        LOG_WRN("WDT SELFTEST VERDICT: phase0 reset code %u (%s), "
                "phase1 reset code %u (%s) => %s",
                sni.reset_code_after_phase0,
                p0 ? "watchdog, PASS" : "NOT watchdog, FAIL",
                sni.reset_code_after_phase1,
                p1 ? "watchdog, PASS" : "NOT watchdog, FAIL",
                (p0 && p1) ? "PASS" : "FAIL");
    }
}

void wdt_selftest_start(void)
{
    if (sni.phase == PHASE_DONE) {
        LOG_INF("WDT SELFTEST: done — running as normal firmware "
                "(power cycle / System OFF to re-run the test)");
        return;
    }

    k_work_schedule(&selftest_trigger_work, K_SECONDS(WDT_SELFTEST_TRIGGER_S));
    LOG_WRN("WDT SELFTEST: phase %u hang armed for T+%u s",
            sni.phase,
            (unsigned int) WDT_SELFTEST_TRIGGER_S);
}
