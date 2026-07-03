#ifndef _WDT_SELFTEST_H_
#define _WDT_SELFTEST_H_

#include <stdbool.h>
#include <stdint.h>

/* Three-phase destructive watchdog bench self-test (THROWAWAY image only).
 *
 * Proves on real hardware that both hardware WDT channels actually fire and
 * are attributed as "watchdog" (RESETREAS_DOG0 -> reset code 2) in the
 * 19B10007 status payload. One flash, fully automatic:
 *
 *   PHASE 0 (first boot):  T+60 s, hang ONLY the system workqueue.
 *                          Main loop keeps feeding its channel; the sysworkq
 *                          channel starves -> DOG0 reset within 30 s.
 *   PHASE 1 (second boot): T+60 s, irq_lock() + infinite loop. Nothing can
 *                          feed anything, no ISR runs. The WDT counts on its
 *                          own low-frequency clock -> DOG0 reset within 30 s.
 *   PHASE 2 (third boot):  normal operation forever; connect the app and
 *                          read forensics (boot count +2, reset code 2).
 *
 * Phase state lives in a magic-validated __noinit struct of its own (the
 * existing forensics struct is NOT touched). Power cycle / System OFF loses
 * noinit RAM and restarts the test at phase 0; that is the documented way
 * to re-run it.
 *
 * Never merge this: gated behind CONFIG_PAIRENT_WDT_SELFTEST, enabled only
 * in omi.conf on the fw/wdt-selftest branch.
 */

/* Consume/validate the phase byte and record the reset code that ended the
 * previous phase. Call right after forensics_boot(). */
void wdt_selftest_boot(uint8_t reset_code);

/* Arm the T+60 s trigger (end of main init, next to forensics_start()). */
void wdt_selftest_start(void);

/* True once a hang is imminent/active: the forensics HCI probe must stand
 * down so its 10 s "Controller unresponsive" assert (HCI command TX runs on
 * the system workqueue in Zephyr 3.7) cannot reboot us as SREQ before the
 * watchdog gets its chance to prove itself. */
bool wdt_selftest_probe_quiesced(void);

#endif /* _WDT_SELFTEST_H_ */
