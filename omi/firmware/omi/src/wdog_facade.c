#include <zephyr/drivers/watchdog.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

#include "forensics.h"

LOG_MODULE_REGISTER(wdog_facade, CONFIG_LOG_DEFAULT_LEVEL);

#define WATCHDOG_TIMEOUT_MS CONFIG_OMI_WATCHDOG_TIMEOUT_MS

static const struct device *wdt_dev;
static int wdt_channel_id;

/* Second WDT channel fed from the system workqueue (Pairent).
 *
 * 2026-06-11 field freeze: main loop kept running (LED painted, main-loop
 * channel fed) while the system workqueue and BLE host were wedged — buttons
 * and reconnect dead for hours with no reset. The main-loop channel cannot
 * catch that class. This channel starves within WATCHDOG_TIMEOUT_MS whenever
 * the system workqueue stops turning, forcing a SoC reset (reset reason DOG0,
 * surfaced via the 19B10007 status payload). */
static int wdt_channel_sysworkq = -1;

static void sysworkq_feed_handler(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(sysworkq_feed_work, sysworkq_feed_handler);
#define SYSWORKQ_FEED_INTERVAL_MS 2000

static void sysworkq_feed_handler(struct k_work *work)
{
    ARG_UNUSED(work);
    forensics_beat(FB_SYSWORKQ);
    if (wdt_dev && device_is_ready(wdt_dev) && wdt_channel_sysworkq >= 0) {
        wdt_feed(wdt_dev, wdt_channel_sysworkq);
    }
    k_work_reschedule(&sysworkq_feed_work, K_MSEC(SYSWORKQ_FEED_INTERVAL_MS));
}

void watchdog_feed(void)
{
    if (wdt_dev && device_is_ready(wdt_dev)) {
        wdt_feed(wdt_dev, wdt_channel_id);
    }
}

int watchdog_init(void)
{
    int ret;
    struct wdt_timeout_cfg wdt_config;

    // Get watchdog device (nRF5340 has built-in watchdog)
    wdt_dev = DEVICE_DT_GET(DT_NODELABEL(wdt0));
    if (!device_is_ready(wdt_dev)) {
        LOG_ERR("Watchdog device not ready");
        return -ENODEV;
    }

    // Configure watchdog timeout
    wdt_config.flags = WDT_FLAG_RESET_SOC;         // Reset entire SoC on timeout
    wdt_config.window.min = 0U;                    // No minimum window
    wdt_config.window.max = WATCHDOG_TIMEOUT_MS;
    wdt_config.callback = NULL;                    // No callback, just reset

    // Install watchdog timeout
    wdt_channel_id = wdt_install_timeout(wdt_dev, &wdt_config);
    if (wdt_channel_id < 0) {
        LOG_ERR("Watchdog install failed: %d", wdt_channel_id);
        return wdt_channel_id;
    }

    // Second channel: system-workqueue liveness (must install before setup)
    wdt_channel_sysworkq = wdt_install_timeout(wdt_dev, &wdt_config);
    if (wdt_channel_sysworkq < 0) {
        LOG_WRN("Sysworkq watchdog channel install failed: %d", wdt_channel_sysworkq);
        // Non-critical: continue with the main-loop channel only
    }

    // Start watchdog
    ret = wdt_setup(wdt_dev, WDT_OPT_PAUSE_HALTED_BY_DBG);
    if (ret < 0) {
        LOG_ERR("Watchdog setup failed: %d", ret);
        return ret;
    }

    if (wdt_channel_sysworkq >= 0) {
        k_work_schedule(&sysworkq_feed_work, K_NO_WAIT);
    }

    LOG_INF("Watchdog initialized (timeout: %u ms, channels: main=%d sysworkq=%d)",
            WATCHDOG_TIMEOUT_MS,
            wdt_channel_id,
            wdt_channel_sysworkq);
    return 0;
}

int watchdog_deinit(void)
{
    k_work_cancel_delayable(&sysworkq_feed_work);
    return wdt_disable(wdt_dev);
}