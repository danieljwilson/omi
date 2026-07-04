#include "button.h"

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/l2cap.h>
#include <zephyr/bluetooth/services/bas.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/input/input.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/pm/device_runtime.h>
#include <zephyr/sys/poweroff.h>

#include "forensics.h"
#include "haptic.h"
#include "led.h"
#include "mic.h"
#include "speaker.h"
#include "transport.h"
#include "wdog_facade.h"

#include "imu.h"
#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
#include "offline_rec.h"
#include "sd_card.h"
#endif

LOG_MODULE_REGISTER(button, CONFIG_LOG_DEFAULT_LEVEL);

extern bool is_off;

static void button_ccc_config_changed_handler(const struct bt_gatt_attr *attr, uint16_t value);
static ssize_t button_data_read_characteristic(struct bt_conn *conn,
                                               const struct bt_gatt_attr *attr,
                                               void *buf,
                                               uint16_t len,
                                               uint16_t offset);

static struct bt_uuid_128 button_uuid =
    BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x23BA7924, 0x0000, 0x1000, 0x7450, 0x346EAC492E92));
static struct bt_uuid_128 button_characteristic_data_uuid =
    BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x23BA7925, 0x0000, 0x1000, 0x7450, 0x346EAC492E92));

static struct bt_gatt_attr button_service_attr[] = {
    BT_GATT_PRIMARY_SERVICE(&button_uuid),
    BT_GATT_CHARACTERISTIC(&button_characteristic_data_uuid.uuid,
                           BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
                           BT_GATT_PERM_READ,
                           button_data_read_characteristic,
                           NULL,
                           NULL),
    BT_GATT_CCC(button_ccc_config_changed_handler, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
};

static struct bt_gatt_service button_service = BT_GATT_SERVICE(button_service_attr);

static void button_ccc_config_changed_handler(const struct bt_gatt_attr *attr, uint16_t value)
{
    if (value == BT_GATT_CCC_NOTIFY) {
        LOG_INF("Client subscribed for notifications");
    } else if (value == 0) {
        LOG_INF("Client unsubscribed from notifications");
    } else {
        LOG_ERR("Invalid CCC value: %u", value);
    }
}
static const struct device *const buttons = DEVICE_DT_GET(DT_ALIAS(buttons));
static const struct gpio_dt_spec usr_btn = GPIO_DT_SPEC_GET_OR(DT_NODELABEL(usr_btn), gpios, {0});

static bool was_pressed = false;

// Using GPIO callback due to the lower priority of the input subsystem vs. storage.c's thread that prevents the
// callback from working properly.
#define BUTTON_CHECK_INTERVAL 40 // 0.04 seconds, 25 Hz

void check_button_level(struct k_work *work_item);

K_WORK_DELAYABLE_DEFINE(button_work, check_button_level);

#define DEFAULT_STATE 0
#define SINGLE_TAP 1
#define DOUBLE_TAP 2
#define LONG_TAP 3
#define BUTTON_PRESS 4
#define BUTTON_RELEASE 5

// 4 is button down, 5 is button up
static FSM_STATE_T current_button_state = IDLE;
static uint32_t inc_count_1 = 0;
static uint32_t inc_count_0 = 0;

static int final_button_state[2] = {0, 0};
const static int threshold = 10;

static void reset_count()
{
    inc_count_0 = 0;
    inc_count_1 = 0;
}
static inline void notify_press()
{
    final_button_state[0] = BUTTON_PRESS;
    LOG_INF("Button pressed");
    struct bt_conn *conn = get_current_connection();
    if (conn != NULL) {
        bt_gatt_notify(conn, &button_service.attrs[1], &final_button_state, sizeof(final_button_state));
    }
}

static inline void notify_unpress()
{
    final_button_state[0] = BUTTON_RELEASE;
    LOG_INF("Button released");
    struct bt_conn *conn = get_current_connection();
    if (conn != NULL) {
        bt_gatt_notify(conn, &button_service.attrs[1], &final_button_state, sizeof(final_button_state));
    }
}

static inline void notify_tap()
{
    final_button_state[0] = SINGLE_TAP;
    LOG_INF("Button single tap");
    struct bt_conn *conn = get_current_connection();
    if (conn != NULL) {
        bt_gatt_notify(conn, &button_service.attrs[1], &final_button_state, sizeof(final_button_state));
    }
}

static inline void notify_double_tap()
{
    final_button_state[0] = DOUBLE_TAP; // button press
    LOG_INF("Button double tap");
    struct bt_conn *conn = get_current_connection();
    if (conn != NULL) {
        bt_gatt_notify(conn, &button_service.attrs[1], &final_button_state, sizeof(final_button_state));
    }
}

static inline void notify_long_tap()
{
    final_button_state[0] = LONG_TAP; // button press
    LOG_INF("Button long tap");
    struct bt_conn *conn = get_current_connection();
    if (conn != NULL) {
        bt_gatt_notify(conn, &button_service.attrs[1], &final_button_state, sizeof(final_button_state));
    }
}

#define BUTTON_PRESSED 1
#define BUTTON_RELEASED 0

#define TAP_THRESHOLD 300     // 300 ms for single tap
#define DOUBLE_TAP_WINDOW 600 // 600 ms maximum for double-tap
#define LONG_PRESS_TIME 3000  // 3000 ms for long press (power off)

typedef enum {
    BUTTON_EVENT_NONE,
    BUTTON_EVENT_SINGLE_TAP,
    BUTTON_EVENT_DOUBLE_TAP,
    BUTTON_EVENT_LONG_PRESS,
    BUTTON_EVENT_RELEASE
} ButtonEvent;

static uint32_t current_time = 0;
static uint32_t btn_press_start_time;
static uint32_t btn_release_time;
static uint32_t btn_last_tap_time;
static bool btn_is_pressed;

static u_int8_t btn_last_event = BUTTON_EVENT_NONE;

/* GPIO read-fault tracking (pairent.10): gpio_pin_get_dt returning a
 * negative errno used to parse as "released" via the ==1 comparison, which
 * would silently swallow presses (and worse, fake a release mid-long-press)
 * for as long as the driver misbehaves. Hold the last good level instead,
 * and treat a sustained error streak as a hardware/driver fault worth an
 * attributed reboot — requested via the supervisor, never performed here
 * (this handler runs on the shared sysworkq). */
#define GPIO_ERR_LOG_INTERVAL 100    /* ~4 s of errors between repeat logs */
#define GPIO_FAULT_STREAK_LIMIT 250  /* ~10 s at the 40 ms poll cadence */
static uint32_t gpio_err_streak;
static bool last_stable_pressed;

void button_kick(void)
{
    if (is_off) {
        return;
    }
    /* k_work_reschedule is ISR-safe (the supervisor calls this from a
     * k_timer). It self-guards against double-submit: if the FSM work is
     * already pending this only moves the deadline forward, and if the
     * chain was lost (the wedge being healed) it re-arms it. */
    k_work_reschedule(&button_work, K_NO_WAIT);
}

void check_button_level(struct k_work *work_item)
{
    current_time = current_time + 1;

    /* Poll the pin level directly instead of trusting the edge ISR: in the
     * 2026-06-12 85-min freeze (ISSUES #92) this FSM provably kept running
     * (sysworkq alive, WDT fed) yet buttons were dead — consistent with
     * GPIO interrupt delivery dying. Polling keeps taps and long-press
     * power-off working through that failure class; the ISR is kept only
     * as a forensic edge counter. */
    int pin_raw = gpio_pin_get_dt(&usr_btn);
    bool pressed_now;
    if (pin_raw < 0) {
        gpio_err_streak++;
        /* First error and every ~100th: enough to see the fault and its
         * duration in a log capture without flooding at 25 Hz. */
        if (gpio_err_streak == 1 || (gpio_err_streak % GPIO_ERR_LOG_INTERVAL) == 0) {
            LOG_ERR("Button GPIO read failed (%d), %u consecutive", pin_raw, gpio_err_streak);
        }
        if (gpio_err_streak == GPIO_FAULT_STREAK_LIMIT) {
            /* Sustained fault: taps and long-press power-off are gone no
             * matter what we parse. Stamp the noinit health flag, then let
             * the ISR-timer supervisor do the attributed reboot on its next
             * tick — it owns the write-ahead reboot discipline and survives
             * whatever killed the GPIO driver. */
            forensics_health_flag(FHEALTH_GPIO_FAULT);
            forensics_request_reboot(FCAUSE_GPIO_FAULT);
        }
        /* Keep the last stable level: a read error is not a release. */
        pressed_now = last_stable_pressed;
        /* But never let a SYNTHESIZED held level accumulate press duration:
         * if the streak began while the button was physically down, the
         * user's release is invisible, and 75 held ticks (3 s) would reach
         * LONG_PRESS and power the device off — 7 s BEFORE the streak limit
         * above could request the attributed reboot, and from a state the
         * pre-pairent.10 parsing (error == released) could never power off
         * from. Advancing the press start alongside current_time freezes
         * the measured duration for the streak's length: a real long press
         * still lands once reads recover (the required hold merely
         * stretches by the outage), taps are unaffected (no level
         * transitions can happen while the level is synthetic), and a
         * sustained fault is the streak-limit reboot's job alone. */
        if (btn_is_pressed) {
            btn_press_start_time++;
        }
    } else {
        gpio_err_streak = 0;
        pressed_now = (pin_raw == 1);
        last_stable_pressed = pressed_now;
    }
    forensics_button_level(pressed_now);
    forensics_beat(FB_BUTTON_FSM);

    u_int8_t btn_state = pressed_now ? BUTTON_PRESSED : BUTTON_RELEASED;

    ButtonEvent event = BUTTON_EVENT_NONE;

    // Debouncing pressed state
    if (btn_state == BUTTON_PRESSED && !btn_is_pressed) {
        btn_is_pressed = true;
        btn_press_start_time = current_time;
    } else if (btn_state == BUTTON_RELEASED && btn_is_pressed) {
        btn_is_pressed = false;
        btn_release_time = current_time;

        // Check for double tap
        uint32_t press_duration = (btn_release_time - btn_press_start_time) * BUTTON_CHECK_INTERVAL;
        if (press_duration < TAP_THRESHOLD) {
            if (btn_last_tap_time > 0 &&
                (current_time - btn_last_tap_time) * BUTTON_CHECK_INTERVAL < DOUBLE_TAP_WINDOW) {
                event = BUTTON_EVENT_DOUBLE_TAP;
                btn_last_tap_time = 0; // Reset double-tap / single-tap detection
            } else {
                btn_last_tap_time = current_time;
            }
        }
    }

    // Check for single tap
    if (btn_state == BUTTON_RELEASED && !btn_is_pressed) {
        uint32_t press_duration = (btn_release_time - btn_press_start_time) * BUTTON_CHECK_INTERVAL;
        if (press_duration < TAP_THRESHOLD && btn_last_tap_time > 0 &&
            (current_time - btn_press_start_time) * BUTTON_CHECK_INTERVAL > TAP_THRESHOLD) {
            event = BUTTON_EVENT_SINGLE_TAP;
            btn_last_tap_time = 0;
        } else if ((current_time - btn_press_start_time) * BUTTON_CHECK_INTERVAL > TAP_THRESHOLD) {
            event = BUTTON_EVENT_RELEASE;
        }
    }

    // Check for long press
    if (btn_is_pressed && (current_time - btn_press_start_time) * BUTTON_CHECK_INTERVAL >= LONG_PRESS_TIME) {
        event = BUTTON_EVENT_LONG_PRESS;
    }

    // Single tap: flag a moment (works phone-free; BLE notify kept for the app)
    if (event == BUTTON_EVENT_SINGLE_TAP) {
        LOG_INF("single tap detected\n");
        btn_last_event = event;

        notify_tap();
#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
        offline_rec_add_marker();
#ifdef CONFIG_OMI_ENABLE_HAPTIC
        play_haptic_milli(60);
#endif
#endif
    }

    // Double tap: toggle SD-primary recording (works phone-free)
    if (event == BUTTON_EVENT_DOUBLE_TAP) {
        LOG_INF("double tap detected\n");
        btn_last_event = event;
        notify_double_tap();
#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
        offline_rec_toggle();
#ifdef CONFIG_OMI_ENABLE_HAPTIC
        play_haptic_milli(150);
#endif
#endif
    }

    // Long press, one time event
    if (event == BUTTON_EVENT_LONG_PRESS && btn_last_event != BUTTON_EVENT_LONG_PRESS) {
        LOG_INF("long press detected\n");
        btn_last_event = event;
        turnoff_all();
    }

    // Releases, one time event
    if (event == BUTTON_EVENT_RELEASE && btn_last_event != BUTTON_EVENT_RELEASE) {
        LOG_PRINTK("release detected\n");
        btn_last_event = event;
        notify_unpress();

        // Reset
        current_time = 0;
        btn_press_start_time = 0;
        btn_release_time = 0;
        btn_last_tap_time = 0;
    }
    if (event == BUTTON_EVENT_RELEASE) {
        current_button_state = GRACE;
    }

    k_work_reschedule(&button_work, K_MSEC(BUTTON_CHECK_INTERVAL));
    return 0;
}

static ssize_t button_data_read_characteristic(struct bt_conn *conn,
                                               const struct bt_gatt_attr *attr,
                                               void *buf,
                                               uint16_t len,
                                               uint16_t offset)
{
    LOG_INF("button_data_read_characteristic");
    LOG_PRINTK("was_pressed: %d\n", final_button_state[0]);
    return bt_gatt_attr_read(conn, attr, buf, len, offset, &final_button_state, sizeof(final_button_state));
}

static struct gpio_callback button_cb_data;

static void button_gpio_callback(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
    was_pressed = (gpio_pin_get_dt(&usr_btn) == 1);
    forensics_button_edge(was_pressed);
    LOG_INF("Button %s (GPIO callback)", was_pressed ? "pressed" : "released");
}

int button_regist_callback()
{
    int ret;

    // Configure GPIO as input with pull-up
    ret = gpio_pin_configure_dt(&usr_btn, GPIO_INPUT);
    if (ret < 0) {
        LOG_ERR("Failed to configure button GPIO (%d)", ret);
        return ret;
    }

    // Setup interrupt on both edges
    ret = gpio_pin_interrupt_configure_dt(&usr_btn, GPIO_INT_EDGE_BOTH);
    if (ret < 0) {
        LOG_ERR("Failed to configure button interrupt (%d)", ret);
        return ret;
    }

    // Register callback
    gpio_init_callback(&button_cb_data, button_gpio_callback, BIT(usr_btn.pin));
    gpio_add_callback(usr_btn.port, &button_cb_data);

    LOG_INF("Button initialized with GPIO interrupt");

    return 0;
}

int button_init()
{
    int ret;

    // Initialize the buttons device from evt
    if (!device_is_ready(buttons)) {
        LOG_ERR("Buttons device not ready");
        return -ENODEV;
    }

    // Enable runtime power management for the buttons device
    ret = pm_device_runtime_get(buttons);
    if (ret < 0) {
        LOG_ERR("Failed to enable buttons device (%d)", ret);
        return ret;
    }

    // Regist callback
    ret = button_regist_callback();
    if (ret < 0) {
        LOG_ERR("Failed to register buttons callback (%d)", ret);
        return ret;
    }

    return 0;
}

void activate_button_work()
{
    k_work_schedule(&button_work, K_MSEC(BUTTON_CHECK_INTERVAL));
}

void register_button_service()
{
    bt_gatt_service_register(&button_service);
}

FSM_STATE_T get_current_button_state()
{
    return current_button_state;
}

void turnoff_all()
{
    int rc;

    // Immediate feedback: LED off and haptic
    led_off();
    // Set is_off immediately so set_led_state() keeps LEDs off
    is_off = true;

#ifdef CONFIG_OMI_ENABLE_OFFLINE_STORAGE
    // Record that this shutdown was intentional (boot forensics)
    offline_rec_mark_clean_shutdown();
#endif

#ifdef CONFIG_OMI_ENABLE_HAPTIC
    play_haptic_milli(100);
    k_msleep(300);
    haptic_off();
#endif

    // Delays for stability
    k_msleep(1000);

    // // Enter the low power mode
    transport_off();
    k_msleep(300);

    // Always turn off microphone
    mic_off();
    k_msleep(100);

    // Turn off speaker if enabled
#ifdef CONFIG_OMI_ENABLE_SPEAKER
    speaker_off();
    k_msleep(100);
#endif

    // Turn off accelerometer if enabled
#ifdef CONFIG_OMI_ENABLE_ACCELEROMETER
    accel_off();
    k_msleep(100);
#endif

    if (is_sd_on()) {
        app_sd_off();
    }
    k_msleep(300);

    // Put the buttons device to sleep if button is enabled
#ifdef CONFIG_OMI_ENABLE_BUTTON
    pm_device_runtime_put(buttons);
    k_msleep(100);
#endif

    // Disable USB if enabled
#ifdef CONFIG_OMI_ENABLE_USB
    NRF_USBD->INTENCLR = 0xFFFFFFFF;
#endif

    // Log system power off
    LOG_INF("System powering off");

    // Configure usr_btn as input with interrupt to allow wake-up
    rc = gpio_pin_configure_dt(&usr_btn, GPIO_INPUT);
    if (rc < 0) {
        LOG_ERR("Could not configure usr_btn GPIO (%d)", rc);
        return;
    }

    rc = gpio_pin_interrupt_configure_dt(&usr_btn, GPIO_INT_LEVEL_LOW);
    if (rc < 0) {
        LOG_ERR("Could not configure usr_btn GPIO interrupt (%d)", rc);
        return;
    }
    rc = watchdog_deinit();
    if (rc < 0) {
        LOG_ERR("Failed to deinitialize watchdog (%d)", rc);
        return;
    }

    
    /* Persist an IMU timestamp base so we can estimate time across system_off. */
    lsm6dsl_time_prepare_for_system_off();
    k_msleep(1000);
    LOG_INF("Entering system off; press usr_btn to restart");

    // Power off the system using sys_poweroff
    sys_poweroff();
}

void force_button_state(FSM_STATE_T state)
{
    current_button_state = state;
}
