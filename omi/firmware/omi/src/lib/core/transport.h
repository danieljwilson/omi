#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <zephyr/drivers/sensor.h>
#ifdef CONFIG_OMI_ENABLE_BATTERY
extern uint8_t battery_percentage;
#endif
/**
 * @brief Initialize the BLE transport logic
 *
 * Initializes the BLE Logic
 *
 * @return 0 if successful, negative errno code if error
 */
int transport_start();

/**
 * @brief Turn off the BLE transport
 *
 * @return 0 if successful, negative errno code if error
 */
int transport_off();

/**
 * @brief Broadcast audio packets over BLE
 *
 * @param buffer Buffer containing audio data
 * @param size Size of the audio data
 * @return 0 if successful, negative errno code if error
 */
int broadcast_audio_packets(uint8_t *buffer, size_t size);

/**
 * @brief Get the current BLE connection
 *
 * @return Pointer to current connection, or NULL if not connected
 */
struct bt_conn *get_current_connection();

/**
 * @brief Stamp "the GATT link demonstrably moved data just now".
 *
 * Called on notify TX completions, successful status/storage notifies and
 * inbound control writes. Feeds the connectability audit's ghost-connection
 * check (a conn with no GATT movement for 10+ min AND a host state that
 * disagrees with is_connected gets torn down). Any context; single aligned
 * atomic write.
 */
void transport_mark_gatt_activity(void);

/**
 * @brief Whether the connectability audit is currently in its failing state
 *        (bt_le_adv_start erroring repeatedly with no connection present).
 *
 * One of the three gates of the product-dead dog-starve backstop
 * (forensics.c supervisor). ISR-safe (atomic read).
 */
bool transport_conn_audit_failing(void);

#endif // TRANSPORT_H
