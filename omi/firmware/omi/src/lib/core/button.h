#ifndef BUTTON_H
#define BUTTON_H

#include <zephyr/input/input.h>
#include <zephyr/kernel.h>

typedef enum { IDLE, GRACE } FSM_STATE_T;

int button_init();
void activate_button_work();
void register_button_service();
void turnoff_all();
FSM_STATE_T get_current_button_state();

/* ISR-safe re-kick of the self-rescheduling button FSM work item, for the
 * wedge supervisor's self-heal rung (pairent.10): if check_button_level's
 * 40 ms reschedule chain is ever lost while the system workqueue survives
 * (the 2026-07-01 incident shape), resubmitting the work revives it without
 * a reboot. k_work_reschedule is in the ISR-safe k_work subset and
 * re-arming an already-pending item just moves its deadline, so a race with
 * a still-alive FSM is harmless (one early poll). */
void button_kick(void);

void force_button_state(FSM_STATE_T state);

// Input message queue from evt/button.c
extern struct k_msgq input_button;

#endif
