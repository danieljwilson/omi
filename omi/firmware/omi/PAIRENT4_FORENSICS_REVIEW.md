# pairent.4 wedge-forensics — work description for adversarial review

**Branch:** `wedge-forensics-pairent4` @ `24d1d216a` (off `offline-recording` @ `1d961754a` = fw `3.0.19+pairent.3`)
**Target:** OMI CV1, nRF5340 dual-core, nRF Connect SDK 2.9.0 (sdk-zephyr `v3.7.99-ncs2`, sdk-nrf `v2.9.0`)
**Scope:** instrumentation + self-recovery for the ISSUES #92 field-freeze class. **Not** a fix for the freeze's first cause (still open); the goal is that the next freeze either self-resets in ≤60 s with an attributed cause, or names the dead subsystems in boot forensics.

This document is written **for an adversarial reviewer**. It states the load-bearing assumptions and where they could be wrong on purpose — do not treat it as a correctness claim. The "Attack surface" section lists where I think the residual risk is.

---

## 1. The problem (what the field evidence forces)

Three freezes + two fault-reboots over 2026-06-11/12. The defining incident (06-12 ~19:07 CEST, on pairent.3): **85 minutes** with BLE dead (no advertising, phone could not connect), buttons dead (incl. long-press power-off), SD audio capture stopped — but the LED kept painting (main loop alive) and **neither** existing hardware-WDT channel fired (main-loop channel + sysworkq channel, both 30 s). Recovery required a hardware pin reset. SD byte cross-check: usedBytes grew ~6.4 MB ≈ exactly the 27 min of pre-freeze recording then stopped → SD capture died at the wedge moment, not 85 min of silent recording.

Separately, twice that day the device self-rebooted with `resetReason = soft_reset` right after connect + time-sync + storage-drain activity.

## 2. Verification that drove the design (provenance)

Before writing code I ran an 8-reader code fan-out over the firmware + pinned SDK sources. Key adjudicated claims (all citations were checked against `v3.7.99-ncs2` / `v2.9.0`, fetched from GitHub — the SDK is not on the build host):

1. **The two existing WDT channels cannot see this class.** `wdog_facade.c` uses the raw Zephyr `wdt0` driver (not task_wdt), two channels, both `WDT_FLAG_RESET_SOC`, 30 s. Main-loop feed path touches nothing netcore-dependent. The sysworkq feed handler touches nothing either, but rides the system workqueue — so a turning sysworkq (WDT fed 85 min) proves no syswq work item was blocked in a BT/SD call > 30 s.

2. **Idle netcore death is unobservable; with HCI traffic it self-reboots.** `bt_hci_cmd_send_sync` (hci_core.c) has **no error return on timeout** — `k_sem_take(&sync_sem, HCI_CMD_TIMEOUT=10s)` then `BT_ASSERT_MSG("Controller unresponsive…")` → `k_oops` → (with `CONFIG_RESET_ON_FATAL_ERROR=y`) `sys_arch_reboot` → SREQ. So: a netcore wedge **with** HCI commands in flight reboots in ~10 s (= the two daytime soft_resets, which coincided with post-connect auto-procedures + time-sync + drain); a netcore wedge **while idle** generates no HCI traffic, never asserts → the 85-min class. The HCI TX processor runs on the syswq via `process_pending_cmd(K_NO_WAIT)`, which is why the syswq WDT kept being fed.

3. **The pusher parks forever; SD dies with it.** `transport.c` `pusher()` is the single consumer that writes SD **then** BLE per frame. `push_to_gatt` blocks on `k_sem_take(&audio_tx_sem, K_FOREVER)`; `audio_tx_sem` (cap `CONFIG_BT_CONN_TX_MAX-2` = 18) is refilled only by the BLE TX-complete callback `on_audio_tx_done`, which needs HCI Number-of-Completed-Packets from the netcore. Netcore wedge while connected+subscribed → 18 slots drain in <1 s → pusher parks → `write_to_storage()` never called again → SD stops at the wedge moment. No disconnect event ever resets the semaphore. This is the mechanism behind the 6.4 MB cross-check.

4. **"Buttons dead" refutes the netcore as the *sole* cause.** The button FSM (`button.c check_button_level`) runs as a `k_work_delayable` on the system workqueue (proven alive). Every `bt_gatt_notify` in the path is gated on `get_current_connection() != NULL`; marker/toggle/haptic are netcore-independent. So a BLE-dead device would still haptic+marker on a tap and flip the base LED on a recording toggle. Buttons being fully dead while the syswq turned localizes the failure to the **GPIO edge ISR** (`button_gpio_callback` sets `was_pressed`) or its GPIOTE delivery — a *second, app-core-local* failure, not the netcore. (Corollary verified: had a long-press reached `turnoff_all → transport_off`, the `bt_disable`/`bt_conn_disconnect`/`bt_le_adv_stop` sync HCI calls would have assert-rebooted in ~10–25 s under H — and none did, so no long-press was ever processed.)

5. **pairent.3's forensics carried zero signal.** `bootCount` and `prevShutdownClean` were pinned (1 and false) at every incident because the `"pairent"` settings subtree was loaded **only** by `transport_start()`'s `settings_load()` — behind `CONFIG_BT_SETTINGS` and **after** `offline_rec_init()` had already incremented `boot_count` from a `.bss` zero and zeroed the clean flag. Only `resetReason` (app-core `NRF_RESET->RESETREAS`) was trustworthy.

6. **A netcore WDT via config alone is impossible in NCS 2.9.0.** ipc_radio has zero watchdog code. `CONFIG_WATCHDOG=y` only builds the driver; nothing arms/feeds it. So the netcore path is handled by (a) rerouting netcore fatal/assert to a netcore-local reset and (b) an app-core HCI liveness probe; an app-core `sys_reboot` also resets the netcore (nRF5340 PS §4.10.5/§4.10.7).

## 3. What changed (file by file)

**New module — `src/forensics.c` / `forensics.h`:**
- `struct forensics_noinit` in `__noinit` RAM (survives SREQ/WDT/lockup/pin resets, lost on power-on/System-OFF — detected by a magic + inverse-magic pair). Holds 10 per-subsystem `k_uptime_get_32()` heartbeat stamps, a supervisor stamp, a GPIO-edge counter, a polled pin level, a probe state, a written-before-reboot cause, flags, and a fatal PC.
- `forensics_beat(slot)` — plain u32 store, callable from any context. Call sites: main loop (`FB_MAIN_LOOP`), sysworkq feed (`FB_SYSWORKQ`), button FSM (`FB_BUTTON_FSM`), mic handler pre-AAD (`FB_MIC`), post-AAD into codec (`FB_CODEC_IN`), codec output (`FB_CODEC`), pusher per consumed frame (`FB_PUSHER`), SD worker loop + LFS block-device callbacks (`FB_SD_WORKER`), storage loop (`FB_STORAGE`), HCI probe (`FB_HCI_PROBE`).
- **HCI probe thread** (`K_PRIO_PREEMPT(12)`, 2 KB): every 15 s, write `probe_state = IN_FLIGHT`, call `bt_hci_cmd_send_sync(BT_HCI_OP_READ_BD_ADDR, NULL, NULL)`, then `probe_state = OK` + stamp. On a dead controller this call never returns — it asserts at +10 s and the fatal handler reboots; `IN_FLIGHT` at next boot is the attribution. **Not** on the syswq (hci_core has a separate inline-drain assert branch for syswq callers + it would stall the HCI TX processor).
- **Supervisor** — a `k_timer` (ISR context, immune to thread/workqueue wedges; its own death is covered by the existing WDT channels), 5 s period, 120 s boot grace. Branches → cause-attributed `sys_reboot(SYS_REBOOT_COLD)`:
  - `PROBE_STUCK`: `bt_ready` && HCI probe stamp > 75 s old (covers the residual non-asserting path — probe stuck in `bt_hci_cmd_create`'s `K_FOREVER` buffer alloc).
  - `PUSHER_STALL`: codec fresh (<30 s) **and** codec stamp leads pusher stamp by >45 s (signed compare). The 85-min signature.
  - `CODEC_STALL`: post-AAD input fresh (<30 s, `FB_CODEC_IN` not `FB_MIC`) **and** codec output >120 s stale.
  - `SD_STALL`: `is_sd_on()` && `sd_is_boot_ready()` && SD-worker stamp >120 s.
- **Custom `k_sys_fatal_error_handler`** — replaces sdk-nrf's `CONFIG_RESET_ON_FATAL_ERROR` handler (app omi.conf now `=n`); identical reset behavior (`sys_arch_reboot(0)`) plus it records the faulting PC + the probe breadcrumb. `forensics_boot` then attributes a fatal: `IN_FLIGHT` + recent syswq → `FATAL_PROBE_SYSWQ_STALL` (HCI TX is on the syswq, so blame the app core), `IN_FLIGHT` + fresh syswq → `FATAL_PROBE_INFLIGHT` (netcore HCI dead), else `FATAL_OTHER`.
- `forensics_fill_status(out+20)` — the 14-byte v3 appendix.

**`src/lib/core/offline_rec.{c,h}`:** payload v2 (20 B) → v3 (34 B), version byte 2 → 3, append-only. `boot_count_latched` / `prev_clean_latched` snapshot taken in `offline_rec_init` so a later full `settings_load()` re-running the handler can't clobber the served values.

**`src/settings.c`:** `settings_load_subtree("pairent")` in `app_settings_init`, **before** `offline_rec_init` consumes it. This is the bootCount/prevShutdownClean fix (and un-breaks marker/rec_en restore-across-reboots when `CONFIG_BT_SETTINGS` is off).

**`src/lib/core/button.c`:** FSM now reads `gpio_pin_get_dt(&usr_btn)` directly each 40 ms tick instead of trusting `was_pressed` (the edge-ISR shadow). The ISR is demoted to a forensic edge counter. Long-press power-off now survives GPIO-interrupt death.

**`src/lib/core/transport.c`:** `forensics_beat(FB_PUSHER)` per consumed frame; `forensics_bt_ready()` after `bt_enable`; notify falls back to the 20-byte v2 prefix below MTU 37 (`OFFLINE_REC_STATUS_V2_LEN`) so the data-ready notify-on-subscribe isn't lost pre-MTU-exchange.

**`src/sd_card.c`:** `forensics_beat(FB_SD_WORKER)` at the worker loop top, **inside both LFS block-device callbacks** (so a multi-minute allocator scan that is *progressing* keeps the heartbeat fresh — a true SPI wedge does not), and a fresh seed right before `atomic_set(&sd_boot_ready, 1)`. New `sd_is_boot_ready()` accessor.

**`src/wdog_facade.c`, `src/main.c`, `src/lib/core/storage.c`:** heartbeat calls + `forensics_boot()`/`forensics_start()` wiring.

**`omi.conf`:** FW rev `pairent.3` → `pairent.4`; `CONFIG_RESET_ON_FATAL_ERROR=y` → `=n` (our handler takes over).

**`sysbuild.conf` + `sysbuild/ipc_radio.conf`:** netcore gets `RESET_ON_FATAL_ERROR=y` + `BT_CTLR_ASSERT_HANDLER=n` + `ASSERT=y`. **`SB_CONFIG_NETCORE_IPC_RADIO_BT_HCI_IPC=n`** suppresses Nordic's `overlay-bt_hci_ipc.conf`, which merges *after* the project fragment and would otherwise silently flip `BT_CTLR_ASSERT_HANDLER` back to `y`. The project fragment already replicates the overlay's functional content.

**`.github/workflows/build-firmware.yml`:** new gate greps the merged `build/ipc_radio/zephyr/.config` so the overlay-override can't regress (asserts `BT_CTLR_ASSERT_HANDLER != y`, `RESET_ON_FATAL_ERROR=y`, `ASSERT=y`, `IPC_RADIO_BT_HCI_IPC=y`). CI passed ("netcore config OK"), zero new warnings vs the pairent.3 baseline (47 = 47, identical set). Triggers: `push` to `offline-recording` or `wedge-forensics-*`, any firmware-touching `pull_request`, and `workflow_dispatch` — so the gate runs automatically on this branch and on the eventual merge PR, not only on manual dispatch.

## 4. Adversarial review already run (and fixed)

A 3-lens review (Zephyr/NCS API, supervisor false-positives, pairent.3 regression) with every non-nit finding independently verified. Confirmed + fixed before commit:
- **Netcore overlay merge-order** (critical): the headline `BT_CTLR_ASSERT_HANDLER=n` was a no-op until `SB_CONFIG_NETCORE_IPC_RADIO_BT_HCI_IPC=n` + CI gate.
- **SD-stall reboot loop on near-full cards** (critical): boot `lfs_fs_gc` runs minutes at the ~450 MB eviction steady state. Fixed by gating on `sd_boot_ready` + beating from LFS block-device callbacks.
- **VAD false-reboot in quiet rooms** (critical): `CONFIG_OMI_ENABLE_T5838_AAD=y` drops frames in the mic callback during silence. Fixed by gating `CODEC_STALL` on `FB_CODEC_IN` (post-AAD), not `FB_MIC`.
- **`sys_arch_reboot` missing extern** (major): no public header declares it; added the extern (mirrors sdk-nrf/Zephyr).
- **syswq-stall mislabeled as netcore** (minor): added `FATAL_PROBE_SYSWQ_STALL` demotion.

Rejected as unreachable (with reasons in the review): probe-vs-power-off race, MCUboot `__noinit` clobber, sub-40 ms tap regression, IPC-backpressure false assert.

## 5. Attack surface — where to point the adversary

These are the spots I am least certain about; an adversarial reviewer should attack here first:

1. **`__noinit` retention across the specific reset types on this exact partition map.** I assume System-ON SRAM survives SREQ/WDT/lockup/pin and is lost only on POR/brownout/System-OFF, with the magic pair catching the lost case. Verify against the real `pm_static.yml` / linker map that `ni` lands in a retained region and is not in MCUboot's scratch/RAM footprint. (Review checked layout and called it safe, but it's map-dependent.)
2. **Supervisor thresholds vs. real-world tails.** 45 s pusher lag, 120 s codec/SD, 75 s probe. Are there *legitimate* operations that exceed these with the gating condition true? Specifically: a very long storage drain, eviction of many files, lfs GC at the 460 MB watermark mid-recording (the bd-callback heartbeat is supposed to cover this — confirm the callbacks actually fire continuously during a GC scan), and any path where `FB_CODEC_IN` is fresh but the codec legitimately produces nothing for >120 s.
3. **The probe's self-detonation semantics.** On a dead controller the probe reboots the device by design. Confirm there is no state (DFU transfer, an in-flight OTA image swap, a critical SD write) where a probe-triggered reboot is harmful. mcuboot swap is post-reboot, but a reboot *during* a DFU *transfer* would abort it — is the probe gated enough? (I gate on `is_off`, not on "DFU in progress".)
4. **`bootCount` monotonicity claim.** Validate end-to-end on device: the latched value should climb across power cycles now, not stick at 1. Also confirm the `CONFIG_BT_SETTINGS`-on double-load (init load, then `transport_start` load) doesn't corrupt markers/rec_en (the handler re-runs).
5. **Payload v3 forward-compat in the wild.** The app parser was verified append-tolerant (rejects only <16 B, v2-gate is `length>=20 && version>=2`), but the firmware now emits version byte **3**. Confirm nothing app-side or in the storage-sync protocol asserts `version == 2` or `length == 20`.
6. **Behavior-subset claim.** The hard constraint is "pairent.3 behavior is a strict subset." The button FSM polling change is the one user-visible behavior delta. Confirm tap/double-tap/long-press detection windows are unchanged and that polling while the buttons device is runtime-suspended (in `turnoff_all`) reads as released, same as before.

## 6. How to read the forensics (v3 payload, char 19B10007, little-endian)

```
[0]      version (3)
[1]      recording (0/1)
[2]      storage state (0 ok / 1 low / 2 evicting)
[3]      marker count
[4..7]   used bytes (u32)
[8..11]  free bytes (u32)
[12..15] device UTC epoch (u32, 0 = unsynced)
[16]     reset reason: 0 power-on, 1 pin, 2 watchdog(DOG0), 3 lockup,
                       4 soft(SREQ), 5 other, 6 NFC, 7 wake-from-off
[17..18] boot count (u16, persisted, monotonic)
[19]     bit0 = previous shutdown clean
--- v3 appendix (previous life) ---
[20..23] prev uptime at death (u32 ms; 0 = cold/unknown)
[24]     prev cause: 0 none, 1 probe-stuck, 2 pusher-stall, 3 codec-stall,
                     4 sd-stall, 5 fatal+probe-in-flight (netcore HCI dead),
                     6 fatal-other (see PC), 7 fatal+syswq-stall (app core)
[25..26] prev stale bitmap (u16): bit0 main, 1 sysworkq, 2 button-fsm,
                     3 mic, 4 codec-in, 5 codec, 6 pusher, 7 sd-worker,
                     8 storage, 9 hci-probe
[27]     prev probe state (0 bt-not-ready, 1 ok, 2 in-flight)
[28]     prev flags: bit0 recording, bit1 connected, bit2 noinit-valid
[29]     prev button: bit7 last polled pin level, bits0..6 ISR edge count
[30..33] prev fatal PC (u32; 0 = no fatal)
```
The app currently parses + Sentry-surfaces only bytes 0–19. To read 20–33 today, read the raw characteristic via **nRF Connect (mobile)**. App-side parsing of the appendix is a deliberate follow-up.
