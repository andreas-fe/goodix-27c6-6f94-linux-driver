# Goodix GF3268 — Standby Recovery Correction (2026-11-09)

**✅ The reported “already open” failure was diagnosed, corrected and retested with KDE open across a real standby cycle.** The first wake/setup request timed out again in the repeated test; the new bounded retry recovered, standard verification worked and the device closed normally. No service restart or USB reset was needed after that wake.

---

## 1. User-Visible Failure

The notebook had worked with native KDE enrollment. It was then put to sleep while the KDE fingerprint dialog remained open. After waking, the dialog showed:

```text
Open failed with error: Device 27c6:6f94 is already open
```

The user confirmed that the dialog had been open during standby. This context was reproduced in the corrected short test. Merely leaving the dialog open is not enough to establish the root cause: the service log identifies the first failed initialization and the subsequent handle leak.

## 2. Actual Error Sequence

Times below are local CET on 2026-11-09; identifiers and unrelated user metadata are omitted.

| Time | Observation |
|---|---|
|15:30:01 | System enters s2idle standby |
|16:07:44 | Resume notification received by fprintd |
|16:07:47 | Driver opens USB/claims interface and sends initial `e1/04` |
|16:07:50 | Initial receive times out; driver reports open failure |
|Afterward | Further claims cannot enter driver initialization: GUsb is still open |

The inspected libfprint 1.94.5 baseline calls `g_usb_device_open()` before the driver's open callback. An unsuccessful `fpi_device_open_complete()` in that baseline does not close GUsb. The old driver also omitted release/close on its initialization-error path. This left the low-level handle open even though libfprint did not consider the logical device successfully opened. The next claim therefore hit GUsb's “already open” condition.

No acquisition, enrollment commit or deletion was reached by that failed open. After the blocked process was stopped, isolated open/list/close worked without a reset and showed all three templates. Runtime USB control was already `on` with autosuspend disabled; changing that setting was not a supported explanation or correction for the demonstrated handle leak.

## 3. Driver Correction

- Track whether interface 0 was claimed.
- On any initialization error, release that interface if owned, close the framework-opened GUsb handle, clear local suspend/reinitialization state and report the original failure.
- If claiming the interface itself fails, close GUsb before reporting the error too.
- Reset local open/retry state at the next open. Normal close clears interface ownership.
- Retry **only a timeout of the first idempotent `e1/04` setup request**, with at most two additional attempts separated by 300 ms. Each existing receive timeout remains 3 seconds. Exhaustion still reports failure, after complete release, so a later independent claim can reopen.

No general automatic retry of handshake/capture/commit writes was added. There is no automatic USB reset, configuration upload, storage repair, template deletion or sensor re-provisioning. In particular, the one-`a4` enrollment policy is unchanged.

The bounded setup retry handles a transient initial wake response; its finite budget is not a claim that arbitrary wake delays or every transport failure can be hidden. Correct failure cleanup is what prevents a persistent “already open” state if setup still fails.

## 4. Automated Regression Evidence

Five new tests run the **actual USB-type `FpDevice` open/close API**, including both framework and driver ownership, with link-time GUsb fakes:

| Scenario | Required Result |
|---|---|
| First setup timeout | One retry, then successful open/close |
| Every setup request times out | Exactly3 attempts, complete release, later same-object reopen succeeds |
| Setup reports disconnected | No timeout retry, complete release, later same-object reopen succeeds |
| Initialization list is malformed | Complete release after claim, later same-object reopen succeeds |
| Interface claim fails | Framework-opened GUsb closes; later same-object claim/open succeeds |

Every case requires balanced handle open/close and interface claim/release counts, unchanged stored records and zero capture updates, commits or deletes. Reopening reuses the exact same `FpDevice` and GUsb object; neither a daemon restart nor a reset is simulated.

A sixth new test starts an identify waiting for a finger, calls the actual suspend API, cancels the synthetic pending USB read through the real receive callback, and requires the task to remain paused. Resume must refresh the session, re-arm and complete normally. This verifies driver pause/resume control flow; it does not simulate physical USB power loss or a long system sleep.

**Passed:**51 public Python tests,19 native API simulations, libfprint SSM/device suites, native build and isolated hardware open/list. The installed working library was built with the same C logic and locally configured static transport keys; the public constants remain redacted.

## 5. Installed Hardware Reproduction

The corrected library was installed with operating-system administrator authentication and a private previous-library/fingerprint-reference backup. Two consecutive normal fprintd Claim/List/Release cycles passed and listed all three entries.

The user then repeated standby with the KDE fingerprint dialog open and no deliberate new enrollment:

| Time | Corrected Driver Observation |
|---|---|
|16:18:42 | System enters standby |
|16:18:47 | System resumes; same fprintd process receives resume notification |
|16:18:49 | Initial device setup starts |
|16:18:52 | First setup receive times out; driver logs `initial setup timed out; retry 1/2` |
|16:18:53 | Retry returns successfully; remaining initialization and list complete |
|16:18:54 | Standard identify returns `verify-match`; normal close follows |
|16:19:38 | Separate `fprintd-verify -f right-thumb` returns `verify-match`; normal close follows |

The user reported no error in the KDE dialog after wake. The dedicated thumb test used the original stored right thumb after closing that dialog. fprintd still listed right-index-finger, right-little-finger and right-thumb. The daemon did not need restarting between this wake and either successful match.

The repeated timeout is useful evidence: this was not merely a run in which the original triggering condition disappeared. The corrected driver actually entered and successfully completed its new recovery branch.

## 6. Scope and Remaining Checks

- The original failing sleep lasted about 38 minutes. The corrected observed reproduction slept about 5 seconds. A longer corrected sleep and repeated cycles remain appropriate follow-up tests; no long-duration reliability claim is made.
- Standard verification after wake passed. This correction did not perform another new-template enrollment or deletion after wake; those write paths retain their previous validation boundaries.
- Active identify pause/resume has new simulation coverage. Broader physical tests while an authentication operation is pending remain open.
- Cold boot and first-time provisioning of an empty sensor remain separate unverified areas.

The driver and tests are in `driver/` and `tests/native_goodixsdcp.c`. Build/test/install instructions and protected-library rollback are in [Native Driver Integration](NATIVE_DRIVER_INTEGRATION.md). Rollback of a library does not remove sensor templates or automatically restore old host references.
