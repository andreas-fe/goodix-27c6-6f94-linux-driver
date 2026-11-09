# Goodix GF3268 — Enrollment After Deleting Every Finger (2026-11-09)

**✅ Confirmed on hardware: delete every stored finger → verify an empty sensor → enroll a new first finger entirely in KDE → verify and unlock.** No old fingerprint record or saved Windows SID was used to construct the new entry.

This closes the previously open **empty template store** case on the tested GF3268/firmware `01010032`. It does **not** establish first-time initialization of a factory-new or factory-reset sensor. These are different states.

---

## 1. Hardware and Starting State

Honor MagicBook Art 14, CachyOS/KDE, Goodix GF3268 USB `27c6:6f94`, firmware `01010032`, MCU `GM188B0`, algorithm `1.04.05.`. There were three on-chip records and corresponding fprintd registrations: right thumb, right little finger and right index finger.

Before deletion, the working library, Linux reference files and exact readable sensor-record metadata were saved privately. These are **not restorable biometric-template backups**. Restoring a library or host reference does not reconstruct a deleted fingerprint on the chip. The user confirmed that Windows boot and new Windows enrollment were available as an independent fallback. Windows was not used during the successful empty-store enrollment.

The standalone audit used only `d0/00` and `a6/00`; it did not delete, enroll, upload configuration or reset USB.

## 2. Staged Deletion and Independent Evidence

| Step | Observed Result |
|---|---|
| Delete only right index in KDE | fprintd device deletion completed and host slot was removed |
| Independent sensor read | `3 → 2` records |
| Resolve requested record | Saved host FpPrint account ID selected exactly the missing record |
| Preserve unrelated records | Both remaining 100-byte records byte-for-byte unchanged |
| Preserve unrelated host references | Thumb/little-finger files byte-for-byte unchanged |
| Delete remaining thumb and little finger in KDE | Both device deletions completed |
| Independent sensor read | Exactly zero records, same firmware |
| Host-reference check | All three previous host registrations absent |

This also validates real targeted deletion, beyond the earlier simulation-only coverage. The full deletion was performed deliberately by the user through KDE; no automatic clear-storage or garbage-collection deletion was introduced.

## 3. First Attempt: Precheck Error, Not a Failed Commit

The first empty-store KDE attempt failed immediately after the first touch. Native capture/commit had **not** started. fprintd first calls identify as an enrollment duplicate precheck. On this empty sensor, `a5` returned the one-byte value `03`.

The legacy handler turned that response into a center-finger retry. It reported the retry but also supplied the retry error to `fpi_device_identify_complete()`. libfprint forbids that domain in the completion call and converted it to a general error; KDE displayed an unknown error.

The correction has two parts:

1. If the list freshly read during open is empty, identify completes with no match **without acquiring a finger or sending `a5`**. A match is impossible in an independently confirmed empty store. Status `03` is not globally redefined as no match.
2. General verify/identify retry errors are delivered through the report callback and cleared before completion. The normal API retains the retry result instead of converting it to a general error.

Actual-libfprint-API regressions cover both behaviors. No native `a1/a0/a4`, new-identity generation or stored-template write occurred during this first failed precheck.

## 4. New Local Identity Instead of an Old Windows Record

When `a6` contains records, the established path still reuses their Type-4 metadata. When the count is zero, the driver constructs a new 100-byte Type-4 scaffold:

```text
6-byte observed record header: 62 00 43 04 f5 00
16-byte fresh prepared account ID
16 zero bytes
32-byte fresh SDCP enrollment MAC
1-byte identity length: 28
28-byte new SID-shaped local identifier
1 zero terminator
```

The identifier has the binary layout `S-1-5-21-<three CSPRNG-generated 32-bit values>-1000`. This follows the [Microsoft SID packet representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861); a valid encoding alone was only a hypothesis until hardware accepted the resulting record.

This is local sensor metadata, **not a Windows account, Windows Hello credential or authorization to release Windows credentials**. No original SID, cached template record, saved host reference or TPM secret is read by this branch. It is generated afresh after the sensor list has been validated as empty.

The remaining native flow is unchanged: fresh authenticated SDCP sessions, verified reconnect MACs, thirteen accepted updates split 5+8, duplicate check, exactly one Type-4 `a4`, and exact readback. The sensor-assigned account ID from readback becomes the normal FpPrint reference. A lost commit response can only be recovered by matching readback; the write is not repeated automatically.

## 5. Successful KDE Enrollment and Verification

The corrected driver logged:

```text
identify precheck: sensor list is empty, no match
empty-store trial: fresh local identity, no prior-record metadata
enroll progress: 1 of 13 ... 13 of 13
native enrollment completed successfully
Print for finger FP_FINGER_RIGHT_THUMB enrolled
enroll-completed
```

The user reported KDE success. A separate standard service check after closing the dialog returned:

```text
fprintd-verify -f right-thumb
  → verify-match (done)
```

The user subsequently confirmed practical screen unlocking too.

Independent read-only postcheck established:

- Exactly one record, after the earlier independently measured zero state.
- The new record differed from all original records.
- Its 28-byte identity differed from every original identity and had the generated local format.
- The new Linux thumb reference matched the actual stored account ID.
- Old index/little-finger host references remained absent.

The compile-time trial switch was then removed; the hardware-tested empty-store path is now ordinary native driver behavior. The regular build passed all 23 API simulations and the libfprint SSM/device suites and was installed. Its standard Claim/List/Release succeeded and retained the newly enrolled thumb. No special mode or helper is needed for normal KDE/fprintd enrollment.

## 6. Could Other Windows Fingers Explain the Result?

The sensor's own `a6` list contained **zero records** before enrollment. No additional listed Windows fingerprint template remained to match or supply the new record's identity. The new identity was independently shown to differ from the originals. Hidden copies outside this documented list are not needed to explain the observed operation, and the experiment offers no evidence for them.

However, deleting fingerprint records is **not a factory reset**. Firmware, vendor transport keys, device credentials, calibration or other provisioning state may remain. Windows may also retain host-side bookkeeping that is not a usable on-chip finger template. The test therefore demonstrates enrollment after full template deletion on a previously provisioned device; it does not prove the entire sensor can be initialized from factory state without Windows.

## 7. Final Scope and Reproduction

| Case | Status |
|---|---|
| Native additional-finger enrollment in KDE | Hardware passed |
| Targeted KDE deletion with unrelated-record preservation | Hardware passed |
| Delete every template, new local identity, first new enrollment | Hardware passed |
| New first-finger fprintd verification | Hardware passed |
| Practical unlock with that new first finger | User confirmed |
| Complete reboot and longer standby/unlock | User confirmed on the preceding driver state |
| Reboot/long standby specifically after this new local identity | Not separately confirmed yet |
| Factory-new/factory-reset initialization | Untested |
| Other firmware/models | Untested |
| Full attestation and complete match-token validation | Open |

Do not delete working fingerprints merely to install this release. Existing registrations stay compatible. For a deliberate reproduction, retain password access and an independent recovery path, use KDE for deletion, independently check the on-chip count, and attempt one native enrollment. Metadata snapshots cannot restore a fingerprint. Avoid blindly retrying an uncertain commit or attempting a generic storage repair.

Build and configuration: [Reproducible Build and Installation](BUILD_AND_INSTALL.md). Package/update behavior: [Maintenance](MAINTENANCE.md). Earlier protocol chronology remains in [Native Enrollment](NATIVE_ENROLLMENT.md) and HANDOVER Sections 55–65; this report supersedes the old statement that an existing Type-4 record is always required.
