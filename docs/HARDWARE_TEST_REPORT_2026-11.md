# Goodix GF3268 — Hardware Test Report (2026-11-08 / 2026-11-09)

## Result

**✅ A previously unregistered finger was enrolled under Linux, stored as a new Type-4 record, matched over fresh connections, bound through the existing goodixsdcp driver and verified by fprintd.**

The existing fingerprint remained usable. An unregistered control finger was rejected. This report records the successful result and the intermediate failures so that future work does not repeat the earlier incorrect TPM/lockout assumptions.

---

## 1. Initial State and Scope

| Item | Observed Value |
|---|---|
| Machine | Honor MagicBook Art 14 |
| Host distribution | CachyOS |
| USB ID | `27c6:6f94` |
| Sensor / MCU | `GF3268` / `GM188B0` |
| Firmware / algorithm | `01010032` / `1.04.05.` |
| USB interface / endpoints | Interface0, OUT01, IN83, maximum packet size64 |
| Existing templates | One Type-4 record |
| Existing Linux finger | Right thumb |
| New test finger | Right little finger, user-confirmed never registered before |
| Negative control | Right ring finger, user-confirmed unregistered |

USB access worked as the normal user through existing device access rights. fprintd was initially inactive. No package, PAM setting, installed driver or MCU firmware was replaced for the experiment. Device serials, Windows SIDs and actual enrollment identifiers are intentionally omitted from this public report.

---

## 2. Offline Evidence Before Sensor Writes

The local research archive contained newer September prototypes that were not described in the public July/August handover. Their existence and printed success messages did not establish a successful enrollment.

The investigation instead checked existing source code, driver disassembly and raw USB captures:

- The regular `goodixmoc` parser accepted the real GF3268 `d0`, `a6`, `a5` and `a1` response bodies. This established structural compatibility, not commit compatibility.
- The enrollment capture contained `a7/02 + 01 00 + one record`; the next list contained one fewer record, with exactly that entry removed.
- The deletion capture contained `a7/02 + 02 00 + two records`; the next list contained zero entries.
- The two successful Windows enrollment captures contained exactly thirteen successful `a0` updates. One required fourteen attempts because of a `72` overlap retry. Neither contained a `74` completion response.
- The five-success / eight-success parameter phases matched the Windows engine's inspected configuration and sample-count state machine.

Relevant disassembly observations from the locally obtained vendor DLLs:

| Module / VA | Observation |
|---|---|
| WBDI `0x18007d20b–0x18007d28d` | `a0` parser logs Overlay / PreOverlay |
| WBDI `0x18007d2ef–0x18007d444` | Quality / Coverage parsing belongs to `a2` |
| WBDI `0x18007d52a` | `a3` response interpreted as a duplicate check |
| Engine `0x180097835–0x180097852` | Zero `a0` status increments the accepted-sample counter |
| Engine `0x180097877–0x180097929` | `72/73` overlap handling; other nonzero status takes an error path |
| Engine `0x1800979a0` | Completion depends on the host sample counter reaching the configured target |
| Engine table `0x18012e010` | Inspected entry contains thirteen samples, split5+8, with100/80 overlap thresholds |

These addresses describe the local vendor binary build. They are not stable addresses for other driver versions. The association of that configuration entry with the tested firmware is supported by both saved Windows traces and the later hardware result; it is not a claim about every Goodix algorithm variant.

The existing implementation and Microsoft's published SDCP specification also identified the `e3/01` nonce exchanges as reconnects, not administrator-identity registration.

---

## 3. Isolated Regular goodixmoc Investigation — November 8

A separate libfprint build was prepared from the local1.94.5 baseline. It exposed only `27c6:6f94`, rejected firmware other than01010032, skipped probe/open USB resets and configuration uploads, and blocked `c0` and `a7` before constructing a transfer. A template-list failure could not trigger automatic storage repair.

The test harness loaded this separate library explicitly. It reserved a private reference path before enrollment, compared old/new record identities afterward, and included recovery handling for a commit that might succeed before a later API failure. The system library was not replaced.

| Attempt | Observation | Postcheck |
|---|---|---|
| Read-only open/list | Ordinary driver opened the device and read its template list | One original entry |
| First capture | `e0` and `a1` succeeded; `a2` never returned a sample | Cancelled; original preserved |
| Add missing `b0/02` before first capture | Eight updates accepted; `a2=c0` ended the attempt | Original preserved |
| Treat `a2=c0` as no finger and re-arm | All thirteen updates accepted, `a3=00`, ordinary Type-1 `a4=9f` | One original entry, unchanged |

The `b0` result matters: preparation was missing before the first capture. It was not necessary to infer a TPM failure from a silent acquisition request. The `c0` retry behavior was already documented in the existing goodixsdcp implementation.

The final ordinary-driver attempt proved the complete acquisition path. It did **not** establish a working Type-1 commit. The numerical meaning of every firmware status remains unproven; `9f` is recorded as the observed rejection of this particular commit format.

An external [August hardware report](https://github.com/rs0x29a/Linux-on-HONOR-MagicBook-14-Pro-2026-AI_ZQC-P_M1010/issues/10) described working regular-driver enrollment for the same USB ID on another Honor model. Its [device notes](https://github.com/rs0x29a/Linux-on-HONOR-MagicBook-14-Pro-2026-AI_ZQC-P_M1010/blob/main/patch/fingerprint/README.md) list firmware01010106, while this sensor uses01010032. It motivated the isolated test but did not prove that a two-line ID patch was sufficient here.

---

## 4. SDCP Session Validation — November 9

Before involving the user again, `--session-check` established and verified two fresh SDCP sessions. It checked:

1. ECDH-derived server key confirmation.
2. Different session keys for fresh exchanges.
3. A reconnect nonce and the corresponding `HMAC(s, "reconnect\0" || nonce)`.
4. Exact preservation of the original stored record.

Observed summary:

```json
{
  "commit_attempted": false,
  "templates_before": 1,
  "fresh_sessions_and_reconnects_verified": true,
  "accepted_samples": 0,
  "templates_after": 1,
  "original_records_preserved": true
}
```

No fingerprint acquisition or commit occurred during that check.

---

## 5. Successful New Enrollment

After the user confirmed readiness, the new right little finger was captured with the corrected thirteen-update policy. Reconnect MACs were checked before samples. `a3` reported no duplicate, and **one** Type-4 commit was attempted with the enrollment identifier calculated from the current session key and the original `a1` nonce.

The sensor accepted the commit. Public summary, with identifiers omitted:

```json
{
  "commit_attempted": true,
  "fresh_sessions_and_reconnects_verified": true,
  "commit_confirmed": true,
  "accepted_samples": 13,
  "templates_before": 1,
  "templates_after": 2,
  "original_records_preserved": true,
  "new_record_confirmed": true
}
```

The new record contained the expected32-byte enrollment identifier. Every byte of the original record remained present. The process retained private before/prepared/after metadata, using exclusive0600 files synchronized to disk. No private reference content was published.

---

## 6. Matching, Target Resolution and Negative Control

The first target-check implementation incorrectly required the prepared random account field to equal the stored account field. The device had replaced that field while retaining the expected enrollment identifier. A match could therefore be reported as “some finger matched, target did not.”

The corrected check resolves the actual sensor record by enrollment identifier, then compares the returned match record with it. A regression test covers this distinction. This correction concerns host-side record association; it did not require rewriting or reenrolling the template.

One individual touch returned no match, and one earlier check timed out waiting for a new touch. With a fresh, flat central placement, the new stored record matched:

```json
{
  "capture_quality": 39,
  "capture_coverage": 100,
  "matched_any": true,
  "matched_target": true,
  "templates_unchanged": true
}
```

The unregistered right ring finger was then used as a negative control:

```json
{
  "capture_quality": 31,
  "capture_coverage": 83,
  "matched_any": false,
  "matched_target": false,
  "templates_unchanged": true
}
```

These are individual validation observations, not a statistical false-acceptance/false-rejection study. The match checker validates transport and record association; it does not claim full Windows-style match-token attestation.

---

## 7. Linux Integration and Existing-Finger Preservation

The existing system-wide goodixsdcp driver was used without replacement:

```text
fprintd-enroll -f right-little-finger
  → enroll-stage-passed
  → enroll-completed

fprintd-verify -f right-little-finger
  → verify-match (done)

fprintd-verify -f right-thumb
  → verify-match (done)
```

fprintd listed both the right little finger and the original right thumb. The new entry was therefore usable through the ordinary Linux verification service, and the existing access path still worked.

The new template was created by Linux using its own SDCP session key. No Windows session, TPM key extraction or new Windows enrollment was involved in this test. The already provisioned Type-4 identity metadata was reused. This distinction is essential: the result demonstrates **additional enrollment on a provisioned sensor**, not first-time provisioning from an empty store.

---

## 8. Automated Checks and Limits

The public experimental tools have **40 passing offline tests** (38 original experiment checks and two additional public-package key guards):

- 14 metadata-probe tests.
- 23 SDCP enrollment-policy/session/public-key-configuration tests.
- 3 match/target-resolution tests.

The original goodixmoc replay test could not run because `umockdev-run` was unavailable. It was skipped, not counted as passing. The isolated library and harness compiled successfully; the tested C driver changes generated no new warnings. The old baseline produced unrelated existing warnings elsewhere.

Still open:

- Reboot/cold-start persistence test.
- Recognition-rate and failure-recovery testing beyond this session.
- Empty-store provisioning.
- Native C-driver capture/commit integration.
- Firmware variants beyond01010032.
- Complete certificate-chain/firmware attestation and match-token verification.

For the runnable workflow and protocol details, see [Native Linux Enrollment](NATIVE_ENROLLMENT.md).

## Public Reproduction Note

The source export retains the original project's redacted static transport constants. The hardware results above used locally configured keys, not zero placeholders. Set the private `GOODIX_AES_KEY` and `GOODIX_MAC_KEY` for Python SDCP use. The public client's startup checks reject absent/zero keys; metadata probing remains available without them. The portable vendor-key emulator paths were checked offline and reproduced both working transport keys. No derived key values or vendor binaries were published. See the [key-setup instructions](NATIVE_ENROLLMENT.md#public-transport-key-setup-required-for-sdcp).
