# Goodix GF3268 — Native Linux Enrollment (Hardware-Validated)

**Status: ✅ Additional new fingers can be enrolled directly through KDE/fprintd with the native C driver on the tested GF3268 firmware.**

The later native integration on **2026-11-09** completed a new KDE enrollment and standard `fprintd-verify` successfully. It supersedes the Python-capture / C-bind workflow below. See [Native Driver Integration](NATIVE_DRIVER_INTEGRATION.md) for the implementation, validation and rollback details.

On **2026-11-09**, a right little finger that had never been registered in Windows Hello or Linux was captured, committed to the sensor, matched after fresh SDCP connections, bound to the Linux user, and successfully verified through **fprintd**. The original right thumb remained functional. An unregistered right ring finger was rejected.

This supersedes the previous conclusion that every new fingerprint enrollment is blocked by the Windows TPM. The successful experiment reused the identity metadata of an existing on-chip Type-4 record. **First-time provisioning of an empty sensor is still unresolved.**

---

## 📊 What Was Actually Verified

| Operation | Result | Evidence |
|---|---|---|
| Fresh SDCP connection | ✅ | Server key-confirmation MAC verified |
| New connection keys | ✅ | Two fresh connections produced different session keys |
| SDCP reconnect | ✅ | Response MAC checked against the request nonce |
| Capture a previously unregistered finger | ✅ | 13 successful `a0` updates |
| Duplicate check | ✅ | `a3` returned `00` |
| Store the new Type-4 template | ✅ | One `a4` attempt, successful response, record count `1 → 2` |
| Preserve the original fingerprint | ✅ | Exact original record preserved; old thumb subsequently verified |
| Match the new stored fingerprint | ✅ | Returned record matched the new persistent enrollment identifier |
| Reject an unregistered control finger | ✅ | Right ring finger returned no match |
| Bind the new template to Linux | ✅ | `fprintd-enroll` completed |
| Verify the new finger through fprintd | ✅ | `verify-match` |
| Cold boot / reboot persistence | ⏳ | Not tested in this session |
| First enrollment on an empty sensor | ❌ / Open | Not implemented or demonstrated |
| Direct new capture inside the C driver | ✅ | KDE completed thirteen native captures, commit and readback |
| New native fingerprint through standard verification | ✅ | `fprintd-verify -f right-index-finger` → `verify-match` |
| Existing fingerprint after native integration | ✅ | Original right thumb → `verify-match` |

**Tested hardware:** Honor MagicBook Art 14, USB `27c6:6f94`, sensor `GF3268`, firmware **`01010032`**, MCU `GM188B0`, algorithm `1.04.05.`. Interface `0`, Bulk OUT `0x01`, Bulk IN `0x83`, 64-byte maximum packet size. The host runs CachyOS; the existing custom `goodixsdcp` installation was retained.

The new tools deliberately reject other firmware versions. The same USB ID alone is not proof of protocol compatibility.

---

## 🧭 Current Standard Workflow

```text
KDE / fprintd EnrollStart
    ↓ fprintd duplicate precheck
native goodixsdcp C driver
    ↓ firmware guard + existing Type-4 identity snapshot
fresh authenticated SDCP sessions + thirteen accepted captures
    ↓ duplicate check + single Type-4 commit + exact readback
normal FpPrint / fprintd registration
    ↓ standard verification
Linux authentication
```

Build and install the updated C source as described in the [README](../README.md#-building--installing-the-driver). The public static AES/HMAC transport constants must be configured locally. Then use KDE System Settings → Users → Fingerprint, or:

```bash
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger
```

Choose the intended account and a free finger slot. KDE and fprintd use the same native driver. No external capture client, bind script, TPM call or Windows session is part of additional enrollment. Existing Type-4 identity metadata is still necessary. Existing host references retain their representation and do not need conversion.

The driver reports thirteen enrollment stages; fprintd exposes fourteen including its precheck. Low-quality or overlapping placements retry without advancing. Lift the finger completely between samples and vary its position.

---

## 🔬 Historical Python Workflow — Protocol Research

The following procedure records the earlier successful proof of concept. It created a template in Python, then used the **old** C driver to bind it to Linux. It is retained for protocol research and reproduction of the earlier experiment. The updated C driver performs new capture itself; its `fprintd-enroll` must no longer be treated as a bind-only command for a template created separately.

### 1. Prerequisites


- An existing, valid **Type-4 record** on the sensor. The tool reuses its identity metadata; it does not generate an initial Windows SID or provision an empty device.
- The exact tested firmware, `01010032`.
- Python 3, the Python `cryptography` package, and `libusb-1.0`.
- Privately configured static transport keys. The public crypto module intentionally contains zero placeholders; see the key-setup section below. These are distinct from the fresh ECDH-derived SDCP session keys.
- User access to the USB device, or appropriate administrative access where required by the local USB policy.
- Exclusive use of the sensor during standalone Python operations. Do not run competing fingerprint applications simultaneously.
- For the final Linux bind: the existing `goodixsdcp` driver and fprintd setup described in the main README.

The tools do not stop services, detach kernel drivers, install packages, or change device permissions automatically. A busy interface is reported as an error. Do not treat every error as permission to reset the sensor or clear its storage.

Run commands from the repository root. First create a private directory for local metadata:

```bash
mkdir -p experiments/private
chmod 700 experiments/private
```

### Public Transport-Key Setup (Required for SDCP)

The original public release deliberately redacts its static AES/HMAC transport constants. This update preserves that policy. The successful hardware tests used a locally configured crypto module and a locally configured C driver, not the public zero defaults.

The read-only `d0/a6` probe does not need those constants. Encrypted SDCP does: configure **`GOODIX_AES_KEY`** with the locally derived16-byte AES key (32 hex characters), and **`GOODIX_MAC_KEY`** with the32-byte HMAC key (64 hex characters), in the environment of the Python process. The new client rejects zero/invalid keys before opening USB for an SDCP operation. `GOODIX_KI` alone does not automatically populate the two key variables in the existing crypto module.

A compatible vendor adapter can be obtained as explained in [Windows Driver Adapter DLLs](../windows_binaries/README.md). The existing emulator now resolves its helper imports relative to `protocol/` and accepts an explicit DLL path:

```bash
# Requires the optional Python unicorn package; this is offline analysis.
export GOODIX_SENSOR_ADAPTER_DLL="/absolute/path/to/GoodixMocSensorAdapter.dll"
python3 protocol/emulate_ki.py
```

Its output contains locally derived keys. Keep that output private and transfer the values into your local environment; do not paste it into issues or commits. DLL offsets are build-specific. The portable emulator path was checked offline against the local compatible vendor DLL: both derived transport keys matched the working installation, without publishing the values.

If rebuilding the C driver from this public source, its deliberately redacted transport constants must also be configured locally. Exporting Python environment variables does not configure the compiled C driver. For native desktop enrollment, install the updated C source with locally configured transport constants. Retaining an older bind-only binary does not add native capture.

The offline tests use synthetic keys/peers and can pass without real transport keys. Passing them establishes software behavior, not live sensor connectivity with placeholders.

### 2. Inspect the Sensor Without Enrollment

```bash
python3 scripts/goodix_probe.py --live --list
```

This sends only `d0/00` and `a6/00`. Output includes firmware and template count, not template identifiers or user identity data.

The same program can check an existing capture offline:

```bash
python3 scripts/goodix_probe.py \
  --capture captures/goodix_handshake_and_enroll.pcapng
```

It validates Goodix CRC8/CRC32, handles fragmented packets and ACKs, and ignores device transfer padding. Some captured IN-transfer padding contains nonzero stale buffer data; it is not a second protocol message and is never printed.

### 3. Check the SDCP Session Before Asking for a Finger

```bash
python3 experiments/goodix_sdcp_trial.py --session-check
```

This requires no finger. It checks two new connections, key changes, reconnect MACs, and unchanged original records. It sends no `a1/a0/a3/a4`, no `a7`, and no `c0`.

Expected successful fields:

```json
{
  "commit_attempted": false,
  "fresh_sessions_and_reconnects_verified": true,
  "original_records_preserved": true
}
```

### 4. Capture a New Finger and Attempt One Commit

Choose a finger that is not already stored. The program does not perform a separate `a5` freshness precheck; it performs the `a3` duplicate check before storage. Use a **new reference filename for each deliberate experiment**:

```bash
python3 experiments/goodix_sdcp_trial.py --enroll \
  --reference experiments/private/new-finger.json
```

Lift the finger fully between samples and vary the position: center, tip, left edge, right edge and lower pad. The counter advances on accepted sensor updates, not on a fabricated coverage percentage.

The workflow creates three private files:

| File | Contents | When Written |
|---|---|---|
| `new-finger.json` | Exact original records and device version | Before enrollment begins |
| `new-finger.json.commit.json` | Prepared Type-4 commit record | Before `a4` |
| `new-finger.json.after.json` | Actual records returned by the sensor | During the postcheck |

Files are created exclusively with mode `0600` and synchronized to disk. Existing files are not overwritten. They contain sensitive identifiers and identity metadata, **not raw fingerprint images**. They must remain private. No SDCP session keys are saved there.

Success requires all of the following:

```json
{
  "commit_attempted": true,
  "commit_confirmed": true,
  "accepted_samples": 13,
  "templates_before": 1,
  "templates_after": 2,
  "original_records_preserved": true,
  "new_record_confirmed": true
}
```

The count values above describe the actual test; the important relationship is exactly **one additional record**, with every original record preserved.

**Do not automatically repeat enrollment after a timeout or uncertain commit response.** The device may have stored a template before the response was lost. The tool sends `a4` at most once and records the postcheck state for investigation. A failed cleanup is reported as an error even if the commit itself succeeded.

### 5. Match the New Entry After a Fresh Connection

```bash
python3 experiments/goodix_match_trial.py \
  --target-reference experiments/private/new-finger.json.commit.json
```

Lift the newly enrolled finger, then place it centrally on the sensor. `matched_any=true` alone is insufficient: another pre-existing fingerprint might have matched. Require **`matched_target=true`** and `templates_unchanged=true`.

The sensor assigns part of the stored account field during commit. The program therefore locates the actual stored record using its persistent 32-byte enrollment identifier, rather than requiring the prepared random account bytes to remain unchanged.

This checks the on-chip matching result and record association. It does not implement full Windows credential release or full cryptographic verification of the complete returned match-token structure.

### 6. Historical Bind with the Old Driver and Verification

After the standalone program has exited:

```bash
fprintd-enroll -f right-little-finger
fprintd-verify -f right-little-finger
```

For the old bind-only C driver used in the initial experiment, the first command bound the already stored fingerprint. Do not use this as a bind procedure with the updated native-capture driver. The second must finish with:

```text
Verify result: verify-match (done)
```

Also check a previously registered finger and an unregistered control finger. In the hardware session, the existing right thumb remained functional and the unregistered right ring finger was rejected.

---

## 🔬 The Corrected Protocol

### SDCP Connection and Reconnect

The successful implementation uses a fresh ECDH P-256 exchange and the reconstructed SP800-108 KDF:

```text
Z       = ECDH(client_private, server_ephemeral_public)
master  = KDF(Z, "master secret\0", client_nonce || server_nonce, 32)
keys    = KDF(master, "application keys\0", empty, 64)
s       = keys[0:32]
```

The server key-confirmation MAC is checked against the received transcript. A second fresh connection must produce a different session key.

The 32-byte `e3/02 → e3/01` exchanges are **reconnects**, not identity registration:

```text
request  = fresh random nonce
response = 00 || HMAC-SHA256(s, "reconnect\0" || nonce)
```

The response MAC is verified before continuing. Sending an `identify` HMAC over arbitrary bytes was merely another way to generate 32 bytes; it did not authorize an administrator identity.

### Capture Policy for Firmware 01010032

The Windows engine counts successful `a0` status bytes. Both successful captures contain exactly thirteen accepted updates:

| Phase | Accepted Updates | `a0/00` Payload |
|---|---:|---|
| First | 5 | `01 64 64` |
| Second | 8 | `01 64 50` |

Interpretation:

- `a0 → 00 XX YY`: successful update; `XX/YY` are Overlay/PreOverlay.
- **`a0 → 00 00 00` is also a successful update.** It is not a “no image” response.
- `72/73`: overlap retry; do not advance the accepted-sample counter.
- `74`: error in the inspected Windows path, not “capture complete.”
- `a2 → c0`: no finger; wait/re-arm within a bounded polling/time budget.
- `a3 → 00`: no duplicate found. `a3` is not a template-finalization command.

Quality/Coverage belongs to the `a2` result parser. Earlier notes confused it with `a0`. The count policy is verified for the captured firmware/configuration, not a universal rule for all Goodix devices.

The working per-sample sequence is:

```text
verified reconnect
    → b0/02 00
    → a2/00 00 0f 41 01
    → a0/00 <phase parameters>
```

The `b0/02` preparation is required before the first acquisition as well as later acquisitions. In the isolated regular-driver experiment, adding this missing first preparation changed the result from no capture to accepted samples.

### Type-4 Commit

The sensor supplies a fresh 32-byte nonce in `a1_response[1:33]`. The successful commit uses:

```text
enrollment_id = HMAC-SHA256(s, "enroll\0" || a1_nonce)
```

The 100-byte record has the following observed layout:

```text
6-byte header
16-byte prepared account field
16 zero bytes
32-byte enrollment_id
1-byte identity length = 28
28-byte existing identity metadata / SID
1 zero terminator
```

The stored-record flag in the header is normalized for commit. The sensor may assign different account bytes when storing the entry; the enrollment identifier remained unchanged and was used to verify the new record.

An ordinary Type-1 `goodixmoc` commit after the same thirteen-sample capture returned **`9f`**. The Type-4 commit with the SDCP-derived identifier succeeded. These observations establish working and rejected paths, not a complete firmware error-code dictionary.

---

## ⚠️ Corrections to Earlier Conclusions

**`a7/02` deletes records.** Its prefix `01 00` means a little-endian count of one record, not “register identity.” The saved Windows enrollment capture shows two entries before this command and one afterward; the exact supplied entry disappears. A separate deletion capture passes two records and leaves zero. Older experiments that called this authorization were deleting existing entries themselves. Their storage losses do not prove a TPM lockout.

**The old capture loop discarded valid updates.** Treating `00 00 00` as no frame and `74` as completion caused the host to diverge from the Windows state machine. Correct counting, phase parameters and preparation were sufficient to reach thirteen accepted updates.

**A TPM was not needed for the tested additional enrollment.** Linux generated its own session keys and enrollment MAC. The experiment does not prove that an empty device can be provisioned without Windows, nor does it make a Linux-created enrollment automatically authorized to release Windows Hello credentials. See [Microsoft's SDCP enrollment specification](https://github.com/microsoft/SecureDeviceConnectionProtocol/wiki/Secure-Device-Connection-Protocol#enrollment).

Older sections of `HANDOVER_COWORK.md` are retained as history. The November correction and validation sections supersede the earlier TPM-only, `a7` registration and `74` completion claims.

---

## 🧪 Tests, Artifacts and Remaining Work

```bash
python3 -m unittest discover -s tests -q
```

**51 Python tests pass in the public package** (40 protocol/tool checks, eight actual C crypto tests and three protected-installer tests). Thirteen additional native driver simulations run through the actual libfprint API using fake USB responses. The tests cover: metadata transport, CRC integrity, ACKs, fragmentation, resource cleanup, command boundaries, actual ECDH-derived server MACs, bad-MAC rejection, reconnect verification, the 13-update trace policy, private references, lost commit replies, cleanup failures and target-record resolution.

The isolated regular-driver investigation is included as `goodixmoc-6f94-safe.patch` and `goodixmoc_trial.c`. The patch targets the project's local libfprint-1.94.5 baseline and is a diagnostic artifact, not an upstream-ready or version-independent patch. It disables configuration writes, deletion and automatic resets for the tested device. Its Type-1 commit did not solve enrollment.

Remaining work:

1. Reboot/cold-start validation and longer-term recognition-rate measurements.
2. First-time provisioning with an empty template store.
3. Live GUI deletion/re-enrollment and broader suspend/failure-recovery validation of the updated driver (targeted deletion is currently simulation-tested).
4. Expand model/firmware coverage only after device-specific validation.
5. Complete certificate-chain/firmware attestation and full match-token verification before claiming the experimental client provides the entire Windows SDCP security model.

Detailed observations, including the unsuccessful intermediate attempts: [Hardware Test Report](HARDWARE_TEST_REPORT_2026-11.md).
