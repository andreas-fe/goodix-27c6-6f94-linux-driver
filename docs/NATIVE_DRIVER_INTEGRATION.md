# Goodix GF3268 — Native Driver Integration (2026-11-09)

**✅ New enrollment now runs entirely inside the libfprint C driver.** KDE completed a genuinely new enrollment through fprintd; the newly registered finger and original right thumb both passed standard verification afterward.

This replaces the previous Python-capture / C-host-bind workflow for additional new fingers. It does not implement first-time provisioning of an empty device.

---

## 1. Observed Standard-API Result

Tested on Honor MagicBook Art 14, CachyOS/KDE, USB `27c6:6f94`, GF3268 firmware `01010032`, MCU `GM188B0`, algorithm `1.04.05.`. The user selected the free **right-index-finger** slot in KDE. The slot name is host metadata; no claim about the physical finger beyond the user's test is inferred from it.

```text
KDE → fprintd EnrollStart
  → duplicate precheck: no match
  → 13 of 13 native driver updates accepted
  → Type-4 commit + readback
  → enroll-completed

fprintd-list
  → right-index-finger
  → right-little-finger
  → right-thumb

fprintd-verify -f right-index-finger
  → verify-match (done)

fprintd-verify -f right-thumb
  → verify-match (done)
```

The successful enrollment can only complete after native readback confirms exactly one added template, the expected enrollment identifier and byte-for-byte preservation of the originals. Both earlier host registrations remain listed. The original thumb was also physically verified; the old little finger was not physically reverified in this final native test.

No Python enrollment process, separate host bind, Windows call, TPM operation or PAM configuration change was used for this native enrollment.

## 2. Enrollment State Machine

1. Read `d0`; require GF3268 firmware `01010032`.
2. Read/validate `a6`; retain all original records and reuse valid existing Type-4 identity metadata. Empty/full stores fail explicitly.
3. Establish two fresh P-256 ECDH/SDCP connections, verifying server key confirmation. Clear private ECDH material after derivation.
4. Prepare `b0/02` and `e0/01`; get the fresh `a1` enrollment nonce.
5. Before each capture, verify `e3` reconnect MAC and prepare `b0/02`.
6. Acquire through `a2`; require quality ≥15 and coverage ≥65. No-finger status `c0` waits/re-arms.
7. Accept exactly thirteen successful `a0` responses: five with `016464`, eight with `016450`. A successful `000000` counts. `72/73` retries without advancing; `74` is an error.
8. Require `a3=00` (no duplicate).
9. Compute `HMAC(session_key, "enroll\0" || a1_nonce)`, construct the 100-byte Type-4 record and submit **one** `a4`.
10. Read `a6`; require exactly one added entry, one expected enrollment identifier and unchanged original records. Use the actual sensor-assigned account ID for the standard `FpPrint`.
11. Disable the power-button shield, clear session material and complete the ordinary enrollment API.

The driver exposes 13 stages; fprintd adds its identify precheck, making 14 on D-Bus. Existing `FpPrint` data remains `(y@ay@ay)` with the account field and SID metadata, preserving old references.

## 3. Error, Cancellation and Write Handling

- Firmware mismatch, malformed records and failed authentication stop before commit.
- Retry limits are 90 acquisition polls, 39 update attempts and 180 seconds total. Accepted captures are spaced to allow lifting/repositioning.
- Cancellation unwinds the cancellable read and sends shield-off cleanup. A hardware no-finger/cancel test preserved both original records before installation.
- The commit-attempt flag is set **before** submission. The driver never automatically sends a second `a4`. A lost response may be recovered only by successful matching readback.
- Failure to confirm storage is an error; it is not a reason to clear or reset the sensor. A post-commit failure can leave an unbound sensor record; recovery beyond a successful readback remains an area for further live testing.
- Packet reception checks CRC8/CRC32, assembles fragments and ignores ACKs. The old command SSM completes before its callback starts another command.
- Normal close disables the shield and releases USB. There is no automatic USB reset or MCU configuration upload.
- Verify/identify retain the suspend/resume path. Enrollment is cancelled across suspend instead of jumping into verify states. The updated native build has not had a fresh end-to-end suspend hardware test.

## 4. fprintd Precheck Correction

The first KDE attempt failed **before native capture**. The legacy identify path reported no match, then waited for another lift read. That read timed out and the error path attempted to report identify twice. No native commit occurred during these failed prechecks.

The corrected no-match path reports once and completes immediately. A regression test uses the actual identify API and requires one acquisition poll, immediate completion, no commit and no data modification. After installing this correction, KDE advanced through all native stages and completed successfully.

## 5. Targeted Deletion and Existing Records

The former delete callback only removed a host association. The updated callback reads current records, selects exactly the requested account, sends `a7/02` with LE count 1 plus that record, and verifies removal with all other record bytes preserved. Already absent records succeed idempotently.

Unclaimed device-only entries without user/finger metadata are refused. This protects Windows/device-only records from fprintd's automatic garbage collection. Unconditional clear-storage is not advertised. This can mean a full sensor fails enrollment rather than silently deleting an unclaimed record.

**Deletion is validated by simulation, not by a live KDE deletion in this session.** The successful new enrollment did not delete any existing finger. When deliberately deleting the last identity-bearing template, subsequent native enrollment cannot recreate the empty-store identity; initial provisioning remains unresolved.

## 6. Build, Tests and Installation

Use the [README build integration](../README.md#-building--installing-the-driver), a compatible libfprint 1.94.5 source/build tree and OpenSSL 3. The public static AES/HMAC transport constants remain zero placeholders. Configure them privately before a live build; Python key environment variables do not configure C. No binary carrying the working constants is published.

```bash
python3 -m unittest discover -s tests -q

# Point these at your separate, configured libfprint source/build trees:
python3 scripts/test_native_driver.py --source /path/to/libfprint --build /path/to/build
meson test -C /path/to/build fpi-ssm fpi-device --print-errorlogs
```

Observed results:

| Check | Result |
|---|---|
| Existing protocol/tool Python tests |40 passed |
| Actual C crypto with independent Python ECDH/KDF/HMAC peer |8 passed |
| Protected installer transactions |3 passed |
| Actual C driver API simulations |13 passed |
| libfprint SSM/device test suites |2 suites passed |
| Native build and old public API symbol preservation |Passed |
| Hardware open/list and no-finger cancellation |Passed |
| KDE native enrollment + new-finger/old-thumb verification |Passed |

The 13 driver simulations cover success, no-finger retry, overlap, bad reconnect, duplicate, rejected commit, lost commit reply, changed original, cancellation, wrong firmware, empty store, targeted deletion including refusal of unclaimed cleanup, and no-match precheck completion. Initial session acceptance/USB are simulated there; the separate eight crypto tests exercise actual C crypto against an independent synthetic peer.

The optional `scripts/install_native_driver.py` is specific to systems using `/usr/lib/libfprint-2.so.2.0.0`, systemd and `/var/lib/fprint` (the tested Arch/CachyOS layout). Inspect paths and ABI before use elsewhere. It requires administrator authentication, an explicit checksum and a **locally built** candidate:

```bash
sha256sum /absolute/path/to/build/libfprint/libfprint-2.so.2.0.0
sudo python3 scripts/install_native_driver.py \
  --candidate /absolute/path/to/build/libfprint/libfprint-2.so.2.0.0 \
  --expected-sha256 <the-reviewed-local-checksum>
```

The installer validates SHA/ELF before service changes, stops fprintd, backs up the old library and fingerprint references under root-private `/var/lib/goodixsdcp-backups/`, replaces the library atomically, refreshes the linker cache and starts fprintd. Installation failure restores the old library. It never provisions or clears sensor storage.

Rollback of the library:

```bash
sudo python3 scripts/install_native_driver.py \
  --restore-backup /var/lib/goodixsdcp-backups/<selected-backup>
```

Reference backups are private and **not restored automatically**: restoring old references can discard registrations added afterward. Library rollback also does not undo sensor enrollment. Distribution package upgrades can overwrite the custom library; rebuild/reinstall after a libfprint update.

## 7. Remaining Scope

- Reboot/cold-start persistence and a fresh suspend/resume validation of this build.
- Live targeted deletion/re-enrollment and broader error-recovery testing.
- Empty-store identity provisioning.
- Other firmware and models.
- Full certificate-chain/firmware attestation and complete match-token validation. Verified connection/reconnect MACs are not a claim of the entire Windows Hello security model.

Private sensor records, SIDs, enrollment/account identifiers, vendor binaries and working transport constants remain excluded from the public repository.
