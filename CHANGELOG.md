# Changelog — Goodix GF3268 Driver (`goodixsdcp`)

Latest changes first. Details can be found in `HANDOVER_COWORK.md` (section numbers).

## 2026-11-09 — Standby setup recovery and failed-open cleanup

**Problem:** With the KDE fingerprint dialog open across standby, the initial post-wake setup request timed out. The failed initialization leaked the GUsb handle/interface, so later claims returned “Device 27c6:6f94 is already open”.

**Fix:** Fully release failed opens and failed claims; clear local open/suspend state. Retry only an initial `e1/04` timeout, at most twice, without USB reset or capture/commit retries. Five USB-type actual-API regressions require balanced ownership and successful same-object reopening; an additional test checks active identify pause/session refresh across suspend/resume.

**Hardware:** The repeated short standby with KDE open hit the same first-request timeout. The new retry recovered, standard matching and close succeeded, and a separate original-thumb `fprintd-verify` passed. All three entries remain registered; no service restart was needed after wake.51 Python tests and 19 native simulations pass. A long corrected sleep matching the original approximately 38-minute failure remains untested.

Details: [Standby recovery report](docs/STANDBY_RECOVERY.md), HANDOVER Section 64.

## 2026-11-09 — Native C enrollment through KDE confirmed

**Result:** A new finger was enrolled directly in KDE using the updated system-wide `goodixsdcp` C driver. All thirteen native capture stages and commit/readback completed; standard fprintd verification accepted the new entry and the original right thumb. The previous two entries remain registered. Python capture and separate host bind are no longer needed for new fingerprints.

**Driver:** Fresh authenticated ECDH/SDCP sessions, verified reconnects, firmware guard, thirteen-update5+8 policy, one Type-4 commit and exact preservation/readback checks. Existing FpPrint representation is retained. Packet CRC/fragmentation/command-lifetime handling, cancellation/cleanup and targeted deletion were updated. Unclaimed device-only records are protected from fprintd automatic cleanup; clear-storage is not advertised.

**KDE correction:** The initial live attempt exposed a legacy identify no-match/lift-wait timeout before enrollment. The no-match path now completes immediately and reports once; an actual-API regression covers it. The subsequent KDE enrollment passed.

**Checks:** 51 Python tests, 13 actual-driver simulations, two libfprint suites, native build/API compatibility, hardware open/list/cancellation, KDE enrollment and new/old standard verification passed. Targeted deletion is simulation-tested; live GUI deletion, cold-start persistence and a fresh suspend test remain open. Existing Type-4 identity metadata and firmware 01010032 are required. Public transport-key redaction is retained; no private-key binary is included.

Details: [Native integration](docs/NATIVE_DRIVER_INTEGRATION.md), [enrollment guide](docs/NATIVE_ENROLLMENT.md), [hardware report](docs/HARDWARE_TEST_REPORT_2026-11.md), HANDOVER Sections61–63. The entry below describes the earlier Python proof of concept.

## 2026-11-09 — New Linux enrollment confirmed on hardware

**Result:** A new right little finger, never registered in Windows Hello, was captured and committed under Linux on GF3268 firmware `01010032`. It was then matched over fresh connections, bound through the existing goodixsdcp driver and accepted by fprintd. An unregistered ring finger was rejected; the existing right thumb still verified.

**Protocol corrections:**
- `a7/02` is a count+records deletion request, not identity registration.
- `a0=000000` counts as an accepted update. The tested sequence is thirteen successes, split5+8, with parameters `016464` then `016450`.
- `72/73` retry; `74` is not completion; `a3` is duplicate checking.
- `e3/01` is reconnect with nonce/MAC, not administrator authorization.
- Preparation before the first acquisition and proper `a2=c0` waiting enabled full capture.
- The regular Type-1 commit returned `9f`; a Type-4 commit using the negotiated SDCP enrollment MAC succeeded.

**Added:** Read-only metadata probe, guarded experimental SDCP enrollment client, target-specific match checker, isolated regular-driver investigation artifacts, 40 offline tests, detailed reproduction guide and hardware report. New public tools use the existing `protocol/` crypto module and English output. The intentional transport-key redaction is preserved; startup guards reject placeholders. Vendor-emulator import/DLL paths are made portable and checked offline against the compatible local DLL. No private reference files or new biometric captures are included.

**Scope:** Existing Type-4 identity metadata is reused. Empty-store provisioning, cold-start validation, complete attestation and native C capture integration remain open. The installed C driver's enrollment behavior is still bind. This result supersedes the earlier blanket TPM-only claim.

Details: [Enrollment guide](docs/NATIVE_ENROLLMENT.md), [hardware report](docs/HARDWARE_TEST_REPORT_2026-11.md), HANDOVER Sections 55–60.

## 2026-08-01 — Standby/Resume fixed at the root (validated)

**Problem:** After (prolonged) standby, the lock screen could only be unlocked via password. Log: `Device reported an error during identify: Cannot run while suspended.` + `ReleaseDevice failed: … still busy`.

**Cause:** A Verify action was already running when closing the lid. libfprint then sets the internal `is_suspended` flag. Because the driver had **no** `suspend`/`resume` vfuncs, libfprint fell back to the NOT_SUPPORTED path, set the abort reason to "Cannot run while suspended" and left the flag lingering → the next Verify attempt was rejected, the device remained "busy" (with subsequent faillock lockouts).

**Fix (in the driver):**
- `goodixsdcp.c`/`.h`: new vfuncs `dev_suspend` / `dev_resume` / `dev_cancel`.
- Dedicated `GCancellable` (`self->cancel`) for the long "wait for finger" reads; `dev_cancel` cancels it → all libfprint abort paths reach the read (pattern analogous to `fpcmoc`/`synaptics`).
- Command SSM extended with `GSDCP_CMD_SUSPENDED` / `GSDCP_CMD_RESUME`.
- Suspend **pauses** the read and acknowledges with `NULL` (no abort reason); Resume re-arms the read and reliably clears `is_suspended`.

**Validation (Hardware, 2026-08-01):** Real-world test passed — Lock → Suspend → Wake → Finger → unlocked on the first attempt; `journalctl -u fprintd` clean, no more "Cannot run while suspended".

**Note:** The previous fixes `system/60-goodix-gf3268-fp.rules` (USB autosuspend off) and `system/fprintd-resume.service` are therefore **no longer necessary** and remain documented only as an optional fallback.

Affects: `driver/goodixsdcp.c`, `driver/goodixsdcp.h`, `system/README.md`, `README.md`, `HANDOVER_COWORK.md` (Section 54). — HANDOVER §53/§54.

## Base (Previous Project State)

Native libfprint driver `goodixsdcp` for the Goodix GF3268 (`27c6:6f94`):
- **Transport Crypto** (fixed AES/HMAC session keys) + Goodix Framing (CRC8/CRC32), verified against traffic captures. — HANDOVER §36.
- **SDCP Handshake** (ECDH P-256 + SP800-108-KDF), live confirmed.
- **Verify/Identify** via `a2` Finger Detection + `a5` on-chip SDCP Match.
- **Enroll = Bind:** place a finger previously registered in Windows Hello → on-chip matched → registered as `FpPrint`. That was the historical workflow; the TPM-only conclusion in HANDOVER §40–52 is superseded by the validated Python SDCP enrollment path in §55–60.
- Integration into **fprintd/KDE/PAM** (Lock screen, Login, sudo).

Complete reverse engineering journey and limitations: `README.md` + `HANDOVER_COWORK.md`.
