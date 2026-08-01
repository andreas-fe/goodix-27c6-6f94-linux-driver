# Standby/Resume Fix for the Goodix GF3268

**Symptom:** After (prolonged) standby, the lock screen can only be unlocked via password; the fprintd log displays `Device reported an error during identify: Cannot run while suspended.` and `ReleaseDevice failed: The device is still busy with another operation`. After a password login, the fingerprint scanner works again.

**Root Cause:** When closing the laptop lid, a Verify action is usually already running on the lock screen (waiting for a finger). During suspend, `libfprint` sets its internal `is_suspended` flag. Because the driver previously had **no** `suspend`/`resume` vfuncs, `libfprint` fell back to the NOT_SUPPORTED path: it aborted the action with the reason "Cannot run while suspended" and left the flag lingering → the next Verify attempt was rejected and the device remained "busy". Rapid lock screen retries additionally triggered the `faillock` account lockout.

**Fix (in the driver, included as of this version):** The driver now implements `suspend`/`resume`/`cancel`. On suspend, the running finger read is cleanly **paused** (using its own `GCancellable`, parking the SSM in `GSDCP_CMD_SUSPENDED`) and the suspend is acknowledged with `NULL` — this allows `libfprint` to keep the Verify action alive without setting an abort reason. On resume, the read is re-armed and the resume is acknowledged, which reliably clears the `is_suspended` flag.
→ This resolves the "Cannot run while suspended" error at its root. **No** additional udev/systemd intervention is required; it is sufficient to build and install the new driver version (see `../README.md`, Step 5), and then run `sudo systemctl restart fprintd`.

## Optional Additions (only if residual effects persist)

The following two measures are **no longer required** since the driver now handles suspend/resume natively. They remain documented as fallbacks.

### Fix A: Disable USB Autosuspend (prevents power-save drifts)

```bash
sudo cp 60-goodix-gf3268-fp.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```
Check (should be `on`):
```bash
for d in /sys/bus/usb/devices/*; do
  [ -f "$d/idVendor" ] && [ "$(cat $d/idVendor)" = "27c6" ] && \
  [ "$(cat $d/idProduct)" = "6f94" ] && echo "$d -> $(cat $d/power/control)"
done
```

### Fix B: Restart fprintd on resume (forces a clean re-open)

```bash
sudo cp fprintd-resume.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable fprintd-resume.service
```

## Test
Put the notebook into standby (preferably for a few hours), wake it up, and place a finger on the lock screen. Expectation: Unlocking works on the first attempt, without needing a password login first.

If the first finger attempt fails after a **very long** standby, but with a **different** symptom (silent timeout instead of "Cannot run while suspended"), then the sensor has lost the transport session over the suspend cycle; the next follow-up step would be to additionally replay the handshake (POV/HELLO/CAL/PSK) in the resume path before re-arming the read.
