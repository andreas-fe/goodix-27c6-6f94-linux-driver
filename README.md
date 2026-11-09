# Goodix GF3268 (USB ID 27c6:6f94) — Native Linux Fingerprint Driver & Protocol Analysis

A native `goodixsdcp` driver for **libfprint**, with native new-finger enrollment and protocol research, supporting the **Goodix GF3268** fingerprint sensor (USB ID `27c6:6f94`), commonly found in laptops like the **Honor MagicBook Art 14**.

The driver integrates seamlessly into **fprintd** for system-wide authentication across Linux desktop environments (KDE Settings, GNOME Settings, Lock Screen, Display Manager Login, `sudo`, `pam_fprintd`).

---

## 📊 Current Status & Feature Matrix

| Feature              | Status | Protocol / Mechanism                              |
|----------------------|--------|--------------------------------------------------|
| Verify / Identify    | ✅     | `a5` SDCP Match-on-Chip (hardware template match) |
| Enroll NEW Finger    | ✅ Tested | Native C SDCP capture → Type-4 commit → `FpPrint`; firmware `01010032` |
| List / Delete        | ✅ / See scope | `a6` list; targeted `a7/02` deletion with preservation checks (deletion simulated, GUI deletion not yet hardware-tested) |
| Desktop & PAM        | ✅     | Lock Screen, `sudo`, Login, GUI Enrollment        |
| Empty-Store Provisioning | ⏳ Open | Existing valid Type-4 identity still required |

> **Native enrollment update — 2026-11-09:** A new finger was enrolled directly in **KDE System Settings** using the installed C driver, then accepted by `fprintd-verify`. The original right thumb still verified. No Python capture or separate host bind is needed for new enrollment. Existing Type-4 identity metadata is still required. Empty-store provisioning and reboot/cold-start validation remain open. See the [enrollment guide](docs/NATIVE_ENROLLMENT.md), [native integration details](docs/NATIVE_DRIVER_INTEGRATION.md) and [hardware report](docs/HARDWARE_TEST_REPORT_2026-11.md).

---

## 🆕 Enrolling Additional New Fingers Under Linux

**Hardware-validated on GF3268 firmware `01010032` (2026-11-09).** No Windows session or TPM operation was needed for the additional finger; the existing on-chip identity metadata was reused.

Use **KDE System Settings → Users → Fingerprint** with the newly built/installed driver. Select an unused finger slot and follow the prompts, lifting and repositioning the finger between captures. The driver accepts thirteen updates; fprintd adds one duplicate precheck, so the standard interface reports fourteen stages.

The same operation is available through standard fprintd commands:

```bash
# Choose a genuinely new finger and a free slot.
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger
fprintd-list "$USER"
```

The public C source retains redacted static transport keys. Configure those locally before building; exporting the Python key variables does not configure C. See the [key setup](docs/NATIVE_ENROLLMENT.md#public-transport-key-setup-required-for-sdcp) and installation instructions below. The Python tools remain available for protocol research; the standard desktop workflow does not invoke them.

**Hardware validation:** KDE completed all thirteen native captures and enrollment; the new finger and original thumb both returned `verify-match`. **51 Python tests and 13 native driver simulations pass.** The native lifecycle simulations use the actual libfprint API with fake USB responses; they are distinct from the hardware test. No empty-store or cold-boot success is claimed.

---

## 📁 Repository Structure

```
.
├── README.md                 # Project documentation and installation guide
├── HANDOVER_COWORK.md        # Complete reverse-engineering log & protocol analysis
├── driver/                   # Native libfprint C driver implementation
│   ├── goodixsdcp.c          # GObject device class, SSM state machine, verify/enroll
│   ├── goodixsdcp.h          # Driver structure & state definitions
│   ├── goodixsdcp_crypto.c   # Transport crypto + fresh ECDH/SDCP enrollment keys
│   └── goodixsdcp_crypto.h   # Framing constants & crypto function prototypes
├── protocol/                 # Reference Python implementations & diagnostic tools
│   ├── goodix_crypto.py      # Session crypto & framing reference
│   ├── goodix_gf3268.py      # Low-level USB transport & framing (CRC8/CRC32)
│   ├── sdcp_session.py       # SDCP handshake & key derivation
│   ├── sdcp_capture.py       # Live handshake capture & verification tool
│   ├── check_finger.py       # Sensor template oracle (`a5` check)
│   ├── goodix_verify.py      # Standalone verification (runs without libfprint)
│   ├── emulate_ki.py         # Unicorn engine master key & session key emulation
│   └── re_tools/             # PE / pcapng / pdata analysis scripts
├── docs/                     # Native enrollment guide & November hardware report
├── scripts/                  # Probe, native test runner & protected local installer
├── experiments/              # Guarded SDCP enrollment, match checker & diagnostic MOC patch
├── tests/                    # Python tests + native C lifecycle simulation
├── captures/                 # Protocol traffic captures
│   ├── goodix_handshake_and_enroll.pcapng
│   └── goodix_unlock_success.pcapng
└── windows_binaries/         # Instructions for obtaining vendor driver DLLs
    └── README.md
```

---

## 🛠️ Building & Installing the Driver

The driver is designed to be integrated into an existing `libfprint` source tree. Configure its private transport-key constants locally first. This implementation uses OpenSSL 3 APIs; install the corresponding development dependencies. No ready-to-use private-key binary is published.

### 1. Fetch `libfprint` Sources
```bash
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
cd libfprint
```
*(Tested against libfprint version 1.94.5).*

### 2. Copy Driver Files
```bash
mkdir -p libfprint/drivers/goodixsdcp
cp /path/to/driver/*.c libfprint/drivers/goodixsdcp/
cp /path/to/driver/*.h libfprint/drivers/goodixsdcp/
```

### 3. Update Meson Build System (4 Edits)

**`meson.build`** — Add `'goodixsdcp'` to `default_drivers`:
```meson
    'goodixsdcp',
```

**`meson.build`** — Add helper mapping to `driver_helper_mapping`:
```meson
    'goodixsdcp' : [ 'goodixsdcp_crypto' ],
```

**`meson.build`** — Add OpenSSL dependency in the helper loop (`foreach i : driver_helpers`):
```meson
    elif i == 'goodixsdcp_crypto'
        openssl_dep = dependency('openssl', required: false)
        if not openssl_dep.found()
            error('openssl is required for @0@'.format(driver))
        endif
        optional_deps += openssl_dep
```

**`libfprint/meson.build`** — Add source files to `driver_sources` and `helper_sources`:
```meson
    'goodixsdcp' :
        [ 'drivers/goodixsdcp/goodixsdcp.c' ],
```
```meson
    'goodixsdcp_crypto' :
        [ 'drivers/goodixsdcp/goodixsdcp_crypto.c' ],
```

### 4. Build & Test Standalone (without `fprintd`)
```bash
meson setup build -Ddrivers=goodixsdcp -Ddoc=false -Dintrospection=false -Dgtk-examples=false
ninja -C build
sudo ./build/examples/enroll     # Capture a NEW finger with thirteen accepted updates
sudo ./build/examples/verify     # Touch finger -> verify-match
```

### 5. Install System-Wide (fprintd / KDE / GNOME / PAM)
```bash
# On Arch / CachyOS:
sudo pacman -S --needed fprintd

# On Debian / Ubuntu / Fedora:
# sudo apt install fprintd  /  sudo dnf install fprintd

meson setup build-install -Dprefix=/usr --libdir=lib \
      -Ddrivers=goodixsdcp -Ddoc=false -Dintrospection=false -Dgtk-examples=false
ninja -C build-install
sudo ninja -C build-install install
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl restart fprintd
```

Configure PAM via `/etc/pam.d/` (`auth sufficient pam_fprintd.so`) or enroll fingerprints directly in KDE System Settings → Users → Fingerprint.

---

## 🔬 Protocol & Reverse Engineering Highlights

The full reverse-engineering journey is documented chronologically in `HANDOVER_COWORK.md` (Sections 1–63; the latest protocol corrections and integration are in Sections 55–63):

1. **Transport Encryption:** Custom GTLS framing layer (`MAC (32B) + Header (01 FF) + Length (4B) + IV (16B) + Ciphertext`). Uses AES-128-CBC and HMAC-SHA256. Verified 159/159 against captured USB traffic.
2. **SDCP Handshake:** ECDH (P-256) + SP 800-108 Counter-Mode KDF (SHA-256). Reconstructed via disassembly of `GoodixMocSensorAdapter.dll` and live execution (`sdcp_capture.py`, `sdcp_session.py`).
3. **Match-on-Chip (MoC):** Sensor performs internal fingerprint template matching on hardware (`a2` touch detection + `a5` SDCP match). Raw fingerprint images never leave the sensor MCU.

---

## ⚠️ Notes & Security Considerations

- **fprintd vs Python Tools:** Standalone tools require exclusive access to the USB interface. Finish other fingerprint operations first. If fprintd owns the interface, stop it before standalone testing and restore it afterward; the new tools do not manage services automatically. Do not stop the only working authentication path without retaining password access.
- **Private enrollment references:** `experiments/private/` is ignored by Git. Before/commit/after files contain sensitive identifiers and identity metadata; do not publish them. They are not raw fingerprint images.
- **Experimental scope:** Additional enrollment is tested on firmware `01010032` with an existing Type-4 record. The native enrollment path checks server key confirmation and reconnect MACs, but does not implement the complete Windows attestation/credential-release model.
- **System Updates:** Upgrading your distribution's `libfprint` package will overwrite `/usr/lib/libfprint-2.so`. Simply rebuild and re-install (Step 5) after system upgrades, or add `libfprint` to `IgnorePkg` in `/etc/pacman.conf`.
