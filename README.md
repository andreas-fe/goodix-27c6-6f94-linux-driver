# Goodix GF3268 (USB ID 27c6:6f94) — Native Linux Fingerprint Driver & Protocol Analysis

A clean, production-ready driver package implementing the `goodixsdcp` driver for **libfprint** to support the **Goodix GF3268** fingerprint sensor (USB ID `27c6:6f94`), commonly found in laptops like the **Honor MagicBook Art 14**.

The driver integrates seamlessly into **fprintd** for system-wide authentication across Linux desktop environments (KDE Settings, GNOME Settings, Lock Screen, Display Manager Login, `sudo`, `pam_fprintd`).

---

## 📊 Current Status & Feature Matrix

| Feature              | Status | Protocol / Mechanism                              |
|----------------------|--------|--------------------------------------------------|
| Verify / Identify    | ✅     | `a5` SDCP Match-on-Chip (hardware template match) |
| Enroll (Host Bind)   | ✅     | Touch Windows-enrolled finger → match → bind `FpPrint` |
| List / Delete        | ✅     | `a6` Template List / Host-side template unbinding |
| Desktop & PAM        | ✅     | Lock Screen, `sudo`, Login, GUI Enrollment        |
| Enroll NEW Finger    | ❌     | Host TPM-bound — currently requires Windows Hello (see below) |

> **Enrollment Model:** Enrolling brand-new fingerprint templates natively under Linux is currently blocked by host-side TPM authorization checks (`ff` error). The Linux driver enrollment operates as a **Host Bind**: placing a finger previously registered in Windows Hello allows the Match-on-Chip sensor to identify it, after which `fprintd` binds the registered template ID. Native authentication then runs 100% locally under Linux.

---

## 📁 Repository Structure

```
.
├── README.md                 # Project documentation and installation guide
├── HANDOVER_COWORK.md        # Complete reverse-engineering log & protocol analysis
├── driver/                   # Native libfprint C driver implementation
│   ├── goodixsdcp.c          # GObject device class, SSM state machine, verify/enroll
│   ├── goodixsdcp.h          # Driver structure & state definitions
│   ├── goodixsdcp_crypto.c   # Transport encryption (AES-128-CBC + HMAC-SHA256)
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
├── captures/                 # Protocol traffic captures
│   ├── goodix_handshake_and_enroll.pcapng
│   └── goodix_unlock_success.pcapng
└── windows_binaries/         # Instructions for obtaining vendor driver DLLs
    └── README.md
```

---

## 🛠️ Building & Installing the Driver

The driver is designed to be integrated into an existing `libfprint` source tree.

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
sudo ./build/examples/enroll     # Touch Windows-registered finger -> binds template
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

The full reverse-engineering journey is documented chronologically in `HANDOVER_COWORK.md` (Sections 1–52):

1. **Transport Encryption:** Custom GTLS framing layer (`MAC (32B) + Header (01 FF) + Length (4B) + IV (16B) + Ciphertext`). Uses AES-128-CBC and HMAC-SHA256. Verified 159/159 against captured USB traffic.
2. **SDCP Handshake:** ECDH (P-256) + SP 800-108 Counter-Mode KDF (SHA-256). Reconstructed via disassembly of `GoodixMocSensorAdapter.dll` and live execution (`sdcp_capture.py`, `sdcp_session.py`).
3. **Match-on-Chip (MoC):** Sensor performs internal fingerprint template matching on hardware (`a2` touch detection + `a5` SDCP match). Raw fingerprint images never leave the sensor MCU.

---

## ⚠️ Notes & Security Considerations

- **fprintd vs Python Tools:** While `fprintd` is running, it claims the USB device interface. Stop `fprintd` (`sudo systemctl stop fprintd`) before running standalone Python diagnostic scripts in `protocol/`.
- **System Updates:** Upgrading your distribution's `libfprint` package will overwrite `/usr/lib/libfprint-2.so`. Simply rebuild and re-install (Step 5) after system upgrades, or add `libfprint` to `IgnorePkg` in `/etc/pacman.conf`.
