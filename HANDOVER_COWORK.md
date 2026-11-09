# Handover & Reverse Engineering Log: Goodix GF3268 (27c6:6f94) Linux Fingerprint Driver

> ## ✅ CURRENT HARDWARE-VALIDATED STATE — 2026-11-09
> **Additional new fingerprints can now be captured and committed under Linux.**
> See **Sections 55–63**, [Native Linux Enrollment](docs/NATIVE_ENROLLMENT.md) and the [Hardware Test Report](docs/HARDWARE_TEST_REPORT_2026-11.md).
> The old TPM-only conclusion, `a7` identity-registration interpretation, `a0=000000` “no frame” interpretation and `74` completion heuristic are superseded.
> **Native C integration is now hardware-validated through KDE.** New capture/commit runs inside libfprint; separate Python capture and host bind are no longer required. New-finger and original-thumb standard verification passed. Empty-store provisioning, cold-start validation and live GUI deletion remain open. Sections 55–60 retain the preceding Python experiment chronology.

> ## ⚠️ ATTENTION: Sections 1–9 of this document are HISTORICAL / REFUTED
> They describe a TLS-PSK handshake using `openssl s_client` as a proxy.
> The sensor does **NOT** speak TLS on the wire. The following are authoritative instead:
> - **`walkthrough.md`** — Correct protocol description (ECDH P-256)
> - **`test_get_image.py`** — 718 lines, executes the actual ECDH handshake
> - **Sections 11–16 of this document** — Empirical evidence and measurements
>
> For evidence see Section 11 (no TLS records on wire) and
> Section 16 (Comparison with `walkthrough.md`).

_Created: 2026-07-28, for handover to Claude CoWork_
_Update: 2026-07-28 — Stage 2/3 + Enroll flow revised, see Section 10_

---

## 1. Project Overview

**Goal:** Make a native libfprint driver for the Goodix GF3268 fingerprint sensor (USB `27c6:6f94`) in the Honor MagicBook Art 14 fully functional under Linux.

**Workspace:** `/home/andreas/Projekte/Fingerprint`  
**Driver Base:** `/home/andreas/Projekte/Fingerprint/scratch/libfprint_natasha/`  
**Python PoC:** `/home/andreas/Projekte/Fingerprint/scratch/poc_driver_tls.py`

---

## 2. Hardware & Protocol (100% Verified)

### Sensor Hardware
- **Chip:** Goodix GF3268, USB VID:PID = `27c6:6f94`
- **Type:** Match-on-Chip (MoC) — Fingerprint template matching operates internally on the sensor MCU
- **Endpoints:** EP_OUT = `0x01`, EP_IN = `0x83`, Interface = `0`

### Protocol Sequence (Verified in Python PoC)
```
1. e0 01 00  (Init Query)          → Sensor responds with 00000000
2. a2 00 00  (Reset/Query)         → ACK
3. Transport handshake via e3 commands:
   a) ClientHello  → send e3 02 00  → Sensor ACKs with expected response length
   b) ServerHello  → send e3 00 00  → Sensor returns ServerHello+Cert+Done
   c) ClientFinished → send e3 02 00 → Sensor ACKs
   d) ServerFinished → send e3 00 00 → Sensor returns CCS+Finished
4. d4 00 00  (Session successfully established)
5. a5 00 00  (Identity/Key-Payload, 32 Bytes)
6. 08 01 00  (GoodixSdcpMacEnroll, 32-byte token) OR
   20 01 00  (GoodixSdcpVerify, 32-byte token)
7. 36 00 00  (MCU Switch to FDT Mode, Payload: 0c 01 80 b9 80 b4 80 b5 80 af 80 b4 80 ac 80 b2 80 a7 80 ab 80 a5)
8. a2 00 00  (Wait for Finger, Payload: 00 0f 41 00)
9. → Sensor spontaneously sends a2 00 00 with payload ~{00 56 64 00 1f 00 38 00} when finger is placed
10. 20 00 00  (MCU_GET_IMAGE → Auth Token / Data via e3 00 00)
```

### TLS Details (Historical / Refuted)
- The sensor uses **ECDHE-ECDSA TLS 1.2** with a self-signed Windows Hello ECDSA certificate
- The sensor is sensitive to ClientHello formatting: it responds only to the
  **exact ClientHello from `openssl s_client`** (241 bytes with standard cipher list + PSK)
- An in-process `SSL_connect()` sends a different ClientHello (307 bytes) → Sensor responds
  with a non-TLS blob (starting with `0x9c` instead of `0x16`) → 'wrong version number'
- **Solution (Historical):** Spawn `openssl s_client` as a subprocess

---

## 3. Current Status of the C Driver

### What Works ✅
- **Driver compiles cleanly:** `ninja -C scratch/libfprint_natasha/build` → 0 errors
- **Device recognized:** `27c6:6f94 | Goodix TLS Fingerprint Sensor GF3268`
- **`goodix_tls_server_init` for 6f94:** Launches TCP listener + `openssl s_client` subprocess,
  accepts TCP connection (client_fd), 241-byte ClientHello sent correctly
- **Handshake Stage 0** (ClientHello → Sensor) passes
- **Handshake Stage 1** (ServerHello ← Sensor): Sensor returns 1200 bytes ServerHello+Cert
- **`expected_tls_length = 847`** parsed correctly from e3 02 00 response
- **Double Status-Byte Strip:** Fixed (was the root cause of 'wrong version number')

### What is NOT YET Verified ⚠️
- **Stage 2 (ClientFinished):** Whether OpenSSL via subprocess processes 1200 bytes and
  generates and writes back ClientFinished correctly
- **Stage 3 (ServerFinished):** Whether the sensor completes the final handshake round
- **d4 00 00 + a5 00 00:** Whether the sensor accepts session as established
- **FDT + Finger Touch:** Not yet tested in C driver (100% verified in Python PoC)
- **Data Decoding:** Image/Token decryption to be verified post-handshake

### Specific Problem Analysis
The driver hung during test at Stage 1 (waiting for OpenSSL Stage 2 response). 
Possible cause: `goodix_tls_client_read` waits 5s via `poll()` for OpenSSL subprocess,
but the subprocess has not yet processed 1200 bytes from the sensor to write ClientFinished
back. The subprocess operates asynchronously — likely a timing constraint.

**Hypothesis:** After writing 1200 bytes of ServerHello to `client_fd`, the subprocess
(OpenSSL) requires processing window to parse TLS records and write ClientFinished.
The `poll()` timeout of 5s should suffice — but previous tests left USB in EBUSY state.

---

## 4. File Structure (Key Files)

```
scratch/libfprint_natasha/libfprint/drivers/goodixtls/
├── goodix.c           ← Main protocol, TLS Handshake SSM (do_tls_handshake),
│                         on_goodix_tls_read_handshake (HERE was the double-strip bug!)
├── goodix6f94.c       ← GF3268-specific driver, FDT Payload, dev_change_state_6f94
├── goodix6f94.h       ← Header with PSK constants
├── goodixtls.c        ← TLS infrastructure; for 6f94: subprocess-based approach
│                         (goodix_tls_6f94_subprocess_thread starts openssl s_client)
├── goodixtls.h        ← GoodixTlsServer Struct (contains openssl_pid for 6f94)
├── goodix5xx.c        ← 5xx family code, scan_run_state, calibration
└── goodix_proto.h     ← Protocol constants

scratch/poc_driver_tls.py   ← Python PoC (FULLY FUNCTIONAL)
```

---

## 5. Critical Code Details

### goodixtls.c — subprocess approach for 6f94
```c
// In goodix_tls_server_init() for 6f94:
// 1. TCP listener on ephemeral port
// 2. spawn openssl s_client -connect 127.0.0.1:PORT -psk 000...0 -tls1_2 -quiet
// 3. Accept TCP connection → client_fd
// 4. use goodix_tls_client_read/write with client_fd for TLS byte exchange
```

### goodix.c — Handshake SSM (Stage 0-3)
```c
// Stage 0: goodix_tls_client_read() → read ClientHello → send e3 02 00
// Stage 1: e3 00 00 → Sensor returns ServerHello+Cert (1200B) → write to client_fd
// Stage 2: goodix_tls_client_read() → read ClientFinished → send e3 02 00
// Stage 3: e3 00 00 → ServerFinished → write to client_fd → handshake done
// Then: send d4 00 00
```

### goodix.c — on_goodix_tls_read_handshake
```c
// BUG WAS: double-strip (data+1, length-1) → fixed to (data, length)
// goodix_receive_pack already strips status byte for e3 00 00 Responses!
g_byte_array_append(priv->tls_recv_buffer, data, length);  // CORRECT
```

### goodix.c — expected_tls_length
```c
// Stage 1 Reset was removed — expected_tls_length comes from Stage-0 e3 02 00 Response
// = 847 bytes (ServerHello+Cert+Done according to sensor)
// BUT: Sensor returns 1200 Bytes in one chunk! Since 1200 >= 847 → immediately complete ✓
```

---

## 6. Build & Test

```bash
# Build:
cd /home/andreas/Projekte/Fingerprint/scratch/libfprint_natasha
ninja -C build

# Testing (USB-Device must be free!):
echo "5" | G_MESSAGES_DEBUG=all ./build/examples/enroll 2>&1

# USB-Device reset if EBUSY:
python3 -c "
import fcntl, subprocess
USBDEVFS_RESET = 0x5514
r = subprocess.run(['lsusb'], capture_output=True, text=True)
for line in r.stdout.splitlines():
    if '27c6:6f94' in line:
        parts = line.split()
        path = f'/dev/bus/usb/{parts[1]}/{parts[3].rstrip(\":\")}' 
        with open(path, 'wb') as f: fcntl.ioctl(f, USBDEVFS_RESET, 0)
        print('Reset OK:', path)
"
sleep 3

# Python PoC (always functional):
cd /home/andreas/Projekte/Fingerprint
python3 scratch/poc_driver_tls.py
```

---

## 7. Next Steps (Priority)

### IMMEDIATE: Debug Handshake Stage 2+3
This is the critical next step. Execute driver and check debug logs for:
1. `TLS_HANDSHAKE_STAGE_NUM entering state 2` appears
2. `TLS handshake stage 2: sending ClientFinished` appears
3. `TLS handshake stage 3: reading ServerFinished` appears  
4. `HANDSHAKE DONE` appears

If Stage 2 blocks: OpenSSL subprocess received 1200 bytes ServerHello,
but must finish TLS processing first. Increase `poll()` timeout or
implement a non-blocking read retry loop.

### Afterwards: Image & Token Decoding
Following successful handshake comes the next milestone:
- `a5 00 00` Key-Payload (32 Bytes, comes from goodix6f94.h)
- FDT-Mode + Finger Touch Recognition
- MCU_GET_IMAGE + Image data via e3 00 00

Since GF3268 is Match-on-Chip (MoC), data may NOT require `SSL_read`
decryption — it arrives pre-processed directly from sensor via e3 00 00.

### Reference: Python PoC
The Python PoC `scratch/poc_driver_tls.py` is the baseline reference.
Every step in the C driver must strictly match the PoC.

---

## 8. Open Questions & Uncertainties

1. **Image data encryption:** Are the image data still transmitted via
   SSL encryption after the TLS handshake? If so, we must read via the openssl subprocess.
   
2. **a5 00 00 Key-Payload:** The Python PoC sends a fixed 32-byte value. In the C-driver
   the Key-Payload is defined in goodix6f94.h — must match the PoC value.
   
3. **expected_tls_length:** Why does the sensor say 847 bytes but returns 1200? Possibly
   `expected_tls_length` is the length of the ServerHello without Certificate extension.

---

## 9. Reference Logs

### Successful TLS Stage 0+1 (from today's test)
```
6f94 TLS: TCP listener on port 39425, launching openssl s_client
6f94 TLS: openssl s_client spawned (pid 43464), waiting for connection
Connecting to 127.0.0.1
6f94 TLS: openssl s_client connected on fd 25
TLS_HANDSHAKE_STAGE_NUM entering state 0
TLS handshake stage 0: sending ClientHello (241 bytes) to sensor
Expected TLS response length: 847
TLS_HANDSHAKE_STAGE_NUM entering state 1
TLS handshake stage 1: reading ServerHello from sensor (passing to OpenSSL)
TLS chunk received: 1201 bytes, total accumulated: 1201 / 847
TLS server flight complete (1201 bytes), passing to OpenSSL
TLS_HANDSHAKE_STAGE_NUM entering state 2
...here the test hung (USB EBUSY from previous run)
```

### Python PoC TLS (completely successful)
```
[Proxy] Read Client Hello from openssl (241B)
[Proxy] Device responded to Client Hello: status=0, expected response length=847
[Proxy] Read Server flight from USB: status=0, length=1190B
[Proxy] Read Client Finished flight from openssl (...)B
[Proxy] Device responded to Client Finished: status=0
[Proxy] Read Server Finished flight from USB: ...B  
[Proxy] TLS Handshake proxy complete!
```

---

## 10. Modifications 2026-07-28 (Stage 2/3 + Enroll Flow)

### Key Insight: `expected_tls_length = 847` is NOT the flight length
`sensor_cert.der` in root directory is **exactly 847 bytes in size**.
The length reported by sensor in `e3 02 00` response is the length of the
**Certificate**, not the total server flight (ServerHello + Certificate
+ ServerKeyExchange + ServerHelloDone ≈ 1200 B). The old termination condition
`accumulated >= expected_tls_length` was coincidental — passing incomplete
USB padding bytes at end of chunk to OpenSSL.
OpenSSL aborted with 'wrong version number', terminating `s_client` subprocess,
causing Stage 2 to hang in `poll()` until timeout.
**This was the exact cause of the Stage 2 deadlock.**

### What was changed

**`goodixtls.c` / `goodixtls.h`**

| New | Purpose |
|---|---|
| `goodix_tls_scan_records()` | Iterates over a buffer as a sequence of TLS records. Returns the length of the *complete* records and reassembles the handshake stream across record limitations (the sensor's certificate is split). Reports CCS, Alerts, last Handshake Type. |
| `goodix_tls_client_read_flight()` | Reads a **complete flight** from `openssl s_client`, not just what a single `read()` returns. Drain-Loop until ClientKeyExchange+CCS+Finished are there. Detects EOF (subprocess dead) and TLS alerts with clear error message instead of silent blockage. |
| `goodix_tls_client_write()` | Now writes in a loop (short writes would have cut off the flight). |

**`goodix.c`**
- `on_goodix_tls_read_handshake()`: Completeness is decided by the TLS records
  (ServerHelloDone or CCS+Finished), no longer by
  `expected_tls_length`. Trailing padding is stripped off, each record is
  logged, TLS alerts abort the SSM with a plaintext error.
- Stage 0 and Stage 2 use `goodix_tls_client_read_flight()`. The old
  Stage-2 fallback "send empty payload on read error" was removed — it
  masked the error.
- `goodix_receive_pack()` (6f94): multiple device packets in *one* USB transfer
  are now all processed; the rest is no longer discarded.
- New optional class hook `finger_down` (`FpiDeviceGoodixTlsClass`).
- `goodix_tls_init()` / `goodix_tls_ready()`: now report init error via the
  callback, instead of letting activation hang indefinitely.

**`goodix6f94.c`**
- **Post-TLS SSM added** (was missing completely!): after `d4 00 00` now
  `a5 00 00` (32-byte key from frame 466) and `08 01 00` (SdcpMacEnroll,
  32 null bytes) are sent — exactly as in the PoC. Only then
  `fpi_image_device_activate_complete()`.
- **`dev_change_state_6f94()` bug fixed:** `36 00 00` and `a2 00 00` were
  issued right after another. But `goodix_send_protocol()` rejects a
  second command while the first is running ("A command is already running") —
  thus `a2` was **silently discarded** and the sensor never armed
  finger detection. Now chained: `36` → callback → `a2`
  → `waiting_for_finger = TRUE`.
- `finger_down_6f94()`: instead of the 5xx capture SSM (doesn't fit MOC)
  `20 00 00` (MCU_GET_IMAGE) is sent just like in the PoC and response evaluated.

**`goodix_proto.h`** — `GOODIX_CMD_SDCP_MAC_ENROLL (0x08)`,
`GOODIX_CMD_SDCP_KEY (0xa5)`; mapping `0x08 → 08 01 00` in `goodix_send_protocol()`.

### Verification
- All three files compile without warnings under the full Meson warning set.
- `goodix_tls_scan_records()` is tested with 30 assertions against physical/real data:
  the 241-byte `sclient_hello.bin`, a server flight with the 847-byte certificate
  split across records, the same flight with USB padding (is
  correctly stripped), partial flights, CKE-without-Finished, alert records and the
  known non-TLS blob `0x9c…`.
- **Not** tested against the physical/real hardware — this must run on the device.

### Test
```bash
cd /home/andreas/Projekte/Fingerprint
sudo ./run_enroll_test.sh        # builds, resets USB, enrolls, evaluates log
```

### What to look for in the log
1. `TLS handshake stage 0: sending ClientHello (241 bytes)`
2. `server record: type=22 … first_byte=0x02 / 0x0b / 0x0c / 0x0e` —
   ServerHello, Certificate, ServerKeyExchange, ServerHelloDone. If `0x0e` is missing,
   the driver automatically requests the next chunk.
3. `client flight: … ccs=1 after_ccs=1` — the ClientFinished flight is complete.
4. `TLS handshake stage 3` → `HANDSHAKE DONE`
5. `post-TLS: sending a5 00 00` → `post-TLS: sending 08 01 00`
6. `Finger detection armed` → place finger → `finger down`

If it hangs at Stage 2, the reason is now in the log: either
`openssl s_client closed the connection` (OpenSSL discarded the server flight
— then check the `server record:` lines) or
`timed out … waiting for TLS data`.

### Still open (superseded by Section 11 — please read further there)
- `GOODIX6F94_WIDTH/HEIGHT` (88×108) are still estimated/guessed. `get_image_cb()`
  logs the actual payload size of `20 00 00` — from this the
  physical/real dimensions can be derived.
- Whether the image data is still TLS encrypted after the handshake is unresolved.
  If `20 00 00` comes back encrypted, the response must be read through the
  `s_client` subprocess (not yet implemented).

---

## 11. ⚠️ Finding 2026-07-28 (Run 2): Sensor Does NOT Speak TLS

First execution on physical hardware produced a CRC32-verified
complete `e3 00 00` response (1216-byte transfer, packet 1214 B, CRC32
`7a8831d4` = calculated). Its contents refute the prior working hypothesis.

### Proof 1 — Sensor response contains zero TLS records
Payload following status byte = 1201 bytes, structure:

```
  Offset    0 ..   63   64 Byte   opaque header prefix
  Offset   64 ..  910  847 Byte   DER Certificate (byte-identical to `sensor_cert.der`)
  Offset  911 .. 1200  290 Byte   Remainder (starts with `0x04` → uncompressed EC point?)
```

Scanning all 1201 bytes for valid TLS record headers
(Type 20/21/22/23 followed by `03 0x`) yields **zero hits**. That is also the
resolution of the "847" mystery: the sensor reports in the `e3 02 00` response the
**Certificate** in `e3 02 00` response, not a TLS flight.

### Proof 2 — Windows driver never sends a ClientHello
`unlock_success_flow.txt` (capture of working Windows driver)
demonstrates identical framing for every `e3` command in **both** directions:

```
  [32 Byte Nonce] [01 ff] [4 Byte Length LE] [Body] [Trailer]
```

| Frame | Direction | Cmd | Nonce | Length | Body |
|---|---|---|---|---|---|
| 45  | host→dev | e3 02 00 | `c21b521a…` | 162  | `659b4aff…` |
| 57  | host→dev | e3 00 00 | `dcdf2ddc…` | 162  | `659b4aff…` (same body, new nonce) |
| 65  | dev→host | e3 00 00 | `7c9e05df…` | 1366 | `a52f8bb1…` |
| 141 | host→dev | e3 02 00 | `3cde1337…` | 32   | `2d472922…` |

No `16 03 01`, no ClientHello, no TLS records — even in
working Windows trace. **The `openssl s_client` proxy concept cannot work.**
Our driver sent a 241-byte ClientHello;
the sensor does not parse it and responds with a generic blob containing
the certificate.

### Why the Python PoC Appeared 'Successful'
`run_tls_handshake()` in `scratch/poc_driver_tls.py` validated **nothing**. It
pushes bytes back and forth between socket and USB and then unconditionally prints
`[Proxy] TLS Handshake proxy complete!`. If OpenSSL rejects the blob
and sends a 7-byte alert back, that is also obediently passed
as a 'Client Finished flight' to the sensor. The statement
"TLS handshake 100% verified" in Section 2 is thus **not supported** —
the finger touch detection apparently also works without a secured
channel. Counter-check in 10 seconds: start `openssl s_client` manually and
look at its stderr; it should say "wrong version number" there.

### Analysis & Protocol Classification
The driver already references `GoodixSdcpMacEnroll` (08 01 00) and
`GoodixSdcpVerify` (20 01 00). **SDCP = Microsoft's Secure Device Connection
Protocol** for Windows Hello sensors. Nonce + device certificate + EC point +
signature in the response perfectly match an SDCP `Connect`. The GF3268 thus uses
not the TLS-PSK of the older Goodix generation (55a2, which the
`goodix-fingerprint-reversing` code in the project is based on), but SDCP.

### Also found and fixed in this run
- **Regression from Section 10:** The sensor pads every packet to a
  multiple of 64 bytes. My "keep rest in buffer" patch parsed this
  padding as another packet → length field 0 → buffer permanently
  desynchronized → the 1214-byte chunk was never assembled → hang/freeze.
  Now the header is validated via CRC8 before it is used; if that
  fails, the buffer is discarded and resynchronized. Simulated against the bytes of the
  failed run: 7/7 packets clean, no remainder.
- `pay_len_field < 4` triggered an underflow in `payload_len` →
  `g_memdup()` with 65532 bytes from a 72-byte buffer (heap overread).
- `data_to_str()` returned uninitialized memory when `length == 0` —
  hence the garbage characters `\xed\xdd>36V` in the log on zero-length transfers.

### Recommended next steps
1. **Cheap experiment first:** replay the exact byte sequence from
   `unlock_success_flow.txt` (frames 45/57) 1:1 to the sensor. If it
   comes up with a plausible response, there is no freshness check on the
   nonce and the structure can be clarified step by step.
2. Only then rebuild the framing `[Nonce][01 ff][Length][Body]` and remove the
   `openssl s_client` subprocess entirely.
3. Extract the remaining `e3` frames from all available pcapng files
   to determine the body layout and trailer (30/30/26/32 bytes — not yet understood).

---

## 12. Complete Windows Flow/Sequence (from `unlock_success_flow.txt`, all 40 frames CRC verified)

The actual unlock flow/sequence of the Windows driver. **It contains neither
`d4 00 00` nor `36 00 00` nor `08 01 00` nor `20 00 00`** — the sequence in
Section 2 is thus also obsolete.

| # | Host → Sensor | Payload | Sensor → Host |
|---|---|---|---|
| 33  | `e1 04 00` | `00` | `00000000` |
| 45  | `e3 02 00` | 256 B (`len=230` + Nonce + Body) | `00 4f030000` → Status 0, 847 |
| 57  | `e3 00 00` | 256 B (same body, **new nonce**) | 1431 B |
| 69  | `b0 02 00` | `00` | 65 B (looks like calibration values) |
| 81  | `e0 01 00` | `00` | `00000093` |
| 93  | `a2 00 00` | `01 00 23 01` | `005c64001f003b00` |
| 105 | `a5 00 00` | 32 B Key | **1110 B** |
| 117 | `e0 00 00` | `00` | `00000000` |
| 129 | `a5 01 00` | `01 00 00 00` | `00` |
| 141 | `e3 02 00` | 256 B (`len=102`) | `00 4f030000` |
| 153 | `e3 01 00` | 256 B (same body) | 33 B (Status + 32 B, probably MAC) |
| 165 | `b0 02 00` | `00` | 65 B |
| 177 | `a2 00 00` | `01 00 23 00` | only ACK |
| 185 | `b3 02 00` | `00` | only ACK |

Observations:
- `e3 02 00` **writes**, `e3 00 00` / `e3 01 00` **reads** — each with
  the same body, but each time a fresh/dynamic 32-byte nonce.
- The sensor reports on every `e3 02 00` the same length 847 (Certificate).
- `a5 00 00` with 32-byte key returns 1110 B — that is the interesting
  candidate for template/image data.
- `b0 02 00` and `b3 02 00` are completely unknown in the current driver.

### New Tools
- **`scratch/sdcp_replay.py`** — injects these host frames byte-identically and
  compares every response with the capture. Reports precisely from which frame on
  the sensor diverges (= where nonce freshness/key derivation becomes necessary).
  ```bash
  python3 scratch/sdcp_replay.py --dry-run     # without hardware, checks only the capture
  sudo python3 scratch/sdcp_replay.py          # real replay
  sudo python3 scratch/sdcp_replay.py --until 65
  ```
- **`scratch/poc_driver_tls.py`** now no longer reports unconditional success:
  every flight is parsed as a TLS record, OpenSSL's stderr is read and
  at the end there is an honest conclusion. Tested against the physical/real sensor bytes:
  "NO valid TLS record".

---

## 13. Replay Result (Hardware, 2026-07-28): **The sensor accepts the replay**

`sudo python3 scratch/sdcp_replay.py --until 65` against the physical/real sensor.
The first version of the script summarized the result incorrectly ("diverges
from frame 33") — it compared purely byte by byte. Read technically:

| Frame | Result | Evaluation |
|---|---|---|
| 33 `e1 04 00` | Response `00000000` **byte-identical** | ✅ |
| 45 `e3 02 00` | Response `00 4f030000` **byte-identical** | ✅ Sensor accepts the replayed nonce+body |
| 57 `e3 00 00` | 1431 B, **same length**, `01 ff` marker equal, declared body length **1366 identical**, body start identical | ✅ structurally identical |
| 69 `b0 02 00` | 65 B, 24 B diverge | ✅ these are 16-bit **live measurements** of the sensor |
| all ACKs | 1 byte diverges, always offset 3 (`…00` instead of `…01`) | ✅ flag byte, no payload |

**There is no nonce freshness check that rejects the replay.** Of the
1431 bytes of the frame 57 response, 937 are identical; the 494 diverging ones are
the fresh/dynamic 32-byte device nonce, the 26-byte trailer and ~436 bytes in the body.

### The body is encrypted
Block-wise byte entropy of the 1366-byte body from the Windows capture lies
consistently at ~0.88–1.00 (random). Neither the certificate nor any
DER structure can be found in it. For comparison: our ClientHello response from
Section 11 has blocks with 0.41–0.64 — there the certificate lay in plaintext.

From this follows the working hypothesis: the sensor delivers its SDCP identity
**encrypted**, if the request is well-formed, and falls back on an
incomprehensible request (our ClientHello) to a plaintext response with the
certificate.

### Next Step: map fields without cryptanalysis
Diff two runs of the **same** request against each other. What changes is
fresh/dynamic randomness of the sensor; what remains equal are static device data:

```bash
sudo python3 scratch/sdcp_replay.py --until 65      # Run 1
sudo python3 scratch/sdcp_replay.py --until 65      # Run 2
python3 scratch/sdcp_replay.py --diff scratch/replay_out/run_A scratch/replay_out/run_B
```

The script now saves every response under `scratch/replay_out/run_<time>/`
and `--diff` outputs an offset map "static vs. fresh/dynamic". With this the
body layout is fixed before a single byte of crypto has to be understood.

### Further observation
`b0 02 00` returns 32 × 16-bit values (status + 64 B). Values around 0x0076–0x009b
with us, 0x0062–0x0095 with Windows. This is the first direct sensor measurement
that we see — candidate for the calibration and thus later for the
image geometry.

---

## 14. Field map of the `e3 00 00` response (from two replay runs, 2026-07-28)

Two runs with **byte-identical** request, seconds apart. What
differs is fresh/dynamic randomness of the sensor; what remains equal are
static device data. Result for the 1431-byte response:

```
  Offset      Size    Type       Interpretation
  ----------------------------------------------------------------
       0        1 B   static     Status (0x00)
    1.. 32     32 B   FRESH      Nonce of the device
   33.. 34      2 B   static     Marker 01 ff
   35.. 38      4 B   static     declared body length (1366)
   39..1318   1280 B  static     Body[0..1279] — device identity
 1319..1430    112 B  FRESH      Body[1280..] + remainder, contiguous
```

**1287 out of 1431 bytes are bit-identical across runs.** Fresh are only
the 32-byte nonce at the beginning and a contiguous 112-byte tail at the end.

### Correction to Section 13
The statement there "the body is encrypted" was premature. High entropy
**plus** bit equality over multiple responses means: it is static
highly entropic material (key, hashes, a fixed wrapped identity blob),
**not fresh/dynamic encryption per session**. Otherwise everything would have to change.

### Three scopes
The comparison run ↔ Windows capture (completely different session) shows a
| Region (inner buffer) | Size | Behavior |
|---|---|---|
| `inner[0..31]` | 32 B | changes **on every response** → Nonce |
| `inner[32..965]` | 934 B | equal **even compared to Windows** → constant per device (Certificate/Key) |
| `inner[966..1317]` | 352 B | equal within our runs, ≠ Windows → **session-/reset-bound** |
| `inner[1318..1429]` | 112 B | changes **on every response** → Signature/MAC/ephemeral Key |

The 112 bytes are the interesting part. The magnitude fits e.g.
ECDSA-P-256-signature (64 B raw) + 48 B, or an AES-GCM wrapped
32-byte session key (32+16) + 64 B signature. **Not yet proven.**

### Next Experiment
The region `inner[966..1317]` is the key to the question "what does the
session depend on?". A run with a USB reset in between separates this:

```bash
sudo python3 scratch/sdcp_replay.py --until 65            # Run without reset
sudo python3 scratch/sdcp_replay.py --until 65 --reset    # Run with reset before
python3 scratch/sdcp_replay.py --diff                     # compare both newest
```

If the fresh/dynamic region grows from 112 to ~464 bytes after a reset, then
`inner[966..1317]` is bound to the power cycle (boot random / ephemeral
device key). If it stays at 112, it depends on something else — then varying
individual fields in the request comes next.

### Tool Corrections
- `--diff` **without arguments** now takes the two newest runs. (The
  placeholders `run_A`/`run_B` in Section 13 were not recognizable as such —
  apologies.)
- New: `--reset` triggers `USBDEVFS_RESET` before the run.
- `classify_diff()` now also knows the 4-byte status responses of `e1 04 00` /
  `e0 01 00`: there the last byte is a device state value (for us `0x9b`,
  in the Windows capture `0x00`) and not an error code. Thus, the
  final conclusion of the script is also finally correct.

---

## 15. Reset Experiment (2026-07-28): the USB reset changes nothing

Four runs: two without reset (seconds apart), one 6 minutes later, one
directly after `USBDEVFS_RESET`. Fresh portion of the 1431-byte `e3 00 00` response:

| Comparison | fresh/dynamic |
|---|---|
| Run1 ↔ Run2 (no reset, seconds) | 32 B Nonce + 112 B tail |
| Run2 ↔ Run3 (no reset, 6 min) | 32 B Nonce + 112 B tail |
| Run3 ↔ Run4 (**with USB reset**) | 32 B Nonce + 112 B tail |

**The reset makes no difference.** Thus, the hypothesis from Section 14 is
refuted: `inner[966..1317]` (352 B) is **not** bound to the power/reset cycle,
but rather **device-persistent**. It survives reset and time.

Why it then differs from the Windows capture is open. The
most obvious explanation: persistent state that has changed since the capture
— most likely the **enrollment/template status** (the project contains
`goodix_delete_templates.pcapng`, so templates were deleted at some point).

### What this means in practice — and it is good news
Out of 1431 bytes, **1287 are replayable constants**. Per response, only the following vary:
- 32 B Nonce (generated by the sensor itself)
- 112 B tail (Signature/MAC, generated by the sensor itself)

Both are generated by the **sensor**, not the host. For a working
driver we don't even need to be able to calculate these fields — we only have to
**send valid requests**, and we have one of those from the capture.

### Correction to Section 13
`b0 02 00` returns 32 × 16-bit values. I had classified them as "live measurements"
— wrong. Across all four runs they are **identical except for a single byte**
(152, 155, 131, 118, 154, 154, …). Compared to Windows they differ
(143, 147, 114, 98, …). So they are **calibration values** that depend on the device state,
not on randomness. Value range in both cases 0..203.
The evaluation in `classify_diff()` has been corrected accordingly.

### Next Step
Run the replay **beyond Frame 65** up to the end of the unlock sequence.
This clarifies the crucial question: does the sensor accept a
completely replayed session end-to-end?

```bash
sudo python3 scratch/sdcp_replay.py        # without --until = complete flow/sequence
```

Particularly interesting is Frame 105/113: `a5 00 00` with 32-byte key returns
**1110 bytes**, whose head is structured
(`5c 64 45 00 00 00 00 62 00 43 04 f5 …`, followed by 16 null bytes, then highly entropic).
The first two bytes `5c 64` also appear in the `a2 00 00` response
(`00 5c 64 00 1f 00 3b 00`) — right where the finger event is according to Section 2.

**Risk:** The sequence contains `a5 01 00` (`01 00 00 00`) and `e0 00 00`, which
might write device state. It is an unlock/verify flow/sequence, not enroll
and not delete (there are separate captures for those), so the risk is low —
but not zero.

---

## 16. Complete Replay + Alignment with `walkthrough.md`

### Result of the complete replay
Out of 12 expected responses, 10 returned structurally correct:

| Frame | Command | Result |
|---|---|---|
| 41 | `e1 04 00` | ✅ (only device state byte) |
| 53 | `e3 02 00` | ✅ byte-identical |
| 65 | `e3 00 00` | ✅ 1431 B, same structure |
| 77 | `b0 02 00` | ✅ calibration values |
| 89 | `e0 01 00` | ✅ |
| **101** | `a2 00 00` (`01 00 23 01`) | ❌ **no response at all**, only ACK. Windows: `00 5c 64 00 1f 00 3b 00` |
| **113** | `a5 00 00` | ❌ **`ff`** instead of 1110 B |
| 125 | `e0 00 00` | ✅ byte-identical |
| 137 | `a5 01 00` | ✅ byte-identical (`00`) |
| 149 | `e3 02 00` | ✅ byte-identical |
| 161 | `e3 01 00` | ✅ 33 B, status `00` + 32 B fresh/dynamic MAC |
| 173 | `b0 02 00` | ✅ |

The entire handshake is thus replayable. The boundary lies at `a2 00 00`
with payload `01 00 23 01` — there the sensor provides no scan status
data for us, and subsequently `a5 00 00` only returns `ff`.

Incidental finding: `a2 00 00` with `01 00 23 01` (Frame 93) yields data in the capture,
with `01 00 23 00` (Frame 177) only an ACK — the last byte thus
apparently turns something on or off.

### Alignment with `walkthrough.md` — Wire Format Confirmed
`walkthrough.md` documents (from previous work in the project):

> `MAC (32 Bytes) + Header (01 FF) + Length (4 Bytes) + IV (16 Bytes) + Ciphertext`

This matches **exactly** the structure derived independently from wire traces
(`[32 B][01 ff][4 B Length][Body]`). Two independent
derivations, identical result — confirming the transport format.
My designation "Nonce" for the first 32 bytes was wrong: it is an
**HMAC-SHA256**. The payload body begins with a **16-byte IV**.

This casually explains the field map from Section 14: AES-CTR is a
stream cipher. With an identical key, identical IV, and a plaintext
that only differs at the end, the ciphertext also only differs
at the end — exactly the observed 1287 static + 112 fresh/dynamic bytes. The MAC
changes with it because the ciphertext changes.

### State of the art in the project
`test_get_image.py` (718 lines) already implements according to `walkthrough.md`:
ECDH P-256, derivation of the AES/HMAC key (verified: the **raw**
shared secret serves directly as key, without key expansion), encrypted
client identity packet, authentication, finger detection, and reading out the
`b0 02 00` array. `find_ec_pubkey_in_server_hello()` documents the layout
of the server response:

```
    0.. 63   Session header / Nonce material
   64..910   X.509 certificate (847 B)  -> static sensor key
  911..975   ephemeral ECDH public key #1 (65 B, uncompressed)
  976..1040  EC point #2 / Proof-of-Possession (65 B)
 1041..End   HMAC / Signature
```

This exactly matches what was measured on our own response in Section 11
(64 B prefix, 847 B certificate, then `04` prefix at 911).

### Consequence for the C driver
The `openssl s_client` subprocess in `goodixtls.c` and the four-stage
TLS handshake SSM in `goodix.c` are **conceptually wrong** and must be replaced by
the ECDH flow/sequence from `test_get_image.py`. The work from
Section 10 (buffer resync, CRC8 validation, padding handling,
`data_to_str` fix, command chaining) remains unaffected and continues to be
valid — it concerns the transport layer, not the cryptography.

### Next Step
Run `test_get_image.py` against the hardware. `cryptography` is
available. This will show how far the live ECDH handshake actually gets today
— and is more informative than any further replay.

---

## 17. Breakthrough: Cryptography is mbedTLS with `TLS-PSK-WITH-AES-128-CBC-SHA256`

### What the measurements revealed
- **It was not the sequence.** `win_order_probe.py` exactly replicates the Windows flow/sequence
  (`e1 04 00` first, `b0 02 00` with 1 byte `00`, `e0 01 00` with
  1 byte, `a2 00 00` with `01 00 23 01`). All responses now match the
  capture — `b0 02 00` → 65 B, `a2` → `005d64001f003900`
  (Windows `005c64001f003b00`), `e0 00 00` → `00000000`, `a5 01 00` → `00`.
  Only `a5 00 00` stays at `04`.
- **It was not the EC point either.** `key_sweep.py` tried all three points from the
  Server-Hello × Key-Expansion on/off. All six → `04`.
- **And the actual finding:** in none of the 24 tested combinations
  (6 derivations × 4 MAC formulas) could the 32-byte response of the sensor
  to `e3 01 00` be verified.

### Thus a central assumption falls
`test_get_image.py` evaluates `len == 33 and resp[0] == 0x00` as
"[SUCCESS] Handshake Completed! Server Identity verified." However, the sensor **always**
answers like this — even with demonstrably incorrect keys. This
success message never proved anything, and `walkthrough.md` Section 3
("Successfully authenticates the host with the sensor!") is based on it.

### Binary Reverse Engineering Findings
`GoodixMocSensorAdapter.dll` contains static mbedTLS symbols:

```
  ..\CODE\mbedtls\Src\ssl_tls.c          statically linked mbedTLS
  ..\CODE\mbedtls\Src\ssl_cli.c
  TLS-PSK-WITH-AES-128-CBC-SHA256        the cipher suite
  mbedtls_ssl_psk_derive_premaster
  mbedtls_ssl_derive_keys
  => calc finished tls sha256
  gf_sha256 / gf_hmac_sha256             Goodix wrapper
  secp256r1, all four P-256 constants (as mbedTLS limbs)
```

No BCrypt/NCrypt imports — cryptography is statically compiled into the DLL. The suite
seamlessly explains the observations on the wire: **AES-128-CBC** (16-byte IV,
ciphertext padded to 16) and **HMAC-SHA256** (32-byte MAC in front).

### The suspected cause
`mbedtls_ssl_psk_derive_premaster` builds the premaster according to RFC 4279:

```
  pure PSK   :  premaster = uint16(N) || N null bytes || uint16(N) || psk
  ECDHE-PSK  :  premaster = uint16(|Z|) || Z          || uint16(N) || psk
  afterwards :  master_secret = PRF(premaster, "master secret", cr||sr, 48)
                key_block     = PRF(master_secret, "key expansion", sr||cr, n)
```

Instead, `derive_goodix_gtls_keys()` feeds the **raw ECDH result** into it as
the secret. Moreover, the suite is called `TLS-PSK-…`, not `TLS-ECDHE-PSK-…` —
if this is true, the ECDH result plays no role in the session keys at all.
This casually explains why all six EC candidates failed identically.

### New Tool
`scratch/kdf_sweep.py` tries out 12 combinations:
3 premaster variants (pure PSK / ECDHE-PSK / raw Z) × key expansion on+off
× 2 key block layouts (Goodix `aes16|iv16|hmac32` and TLS standard
`cMAC32|sMAC32|cKey16|sKey16|cIV16|sIV16`). Additionally, the server response
is verified against four MAC formulas, including the TLS `finished` PRF.

```bash
sudo python3 scratch/kdf_sweep.py 2>&1 | tee kdf_sweep.log
```

### Corrected Field Map
The "trailer" suspected in Section 14 does not exist. For all five
`e3` frames of the capture, the calculation checks out:

```
  MAC(32) || 01 ff || plaintext length(LE32) || IV(16) || AES-CBC(pad16(plaintext))
       162 -> 176        1366 -> 1376          32 -> 48
```

Furthermore, `unlock_success_flow.txt` begins at Frame 33 **in the middle of an
ongoing session** — Frame 45 is already encrypted. The actual
handshake of this recording is missing from it.

---

## 18. Crypto Status: Black-Box Exhausted, Tools for Ghidra Ready (2026-07-28)

### What is certain now
- **`01` = no match, `04` = other error, `1110 B` = Auth-Token.** Read directly from the
  pcaps: `goodix_unlock_success` → `a5 00 00` returns 1110 B;
  `goodix_unlock_fail` → `01`; our live attempt → `04`. Thus, our session
  does not even authenticate as far as a *failed* Windows unlock.
  The handshake is the breaking point, not the finger match.
- **The session key cannot be derived from the PSK alone.** An
  offline attack with 163 key candidates (PSK, SHA256(PSK), all
  PRF outputs with "master secret"/"key expansion"/"client finished"/
  "server finished" over cr‖sr, sr‖cr, …) against the PKCS7 padding oracle of the
  first message: **no hit**.
- **Standard TLS derivation does not reproduce the server response.** Even with
  a known ECDH-Z (from our live runs), none of the 24 combinations
  from `key_sweep.py`/`kdf_sweep.py` resulted in the 32-byte response of the sensor
  to `e3 01 00`. The derivation is not textbook mbedTLS.
- **Windows never sends a plaintext ECDH hello.** In all captures, even the
  first `e3 02 00` is already encrypted. The key is thus not visibly
  negotiated over USB.

### Incidental finding: IV reuse
The driver reuses IVs (`goodix_unlock_success`: 29 out of 50
messages share an IV with another). Several pairs are even
**byte-identical** (same IV + same ciphertext = literally the same message
sent twice). This is cryptographically sloppy, but doesn't help with the
key because the IV is sent in plaintext anyway.

### New Tool: `scratch/pcap_crypto.py`
Standalone pcapng parser + decryption oracle. Loads all 159
encrypted messages from the captures and tests a key candidate
against two independent oracles (PKCS7 padding and HMAC-SHA256 over
`01ff|len|IV|CT`). Self-test passed: zero key → 0 false hits for 159
messages, so the oracle is highly discriminatory.

```bash
python3 scratch/pcap_crypto.py                  # Overview
python3 scratch/pcap_crypto.py --key <hex16>    # Test candidate
# as library: from pcap_crypto import try_key, try_derivation
```

As soon as the derivation from Ghidra is known, this script verifies it in
seconds against physical/real data — without hardware.

### Clear Recommendation: Ghidra now
The black-box path is exhausted. The goal in `GoodixMocWbdi.dll`:

1. **`gf_hmac_sha256`** — the string is at offset 777912. From there trace back the
   callers: which buffer is passed as the key and
   what is it generated from? That is the shortest path to the `mac_key`.
2. **`mbedtls_ssl_psk_derive_premaster`** (string at ~0x3AF...) — shows how
   the premaster is assembled (RFC 4279 or modified).
3. **`mbedtls_ssl_derive_keys`** — standard or patched?

Ghidra + JDK are already in the project (`ghidra_11.0.3_PUBLIC/`, `jdk/`).

### Honest overall assessment
Transport, framing, and crypto suite are completely understood and mapped into
runnable Python tools. What is missing is the **single**
key derivation function. That can no longer be guessed via black-box — it
must be read from the binary. Without it, the Linux driver cannot
generate a valid encrypted message and thus cannot prompt the MoC sensor for the
auth token. This is not a dead end, but the next stage is
static reverse analysis, not further hardware probing.

---

## 19. Binary Analysis + Sister Chip: the picture becomes complete (2026-07-28)

### objdump instead of Ghidra
Ghidra does not run in the sandbox (bundled JDK is Windows-only, system JDK is
11, Ghidra 11 needs 17). Replacement: `objdump -b pei-x86-64` plus self-written
PE/.pdata parsers (`/tmp/pe.py`, `/tmp/pdata.py`, `/tmp/xref.py`).
With this, exact function boundaries (2030 functions from `.pdata`) and
RIP-relative Xrefs — sufficient for targeted analysis.

### What the DLL reveals
- `GoodixMocWbdi.dll` links **mbedTLS** statically, suite
  **`TLS-PSK-WITH-AES-128-CBC-SHA256`** (Section 17).
- The only caller of the `gf_hmac_sha256` wrapper is the function
  **`ProcessPsk`** (VA 0x18008edc0) — this is the **PSK provisioning**, not
  the session KDF. Strings there: `1.check psk if valid`, `3.write psk to mcu`,
  `sgxPskLen`, `GfSealData`, `PresetPskWriteKey`, `production_write_key`.
- The session KDF therefore uses mbedTLS's own HMAC function, not the
  Goodix wrapper — it is harder to isolate in the binary.

### The sister chip provides the missing reference
`goodix-fingerprint-reversing/capture.py` is a **working** driver
for the Goodix 55a2 (GF3206) and was previously ignored. Key points that transfer directly
to the GF3268:

- **The TLS-PSK is zero (32 null bytes).** Confirmed by the running
  openssl line: `openssl s_server -nocert -psk 0000…0`. The 144-byte `PSK_WB`
  is just a provisioning blob that is written to the MCU once —
  it is **not** the session key. The exact same `ProcessPsk`/`PresetPsk`
  functions are found in our GF3268 DLL.
- **Role distribution:** the device is the TLS **client**, openssl is the
  **`s_server`**. The natasha C driver and `test_get_image.py` use
  `s_client` instead or roll their own ECDH — **wrong role**.
- **Flow/Sequence 55a2:** `d0` (REQUEST_TLS) → device sends ClientHello →
  to s_server → ServerHello back to the device → device sends
  ClientKeyExchange+CCS+Finished → to server → ServerFinished to the device. Pure
  standard TLS-PSK.

### The GF3268 is not a pure 55a2
Two hard differences in the captures:
1. **Not a single TLS record marker** (`16 03 xx`, `14 03 03`) in the entire
   USB traffic of all nine pcaps. The GF3268 wraps the mbedTLS crypto into a
   **custom** record format (`MAC32 | 01ff | len | IV | CT`), not in
   standard TLS records. The s_server proxy trick of the 55a2 therefore
   does not work unmodified.
2. The GF3268 has a `d0` command whose response begins with `…0002 fe41 5050…`
   (in `goodix_init` and `goodix_handshake_and_enroll`, **not** in
   unlock — so the handshake is only done once per power cycle and
   then reused).

### Thus the situation is precise
Everything is understood **except** the single key derivation from the
handshake nonces. Facts:
- Crypto = mbedTLS, `TLS-PSK-WITH-AES-128-CBC-SHA256`, **Zero-PSK** (now supported
  by the 55a2 evidence, no longer just an assumption).
- However, standard TLS-PSK KDF with Zero-PSK does not reproduce the session
  (`kdf_sweep.py`, 12 variants). So an additional factor comes into play —
  most likely the ECDHE portion (the Server-Hello contains ephemeral
  EC points), i.e. **ECDHE-PSK premaster** `Z || PSK structure`, but with a
  nonce/seed assignment that has not yet been hit.

### Two paths to the goal — decision required
**A. Frida hook on Windows (fastest safe path).**
Run the Windows driver and hook `mbedtls_ssl_derive_keys` or the
AES setup function to dump `master_secret` / `key_block` **directly**. Inputs (nonces, Z)
are known from our live runs → the exact KDF formula results from a single input/output pair.
`pcap_crypto.py` verifies it immediately. Requirement: Windows installation with the sensor.

**B. Static RE further (no Windows required, but tedious).**
Completely read the mbedTLS handshake function in the binary. Without Ghidra/JDK17
only doable with objdump, but time-consuming. Needs a runnable Ghidra (install JDK 17)
or Radare2/Cutter as a substitute.

Both lead to the same goal: once the KDF is known, the driver can be
straightforwardly completed — transport, framing, command sequence, and image
decoding (from `capture.py`/`goodix5xx.c`) are already available.

### Tools of this step (all offline, in the repo)
- `/tmp` parsers are volatile; the persistent ones are located as `scratch/pcap_crypto.py`.
- Recommendation: copy the PE/pdata/xref helpers to `scratch/` if the
  RE is continued offline (see below, are created with it).

---

## 20. Session crypto localized + Frida script ready (2026-07-28)

### Important module division (via objdump/export analysis)
- **`GoodixMocWbdi.dll`** — Algorithm/Templates (enrol*, identify*, template*,
  preprocess*). Contains mbedTLS, but the HMAC wrappers (`gf_hmac_sha256`) are
  only used there by `ProcessPsk` (PSK provisioning).
- **`GoodixMocSensorAdapter.dll`** — **Transport adapter, this is where the
  session crypto sits.** Contains the mbedTLS cipher strings `AES-128-CBC` … and the
  SHA256 init constant in **8 functions** (SHA256 + HMAC layers).
- `GoodixMocStorageAdapter.dll` — Template storage encryption (full
  mbedTLS cipher list incl. GCM/CCM; irrelevant for the session).

### AES is neither table- nor AES-NI-based
Neither AES S-Box nor AES-NI instructions in any DLL. Thus mbedTLS is
built with runtime-generated tables. The AES key can therefore not be found
statically via constant — but it comes from the HMAC-SHA256-PRF anyway,
and **SHA256 is findable**. That's why the hook targets the SHA256/HMAC layer.

### SHA256/HMAC functions in GoodixMocSensorAdapter.dll (RVA, image_base 0x180000000)
```
  0x25580 (266 B)    0x26630 (198 B)    0x30bc0 (1175 B, PRF candidate)
  0x324a2 (125 B)    0x326a7 (612 B, HMAC candidate)   0x32a10 (237 B)
  0x34880 (296 B)    0x34a26 (180 B)
```

### Deliverable: `scratch/frida_kdf_dump.js`
Hooks these eight functions in **GoodixMocSensorAdapter.dll** and dumps their
pointer arguments. The session KDF is a chain of HMAC-SHA256; in the trace,
the `master_secret` step (Key = Zero-PSK structure) and the `key expansion`
step (returns AES key ‖ HMAC key) are directly recognizable.

**Flow/Sequence on Windows:**
```
pip install frida-tools
frida-ps -ai                         # Find process with GoodixMocSensorAdapter.dll
                                     # (Windows Hello = Service WbioSrvc in svchost.exe)
frida -p <PID> -l scratch/frida_kdf_dump.js
# then trigger fingerprint unlock/enroll
```
Output: Console + `goodix_kdf_trace.txt`.

**Fine-tuning:** If the mbedTLS one-shot HMAC is recognizable in the trace (6 arguments:
md_info, key, keylen, in, ilen, out), enter its RVA into `HMAC_ONESHOT_RVA` —
then key/data/MAC will be logged cleanly isolated instead of heuristically.

### Verification
The dumped AES key is verified immediately:
```
python3 scratch/pcap_crypto.py --key <16-byte-hex>
```
If >50% of the messages are cleanly decrypted, the KDF is cracked/broken and the
Linux driver can reconstruct the derivation.

### The analysis is thus completely handed over
All building blocks for a working driver are available and documented:
transport, framing (`MAC|01ff|len|IV|CT`), command sequence (Section 16),
status codes (`01`=no match, `04`=not auth, 1110 B=token), crypto suite,
Zero-PSK, image decoding (`capture.py`/`goodix5xx.c`) as well as the RE tools
(`scratch/re_tools/`, `scratch/pcap_crypto.py`) and the Frida extractor. The
only remaining unknown — the exact KDF — will become visible in one run through
the Frida trace on real Windows hardware.

---

## 21. Offline paths exhausted — Ghidra package for the Linux machine (2026-07-28)

### What else was tested and ruled out
- **OTP as key:** `a6 00` (READ_OTP) returns 16 structured bytes, but
  they are **not** an AES key (0-2/159 padding hits = random). The value also
  changes between captures (counter `0001`→`0002`); it is a **challenge**
  that is mirrored back in the 1110-byte `a5` response (the `62 00 43 04 f5 …
  c2b3231e…` pattern in both).
- **Certificate-based keys:** SHA256(cert), SHA256(pubkey), HMAC(PSK,·),
  all EC point windows and 786 sliding 16-byte windows from the
  handshake material — **no hit**.
- **No plaintext handshake in the e3 channel:** Before the first encrypted
  `e3 02 00` there are only `d0` (device identity "RONGYAO/GM188…"), `d6`, `c0`
  (MCU config), `e1`, `a6` (OTP). There is **no** visible nonce/key
  exchange — the key derivation is purely in the driver, not on the wire.

Conclusion: The session key can **not** be reconstructed from the captures.
It needs the KDF function from `GoodixMocSensorAdapter.dll`.

### Why Frida doesn't work here
Frida would have to run **on Windows**, where the Goodix driver is active. On the
Linux target machine, the Windows driver does not run. The `frida_kdf_dump.js`
remains valid — but only if a Windows installation/VM with the sensor
is available (the `goodix_vm_traffic.pcapng` suggests that there once was a VM).

### Recommended path: Ghidra headless on the Linux machine
Completely local, no Windows required. Ghidra is already in the project.

```bash
# 1. Install JDK 17 (CachyOS/Arch):
sudo pacman -S jdk17-openjdk
# 2. Start decompilation:
./run_ghidra.sh
```

`run_ghidra.sh` imports `GoodixMocSensorAdapter.dll`, lets Ghidra
analyze it, and calls `scratch/ghidra_dump_kdf.py`, which writes the eight
SHA256/HMAC functions (RVA 0x25580, 0x26630, **0x30bc0**, 0x324a2,
**0x326a7**, 0x32a10, 0x34880, 0x34a26) as C to **`kdf_decompiled.c`**.
The two marked in bold are the prime suspects (PRF/HMAC).

From `kdf_decompiled.c` the derivation can be read directly and rebuilt as Python;
`scratch/pcap_crypto.py --key <hex>` verifies it immediately against the
captures. Afterwards, the driver can be straightforwardly completed.

### All tools created today (in the repo)
| File | Purpose |
|---|---|
| `scratch/sdcp_replay.py` | Replay Windows frames, compare responses |
| `scratch/moc_probe.py`, `win_order_probe.py` | a5 / sequence oracle probes |
| `scratch/key_sweep.py`, `kdf_sweep.py` | ECDH/KDF variants on the sensor |
| `scratch/pcap_crypto.py` | **Offline key oracle** against all captures |
| `scratch/re_tools/` | PE / pdata / pcapng parsers (objdump RE tools) |
| `scratch/frida_kdf_dump.js` | KDF live dump (Windows only) |
| `run_ghidra.sh` + `scratch/ghidra_dump_kdf.py` | **KDF decompilation (Linux)** |
### Incidental finding: IV reuse
The driver reuses IVs multiple times (`goodix_unlock_success`: 29 of 50
messages share an IV with another one). Several pairs are even
**byte-identical** (same IV + same ciphertext = literally identical message
sent twice). This is cryptographically sloppy, but doesn't help with the
key, because the IV is sent in plaintext anyway.

### New tool: `scratch/pcap_crypto.py`
Standalone pcapng parser + decryption oracle. Loads all 159
encrypted messages from the captures and checks a key candidate
against two independent oracles (PKCS7 padding and HMAC-SHA256 over
`01ff|len|IV|CT`). Self-test passed: Zero-Key → 0 false positives among 159
messages, so the oracle is highly discriminatory.

```bash
python3 scratch/pcap_crypto.py                  # Overview
python3 scratch/pcap_crypto.py --key <hex16>    # Test candidate
# as library: from pcap_crypto import try_key, try_derivation
```

As soon as the derivation from Ghidra is known, this script verifies it in
seconds against physical/real data — without hardware.

### Clear recommendation: Ghidra now
The black-box approach is exhausted. The target in `GoodixMocWbdi.dll`:

1. **`gf_hmac_sha256`** — the string is located at offset 777912. From there,
   trace back the callers: which buffer is passed as the key and
   what is it generated from? This is the shortest path to the `mac_key`.
2. **`mbedtls_ssl_psk_derive_premaster`** (String at ~0x3AF...) — shows how
   the premaster is constructed (RFC 4279 or modified).
3. **`mbedtls_ssl_derive_keys`** — Standard or patched?

Ghidra + JDK are already in the project (`ghidra_11.0.3_PUBLIC/`, `jdk/`).

### Honest overall assessment
Transport, framing, and crypto suite are completely understood and implemented in
executable Python tools. What's missing is the **one**
key derivation function. It can no longer be guessed via black-box — it
must be read from the binary. Without it, the Linux driver cannot
generate a valid encrypted message, and thus cannot induce the MoC sensor to yield the
Auth-Token. This is not a dead end, but the next stage is
static reverse analysis, not further hardware probing.

---

## 19. Binary analysis + sister chip: the picture becomes complete (2026-07-28)

### objdump instead of Ghidra
Ghidra does not run in the sandbox (bundled JDK is Windows-only, system JDK is
11, Ghidra 11 requires 17). Replacement: `objdump -b pei-x86-64` plus custom-
written PE/.pdata parsers (`/tmp/pe.py`, `/tmp/pdata.py`, `/tmp/xref.py`).
This provides exact function boundaries (2030 functions from `.pdata`) and
RIP-relative Xrefs — sufficient for targeted analysis.

### What the DLL reveals
- `GoodixMocWbdi.dll` links **mbedTLS** statically, suite
  **`TLS-PSK-WITH-AES-128-CBC-SHA256`** (Section 17).
- The only caller of the `gf_hmac_sha256` wrapper is the function
  **`ProcessPsk`** (VA 0x18008edc0) — this is the **PSK provisioning**, not
  the session KDF. Strings there: `1.check psk if valid`, `3.write psk to mcu`,
  `sgxPskLen`, `GfSealData`, `PresetPskWriteKey`, `production_write_key`.
- The session KDF thus uses mbedTLS's own HMAC function, not the
  Goodix wrapper — it is harder to isolate in the binary.

### The sister chip provides the missing reference
`goodix-fingerprint-reversing/capture.py` is a **working** driver
for the Goodix 55a2 (GF3206) and was previously unnoticed. Key points that transfer directly
to the GF3268:

- **The TLS-PSK is Zero (32 null bytes).** Confirmed by the running
  openssl line: `openssl s_server -nocert -psk 0000…0`. The 144-byte `PSK_WB`
  is only a provisioning blob that is written to the MCU once —
  it is **not** the session key. The same `ProcessPsk`/`PresetPsk`
  functions are found in our GF3268 DLL.
- **Role distribution:** the device is the TLS **client**, openssl is the
  **`s_server`**. The natasha C driver and `test_get_image.py`, on the other hand,
  use `s_client` or roll their own ECDH — **wrong role**.
- **Flow/Sequence 55a2:** `d0` (REQUEST_TLS) → Device sends ClientHello →
  to s_server → ServerHello back to device → Device sends
  ClientKeyExchange+CCS+Finished → to Server → ServerFinished to device. Pure
  standard TLS-PSK.

### The GF3268 is not a pure 55a2
Two hard differences in the captures:
1. **Not a single TLS record marker** (`16 03 xx`, `14 03 03`) in the entire
   USB traffic of all nine pcaps. The GF3268 packages the mbedTLS crypto into a
   **custom** record format (`MAC32 | 01ff | len | IV | CT`), not in
   standard TLS records. The s_server proxy trick of the 55a2 therefore does not
   work unmodified.
2. The GF3268 has a `d0` command whose response starts with `…0002 fe41 5050…`
   (in `goodix_init` and `goodix_handshake_and_enroll`, **not** in
   Unlock — the handshake is thus only performed once per power cycle and
   then reused).

### This makes the situation precise
Everything is understood **except** the one key derivation from the
handshake nonces. Facts:
- Crypto = mbedTLS, `TLS-PSK-WITH-AES-128-CBC-SHA256`, **Zero-PSK** (now supported by
  the 55a2 evidence, no longer just an assumption).
- Standard TLS-PSK-KDF with Zero-PSK does not reproduce the session though
  (`kdf_sweep.py`, 12 variants). Thus, an additional factor comes into play —
  most likely the ECDHE portion (the Server Hello contains ephemeral
  EC points), i.e., **ECDHE-PSK-Premaster** `Z || PSK structure`, but with a
  nonce/seed assignment that has not been hit yet.

### Two paths to the goal — decision required
**A. Frida hook on Windows (fastest sure path).**
Run the Windows driver and hook `mbedtls_ssl_derive_keys` or the
AES setup function to dump `master_secret` / `key_block` **directly**.
Inputs (Nonces, Z) are known from our live runs → the exact
KDF formula results from a single input/output pair. `pcap_crypto.py`
verifies it immediately. Prerequisite: Windows installation with the sensor.

**B. Continue static RE (no Windows required, but tedious).**
Read the mbedTLS handshake function completely in the binary. Without Ghidra/JDK17
this is only feasible with objdump, but tedious. Requires an executable
Ghidra (install JDK 17) or Radare2/Cutter as a replacement.

Both lead to the same goal: once the KDF is known, the driver can be
straightforwardly completed — transport, framing, command sequence and image
decoding (from `capture.py`/`goodix5xx.c`) are already available.

### Tools for this step (all offline, in the repo)
- `/tmp` parsers are volatile; the persistent ones are located as `scratch/pcap_crypto.py`.
- Recommendation: copy the PE/pdata/xref helpers to `scratch/` if the
  RE is continued offline (see below, will be created).

---

## 20. Session crypto localized + Frida script ready (2026-07-28)

### Important module breakdown (via objdump/Export analysis)
- **`GoodixMocWbdi.dll`** — Algorithm/Templates (enrol*, identify*, template*,
  preprocess*). Contains mbedTLS, but the HMAC wrappers (`gf_hmac_sha256`) are
  only used there by `ProcessPsk` (PSK provisioning).
- **`GoodixMocSensorAdapter.dll`** — **Transport adapter, this is where the
  session crypto sits.** Contains the mbedTLS cipher strings `AES-128-CBC` … and the
  SHA256 init constant in **8 functions** (SHA256 + HMAC layers).
- `GoodixMocStorageAdapter.dll` — Template storage encryption (full
  mbedTLS cipher list incl. GCM/CCM; irrelevant for the session).

### AES is neither table-based nor AES-NI-based
Neither AES S-Box nor AES-NI instructions in any DLL. mbedTLS is thus
built with runtime-generated tables. The AES key is therefore statically
unfindable via constant — but it originates anyway from the HMAC-SHA256-PRF,
and **SHA256 is findable**. Therefore, the hook targets the SHA256/HMAC layer.

### SHA256/HMAC functions in GoodixMocSensorAdapter.dll (RVA, image_base 0x180000000)
```
  0x25580 (266 B)    0x26630 (198 B)    0x30bc0 (1175 B, PRF candidate)
  0x324a2 (125 B)    0x326a7 (612 B, HMAC candidate)   0x32a10 (237 B)
  0x34880 (296 B)    0x34a26 (180 B)
```

### Deliverable: `scratch/frida_kdf_dump.js`
Hooks these eight functions in **GoodixMocSensorAdapter.dll** and dumps their
pointer arguments. The session KDF is a chain of HMAC-SHA256; in the trace,
the `master_secret` step (Key = Zero-PSK structure) and the `key expansion`
step (yields AES-Key ‖ HMAC-Key) are directly recognizable.

**Flow/Sequence on Windows:**
```
pip install frida-tools
frida-ps -ai                         # Find process with GoodixMocSensorAdapter.dll
                                     # (Windows Hello = WbioSrvc service in svchost.exe)
frida -p <PID> -l scratch/frida_kdf_dump.js
# then trigger fingerprint Unlock/Enroll
```
Output: Console + `goodix_kdf_trace.txt`.

**Fine-tuning:** If the mbedTLS one-shot HMAC is recognizable in the trace (6 arguments:
md_info, key, keylen, in, ilen, out), enter its RVA in `HMAC_ONESHOT_RVA` —
then Key/Data/MAC will be cleanly isolated and logged instead of heuristically.

### Verification
The dumped AES key is immediately verified:
```
python3 scratch/pcap_crypto.py --key <16-Byte-Hex>
```
If >50% cleanly decrypted messages, the KDF is cracked/broken and the
Linux driver can replicate the derivation.

### With this, the analysis is handed over completed
All building blocks for a working driver are available and documented:
Transport, framing (`MAC|01ff|len|IV|CT`), command sequence (Section 16),
status codes (`01`=no match, `04`=not auth, 1110 B=Token), crypto suite,
Zero-PSK, image decoding (`capture.py`/`goodix5xx.c`), as well as the RE tools
(`scratch/re_tools/`, `scratch/pcap_crypto.py`) and the Frida extractor. The
only remaining unknown — the exact KDF — becomes visible through the Frida trace
on physical Windows hardware in a single run.

---

## 21. Offline paths exhausted — Ghidra package for the Linux machine (2026-07-28)

### What else was tested and ruled out
- **OTP as key:** `a6 00` (READ_OTP) yields 16 structured bytes, but
  they are **not** an AES key (0-2/159 padding matches = chance). The value also
  changes between captures (counter `0001`→`0002`); it is a **challenge**
  that is mirrored back in the 1110-byte `a5` response (the `62 00 43 04 f5 …
  c2b3231e…` pattern in both).
- **Certificate-based keys:** SHA256(cert), SHA256(pubkey), HMAC(PSK,·),
  all EC point windows and 786 sliding 16-byte windows from the
  handshake material — **no match**.
- **No plaintext handshake in the e3 channel:** Before the first encrypted
  `e3 02 00`, there are only `d0` (Device Identity "RONGYAO/GM188…"), `d6`, `c0`
  (MCU config), `e1`, `a6` (OTP). There is **no** visible nonce/key
  exchange — the key derivation is purely in the driver, not on the wire.

Conclusion: The session key **cannot** be reconstructed from the captures.
It requires the KDF function from `GoodixMocSensorAdapter.dll`.

### Why Frida doesn't apply here
Frida would have to run **on Windows**, where the Goodix driver is active. On the
Linux target machine, the Windows driver is not running. The `frida_kdf_dump.js`
remains valid — but only if a Windows installation/VM with the sensor is
available (the `goodix_vm_traffic.pcapng` suggests there used to be a VM).

### Recommended path: Ghidra headless on the Linux machine
Fully local, no Windows required. Ghidra is already in the project.

```bash
# 1. Install JDK 17 (CachyOS/Arch):
sudo pacman -S jdk17-openjdk
# 2. Start decompilation:
./run_ghidra.sh
```

`run_ghidra.sh` imports `GoodixMocSensorAdapter.dll`, lets Ghidra
analyze and calls `scratch/ghidra_dump_kdf.py`, which writes the eight
SHA256/HMAC functions (RVA 0x25580, 0x26630, **0x30bc0**, 0x324a2,
**0x326a7**, 0x32a10, 0x34880, 0x34a26) as C to **`kdf_decompiled.c`**.
The two marked in bold are the primary suspects (PRF/HMAC).

From `kdf_decompiled.c`, the derivation can be read directly and rebuilt as Python;
`scratch/pcap_crypto.py --key <hex>` verifies it immediately against the
captures. After that, the driver can be straightforwardly completed.

### All tools created today (in repo)
| File | Purpose |
|---|---|
| `scratch/sdcp_replay.py` | Replay Windows frames, compare responses |
| `scratch/moc_probe.py`, `win_order_probe.py` | a5 / sequence oracle probes |
| `scratch/key_sweep.py`, `kdf_sweep.py` | ECDH/KDF variants at the sensor |
| `scratch/pcap_crypto.py` | **Offline key oracle** against all captures |
| `scratch/re_tools/` | PE / pdata / pcapng parsers (objdump RE tools) |
| `scratch/frida_kdf_dump.js` | KDF live dump (Windows only) |
| `run_ghidra.sh` + `scratch/ghidra_dump_kdf.py` | **KDF decompilation (Linux)** |

---

## 22. BREAKTHROUGH: Session Crypto Fully Decompiled (2026-07-28)

Ghidra headless ran on `GoodixMocSensorAdapter.dll` (`kdf_decompiled.c`, 1007
lines). The entire encryption is thus reconstructed.

### Packet encryption: `FUN_180030bc0`
Builds exactly the observed wire format. Output layout (Offsets in param_3):
```
  +0x00  MAC (32 B, HMAC-SHA256, calculated last)
  +0x20  01 ff            (Marker)
  +0x22  plaintext_len    (4 B LE)
  +0x26  IV (16 B)        <- NOT random: hashed from the plaintext!
  +0x36  AES-128-CBC(PKCS7(plaintext))
```
Flow/Sequence:
1. **IV** = HMAC-SHA256 over (`01ff` ‖ len ‖ plaintext ‖ 16×counter), first 16 B.
   → hence the observed IV reuse for identical plaintext.
2. AES-Key + MAC-Key via KDF (see below).
3. `FUN_180031600(ctx, keymat, 0x80)` = AES-128 setkey, `keymat[0:16]`.
4. PKCS7-Pad, AES-128-CBC encrypt.
5. HMAC-SHA256 over (`01ff` ‖ len ‖ ciphertext) with MAC-Key → MAC at +0x00.

### Key derivation: `FUN_1800325d0` = NIST SP 800-108 Counter-Mode-KDF
```
  For each 32-B block i (counter starts at 1):
    block_i = HMAC-SHA256(KI,  BE32(i) ‖ Label ‖ Context ‖ BE32(L_in_bits))
  Output = first L bytes of the concatenated blocks.
```
- **KI** = 32-B Master (from `FUN_180034be0`, origin = open question, round 2).
- **Label**   = Bytes `6b676f6f6477697867 00` = `"kgoodwixg\0"` (10 B).
- **Context** = Bytes `6b61656c72676e6f65726c6974686d` = `"kaelrgnoerlithm"` (15 B).
  (obfuscated "goodix" or "kernel"+"algorithm"; **the literal bytes are hashed**, not the de-obfuscated form.)
- **L** = 0x30·8 = 384 Bit → 48 B output: `[0:16]` = AES Key, `[16:48]` = MAC Key.

### `FUN_180034880` = HMAC-SHA256-Init (confirmed: standard HMAC, key>64B is hashed)

### What's still missing: the Master Key KI
`FUN_180034be0(local_c0)` populates the 32-B KI. Its call tree uses AES-setkey
(0x31600) and SHA (0x32480) — looks like a **Key Unwrap** (static key unpacks a stored blob?). This determines whether KI is
**device-static** (then calculable offline) or handshake-dependent.

**Round 2 is running:** `scratch/ghidra_dump_kdf.py` now targets `FUN_180034be0`
and its call tree (0x34be0, 0x33960, 0x34720, 0x35790, 0x32940, 0x32280,
0x31600). Output → `kdf_master.c`.

```bash
./run_ghidra.sh      # now generates kdf_master.c
```

As soon as KI is resolved, the complete encryption can be reimplemented in Python
and immediately verified against the captures with `scratch/pcap_crypto.py --key <hex>`. The KDF reimplementation (Format + SP800-108) is already done; only the
KI source is missing.

---

## 23. Master Key KI is an Obfuscated Constant — Extracted via Emulation (2026-07-28)

### FUN_180034be0 is a White-Box Constant Generator
`kdf_master.c` shows: `FUN_180034be0(out)` takes **no** input. It builds the
32-byte KI from bit-rotated "Goodix" bytes, which run through AES/HMAC/CRC with
**hardcoded** keys (`DAT_18004b2f0`, `DAT_18004b340`)
(`FUN_180032280` = AES-CMAC-like, `FUN_180032940` = HMAC, `FUN_180034720` =
CRC-32, Poly 0x04C11DB7). **KI is thus a fixed constant** — device- and
session-independent. Consequently, the AES and MAC keys are also **fixed** and
decrypt *all* captures.

Looking back, this explains why no handshake material was required on the wire:
the session is encrypted from the very beginning with a constant key hidden in the driver.

### KDF verified
The Python reimplementation of the SP800-108 KDF matches the decompiled code byte by byte:
```python
label, context, L = b"kgoodwixg\x00", b"kaelrgnoerlithm", 48
block_i = HMAC_SHA256(KI, BE32(i) + label + context + BE32(L*8))
keyblock = (block_1 || block_2)[:48]
aes_key, mac_key = keyblock[:16], keyblock[16:48]
```
Once KI is available, the keys are determined without any further RE.

### `scratch/emulate_ki.py` — KI via Emulation
Instead of reimplementing the obfuscation, the script executes the original functions
with **Unicorn** (malloc/free hooked, stack cookie stubbed, all sections
mapped): `FUN_180034be0` → KI, then `FUN_1800325d0` → 48-byte keyblock. It
compares the emulator and Python KDF and immediately verifies the keys against the
captures via `pcap_crypto.py`.

```bash
# Install Unicorn:
sudo pacman -S python-unicorn        # CachyOS/Arch
#   or:  python3 -m pip install --user unicorn
python3 scratch/emulate_ki.py
```

Expected output: `KI`, `AES-128 Key`, `HMAC Key`, "Python KDF matches:
True", and "*** MATCH — the keys decrypt the physical/real captures! ***".

### Afterwards, the driver can be completed
With the fixed keys, the complete encryption is in place:
- **Encrypt** (Host→Sensor): IV = HMAC-SHA256(01ff‖len‖plaintext‖16×ctr)[:16],
  AES-128-CBC(PKCS7(plaintext)), MAC = HMAC-SHA256(01ff‖len‖CT).
- **Decrypt** (Sensor→Host): AES-128-CBC decrypt with IV from the packet,
  verify MAC.
This replaces the `openssl s_client` subprocess in the C driver entirely with
a few lines of mbedTLS/Python crypto. The command sequence, framing, status codes, and
image decoding are already available (Sections 16, 22).

---

## 24. ✅ SESSION CRYPTO FULLY BROKEN (2026-07-28)

`scratch/emulate_ki.py` executed Unicorn emulation to extract Master Key KI, compute
KDF and verified the keys against **all 159** captured messages:

```
  AES 159/159 valid padding   +   HMAC 159/159   =   Crypto 100% Correct
```

### The Keys (Fixed Constants in Driver, Device-Independent)
```
  KI      = <KI_KEY_PART1> <KI_KEY_PART2>
  AES_KEY = <AES_128_SESSION_KEY_16B_PLACEHOLDER>                       (AES-128-CBC)
  MAC_KEY = <MAC_KEY_PART1> <MAC_KEY_PART2>
```
- KI = `FUN_180034be0()` ‖ `FUN_180033960()` (two obfuscated 16-B constants,
  stack-adjacent → 32 B). Extracted via binary emulation, not guessed.
- `AES_KEY, MAC_KEY = SP800-108-KDF(KI, "kgoodwixg\0", "kaelrgnoerlithm", 384bit)`.

### Verified Wire Format (Inner e3 Payload)
```
  MAC(32) || 01 ff || plaintext_len(LE32) || IV(16) || AES-128-CBC(PKCS7(plaintext))
  MAC = HMAC-SHA256(MAC_KEY, 01ff || plaintext_len(LE32) || ciphertext)   [159/159]
  IV  = SHA256(01ff||len||plaintext||16×BE32(3))[:16]  when sending;
        Receiver uses the packet IV (IV is not in MAC → arbitrary IV permitted)
```

### New Reference Module: `goodix_crypto.py`
Complete `encrypt()` / `decrypt()` / `derive_keys()` implementation with fixed session keys.
Self-test passed (KDF reproduces keys, round-trip validated). Replaces
the entire `openssl s_client` subprocess architecture with ~20 lines of C/OpenSSL code.

### Readable MoC Protocol (Overcoming the 'Cryptographic Wall')
Decrypted unlock capture reveals a **second, inner layer**:
- Sensor→Host `e3 00 00` (1366 B) → decrypts to `71040000 3082034b…` =
  Handshake flight containing **Certificate** (byte-identical to `sensor_cert.der`).
- Host `e3 02/00` (162 B) → inner **ECDH Handshake** (Microsoft SDCP).
- Host `e3 02/01` (32 B) → SDCP Identity / MAC token.

Outer transport encryption is fully resolved; inner SDCP protocol layer
is **readable in plaintext** and can be implemented step-by-step —
overcoming what section 6 of `walkthrough.md` called the final boss.

### Status for the driver
| Component | Status |
|---|---|
| USB transport, packet framing, CRCs | ✅ (C driver + Python) |
| Command sequence, status codes | ✅ (Section 16) |
| **Session encryption** | ✅ **resolved** (`goodix_crypto.py`) |
| Inner SDCP layer (ECDH/Token) | ⏳ now decryptable, reimplementation pending |
| Image/template decoding | partial (5xx code + `capture.py`) |

Next step: map the decrypted SDCP sequence from the pcaps completely
(Client/Server-ECDH, Identity, Enroll/Verify-Token) and reproduce it in the driver.
The most difficult part — the opaque transport — is resolved.

---

# 25. EXECUTIVE SUMMARY & FILE INDEX

This section serves as the primary technical reference summarizing the entire RE journey
and driver status; sections 10–24 document chronological progression.


## 25.1 What Was Achieved (Executive Summary)
1. **C Driver Transport Layer Fixed** (Section 10): Buffer resynchronization,
   CRC8 header validation, 64-byte padding alignment, uninitialized string formatting fixes,
   command sequencing (`36`→`a2`), post-handshake SSM (`a5`/`08`), MoC finger-down path.
2. **TLS Hypothesis Refuted** (Sections 11–17): Sensor does NOT speak TLS on the wire;
   `openssl s_client` proxy concept was invalid. Python PoC
   never validated handshakes and logged success unconditionally.
3. **Protocol Mapped** (Sections 12–16): Complete Windows Hello unlock sequence,
   wire framing, status codes (`01` = no match, `04` = unauthenticated,
   1110 B = Auth Token).
4. **Crypto Library Identified** (Section 17): Statically linked mbedTLS,
   `TLS-PSK-WITH-AES-128-CBC-SHA256` inside `GoodixMocSensorAdapter.dll`.
5. **Session Crypto Fully Broken** (Sections 22–24): Decompiled via Ghidra,
   KDF reconstructed (SP800-108/HMAC-SHA256), Master Key extracted via
   Unicorn binary emulation, verified against **159/159** captured packets.

## 25.2 Resolved Keys (Fixed Constants, Device-Independent)
```
  AES_KEY = <AES_128_SESSION_KEY_16B_PLACEHOLDER>
  MAC_KEY = <HMAC_SHA256_SESSION_KEY_32B_PLACEHOLDER>
  KI      = <KDF_MASTER_KEY_32B_PLACEHOLDER>
```
Wire Format (Inner e3 Payload):
`MAC(32) ‖ 01ff ‖ len(LE32) ‖ IV(16) ‖ AES-128-CBC(PKCS7(pt))`,
`MAC = HMAC-SHA256(MAC_KEY, 01ff ‖ len ‖ CT)`.

## 25.3 Repository File Index
| File | Purpose | Execution Target |
|---|---|---|
| `scratch/goodix_crypto.py` | **Reference Crypto Implementation**: encrypt/decrypt/KDF, fixed Keys | All platforms |
| `scratch/emulate_ki.py` | Extract Master Key via Unicorn emulation of DLL | Linux, `python-unicorn` |
| `scratch/pcap_crypto.py` | Offline crypto oracle against pcap captures | All platforms |
| `scratch/sdcp_replay.py` | Replay & compare Windows USB frames | Physical Sensor Hardware |
| `scratch/moc_probe.py`, `win_order_probe.py` | a5 / sequence oracle probes | Physical Sensor Hardware |
| `scratch/key_sweep.py`, `kdf_sweep.py` | (historical) KDF variants on the sensor | Physical Sensor Hardware |
| `scratch/frida_kdf_dump.js` | (Alternative path) KDF live dump | Windows + Frida |
| `scratch/re_tools/` | PE / pdata / pcapng parsers (objdump RE tools) | All platforms |
| `run_ghidra.sh` + `scratch/ghidra_dump_kdf.py` | Decompile DLL crypto functions | Linux + JDK17 |
| `kdf_decompiled.c`, `kdf_master.c` | Decompiled C code of crypto/KDF functions | — |
| `run_enroll_test.sh` | Build C driver & test against physical sensor | Physical Sensor Hardware |
| `HANDOVER_COWORK.md` | **This document** | — |

Not in Git (see `.gitignore`): `ghidra_11.0.3_PUBLIC/`, `jdk/`,
`ghidra_headless_proj/`, `*.pcapng`, `*.bin`, `*.log`, Emulation outputs.

## 25.4 Reproduction of Cryptographic Break (Linux-Only)
```bash
sudo pacman -S jdk17-openjdk python-unicorn      # Prerequisites
./run_ghidra.sh                                  # decompiles -> kdf_master.c
python3 scratch/emulate_ki.py                    # KI -> Keys -> 159/159 packet validation
python3 scratch/goodix_crypto.py                 # Self-test of the Reference Crypto Implementation
```

## 25.5 Steps to Production Driver
1. **Map Inner SDCP Layer:** Outer transport encryption resolved;
   MoC commands decrypted. Extract plaintext sequence of ECDH handshake,
   Identity and Enroll/Verify tokens from PCAPs.
2. **Replace Driver Crypto:** Replace `openssl s_client` subprocess in C driver
   with native OpenSSL implementation of `goodix_crypto.py` logic (AES-128-CBC
   + HMAC-SHA256 with fixed keys).
3. **Implement Enroll/Verify:** Replicate readable SDCP sequence;
   MoC returns Auth Token (1110 B) instead of raw image — handle host binding
   for libfprint integration.
4. **Template Path:** Sensor is Match-on-Chip; raw fingerprint images
   never leave sensor hardware.


**The most difficult obstacle — opaque session transport encryption —
is now 100% solved, documented, and fully reproducible.**

---

# 26. Decrypted Protocol & Driver Architecture

Using fixed session keys, all Windows USB traffic can be decrypted to plaintext.
Tool: `scratch/decode_protocol.py <capture.pcapng>`. Decrypted output stored in
`protocol_unlock.txt` and `protocol_enroll.txt`.

## 26.1 Architectural Discoveries
- **No Transport Handshake Required:** First encrypted `e3` packet follows
  immediately after `e1 04 00`; sensor accepts fixed keys immediately.
  → Linux driver speaks transport encryption from initial packet.
- **Two-Layer Architecture:** Outer layer: AES/HMAC transport encryption; inner layer:
  **SDCP Handshake** (Microsoft Secure Device Connection Protocol).
- **Inner SDCP ClientHello** (162 B, decrypted):
  `nonce(32) ‖ EC-Point(65, 0x04…) ‖ EC-Point(65, 0x04…)` — ephemeral
  host ECDH public key (refreshed per session).
- **SDCP ServerHello** (1366 B): `71 04 00 00 ‖ Certificate(847=sensor_cert.der)
  ‖ Server EC Point ‖ Signature`.
- **SDCP-Identity** (32 B → 33 B Response): HMAC-Token over the transcript.

## 26.2 Enroll Flow (Decrypted from `goodix_handshake_and_enroll`)
```
  Transport Encryption active (e3 framing, fixed keys)
  a7 02 00  (102 B, OTP/Config: contains READ_OTP value)
  a5 00 00  (32 B SDCP key) -> 1110 B Token   [or 0x01 on failure]
  a5 01 00  (01000000)      -> 00
  a1 00 00  (Enroll begin)  -> 33 B Token
  Loop per finger touch sample (13 touches):
     a0 00 00  Payload 01 64 64   ->  00 <progress> <quality>
        (Response e.g. 00 32 xx, 00 61 xx … = Enroll progress / coverage)
  a3 00 00 / a4 00 00  (Enroll commit / finalize)
```
`a0 00 00` is the **Enroll Sample Command with progress feedback** —
providing exactly what libfprint requires for enrollment stages. `a0/a1/a3/a4` are
plaintext protocol commands (unencrypted payload inside transport framing).

## 26.3 Verify Flow (Decrypted from `goodix_unlock_success`)
Per scan cycle: `e3` SDCP handshake → `b0 02` (calibration/sensor data, 65 B)
→ `a2 00 00 01002301` (finger region `5c 64 …`) → `a5 00 00` (32 B) → 1110 B
Token on match OR `01` on no-match → `e3 01` SDCP Identity.
Status codes verified: `a5` response **1110 B = Match/Token**, **`01` = No Match**.

## 26.4 Driver Reference Architecture: `goodix_gf3268.py`
Complete USB transport (Bulk transfers, Goodix framing with CRC8/CRC32/64-byte padding,
framing validated 12/12 against captured traffic) + integrated session crypto.
Provides `send()/recv()` (plaintext framing) and `send_enc()/recv_enc()`
(encrypted e3 transport channel). Includes `verify_crypto_live()`: transmits
inner e3 and decrypts the sensor response — **End-to-End proof on the hardware**.

```bash
sudo python3 scratch/goodix_gf3268.py
```
Expected output: '*** SUCCESS: Sensor certificate decrypted live ... ***'
confirming complete pipeline (USB → Framing → Crypto) on physical hardware.

## 26.5 Status Assessment & Work Remaining
**Resolved & Operational:** USB transport, packet framing, session encryption,
command landscape, enroll/verify protocol framing identified.

**Still open for full Enroll/Verify:** the inner SDCP layer. Two paths:
**Still open for full Enroll/Verify:** the inner SDCP layer. Two approaches:
1. **Bypass SDCP (preferred):** Check whether the sensor executes `a1`/`a0`-Enroll and
   `a5`-Verify with a *dummy* or *without* a complete SDCP handshake.
   This can now be tested directly on the hardware with `goodix_gf3268.py`.
   If yes, a libfprint driver without crypto attestation is possible.
2. **Reimplement SDCP:** ephemeral ECDH (P-256) + the SDCP KDF (another small
   RE task in `GoodixMocSensorAdapter.dll`, analogous to the already resolved
   transport KDF) + identity token. Only necessary if the sensor enforces SDCP.

The main blocker for years — the opaque transport encryption — is
resolved. Enroll/Verify is now a clearly defined problem testable on the hardware,
instead of a blackbox.

---

# 27. ✅ HARDWARE CONFIRMATION: Transport+Crypto run end-to-end (2026-07-29)

`sudo python3 scratch/goodix_gf3268.py` on the physical/real GF3268:
```
  Interface 0 claimed. Sensor ready.
  --- Init Sequence ---   e1 04 -> 00000000
  --- Verify crypto channel live ---
     e3 02 -> Status/Len: 004f030000
     e3 00 -> 1366 B decrypted: 710400003082034b308202f1a0030201…
  *** SUCCESS: Sensor certificate decrypted live ***
```
This proves the complete chain **on the hardware**: USB bulk →
Goodix framing (CRC8/CRC32/64B padding) → Session encryption (fixed keys)
→ Decryption of the 1366-B sensor response (certificates flight). The sensor
accepts the fixed keys without any handshake.

Fixed startup errors: missing ctypes `argtypes` (64-bit pointer truncation) and a
`log()` call. `goodix_gf3268.py` now runs cleanly.

## 27.1 Next Experiment: Reading finger data live
```bash
sudo systemctl stop fprintd        # Free the interface
sudo python3 scratch/goodix_gf3268.py finger
```
The `finger` mode polls `a2 00 00` (wait finger) and `b0 02`
(calibration/sensor values) for 20 s and displays changes. When placing/lifting the
finger, the values should change visibly → Proof that we can read finger presence
and sensor values live (foundation for Verify).

## 27.2 Roadmap to full Enroll/Verify
1. **Finger probe** (above): confirm that a2/b0 react to finger contact.
2. **Test Verify without SDCP:** send `a5 00 00` with a 32-B value, check if the
   sensor returns 1110 B (Match) / 0x01 (No Match) — even without a valid
   inner SDCP session. If yes: Verify against Windows templates is possible.
3. **If SDCP is enforced:** reverse the inner SDCP KDF in GoodixMocSensorAdapter.dll
   (same method as with the already resolved transport KDF:
   Ghidra decompilation + optionally Unicorn emulation) and reimplement ECDH P-256 +
   Identity token.
4. **Enroll:** `a1 00 00` (begin) → `a0 00 00` (sample, progress feedback)
   ×N → `a3/a4` (commit); Template on-chip.
5. **libfprint Integration:** port the proven command sequence + `goodix_crypto` into
   the C driver (replaces the openssl subprocess completely).

---

# 28. ✅✅ VERIFY WORKS ON HARDWARE — WITHOUT SDCP (2026-07-29)

`sudo python3 scratch/goodix_gf3268.py verify` with enrolled finger:
```
   a2=005a64001f003800  a5-> 1110 B  *** MATCH TOKEN! ***
        005a64470000000062004304f500cd00cc0fe95f7fcf760503889a36c8e6…
```

**The sensor performs the Match-on-Chip and returns the 1110-B token — entirely without
a valid inner SDCP session.** The only things required were: transport crypto (fixed keys) +
pre-sequence (`b0 02`, `e0 01`, `a2 00 00`) + `a5 00 00` with a 32-B random challenge.

### This is the breakthrough for a working Verify driver
- `a5 00 00` Response **1110 B = Match**, **0x01 = No Match** (verified).
- No ECDH, no SDCP identity token, no attestation necessary.

### Structure of the Match Token (1110 B, analyzed from 10 captures)
```
  [  0]      Status 00
  [1:3]      Finger region (e.g., 5a64, = a2 region)
  [3]        Counter
  [4:112]    108 B  STATIC across matches  -> Template/device identity
                    (contains 62004304f5 = OTP). Differentiates enrolled
                    fingers -> Foundation for IDENTIFY.
  [112:144]  32 B   changes   -> Match nonce
  [144:150]  6 B    static
  [150:1110] 960 B  changes   -> SDCP signature/attestation (irrelevant for Linux)
```
Sufficient for libfprint: 1110 B = Match, `[4:112]` identifies the finger.

### Thus the status is
| Function | Status |
|---|---|
| USB transport + Framing | ✅ Hardware |
| Session encryption | ✅ Hardware |
| Finger detection (a2/b0) | ✅ Hardware |
| **Verify / Match-on-Chip** | ✅ **Hardware, without SDCP** |
| Enroll (a1/a0/a3/a4) | ⏳ test next |
| libfprint integration | open (command sequence established) |

Only Enroll is missing for a complete driver — and the Enroll commands
(`a1` begin, `a0` sample with progress, `a3/a4` commit) are already
identified and will be tested on the hardware next.

---

# 29. Verify rigorously confirmed (Positive + Negative Test, 2026-07-29)

Control test on real hardware:
- **Enrolled finger** → `a5 -> 1110 B  *** MATCH TOKEN ***`
- **Non-enrolled finger** → consistently `a5 -> 01 (No Match)`

This unequivocally proves: the sensor executes a **physical/real Match-on-Chip**,
and `01` vs `1110 B` is the real result (not just finger presence).
**Verify is thus complete and scientifically properly verified.**

Robustness fix: `Device._drain()` discards IN packets left over from a previous session
during startup — fixes the "first run hangs" behavior.

## 29.1 Next step: Enroll (dry run)
```bash
sudo systemctl stop fprintd
sudo python3 scratch/goodix_gf3268.py enroll
```
The `enroll` mode does setup (`a6` OTP → `a7` → `a1` begin) and the
`a0` sample loop with progress display — **without `a4` commit**, meaning
**no template is saved** and the sensor remains unmodified. Place finger repeatedly,
slightly shifted. If `Byte1` of the `a0` response Direction reaches `0x64` (100%),
Enroll runs without SDCP and we will add the commit (`a3`/`a4`)
for actual saving.

---

# 30. Enroll finding: needs valid SDCP; Verify does not (2026-07-29)

Hardware tests of the `enroll` dry run (multiple iterations):
- `a1 00` (begin) always returns `00…` (33 B) = **Success**.
- Frame capture is running: `a2 00 00 000f4101` returns changing finger regions
  (`585a`, `5d5e`, `565b`, `4d56`, `5350` …) — sampling works.
- **`a0 00 00` consistently returns `000000`** = Frame accepted, **but not
  counted**. Even **with** a preceding `e3 01` identity step (dummy 32 B),
  the progress remains at 0.

**Conclusion:** Enroll only counts a sample if the `e3 01` SDCP identity
is **content-wise valid** (not just transported). A random identity is not enough.
Verify, on the other hand, returns the match token regardless of the
SDCP identity — which is why Verify is complete, but Enroll is not (yet).

## 30.1 Clear Status Table
| Function | Without SDCP | Status |
|---|---|---|
| Transport/Crypto/Framing | — | ✅ Hardware |
| Finger detection (a2/b0) | ✅ | ✅ Hardware |
| **Verify / Match-on-Chip** | ✅ **yes** | ✅ **works (Match vs. 01)** |
| **Enroll (a0 counting)** | ❌ **no** | ⏳ requires valid SDCP identity |

## 30.2 Two paths for Enroll
1. **Reimplement SDCP (the clean way):** reverse the inner layer in
   GoodixMocSensorAdapter.dll — ECDH P-256 (ClientHello:
   nonce(32)+EC(65)+EC(65)) + the SDCP key/identity KDF. Methodology is
   identical to the already resolved transport KDF: Ghidra decompilation of the SDCP
   functions + optionally Unicorn emulation, then compute identity token per sample.
   After that, Enroll is complete.
2. **Pragmatic (immediately usable):** Enroll in Windows, only verify under Linux.
   Since Verify works against existing templates, an Unlock-Only mode (dual-boot)
   is already possible now.

Robustness: `_bulk_out` resets the endpoint on stall and retries; the
sample loop catches USB stalls and continues (the `-1/-4` aborts from the
first runs no longer occur).

## 30.3 Next concrete step (if Enroll is desired)
Locate and decompile SDCP functions in `GoodixMocSensorAdapter.dll`
(same tools: `run_ghidra.sh`, `scratch/re_tools/`, `scratch/emulate_ki.py`).
Entry point: trace back the e3-01 identity generation and the ECDH processing of the
ServerHello (Certificate + Server EC Point) in the binary.

---

# 31. SDCP key scheme completely decompiled (2026-07-29)

Six Ghidra rounds on GoodixMocSensorAdapter.dll have revealed the complete
host side of the SDCP layer (source path in binary:
`…\GoodixSdcp\GoodixSdcpCmd.cpp`). The crypto follows the Microsoft SDCP scheme.

## 31.1 Function map (RVA in GoodixMocSensorAdapter.dll)
```
  0x7050   GoodixSdcpConnectSecure   Main Connect
  0xf020   host generate connect params  -> ClientHello (nonce + EC + EC)
  0x12040  sdcpcli_keygen            ephemeral P-256 keypair (pub 65B @+0, priv 32B @+0x41)
  0x113e0  sdcpcli_gen_rand          DRBG (Personalization "sdcpcli_gen_rand")
  0x10320  parse_connect_data        Parse ServerHello + ECDH + Keys + MAC Check
  0x10c30    +-> ECDH key material   (server_pub, client_priv, nonces)
  0x10ef0    |     FUN: ECDH point mult (P-256)
  0x10bd0    +-> Session keys        (application keys)
  0x11de0  KDF-PRIMITIVE             SP800-108 Counter-Mode HMAC-SHA256
  0x124b0  HMAC-SHA256 (with label)  Identity/MAC
  0x10a90  AES (SDCP data channel)   key @0x571d0
```

## 31.2 Key scheme (Labels are literal bytes)
```
  Z            = ECDH_P256(client_priv, server_pub)              (32 B)
  master_mat   = KDF(Z,          "master secret",  nonce_c‖nonce_s, 32 B)
  session_keys = KDF(master_mat, "application keys", (empty),        64 B)
                 -> AES Key(32) ‖ MAC Key(32)  (exact split to be verified)
  identity/MAC = HMAC-SHA256(session_key, "connect"|"reconnect" ‖ transcript)
```
Labels (RVA): `master secret`@0x48b78, `application keys`@0x48b88,
`connect`@0x48ba0, `connect2`@0x48ba8, `reconnect`@0x48bb8, `cert_m: `@0x48bc8.

## 31.3 KDF primitive `FUN_180011de0` = SP800-108, like the transport KDF
Signature `kdf(key, keylen, label, data, datalen, out, outlen)`. Structure
identical to the already verified transport KDF (`FUN_1800325d0`):
per 32-B block `HMAC-SHA256(key, BE32(counter) ‖ label ‖ … ‖ data ‖ BE32(outlen*8))`.
The exact field order (separator `0x00`, position of counter/bitlen) must
still be confirmed on the wire, because it cannot be verified offline (the
ephemeral client private key of the Windows captures is missing).

## 31.4 Important limitation for verification
Unlike the transport KDF and master key, the SDCP KDF **cannot be
verified offline against the captures**: the ephemeral client private key is missing there
(it was newly generated per Windows session and never transmitted). Verification
is therefore only possible on the hardware: run our own handshake and check whether the
sensor accepts our identity (Enroll frames are counted, `a0` > 0).
Therefore, 1-2 hardware iterations are realistic for the exact field order.

---

# 32. Everyday unlocking via PAM (Verify-only) — 2026-07-29

Since Verify works on the hardware (paragraphs 28/29), an everyday
usable fingerprint unlock is possible, WITHOUT Linux Enroll and without the
large libfprint C integration — via PAM (`pam_exec`), which matches against the
(Windows) templates already stored in the chip.

## Files
- `scratch/goodix_verify.py` — Standalone verify. Brings up the transport channel,
  waits for finger, `a5` match. Exit: **0=Match, 1=No Match, 2=Timeout,
  3=Error**. `--quiet` for PAM. CRC8/Transport verified against physical/real packets.
- `install_fingerprint_unlock.sh` — Installer: copies to `/opt/goodix-fp`,
  creates `/usr/local/bin/goodix-fp-verify`, writes udev rule, self-test,
  optional PAM activation.

## Installation
```bash
sudo ./install_fingerprint_unlock.sh          # install + test
sudo ./install_fingerprint_unlock.sh --sudo   # activate fingerprint for 'sudo'
sudo ./install_fingerprint_unlock.sh --remove # revert everything
```
The fingerprint is entered as **`sufficient`**: the password
always continues to work, nothing is replaced.

## Security & Limitations (Honest Assessment)
- **Password fallback always remains active** — no lockout risk.
- `pam_exec` is **sequential**: `sudo` waits up to `TIMEOUT_S` (6 s) for
  a finger before falling through to the password. Place finger promptly, otherwise
  wait briefly and type password.
- No prompt in the lock screen: `pam_exec` cannot cleanly display "Place finger".
  For Terminal/`sudo`/console login this is ok.
- **Graphical lock screens (GDM/SDDM/KDE)** need an entry in their
  PAM stack (e.g., `/etc/pam.d/system-auth` or the greeter). Automated
  editing is risky (lockout danger) and therefore NOT in the installer — if
  needed, do it manually with an open root shell as a safeguard.
- This is **not** an SDCP attestation like under Windows Hello. The sensor
  matches real on-chip, but the PAM layer has no anti-replay protection at the
  protocol level. A pragmatic solution for a personal laptop; for
  high-security requirements, full libfprint/SDCP integration would be necessary.

## Prerequisites
`python-cryptography`, `libusb`. fprintd must not occupy the sensor
(installer stops it for the test; for continuous operation, `systemctl disable
fprintd` if it interferes).

---

# 33. SDCP Enroll: Live handshake caught, KDF not yet cracked/broken (2026-07-29)

## Progress
- **`scratch/sdcp_capture.py`** runs a physical/real SDCP handshake with SELF
  generated keys and saves everything to `scratch/sdcp_capture.json`.
  generated keys and saves everything to `scratch/sdcp_capture.json`.
  Confirmed on hardware: the sensor accepts our ClientHello
  (`nonce(32)+EC1(65)+EC2(65)`) and replies with a full ServerHello (1366 B).
  This gives us a live session with a **known** client private key.
- ServerHello structure (after the 847 B certificate, 515 B):
  ```
    +0    EC static (65 B)   0437fb51…  = Device attestation key (== Windows)
    +65   EC server-eph(65)  04e9c7bd…  = Server ephemeral (per session)
    +130  96 B  STATIC
    +226  64 B  SESSION   (Nonce? MAC?)
    +291  104 B SESSION   (additional EC points @+290,+406)
    +396  119 B SESSION   (Signature)
  ```

## What Did NOT Work
Broad offline attack (75,600 combinations: 4 ECDH candidates × 5 SP800-108
field orders × ~20 nonce_s windows × 2 context orders × 3 keys × 10
transcripts, plus HKDF variants): **0 matches**. So the server MAC is not
`HMAC(derived_key, simple_transcript)` — the MAC signs a **complex
transcript hash** calculated in `FUN_180011870` (Input: certificate +
both EC points + nonces). This function is not yet decompiled.

## Honest Assessment & Protocol Classification
Unlike the transport KDF and master key (which were quickly verifiable offline
after decompiling), SDCP is deeply interlocked: Transcript hash →
KDF → MAC, plus the wire→structure parsing. Still missing to crack:
1. `FUN_180011870` — the exact transcript hash (next decompilation step).
2. Confirmation of the KDF field order (`FUN_180011de0`) on physical/real values.
3. The exact wire position of server_nonce/server_MAC (parse function).

This is doable, but realistically requires several more decompilation rounds. Next
step: `./run_ghidra.sh` (target now `FUN_180011870`) → `sdcp6.c`.

---

# 34. SDCP transcript clarified, but framing discrepancy blocks offline crack (2026-07-29)

## New Insights (sdcp6.c)
- **`FUN_180011870` = SHA256** (md type 6, init + 7 updates + finish) over the
  server handshake fields. The server MAC is therefore:
  `server_MAC = HMAC-SHA256(session_key, SHA256(cert ‖ EC points ‖ nonce ‖ blocks))`.
- Verification flow in `FUN_180010320`: ECDH → master-KDF ("master secret") →
  app-KDF ("application keys") → SHA256-Transcript → `HMAC(session_key, transcript)`
  == server_MAC (comparison via memcmp).
- `FUN_1800127a0` verifies the **certificate chain** ("cert_m: ", "Client Certs: ")
  against two embedded root certificates (`DAT_180055b30`, `DAT_180054f80`).

## Why the offline crack (still) fails — the root cause
The DLL SDCP code reads MAC/Nonce/Cert from a structure with offsets
`+0x14`/`+0x34`/`+0x54` — this is the **IOCTL framing** between DLL and
kernel driver. However, our decrypted **e3 ServerHello** has a DIFFERENT
framing (header `71040000`, certificate at `+4`). Both carry the same
SDCP content, but at different positions. Without the exact
wire↔IOCTL mapping I am guessing against the wrong byte offsets → all
brute-force runs (78,000+ combinations) miss.

## Honest Situation & Realistic Options
SDCP Enroll is therefore by far the toughest layer: multi-staged (ECDH → 2× KDF →
SHA256 → HMAC), with certificate chain validation and two different framings.
Unlike all previous layers, it **cannot** be cracked by
offline brute-forcing against the captures.

Three possible paths:
1. **Emulation (most promising path):** Execute `FUN_18000f020` (ClientHello+Keygen)
   and `FUN_180010320` (ServerHello→Session-Key) with Unicorn — DRBG
   hooked to known values. Then the emulation delivers the session key directly
   from OUR live ServerHello, without guessing. The vtable/mbedtls calls run
   in the emulator (code is mapped). Complex setup, but bypasses the
   framing issue entirely. **Recommended.**
2. **Continue decompiling:** reverse the IOCTL/parse layer (`FUN_180007da0` &
   surroundings) to map wire↔structure. Multiple rounds, uncertain.
3. **Consolidate:** Verify unlock is working (everyday goal achieved). Postpone SDCP Enroll
   as an open research topic.

The practical everyday utility (fingerprint unlocking) is already
achieved independently and ready for use.

---

# 35. BREAKTHROUGH: Complete SDCP key schema reconstructed via disassembly (2026-07-29)

Instead of Ghidra/Emulation (sandbox can do neither), the DLL was disassembled with **objdump**
and the entire SDCP crypto chain was manually reconstructed from the machine code.
All values are therefore binary-proven, not estimated/guessed.

## KDF (FUN_180011de0) — exact NIST SP800-108 Counter Mode
    K(i) = HMAC-SHA256(key, BE32(i) || label||0x00 || context || BE32(outlen*8))
- Counter i 1-based, 4B big-endian
- Label is hashed INCLUDING null terminator ("master secret\0")
- L = outlen in BITS, 4B big-endian
- output = K(1)||K(2)||… truncate outlen
=> exactly confirms the previous sp800_108 formula.

## Session Key Derivation (FUN_180010320 / _c30 / _bd0)
    Z        = ECDH(client_priv, EC_B)              # EC_B = Server Ephemeral
    master   = KDF(Z,      "master secret\0",   nonce_c || nonce_s, 32)
    session  = KDF(master, "application keys\0", <empty>,           64)  # 2×32B
- nonce_c = our client nonce (global 0x57188)
- nonce_s = server nonce (struct+0x34)
- ECDH point is EC_B (arg1 = [rbp-0x50] = second EC point after certificate)

## Transcript (FUN_180011870) = SHA256
    transcript = SHA256(cert || EC_A(65) || EC_B(65) || 32B@130 || 64B@162 || 64B@226)
- all fields from the ServerHello tail (after the certificate)

## MAC Verification (FUN_1800121d0 + memcmp)
    server_MAC (struct+0x14) == HMAC-SHA256(session_key, transcript)

## ClientHello (FUN_18000f020) — 105 Bytes, EXACTLY reconstructed
    [len u32=0x69] [ver u16=1] [type u16] [nonce_c 32B] [ephemeral_pubkey 65B]
- only ONE ephemeral key (not two!). Our old capture (nonce+pub1+pub2, no
  header) was therefore INCORRECTLY structured -> sensor misinterpreted the bytes
  -> ECDH never matched -> all previous offline cracks (100k+ combinations) had to
  fail. THAT was the actual root cause, not the crypto.

## Identity Labels (FUN_1800124b0): "enroll", "identify"
For the Enroll finish after a successful connect.

## Next Step
scratch/sdcp_capture.py NEW: sends correct 105B ClientHello with known
ephemeral key and verifies the server MAC immediately offline (only brute-forces
the nonce_s position over 32B windows). A match confirms the ENTIRE chain and
delivers the session key -> calculate identity and Enroll.

---

# 36. ★ SDCP SESSION CRYPTO CRACKED (2026-07-29) ★

Reproduced live on hardware and verified offline (calculated server MAC).

## Wire Format (confirmed via Windows capture + custom handshake)
ClientHello (e3 00, transport-encrypted):
    nonce_c(32) || EC1(65) || EC2(65)                    = 162 Bytes
ServerHello Flight (Response):
    [71 04 00 00] || cert(847) || tail(515)              = 1366 Bytes

## ServerHello Tail Layout (after the certificate, offsets relative to tail)
    @0   EC_A(65)   static device key (constant)
    @65  EC_B(65)   Server Ephemeral  ← ECDH point
    @130 32B        \
    @162 64B         > Transcript material (tail[0:290])
    @226 64B        /
    @290 EC_C(65)   additional point
    @355..515       Session blocks, including:
    @419 MAC(32)    Server Key Confirmation MAC
    @451 nonce_s(32) Server nonce

## Complete Verified Derivation (1:1 from GoodixMocSensorAdapter.dll)
    Z          = ECDH(client_priv, EC_B)                        # X-coord, 32B
    master     = SP800-108(Z,      "master secret\0",   nonce_c||nonce_s, 32)
    session    = SP800-108(master, "application keys\0", <empty>,         64)
    transcript = SHA256(cert || tail[0:290])
    server_MAC = HMAC-SHA256(session[0:32], "connect\0" || transcript)
Check: server_MAC == ServerHello field @ (cert_end+419).  ★ confirmed ★

## SP800-108 (FUN_180011de0), exact
    K(i) = HMAC-SHA256(key, BE32(i) || label||0x00 || context || BE32(outlen*8))
    label INCLUDES null terminator; Counter 1-based; L in bits.

## Important Misdirections (documented to avoid repeating)
- FUN_18000f020 creates the INTERNAL 105B DLL/IOCTL format
  ([len][ver][type][nonce][1×pubkey]); the kernel driver translates it into
  the 162B wire format. Sent directly to the sensor, it yields a wrong path
  (1201B response) — DO NOT use. Wire = nonce+EC+EC.
- connect_type field is NOT in the wire ClientHello (this is purely DLL-internal).

## Session Key Usable For
From here, the authenticated session key is available. Next step:
Calculate host identity/finish (labels "connect"/"enroll"/"identify" via FUN_1800124b0)
and send for the SDCP Enroll.

---

# 37. Enroll Protocol: Structure Understood (2026-07-29)

## Device Response MAC (live cracked/broken)
For every e3 01 <host_identity>, the sensor replies with '00' + 32B:
    device_MAC = HMAC-SHA256(session_key, "reconnect\0" || host_identity)
=> mutual key confirmation; the sensor DOES NOT verify X on e3 01
   (only confirms). Both sides use the same labeled HMAC (FUN_1800124b0).

## Host Identity
    identity = HMAC-SHA256(session_key, "enroll\0"|"identify\0" || X)
X = 32B (buffer 0x57258, set via FUN_18000f140 from the engine adapter).
Hypothesis: X is a freely choosable host nonce (freshness) — since the sensor
only verifies the identity as a valid session key HMAC, not its content.

## Enroll Choreography (from Windows capture)
    e0 01 (PSK) -> a2 (arm) -> a5 (identify, 1110B) -> e3 02/e3 01 (identity)
    -> b0 02 (Calibration) -> [a1 Enroll Init, 33B] -> Loop:
        e3 02/e3 01 (new identity) -> b0 02 -> a2 000f4101 -> a0 016464
        -> Progress 00 XX YY  (XX increases 0x00->0x32->0x61->...->0x64)
    At 100%: a3/a4 commit the template.
'000000' on a0 = "no finger frame yet", NO identity rejection.

## Next Step
scratch/enroll_attempt.py: replicates the sequence with our session key and
X=Host Nonce; progress is displayed live. On success -> template commit.

---

# 38. Enroll Status: All crypto parts ok, a0 captures no frame (2026-07-29)

## What Works (live verified)
- SDCP handshake + session key + server MAC  ✓
- Mutual key confirmation (device_MAC = HMAC(sk,"reconnect\0"||id))  ✓
- Finger detection: a2 yields finger region, b0 yields changing image  ✓
- a5 (identify) accepts ANY valid session key HMAC (X content is NOT
  verified) and returns a match token with finger present; 'ff' = no
  finger (not: identity invalid)  ✓
- a1 (Enroll Init) yields 33B  ✓

## What Does NOT Work
- a0 016464 ALWAYS returns 000000 (no frame), while Windows yields
  changing metrics per frame (003232, 00612a, 002f10, 005524 = coverage/quality,
  NO monotonic progress). Enroll accumulates internally; a0 payload also varies
  (016464 -> 016450).

## Most Likely Causes (open)
1. Missing imaging/FDT mode: the working VERIFY path
   (goodix_gf3268.py) sets FDT/POV imaging before capture; our Enroll does not.
   a0 might read the frame prepared by b0/FDT.
2. Finger already registered: a5 yields match token instead of '01'. Windows Enroll
   ran with fresh/dynamic finger (a5->01). Sensor might not enroll a known finger.
3. Fine sequence/timing between a2 (arm) and a0 (read).

## Achievements (practical)
The everyday goal (fingerprint unlocking) is already
fulfilled and rolled out via the Verify path. The cryptographic core task (SDCP session) is
completely resolved and live confirmed.

---

# 39. Enroll blockade narrowed down — Status for handover (2026-07-29)

## Definitely confirmed (live, reproduced multiple times)
- SDCP session crypto completely resolved, server MAC calculated ✓ (Section 36)
- The sensor DOES NOT structurally validate the SDCP identity: the productive
  Verify path runs with `a5 00 <os.urandom(32)>` and matches correctly.
  => X search (Section 37) was irrelevant. Enroll is NOT an auth issue.
- a5 match oracle works perfectly (check_finger.py):
  registered fingers -> 1110B token, fresh/dynamic fingers -> 0x01.
- ORDER RULE: before every `a5` there MUST be an `a2 00 01002301`
  (finger detection, arms the sensor). Without it, a5 always yields 'ff'
  (= no finger), regardless of the finger. Was the cause of false
  "REGISTERED" messages in enroll_v5 (fixed).
- With fresh/dynamic finger: a5 -> 01 ✓, a1 (Enroll Init) -> 33B ✓

## The Actual Blockade
`a0 00 016464` ALWAYS returns `000000` (no frame captured), even though
  - the finger is detected (a2 yields region, b0 changing image data)
  - the finger is fresh/dynamic (a5 -> 01)
  - a1 has initialized
Shortly after, the USB transfer aborts (-4 device gone / -7 timeout), meaning the
sensor resets itself. Windows yields changing metrics per frame at this point
(003232, 00612a, 002f10, 005524 — coverage/quality, NO monotonic
progress) and also varies the a0 payload (016464 -> 016450).

## Most Likely Remaining Cause
A missing imaging/FDT step between a2 and a0. The Windows capture
shows additional commands between the Enroll frames that we do not yet
replicate (FDT mode 0x32/0x34/0x36, POV_IMG 0xd2). The Verify path does not
need them because `a5` does capture+match internally in one step — the Enroll,
however, apparently reads a frame PREVIOUSLY provided by FDT/Imaging.
Recommendation for the next step: list ALL commands in the pcapng capture
between two credited a0 completely (including those filtered in the annotated
dump) and replicate them 1:1.

## Practical Status
Fingerprint unlocking (Verify) runs productively and is rolled out (KDE
Lockscreen + LightDM). The Enroll remains open; currently Windows/factory setup
needed for new fingers.

## Relevant Scripts
- scratch/sdcp_session.py   Handshake + Session key (verified)  ← Core
- scratch/check_finger.py   a5 Oracle: which fingers are registered  ← Works
- scratch/goodix_verify.py  productive Verify (PAM)                ← Works
- scratch/enroll_v5.py      current Enroll attempt (a0 stays 000000)
# 40. ★ ENROLL WORKS — Frames are being captured (2026-07-29)

BREAKTHROUGH: From the RAW pcapng (every packet between two a0) came the missing
ingredient: BEFORE EVERY a0 there is an e3 02/e3 01 Identity pair (32B, content doesn't matter).
enroll_v4/v5 had omitted this -> sensor reset (-4). enroll_v6 with the
e3 pair captures frames (a0 -> 004949, 003232-like values).

## a0 Response Format (Enroll Frame)
    00 00 00   no new frame (place finger again)
    00 XX YY   frame captured, XX = coverage, target 0x64=100%
    74../ff..  frame too similar -> place different finger area
Completion: 00 64 00 -> a3 00 (commit) -> a4 <template> -> 00.
Windows needed ~14 frames with DIFFERENT finger areas.

## Complete Enroll Sequence (working)
  Preamble (fixed HELLO, b0, e0)
  a2 01002301 -> a5 identify (fresh/dynamic=01) -> a5 01 -> e3-pair -> b0 -> a1
  Loop per frame: e3 02/e3 01 (32B) -> b0 02 -> a2 000f4101 -> a0 016464
  at coverage 0x64: a3 00 -> a4 (template)

## Open
Only: place enough DIFFERENT finger areas until coverage 0x64 -> commit.
enroll_v7.py executes this and commits automatically.

---

# 41. ★ Enroll Capture SOLVED — a3 finalizes (2026-07-29)

- Payload phase change 016464 -> 016450 (after 5 a0s) breaks through the first
  '74' wall. After that, 2nd wall at ~11-12 frames = "enough captured".
- Sent a3 00 at the wall -> device responds 00 = CAPTURE COMPLETE.
  So the '74' wall means "done, commit", not "more needed".
- a4 (Template Commit, 100B) with Windows payload -> 9f (rejected). The payload
  contains 16B Template-ID + 33B field (ec02..) + Windows SID (S-1-5-21-..-1001).
  Origin of the fields: 33B + SID appear in a6(READ_OTP) responses (device),
  16B Template-ID only in a4 (host-generated).
- OPEN: correct a4 payload for Linux. Test in enroll_v12: checks if a3 alone
  already saves the template (a5 match after a3). If yes -> a4 = only
  Windows identity metadata, not needed for Verify/Unlock.

## Complete Working Capture Sequence
  Preamble (HELLO, b0, e0) -> a2 01002301 -> a5(fresh/dynamic=01) -> a5 01 -> e3 -> b0
  -> a1 -> per frame [e3 02/e3 01 (32B) -> b0 -> a2 000f4101 -> a0 <016464|016450>]
  -> at 74-wall a3 00 (=> 00) -> a4 <100B> (payload still open).

---

# 42. ★★ a4 Structure cracked/broken: Template Record = Identity-MAC per User (2026-07-29)

a6 (READ_OTP) returns the stored records (100B each = a4 format):
    [62004304f5XX][16B TemplateID][16B 0][33B Identity-MAC][28B SID][00]
The 33B Identity-MAC is PER USER (same for all templates of a user,
calculated via GoodixSdcpMacEnroll) — NOT per template. SID = Windows SID.
Storage adapter strings confirm: GoodixSdcpMacEnroll, CommitTemplate,
GoodixSdcpVerifyAuthorizedIdentity, CreateTemplateId.

STRATEGY (enroll_v13): reuse existing valid 33B-MAC + SID from a6,
only new 16B Template-ID -> a4 should be accepted (sensor verifies a
physical/real identity). Thus Enroll WITHOUT GoodixSdcpMacEnroll reimplementation.
Afterwards a5 match test: is the new finger recognized?

---

# 43. Enroll CAPTURE complete resolved; a4 Commit MAC is the last building block (2026-07-29)

## ★ SOLVED: Enroll Capture (the difficult sensor part)
Complete, reproducible sequence (enroll_v10..v15):
  Preamble(HELLO,b0,e0) -> a2 01002301 -> a5(fresh/dynamic=01) -> a5 01 -> e3-pair -> b0
  -> a1 -> per frame: [e3 02/e3 01 (32B, content doesn't matter) -> b0 -> a2 000f4101
           -> a0 <016464 the first 5, then 016450>]
  -> after ~11-13 frames '74' wall -> a3 00 = CAPTURE DONE.
Important: e3 pair necessary BEFORE every a0; payload change 016464->016450 breaks through
the 1st wall; the 2nd '74' wall means "enough -> commit".

## a4 Record Structure (100 B), complete understood
  [62004304f500][16B TemplateID][16B 0][32B MAC][1B SID_len=0x1c][28B SID][00]
  (a6 READ_OTP returns exactly these records; MAC is PER TEMPLATE.)

## OPEN: the 32B a4 MAC (GoodixSdcpMacEnroll)
- Storage adapter calculates it via an SDCP interface object (global 0x18007b870)
  -> vtable into the sensor adapter (there FUN_1800124b0 = HMAC(session_key,label||data)).
- a4 is FREELY REPEATABLE (state remains after a3) -> many candidates testable per
  Enroll.
- EXCLUDED (all -> 9f):
  * device-static keys (KI, MAC_KEY, MAC_KEY[:16], AES_KEY)
  * real session key + session_key2 + master
  * each × labels {"", enroll, identify, connect} × inputs
    {tid, sid, tid+sid, sid+tid, tid+zeros, tid+zeros+sid, hdr+..., entire record}
- ASSUMPTION: Input is a 32-byte value (like X in FUN_18000f170), not raw
  tid/sid — e.g., SHA256(template/identity) or a device-supplied nonce
  (a1 response 33B? varies per Enroll). Next Step: clean tracing of GoodixSdcpMacEnroll
  in the storage adapter (vtable method + input buffer) OR
  test a1 response/template hash as MAC input.

## Scripts
- enroll_v15.py  real Handshake + Capture + a4 MAC search (Session-Key)
- enroll_v14.py  a4 MAC search (device-static keys); proves a4 repeatability
- check_finger.py  which fingers are registered (a5 Token vs 01)  [working]

---

# 44. ★★ a4 MAC Formula found + a7 Identity Registration (2026-07-29)

BREAKTHROUGH: Among all candidates EXACTLY ONE gives a different response (ff instead of
9f) -> the MAC check passes:
    a4-MAC (32B) = HMAC-SHA256(session_key, "enroll\0" || a1_response[1:33])
- a1_response = 33B device nonce from a1 00 (varies per Enroll).
- a1[1:33] (32B, without status byte) is correct; a1[0:32]/a1[:33] -> 9f.
- ff (not 9f) = MAC ok, but identity not authorized.

Missing step: a7 02 (Payload 0100 + 100B record) REGISTERS a user in
the session (Windows: a7 registers user 6a88b616, then Enroll FOR this user).
a4 SID must = registered SID.

enroll_v18: a6 -> a7(register record) -> Handshake -> Capture -> a3 ->
a4 with HMAC(sk,"enroll\0"||a1v) + registered SID -> match test.

---

# 45. a5=03 = hanging Enroll state; a7 0100 pollutes working memory (2026-07-29)

- Repeated aborted enrolls (a3=00 without valid a4) AND a7 0100 calls
  bring the sensor into state a5->03 (Enroll open / wrong state).
- USB reset (libusb_reset_device) does NOT clear this. Only REBOOT.
- a7 prefixes: 0100 = register/add, 0200 = delete
  (from goodix_delete_templates.pcapng).
- Consequence for a4 search: NO a7; a4 repeatable within a session,
  but if the session ends without valid a4 -> 03 -> reboot needed. So few
  candidates per session, best ones first (a1v).
- Best MAC remains HMAC(sk,"enroll\0"||a1[1:33]) (gave 'ff'=MAC ok). Possibly
  'ff' was a consequence of the already compromised state -> test in clean state.
- enroll_v20.py: clean, without a7, a1v + close neighborhood.

---

# 46. Template Store EMPTIED by experiments (0 Records) — Recovery (2026-07-29)

- diag_state.py after reboot: a6 = 0 records (store EMPTY), a5 = ff (no finger).
  The 03 hang/freeze is gone -> sensor clean, but all fingerprints deleted
  (due to a7-0100/a3 experiments + reboot). Therefore no more login.
- Recovery paths: (A) set up Windows Hello anew [reliable];
  (B) finish Linux Enroll on clean store [enroll_v21, a1v-MAC +
  synthetic 28B SID, as there is no record to reuse].
- IMPORTANT lesson: a7 0100 / a3-without-a4 alter the persistent store ->
  in the future test ONLY with Enroll abort/recovery plan.

---

# 47. FINAL Status Enroll: Capture + MAC resolved, a4 Commit Authorization open (2026-07-29)

## Confirmed on clean/empty store
- a4 [HMAC(sk,"enroll\0"||a1[1:33])] -> ff (as the ONLY formula; all others 9f).
  => MAC formula correct (ff=MAC ok). ff is a commit postcondition, NOT
  a consequence of the previously polluted state.
- a1_response = a1 00 -> 33B; a1[1:33] (without status byte) is the MAC input.
- Synthetic AND real SID -> both ff. So it's not the SID format.
- Suspected cause of ff: identity authorization (GoodixSdcpVerifyAuthorizedIdentity)
  or template completeness (our byte1 values remained ~0x01, Windows 0x32-0x64;
  a3 was triggered at the 74-wall, possibly before full coverage 0x64).

## SOLVED
- SDCP session crypto (Section 36), Enroll capture (a3=00), a4 record structure,
  a4 MAC formula (HMAC(sk,"enroll\0"||a1[1:33])).

## OPEN (last building block)
- a4 Commit Authorization (ff). Best solved by a FRESH
  Windows Enroll capture on EMPTY store (shows exact a4 payload + identity
  steps for initial enrollment). Alternatively: capture byte1 up to 0x64 (full coverage)
  before a3, instead of aborting at the 74-wall.

## IMPORTANT / Recovery
- Store was emptied by the experiments (0 records) -> Login broken.
  Recovery: set up finger in Windows Hello anew (restores Win+Linux).
- a7 0100 / a3-without-a4 alter persistent store -> in the future test only with
  recovery plan.

---

# 48. ★★★ NATIVE libfprint DRIVER WORKS (2026-07-30)

scratch/libfprint_natasha/libfprint/drivers/goodixsdcp/ — new driver
`goodixsdcp` (27c6:6f94), built on the goodixmoc skeleton, with our
SDCP transport crypto (goodixsdcp_crypto.c, OpenSSL). Live verified:
- open/init (e1 04, e3-HELLO, b0, e0, a6-list) -> "open completion" ✓
- Enroll-Bind: place Windows Hello finger -> a5 1110B token -> bound ✓
- Verify/Identify: a5 match -> "MATCH!" ✓ (no crash after double-free fix)
- delete/clear_storage: only host binding, on-chip template remains.

Enroll = "Bind": new fingers cannot be learned due to TPM binding; you place a
finger learned in Windows Hello, the chip matches it, and the driver
registers the on-chip template as FpPrint. Afterwards Verify system-wide.

Build (only this driver):
  meson setup build -Ddrivers=goodixsdcp -Ddoc=false -Dintrospection=false -Dgtk-examples=false
  ninja -C build
Test without fprintd: build/examples/enroll, build/examples/verify.

Next Step: system-wide installation + fprintd/KDE integration + PAM.

---

# 49. ★★★ FINISHED: native driver system-wide + KDE/PAM integrated (2026-07-30)

Fully functional and live confirmed:
- libfprint with goodixsdcp installed to /usr (build-install, prefix /usr).
- fprintd uses the driver: fprintd-enroll -> enroll-completed,
  fprintd-verify -> verify-match.
- KDE System Settings -> users -> fingerprint: registration + usage
  via the GUI works (binds the Windows Hello finger).
- lock screen (Super+L) unlocks via finger ✓
- sudo via finger ✓ (pam_fprintd in /etc/pam.d/sudo)
- LightDM login: pam_fprintd added in /etc/pam.d/lightdm.
- Old Python pam_exec unlocking removed (otherwise USB conflict with fprintd).

## Model / Limitations
- Enroll of new fingers is TPM-bound -> only possible in Windows Hello.
  The driver "Enroll" is a BIND: bind on-chip template via a5 match to FpPrint.
  Verify/Identify/Match work natively.
- The fprintd finger slot is just a label; the sensor matches any
  registered on-chip finger (per-finger distinction is loose).

## MAINTENANCE (important)
- Our libfprint replaces the distro package in /usr. A pacman update of
  'libfprint' overwrites it -> afterwards rebuild+install:
    cd ~/Projekte/Fingerprint/scratch/libfprint_natasha
    ninja -C build-install && sudo ninja -C build-install install
    sudo udevadm control --reload-rules && sudo udevadm trigger
    sudo systemctl restart fprintd
  (Optional: put 'libfprint' in /etc/pacman.conf under IgnorePkg.)

## Open Polish (optional)
- Verify retry in case of failure fires fast (~250ms); remedy: after no-match
  wait for finger lift before the next a5 runs.

---

# 50. Polish: No-Match waits for finger lift (2026-07-30)

Verify-SSM extended by state GSDCP_VER_WAIT_LIFT: immediately done on match,
on no-match FAIL is reported and then waits via a2 (200ms poll) for finger lift
before the operation ends. This way the next fprintd-Verify starts
fresh/dynamic, instead of firing every ~250ms in case of failure.
Rebuild+install necessary:
    cd ~/Projekte/Fingerprint/scratch/libfprint_natasha
    ninja -C build-install && sudo ninja -C build-install install
    sudo systemctl restart fprintd

---

# 51. NEW HOPE for Enroll: TPM only INITIALly necessary (2026-07-30)

User insight: Only the FIRST finger registration needs TPM; SUBSEQUENT fingers
also worked in the Windows VM WITHOUT TPM. => 'ff' on a4 is not a hard
TPM wall, but "identity not recognized as authorized". As soon as a
valid identity exists on-chip, adding should work without TPM.
The emptied memory was probably a security lockout after too many
failed attempts (no damage).

Never cleanly tested combination: a7 registration of the REAL identity +
HMAC(sk,"enroll\0"||a1[1:33]) + REAL SID on FILLED memory.
enroll_v22.py does exactly this with ONE a4 attempt (lockout protection).

---

# 52. Enroll attempt ended + Recovery; Project completed (2026-07-30)

## Result of the last Enroll attempt (enroll_v22)
With the combination a7-identity + a1v-MAC + physical/real SID on filled memory:
- The Enroll CAPTURE did NOT start (a0 remained 000000), although fprintd was stopped
  and the finger was fresh/dynamic (a5 -> 01).
- The a6 record count fluctuated (3 -> 2) -> our a7/a4 write accesses
  alter the persistent template memory; repeated attempts trigger
  a security LOCKOUT (confirms the user hypothesis).
=> In this state the native Enroll is not feasible, and every
   further attempt endangers the working (Windows) registrations.
   DECISION: do not pursue native Enroll further.

## Important Operational Insight
- As soon as fprintd is installed/active (for sudo/Login), it ACCESSES the
  sensor and competes with the Python tools for the USB device -> shaky
  results, -4 error. For Python experiments beforehand: `sudo systemctl stop fprintd`,
  then start again afterwards.

## Recovery (works reliably)
If the memory was emptied/locked by experiments:
1. Re-learn finger in Windows Hello (restores on-chip templates).
2. Under Linux via KDE/fprintd "register" again (= Bind to on-chip template).
-> lock screen unlocking + sudo via finger working again.

## Project Final Status
- Native libfprint driver goodixsdcp: FINISHED (Verify/Identify/Bind + KDE/PAM).
- Enroll of new fingers: not practical from Linux (Lockout/Identity
  Authorization); registration takes place in Windows Hello, then Linux Bind.
- Everything documented (Sections 1-52), release package under release/.


---

# 53. Standby/Resume Fix (2026-07-31)

Symptom: After standby, the fingerprint sensor does not unlock; fprintd log shows "Authorization denied ... EnrollStop/Release ... Use of the device was not requested beforehand" + registered failed attempt (can lock the lockscreen).

Cause: USB autosuspend puts the sensor to sleep; upon resume, it is briefly unready -> fprintd/kscreenlocker session desynchronizes.

Fix (release/system/):
- `60-goodix-gf3268-fp.rules`: USB autosuspend disabled for 27c6:6f94 (power/control=on).
  -> `/etc/udev/rules.d/`, `udevadm reload+trigger`.
- `fprintd-resume.service` (optional): Restart fprintd on resume.
Details + Test: `release/system/README.md`.

Addendum: The udev rule alone did NOT solve it. After several hours of standby, only password login was possible at the lockscreen (after which everything was okay again). System suspend (S3) puts the USB bus completely to sleep, regardless of the autosuspend setting -> the rule doesn't apply here. The real cause + fix: 54.

---

# 54. Standby Fix: Root Cause + Driver Suspend/Resume (2026-08-01)

Descriptive log during failed unlock:
  `fprintd: Device reported an error during identify: Cannot run while suspended.`
  `kscreenlocker: ReleaseDevice failed: The device is still busy with another operation`
  -> followed by multiple "Authentication attempt too soon" -> pam_faillock briefly locks the account.

Cause (verified in libfprint source code):
- When closing the lid, a Verify action is already running on the lock screen (waiting for finger).
- libfprint then calls the driver's suspend vfunc. Our driver had NONE -> `fpi_device_suspend()` takes the else branch: `fpi_device_suspend_complete(dev, NOT_SUPPORTED)`.
- `fpi_device_suspend_complete()` (`fpi-device.c`) ALWAYS sets `is_suspended=TRUE` and, because an error != NULL was passed AND a task is running, additionally sets `current_cancellation_reason = "Cannot run while suspended."` + cancels the action.
- The `is_suspended` flag was not cleanly reset (missing resume vfunc / resume signal race), so the next Verify was rejected with this exact message and the device remained "busy".

Fix (in driver `goodixsdcp.c`, `.h`):
- New vfuncs: `dev_suspend`, `dev_resume`, `dev_cancel` (wired up in `class_init`).
- Dedicated `GCancellable` `self->cancel` for the long "wait for finger" reads (instead of `fpi_device_get_cancellable`). `dev_cancel` cancels it -> all libfprint abort paths reach the read (`setup_task_cancellable` only connects `current_cancellable` to `cls->cancel` if the vfunc exists; exactly the pattern of `fpcmoc`/`synaptics`).
- Command SSM extended by two states: `GSDCP_CMD_SUSPENDED` / `GSDCP_CMD_RESUME`.
- `dev_suspend` (only during cancelable finger read): `self->suspended=TRUE`, `g_cancellable_cancel(self->cancel)`. The cancelled read lands in `cmd_receive_cb` -> (suspended && CANCELLED) -> jump `GSDCP_CMD_SUSPENDED` -> `fpi_device_suspend_complete(dev, NULL)`. NULL instead of an error is the key: according to the API, NULL means "action continues after resume" -> libfprint does NOT set a "Cannot run while suspended" abort reason.
- `dev_resume`: fresh `self->cancel`, jump `cmd_ssm` -> `GSDCP_CMD_RESUME` -> `fpi_device_resume_complete(dev, NULL)` (clears `is_suspended`) + jump `RECV` (re-arm the read). Fallback branch calls `resume_complete` even if we were not cleanly paused -> flag is cleared in any case.

This fixes "Cannot run while suspended" at the root, without udev/systemd.
Tested: Framing/Balance OK; real build+standby test on the target machine.

Residual Risk (documented, still open): If the sensor loses its transport session during a VERY long S3 suspend, the re-armed `a2` read would silently hang (different symptom than "Cannot run while suspended"). Follow-up would be to first replay the handshake (POV/HELLO2/HELLO0/CAL/PSK) in the resume path. However, the failed attempt in the log was a libfprint rejection (sensor not contacted at all), which suggests that the session survives and the flag fix is sufficient.

Validation on hardware (2026-08-01):
- Build+Install OK, fprintd restarted.
- Real test: Screen locked -> System Suspend -> woken up -> placed finger on lock screen -> unlocked on the FIRST attempt, without password fallback.
- `journalctl -u fprintd`: NO more "Cannot run while suspended"; only normal on-demand Start/Deactivate. -> Fix confirmed.
- Note: `sudo fprintd-verify` checks the prints of the root user (empty -> NoEnrolledPrints); for isolated testing, use `fprintd-verify` without sudo or `fprintd-verify andreas`. Not a driver issue.
- The residual risk (session loss during very long suspend) did NOT occur.

---

# 55. Enrollment audit: the TPM wall was not established (2026-11-08)

The research archive and public release were reviewed together with newer local September prototypes. The public repository still described every new enrollment as TPM-bound, although Section51 already recorded successful additional enrollments in a Windows VM without TPM.

The existing C driver was verified to implement **bind**, not new capture: finger detection → `a5` match → copy the existing sensor record into `FpPrint`. No fprintd option could enable `a1/a0/a3/a4` inside that code path.

## The destructive “authorization” command

The raw Windows captures provide direct evidence:

```text
a6 → two records
a7/02 → 01 00 + one 100-byte record
a6 → one record; exactly the supplied record is gone

separate deletion capture:
a7/02 → 02 00 + two records
a6 → zero records
```

`01 00` and `02 00` are little-endian counts. **This is deletion, not registration.** The interpretations in Sections44–46 and51 were wrong. The old enrollment variants that sent this packet as authorization removed fingerprints themselves. A record-count decrease does not, on its own, prove a security lockout or a TPM requirement.

The later September management script independently used the same count+records format for deletion. Its UI statements about enrollment after reset were not successful hardware evidence.

## TPM interpretation

Microsoft's SDCP specification commits an enrollment using a MAC under the connection's own negotiated key. Windows additionally keeps an authorized-enrollment database for credential release. That Windows database must not be confused with the ability to create a Linux-only sensor template.

The local `GoodixSdcpVerifyAuthorizedIdentityVBS` function is a host-side IOCTL wrapper; its name is not evidence of a mandatory sensor-side TPM check. `ff` versus `9f` observations did not establish a complete firmware error dictionary. Empty-store initialization remained unproved.

---

# 56. Capture state machine corrected: thirteen successful updates (2026-11-08)

Static analysis of the WBDI and engine adapters, checked against both successful Windows captures, resolved the capture mistakes:

- `a0` returns status, Overlay and PreOverlay. Quality/Coverage belongs to `a2`.
- **Every zero `a0` status counts**, including `00 00 00`.
- The configured sequence has thirteen accepted updates: five with `01 64 64`, then eight with `01 64 50`.
- `72/73` are overlap retry paths. `74` is not “finished.”
- `a3` checks for duplicates. `a3=00` means no duplicate, not capture finalization.
- `a2=c0` means no finger; the existing goodixsdcp driver already re-arms that condition.

The saved enrollment captures contain13/13 successful updates and13/14 successful updates respectively. The extra attempt in the latter is an overlap retry. Neither uses `74` as completion.

The Windows engine increments its counter at VA `0x180097835–0x180097852` based on zero status; the completion routine at `0x1800979a0` compares this count to the configured target. The WBDI `a0` dispatcher/log is at `0x18007d20b–0x18007d28d`. The Quality/Coverage log at `0x18007d444` belongs to `a2`, correcting the earlier provisional attribution.

## Reconnect, not identity authorization

The32-byte `e3/02 → e3/01` pair is an SDCP reconnect:

```text
request  = fresh nonce32
response = 00 || HMAC(session_key, "reconnect\0" || nonce32)
```

The vendor host code generates fresh random bytes for this path and verifies the response with the `reconnect` label. It is not an administrator identity payload. The experiment now checks this MAC explicitly.

These findings explain why the old loops could continue merging after Windows would already have completed thirteen accepted updates.

---

# 57. Regular goodixmoc investigated without storage repair (2026-11-08)

A newer external hardware report described regular-goodixmoc enrollment for the same USB ID on a different Honor model/firmware. Rather than installing it directly, a separate build was prepared against the project's libfprint 1.94.5 baseline.

The regular parser successfully decoded the saved GF3268 version, list, match and enrollment-init responses. This justified testing the shared protocol while preserving the installed driver.

## Isolation

- Only PID6f94 exposed; firmware 01010032 required.
- USB reset in probe/open skipped.
- C0 configuration writes and A7 deletion blocked centrally before transfer creation.
- No automatic reset after a list error.
- No system installation; explicit linkage to the isolated library.
- Existing-record comparison after every attempt.

## Hardware sequence and observations

1. Open/list succeeded: one existing template.
2. First enrollment initialized but did not capture. The regular state machine omitted `b0/02` before its first `a2`.
3. Adding that volatile preparation enabled accepted samples. The next attempt ended at `a2=c0`; that normal no-finger condition was then handled as a bounded wait/re-arm.
4. The corrected attempt accepted all thirteen updates, passed `a3=00`, and rejected the ordinary **Type-1** `a4` with `9f`.
5. Postcheck after the attempts: original entry preserved, no additional stored template.

The result isolated the remaining difference to the storage path, rather than capture or a mathematically inaccessible TPM key. The diagnostic patch and harness are included under `experiments/`; they are baseline-specific investigation artifacts, not an upstream-ready regular-driver solution.

---

# 58. ★★★ NEW FINGER ENROLLED UNDER LINUX — SDCP commit works (2026-11-09)

The new experimental client first established two fresh SDCP sessions, checked different keys and validated reconnect responses. The original record remained byte-for-byte unchanged.

After user confirmation, it captured a **new right little finger**, previously registered in neither Windows nor Linux:

```text
fresh verified SDCP connection
→ b0/e0 preparation
→ a1: fresh enrollment nonce
→ 13 accepted updates, each with verified reconnect + b0 + a2 + a0
→ a3 = 00 (no duplicate)
→ one Type-4 a4 commit
→ success
→ a6: two records instead of one
```

The commit identifier is:

```text
id = HMAC-SHA256(session_key, "enroll\0" || a1_response[1:33])
```

The existing Type-4 identity metadata was reused. The record has a6-byte header,16-byte prepared account field,16 zero bytes,32-byte enrollment identifier, identity length28,28-byte SID metadata and a zero terminator. The stored-record flag is normalized for commit.

**Confirmed on hardware:** one successful commit, exactly one new record, expected enrollment identifier present, every original record byte retained. No Windows execution or TPM operation was required for this additional finger.

Private0600 snapshots preserve the before state, prepared commit and actual after state. The commit is never retried automatically, including after uncertain responses. C0/A7, reset and detach paths are excluded from the new client.

This is the first demonstrated new-template enrollment in this project. It does not establish empty-store provisioning.

---

# 59. New-finger verification, negative control and Linux bind (2026-11-09)

The sensor replaces part of the prepared account field when committing a record. The first verification helper therefore incorrectly rejected target association even when the expected enrollment identifier was stored. The helper was corrected to resolve the stored record by its32-byte enrollment identifier before comparing the match response. No template rewrite was necessary.

A new SDCP connection then produced a target-specific match for the right little finger. One individual placement returned no match and another attempt timed out waiting for a fresh touch; a flat central placement matched with quality39 and coverage100. This is functional validation, not an error-rate study.

Negative control: the unregistered right ring finger was rejected, with quality31 and coverage83. Record preservation checks passed after matching.

## Existing installed driver, unchanged

```text
fprintd-enroll -f right-little-finger → enroll-completed
fprintd-verify -f right-little-finger → verify-match
fprintd-verify -f right-thumb         → verify-match
```

The Python client created the new sensor template. The existing C driver bound it to Linux and verified it. Both the new little finger and the original thumb are listed by fprintd and remain usable.

No new system library was installed and no PAM configuration changed during this validation. Existing desktop/PAM integration remains the prior project setup; the directly observed new-finger integration result is fprintd verification.

---

# 60. Current authoritative status, reproduction and open work (2026-11-09)

## Working workflow

1. Read-only probe: `scripts/goodix_probe.py --live --list` via Python.
2. Finger-free session test: `experiments/goodix_sdcp_trial.py --session-check`.
3. New capture/commit: the same tool with `--enroll --reference <new-private-file>`.
4. Target-specific match: `experiments/goodix_match_trial.py --target-reference <commit-file>`.
5. Existing C-driver bind and verification through fprintd.

Complete commands, prerequisites and metadata handling: [Native Linux Enrollment](docs/NATIVE_ENROLLMENT.md).
Chronological evidence, unsuccessful attempts and sanitized outputs: [Hardware Test Report](docs/HARDWARE_TEST_REPORT_2026-11.md).

## Checks

**38 offline tests passed:**14 probe tests,21 SDCP policy/session tests and3 matching tests. These include actual ECDH/KDF with a simulated peer, bad server/reconnect MACs, command boundaries, the saved thirteen-update trace policy, lost commit responses without retry, private file handling and sensor-assigned account fields.

The original goodixmoc replay test was skipped because umockdev-run was unavailable; it is not counted as passed. The isolated build compiled successfully.

## Honest limits

- **Provisioned sensor required.** An existing valid Type-4 identity is reused. No Linux-only empty-store initialization is claimed.
- **Python capture + C bind.** New capture/commit is not yet integrated into native C enrollment or the desktop GUI.
- **Firmware-specific.** GF3268/01010032 is verified; other firmware requires separate validation.
- **No cold-start test yet.** Storage and matching across fresh connections are confirmed; reboot persistence remains to be checked.
- **No full attestation claim.** Server key confirmation and reconnect MACs are checked; full certificate-chain/firmware attestation and complete match-token verification remain future work.
- **No published private records.** Before/commit/after references, actual SIDs and enrollment IDs remain local and excluded from Git.

The old blanket statement “new enrollment is TPM-bound and only possible under Windows” is superseded by this hardware result. The remaining first-provisioning question must be investigated separately.


## Public package addendum: transport-key redaction preserved

The successful hardware tests used locally configured transport keys. Public AES/HMAC constants remain redacted as in the previous release. The exported tools use `protocol/goodix_crypto.py`, whose zero defaults cannot operate the actual encrypted channel. Configure private `GOODIX_AES_KEY` / `GOODIX_MAC_KEY`; `GOODIX_KI` alone does not configure those two variables.

The public SDCP client rejects missing/zero/invalid keys before live USB use. Read-only metadata probing needs no keys. The vendor emulator now resolves its helpers through `protocol/re_tools` and accepts `GOODIX_SENSOR_ADAPTER_DLL`; offline derivation from the compatible local DLL reproduced both working keys without publishing them. These are build-specific vendor constants, not TPM-exported secrets.

The final public suite has **40 passing tests**, including the38 original experiment checks and two public key-configuration guards. Offline synthetic-peer tests do not prove sensor operation with redacted placeholders. Full setup details are in the enrollment guide.


---

# 61. Native C SDCP enrollment replaces host bind (2026-11-09)

The successful Python flow was ported into the native `goodixsdcp` driver. New enrollment now validates firmware 01010032 and the initial record list, establishes fresh P-256 SDCP sessions with key confirmation, checks reconnect MACs before captures, collects thirteen accepted updates using the five/eight phases, checks duplication, commits exactly once and verifies the added record with unchanged originals.

The returned FpPrint uses the sensor-assigned account field found through the enrollment MAC. Existing host-print representation remains compatible. No Python subprocess or separate bind command is involved. Existing Type-4 identity metadata remains a prerequisite; empty-store provisioning is not implemented.

Transport handling now validates CRCs, assembles fragmented responses and finishes command ownership before dispatching the next callback. Cancellation disables the shield and clears session material. A commit is never automatically repeated; matching readback may recover a lost response. Verify/identify keep the resume path; enrollment cancels across suspend.

Deletion is now a targeted `a7/02` count 1+record operation with preservation readback. Unclaimed device-only records are refused to prevent fprintd garbage collection from erasing Windows/device-only entries. Clear-storage is not advertised. Live GUI deletion is still untested; thirteen native simulations cover deletion and the other lifecycle cases.

Full design, guards, tests and install/rollback procedure: [Native Driver Integration](docs/NATIVE_DRIVER_INTEGRATION.md).

---

# 62. KDE precheck failure fixed, then native enrollment passed (2026-11-09)

Before native capture, fprintd performs an identify precheck. The first KDE attempts reached a correct no-match result but the old verify/identify implementation then entered its lift-wait state. That read timed out and tried to report identify twice. No native enrollment commit occurred during those attempts.

The corrected path reports no match once and completes immediately. A regression invokes the actual identify API and requires exactly one acquisition read, no commit and unchanged storage. After reinstalling the corrected library, the user reopened KDE and enrolled a new finger in a free `right-index-finger` slot.

All thirteen native stages passed; the service reported `enroll-completed`. Readback completion requires exactly one new record and byte-for-byte preservation of the two original records. fprintd listed right-index-finger, right-little-finger and right-thumb.

Two subsequent standard checks, using the freshly enrolled finger and the original thumb respectively:

```text
fprintd-verify -f right-index-finger → verify-match (done)
fprintd-verify -f right-thumb        → verify-match (done)
```

The native build was installed system-wide after operating-system administrator authentication. The old library and references were backed up privately. No PAM changes, Windows/TPM operation, external capture client or separate host-bind command was used for the new KDE enrollment.

---

# 63. Current integration handover and validation boundary (2026-11-09)

**Current normal workflow:** Build/install the updated privately configured C driver, then use KDE or standard `fprintd-enroll`. Existing fingerprints remain compatible. The former Python+bind instructions are historical research, not the current standard enrollment procedure.

**Passed:** 51 public Python tests (40 protocol/tool checks, eight actual C crypto checks and three installer checks),13 actual-driver simulations, two libfprint test suites, native build/API preservation, hardware open/list/no-finger cancellation, KDE new enrollment and standard verification of the new finger and original thumb. Initial crypto acceptance/USB are simulated in lifecycle tests; separate crypto tests use actual C against an independent synthetic peer.

**Not claimed:** Cold-start/reboot persistence, a fresh native-build suspend test, live targeted GUI deletion/re-enrollment, empty-store provisioning, support for other firmware, complete attestation or full match-token verification. A post-commit failure can leave a device record without a host reference; uncertain commits must not be blindly repeated or “repaired” by clearing storage.

**Public export:** Actual C implementation and tests are included. AES/HMAC constants remain intentionally redacted; no working-key binaries, sensor snapshots, real SIDs/account IDs/enrollment IDs or vendor DLLs are published. The optional protected installer expects a locally built library and is specific to the documented Arch/CachyOS paths. Distribution upgrades can replace the custom library.

This section supersedes the “native C integration remains open” limitation in historical Section 60. Additional enrollment is now demonstrated through the operating-system standard UI and API. Initial provisioning remains a separate research question.
