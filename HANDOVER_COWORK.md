# Handover: Goodix GF3268 (27c6:6f94) Linux Fingerprint Driver

> ## ⚠️ ATTENTION: Sections 1–9 of this document are DISPROVEN
> They describe a TLS-PSK handshake using `openssl s_client` as a proxy.
> The sensor does **NOT** speak TLS. The following are authoritative instead:
> - **`walkthrough.md`** — Correct protocol description (ECDH P-256)
> - **`test_get_image.py`** — 718 lines, executes the actual ECDH handshake
> - **Sections 11–16 of this document** — Evidence and measurements
>
> For evidence see Section 11 (no TLS records on wire) and
> Section 16 (Comparison with `walkthrough.md`).

_Created: 2026-07-28, for handover to Claude CoWork_
_Update: 2026-07-28 — Stage 2/3 + Enroll flow revised, see Section 10_

---

## 1. Project Overview

**Goal:** Make native libfprint driver for Goodix GF3268 fingerprint sensor (USB 27c6:6f94) 
of the Honor MagicBook Art 14 functional under Linux.

**Workspace:** `/home/andreas/Projekte/Fingerprint`  
**Driver Base:** `/home/andreas/Projekte/Fingerprint/scratch/libfprint_natasha/`  
**Python PoC:** `/home/andreas/Projekte/Fingerprint/scratch/poc_driver_tls.py`

---

## 2. Hardware & Protocol (100% Verified)

### Sensor
- **Chip:** Goodix GF3268, USB VID:PID = `27c6:6f94`
- **Type:** Match-on-Chip (MoC) — Fingerprint matching runs internally on the sensor MCU
- **Endpoints:** EP_OUT = `0x01`, EP_IN = `0x83`, Interface = `0`

### Protocol Sequence (Verified in Python PoC)
```
1. e0 01 00  (Init Query)          → Sensor responds with 00000000
2. a2 00 00  (Reset/Query)         → ACK
3. TLS Handshake via e3 commands:
   a) ClientHello  → e3 02 00 senden  → Sensor ACKs mit erwartetem Antwort-Länge
   b) ServerHello  → e3 00 00 senden  → Sensor returns ServerHello+Cert+Done
   c) ClientFinished → e3 02 00       → Sensor ACKs
   d) ServerFinished → e3 00 00       → Sensor returns CCS+Finished
4. d4 00 00  (TLS successfully established)
5. a5 00 00  (Identity/Key-Payload, 32 Bytes)
6. 08 01 00  (GoodixSdcpMacEnroll, 32-Byte-Token) ODER
   20 01 00  (GoodixSdcpVerify, 32-Byte-Token)
7. 36 00 00  (MCU Switch to FDT Mode, Payload: 0c 01 80 b9 80 b4 80 b5 80 af 80 b4 80 ac 80 b2 80 a7 80 ab 80 a5)
8. a2 00 00  (Wait for Finger, Payload: 00 0f 41 00)
9. → Sensor spontaneously sends a2 00 00 mit Payload ~{00 56 64 00 1f 00 38 00} when finger is touched
10. 20 00 00  (MCU_GET_IMAGE → Image data / token via e3 00 00)
```

### TLS Details (HISTORICAL / REFUTED)
- The sensor uses **ECDHE-ECDSA TLS 1.2** mit einem self-signed Windows Hello ECDSA-Zertifikat
- The sensor is sensitive to bezüglich ClientHello: er antwortet nur korrekt auf den
  **exakten ClientHello von `openssl s_client`** (241 Bytes mit Standard-Cipherliste + PSK)
- Ein in-process `SSL_connect()` sendet eine andere ClientHello (307 Bytes) → Sensor antwortet
  mit einem Non-TLS-Blob (beginnt mit `0x9c` statt `0x16`) → "wrong version number"
- **Solution:** `openssl s_client` als Subprocess spawnen (exakt wie im Python PoC)

---

## 3. Current Status of C Driver

### What Works ✅
- **Driver compiles cleanly:** `ninja -C scratch/libfprint_natasha/build` → 0 Fehler
- **Device recognized:** `27c6:6f94 | Goodix TLS Fingerprint Sensor GF3268`
- **`goodix_tls_server_init` für 6f94:** Startet TCP-Listener + `openssl s_client` Subprocess,
  akzeptiert TCP-Verbindung (client_fd), 241-Byte ClientHello wird korrekt gesendet
- **TLS-Handshake Stage 0** (ClientHello → Sensor) läuft durch
- **TLS-Handshake Stage 1** (ServerHello ← Sensor): Sensor returns 1200 Bytes ServerHello+Cert
- **`expected_tls_length = 847`** wird korrekt aus e3 02 00 Response geparst
- **Doppelter Status-Byte-Strip:** ist gefixt (war der "wrong version number" Ursprung)

### What is NOT YET Verified ⚠️
- **Stage 2 (ClientFinished):** Ob OpenSSL via subprocess die 1200 Bytes verarbeitet und
  das ClientFinished korrekt generiert und zurückschreibt
- **Stage 3 (ServerFinished):** Ob der Sensor die letzte TLS-Runde abschließt
- **d4 00 00 + a5 00 00:** Ob der Sensor TLS als etabliert akzeptiert
- **FDT + Fingerberührung:** Im C-Treiber noch nicht getestet (aber im Python PoC 100% verifiziert)
- **Bilddaten-Dekodierung:** Nach TLS muss Image-Entschlüsselung noch geprüft werden

### Specific Issue Identified
Der Treiber hing beim Test in Stage 1 (warten auf openssl Stage-2 Antwort). 
Possible Cause: `goodix_tls_client_read` wartet 5s per poll() auf den openssl Subprocess,
aber der Subprocess hat die 1200 Bytes vom Sensor noch nicht verarbeitet und die ClientFinished
noch nicht zurückgeschrieben. Der Subprocess läuft eigenständig — möglicherweise Timing-Problem.

**Verdacht:** Nach dem Schreiben der 1200 Bytes ServerHello an client_fd muss der Subprocess 
(openssl) Zeit haben, die TLS-Records zu verarbeiten und die ClientFinished zu schreiben.
Der poll() Timeout von 5s sollte reichen — aber es gab USB EBUSY-Fehler durch vorherige Tests.

---

## 4. File Structure (Important Files)

```
scratch/libfprint_natasha/libfprint/drivers/goodixtls/
├── goodix.c           ← Hauptprotokoll, TLS-Handshake-SSM (do_tls_handshake),
│                         on_goodix_tls_read_handshake (HIER war der double-strip Bug!)
├── goodix6f94.c       ← GF3268-spezifischer Treiber, FDT-Payload, dev_change_state_6f94
├── goodix6f94.h       ← Header mit PSK-Konstanten
├── goodixtls.c        ← TLS-Infrastruktur; für 6f94: subprocess-basierter Ansatz
│                         (goodix_tls_6f94_subprocess_thread startet openssl s_client)
├── goodixtls.h        ← GoodixTlsServer Struct (enthält openssl_pid für 6f94)
├── goodix5xx.c        ← 5xx-Familien-Code, scan_run_state, calibration
└── goodix_proto.h     ← Protokoll-Konstanten

scratch/poc_driver_tls.py   ← Python PoC (VOLLSTÄNDIG FUNKTIONSTÜCHTIG)
```

---

## 5. Critical Code Details

### goodixtls.c — subprocess-Ansatz für 6f94
```c
// In goodix_tls_server_init() für 6f94:
// 1. TCP-Listener auf ephemerem Port
// 2. openssl s_client -connect 127.0.0.1:PORT -psk 000...0 -tls1_2 -quiet spawnen
// 3. TCP-Verbindung akzeptieren → client_fd
// 4. goodix_tls_client_read/write nutzen client_fd für TLS-Byte-Austausch
```

### goodix.c — Handshake SSM (Stage 0-3)
```c
// Stage 0: goodix_tls_client_read() → ClientHello lesen → e3 02 00 senden
// Stage 1: e3 00 00 → Sensor returns ServerHello+Cert (1200B) → client_fd schreiben
// Stage 2: goodix_tls_client_read() → ClientFinished lesen → e3 02 00 senden
// Stage 3: e3 00 00 → ServerFinished → client_fd schreiben → handshake done
// Dann: d4 00 00 senden
```

### goodix.c — on_goodix_tls_read_handshake
```c
// BUG WAR: double-strip (data+1, length-1) → gefixt zu (data, length)
// goodix_receive_pack strippt Status-Byte bereits für e3 00 00 Responses!
g_byte_array_append(priv->tls_recv_buffer, data, length);  // KORREKT
```

### goodix.c — expected_tls_length
```c
// Stage 1 Reset wurde entfernt — expected_tls_length kommt vom Stage-0 e3 02 00 Response
// = 847 bytes (ServerHello+Cert+Done laut Sensor)
// ABER: Sensor returns 1200 Bytes in einem Chunk! Da 1200 >= 847 → sofort komplett ✓
```

---

## 6. Build & Test

```bash
# Bauen:
cd /home/andreas/Projekte/Fingerprint/scratch/libfprint_natasha
ninja -C build

# Testen (USB-Device muss frei sein!):
echo "5" | G_MESSAGES_DEBUG=all ./build/examples/enroll 2>&1

# USB-Device reset falls EBUSY:
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

# Python PoC (immer funktionstüchtig):
cd /home/andreas/Projekte/Fingerprint
python3 scratch/poc_driver_tls.py
```

---

## 7. Next Steps (Priority)

### SOFORT: TLS-Handshake Stage 2+3 debuggen
Das ist der entscheidende nächste Schritt. Führe den Treiber aus und prüfe im Debug-Log ob:
1. `TLS_HANDSHAKE_STAGE_NUM entering state 2` erscheint
2. `TLS handshake stage 2: sending ClientFinished` erscheint
3. `TLS handshake stage 3: reading ServerFinished` erscheint  
4. `HANDSHAKE DONE` erscheint

Wenn Stage 2 blockiert: Der openssl Subprocess hat die 1200 Bytes ServerHello erhalten,
muss aber zuerst das TLS-Processing abschließen. Erhöhe poll() Timeout weiter oder 
füge ein non-blocking read mit retry loop ein.

### Danach: Bilddaten & Image-Dekodierung
Nach erfolgreichem TLS-Handshake kommt die nächste Hürde:
- `a5 00 00` Key-Payload (32 Bytes, kommt aus goodix6f94.h)
- FDT-Mode + Finger-Touch-Erkennung
- MCU_GET_IMAGE + Image data / token via e3 00 00

Da der GF3268 MOC ist, müssen Bilddaten möglicherweise NICHT über SSL_read
dekodiert werden — sie kommen bereits dekodiert aus dem Sensor via e3 00 00.

### Referenz: Python PoC
Der Python PoC `scratch/poc_driver_tls.py` ist der Ground Truth.
Jeder Schritt im C-Treiber muss dem PoC exakt entsprechen.

---

## 8. Open Questions / Uncertainties

1. **Bilddaten-Verschlüsselung:** Werden die Bilddaten nach dem TLS-Handshake noch via
   SSL-Verschlüsselung übertragen? Wenn ja, müssen wir über den openssl subprocess lesen.
   
2. **a5 00 00 Key-Payload:** Der Python PoC sendet einen fixen 32-Byte-Wert. Im C-Treiber
   ist der Key-Payload in goodix6f94.h definiert — muss mit dem PoC-Wert übereinstimmen.
   
3. **expected_tls_length:** Warum sagt der Sensor 847 Bytes aber liefert 1200? Möglicherweise
   ist `expected_tls_length` die Länge des ServerHello ohne Certificate-Extension.

---

## 9. Reference Logs

### Successful Stage 0+1 (aus dem heutigen Test)
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
...hier blieb der Test hängen (USB EBUSY vom vorherigen Run)
```

### Python PoC (historical execution log)
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

## 10. Changes 2026-07-28 (Stage 2/3 + Enroll Flow)

### Key Insight: `expected_tls_length = 847` ist NICHT die Flight-Länge
`sensor_cert.der` im Projektwurzelverzeichnis ist **exakt 847 Bytes groß**.
Die vom Sensor in der `e3 02 00` Antwort gemeldete Länge ist also die Länge des
**Zertifikats**, nicht die des gesamten Server-Flights (ServerHello + Certificate
+ ServerKeyExchange + ServerHelloDone ≈ 1200 B). Die alte Abbruchbedingung
`accumulated >= expected_tls_length` war damit reiner Zufall — sie hat die
USB-Padding-Bytes am Ende des letzten Chunks mit an OpenSSL weitergereicht.
OpenSSL bricht darauf mit „wrong version number" ab, der `s_client`-Subprozess
beendet sich, und Stage 2 hängt anschließend im `poll()` bis zum Timeout.
**Das war die Ursache der Stage-2-Blockade.**

### What was changed

**`goodixtls.c` / `goodixtls.h`**

| Neu | Zweck |
|---|---|
| `goodix_tls_scan_records()` | Läuft einen Puffer als Folge von TLS-Records ab. Liefert die Länge der *vollständigen* Records und reassembliert den Handshake-Stream über Record-Grenzen hinweg (das Certificate des Sensors ist gesplittet). Meldet CCS, Alerts, letzten Handshake-Typ. |
| `goodix_tls_client_read_flight()` | Liest einen **kompletten Flight** vom `openssl s_client`, nicht nur was ein einzelnes `read()` liefert. Drain-Loop bis ClientKeyExchange+CCS+Finished da sind. Erkennt EOF (Subprozess tot) und TLS-Alerts mit klarer Fehlermeldung statt stiller Blockade. |
| `goodix_tls_client_write()` | Schreibt jetzt in einer Schleife (Short-Writes hätten den Flight abgeschnitten). |

**`goodix.c`**
- `on_goodix_tls_read_handshake()`: Vollständigkeit wird an den TLS-Records
  entschieden (ServerHelloDone bzw. CCS+Finished), nicht mehr an
  `expected_tls_length`. Trailing-Padding wird abgeschnitten, jeder Record wird
  geloggt, TLS-Alerts brechen die SSM mit Klartextfehler ab.
- Stage 0 und Stage 2 nutzen `goodix_tls_client_read_flight()`. Der alte
  Stage-2-Fallback „bei Lesefehler leeren Payload senden" ist entfernt — er hat
  den Fehler verschleiert.
- `goodix_receive_pack()` (6f94): mehrere Gerätepakete in *einem* USB-Transfer
  werden jetzt alle verarbeitet; der Rest wird nicht mehr verworfen.
- Neuer optionaler Class-Hook `finger_down` (`FpiDeviceGoodixTlsClass`).
- `goodix_tls_init()` / `goodix_tls_ready()`: melden Init-Fehler jetzt über den
  Callback, statt die Aktivierung ewig hängen zu lassen.

**`goodix6f94.c`**
- **Post-TLS-SSM ergänzt** (fehlte komplett!): nach `d4 00 00` werden jetzt
  `a5 00 00` (32-Byte-Key aus Frame 466) und `08 01 00` (SdcpMacEnroll,
  32 Null-Bytes) gesendet — exakt wie im PoC. Erst danach
  `fpi_image_device_activate_complete()`.
- **`dev_change_state_6f94()` Bug behoben:** `36 00 00` und `a2 00 00` wurden
  direkt hintereinander abgesetzt. `goodix_send_protocol()` verweigert aber ein
  zweites Command, solange das erste läuft („A command is already running") —
  das `a2` wurde also **stillschweigend verworfen** und der Sensor hat die
  Fingererkennung nie scharfgeschaltet. Jetzt verkettet: `36` → Callback → `a2`
  → `waiting_for_finger = TRUE`.
- `finger_down_6f94()`: statt der 5xx-Capture-SSM (passt für MOC nicht) wird wie
  im PoC `20 00 00` (MCU_GET_IMAGE) gesendet und die Antwort ausgewertet.

**`goodix_proto.h`** — `GOODIX_CMD_SDCP_MAC_ENROLL (0x08)`,
`GOODIX_CMD_SDCP_KEY (0xa5)`; Mapping `0x08 → 08 01 00` in `goodix_send_protocol()`.

### Verification
- Alle drei Dateien kompilieren warnungsfrei unter dem vollen Meson-Warnungsset.
- `goodix_tls_scan_records()` ist mit 30 Assertions gegen echte Daten getestet:
  den 241-Byte `sclient_hello.bin`, einen Server-Flight mit über Records
  gesplittetem 847-Byte-Zertifikat, denselben Flight mit USB-Padding (wird
  korrekt abgeschnitten), Teilflights, CKE-ohne-Finished, Alert-Records und den
  bekannten Non-TLS-Blob `0x9c…`.
- **Nicht** gegen die echte Hardware getestet — das muss auf dem Gerät laufen.

### Test
```bash
cd /home/andreas/Projekte/Fingerprint
sudo ./run_enroll_test.sh        # baut, resettet USB, enrollt, wertet Log aus
```

### Worauf im Log zu achten ist
1. `TLS handshake stage 0: sending ClientHello (241 bytes)`
2. `server record: type=22 … first_byte=0x02 / 0x0b / 0x0c / 0x0e` —
   ServerHello, Certificate, ServerKeyExchange, ServerHelloDone. Fehlt `0x0e`,
   fordert der Treiber automatisch den nächsten Chunk an.
3. `client flight: … ccs=1 after_ccs=1` — der ClientFinished-Flight ist komplett.
4. `TLS handshake stage 3` → `HANDSHAKE DONE`
5. `post-TLS: sending a5 00 00` → `post-TLS: sending 08 01 00`
6. `Finger detection armed` → Finger auflegen → `finger down`

Bleibt es bei Stage 2 stehen, steht jetzt der Grund im Log: entweder
`openssl s_client closed the connection` (OpenSSL hat den Server-Flight
verworfen — dann die `server record:`-Zeilen prüfen) oder
`timed out … waiting for TLS data`.

### Noch offen (überholt durch Abschnitt 11 — bitte dort weiterlesen)
- `GOODIX6F94_WIDTH/HEIGHT` (88×108) sind weiterhin geraten. `get_image_cb()`
  loggt die tatsächliche Payload-Größe von `20 00 00` — daraus lassen sich die
  echten Maße ableiten.
- Ob die Bilddaten nach dem Handshake noch TLS-verschlüsselt sind, ist ungeklärt.
  Falls `20 00 00` verschlüsselt zurückkommt, muss die Antwort durch den
  `s_client`-Subprozess gelesen werden (bisher nicht implementiert).

---

## 11. ⚠️ Finding 2026-07-28 (Run 2): Sensor Does NOT Speak TLS

First hardware execution delivered a CRC32-verified
complete `e3 00 00` response (1216-Byte-Transfer, Paket 1214 B, CRC32
`7a8831d4` = berechnet). Deren Inhalt widerlegt die bisherige Arbeitsannahme.

### Proof 1 — Sensor response contains zero TLS records
Payload nach dem Status-Byte = 1201 Bytes, Struktur:

```
  Offset    0 ..   63   64 Byte   undurchsichtiger Vorspann
  Offset   64 ..  910  847 Byte   DER-Zertifikat  (byte-identisch mit sensor_cert.der)
  Offset  911 .. 1200  290 Byte   Rest (beginnt mit 0x04 → unkomprimierter EC-Punkt?)
```

Ein Scan über alle 1201 Bytes nach einem gültigen Record-Header
(Typ 20/21/22/23 gefolgt von `03 0x`) findet **null Treffer**. Das ist auch die
Auflösung des „847"-Rätsels: der Sensor meldet in der `e3 02 00` Antwort die
Länge seines **Zertifikats**, nicht die eines TLS-Flights.

### Proof 2 — Windows driver never sends a ClientHello
`unlock_success_flow.txt` (Mitschnitt des funktionierenden Windows-Treibers)
zeigt für jedes `e3`-Command in **beiden** Richtungen dasselbe Framing:

```
  [32 Byte Nonce] [01 ff] [4 Byte Länge LE] [Body] [Trailer]
```

| Frame | Richtung | Cmd | Nonce | Länge | Body |
|---|---|---|---|---|---|
| 45  | host→dev | e3 02 00 | `c21b521a…` | 162  | `659b4aff…` |
| 57  | host→dev | e3 00 00 | `dcdf2ddc…` | 162  | `659b4aff…` (gleicher Body, neue Nonce) |
| 65  | dev→host | e3 00 00 | `7c9e05df…` | 1366 | `a52f8bb1…` |
| 141 | host→dev | e3 02 00 | `3cde1337…` | 32   | `2d472922…` |

Kein `16 03 01`, kein ClientHello, keine TLS-Records — auch nicht im
funktionierenden Windows-Fall. **Der `openssl s_client`-Proxy kann prinzipiell
nicht funktionieren.** Unser Treiber schickt ein echtes 241-Byte-ClientHello,
der Sensor versteht es nicht und antwortet mit einem generischen Blob, in dem
zufällig das Zertifikat steckt.

### Why the Python PoC appeared 'successful'
`run_tls_handshake()` in `scratch/poc_driver_tls.py` prüft **nichts**. Es
schiebt Bytes zwischen Socket und USB hin und her und druckt danach
bedingungslos `[Proxy] TLS Handshake proxy complete!`. Wenn OpenSSL den Blob
verwirft und einen 7-Byte-Alert zurückschickt, wird auch der brav als
„Client Finished flight" an den Sensor weitergereicht. Die Aussage
„TLS-Handshake 100 % verifiziert" im Abschnitt 2 ist damit **nicht belegt** —
die Fingerberührungserkennung funktioniert offenbar auch ohne gesicherten
Kanal. Gegencheck in 10 Sekunden: `openssl s_client` von Hand starten und
seine stderr ansehen; dort müsste „wrong version number" stehen.

### Analysis & Classification
Der Treiber referenziert bereits `GoodixSdcpMacEnroll` (08 01 00) und
`GoodixSdcpVerify` (20 01 00). **SDCP = Microsofts Secure Device Connection
Protocol** für Windows-Hello-Sensoren. Nonce + Gerätezertifikat + EC-Punkt +
Signatur in der Antwort passen genau auf einen SDCP-`Connect`. Der GF3268 nutzt
also nicht das TLS-PSK der älteren Goodix-Generation (55a2, worauf der
`goodix-fingerprint-reversing`-Code im Projekt basiert), sondern SDCP.

### Ebenfalls in diesem Lauf gefunden und behoben
- **Regression aus Abschnitt 10:** Der Sensor padded jedes Paket auf ein
  Vielfaches von 64 Byte. Mein „Rest im Puffer behalten"-Patch hat dieses
  Padding als weiteres Paket geparst → Längenfeld 0 → Puffer dauerhaft
  desynchronisiert → der 1214-Byte-Chunk wurde nie zusammengesetzt → Hänger.
  Jetzt wird der Header per CRC8 validiert, bevor er benutzt wird; schlägt das
  fehl, wird der Puffer verworfen und resynchronisiert. Gegen die Bytes des
  Fehllaufs simuliert: 7/7 Pakete sauber, kein Rest.
- `pay_len_field < 4` löste einen Underflow in `payload_len` aus →
  `g_memdup()` mit 65532 Bytes aus einem 72-Byte-Puffer (Heap-Overread).
- `data_to_str()` gab bei `length == 0` uninitialisierten Speicher zurück —
  daher die Müllzeichen `\xed\xdd>36V` im Log bei Zero-Length-Transfers.

### Recommended Next Steps
1. **Billiges Experiment zuerst:** die exakte Byte-Sequenz aus
   `unlock_success_flow.txt` (Frames 45/57) 1:1 an den Sensor replayen. Wenn er
   mit einer plausiblen Antwort kommt, gibt es keine Freshness-Prüfung auf der
   Nonce und die Struktur lässt sich schrittweise aufklären.
2. Erst danach das Framing `[Nonce][01 ff][Länge][Body]` nachbauen und den
   `openssl s_client`-Subprozess ersatzlos entfernen.
3. Die restlichen `e3`-Frames aus allen vorhandenen pcapng-Dateien extrahieren,
   um Body-Layout und Trailer (30/30/26/32 Byte — noch nicht verstanden) zu
   bestimmen.

---

## 12. Complete Windows Sequence (aus `unlock_success_flow.txt`, alle 40 Frames CRC-verifiziert)

Der tatsaechliche Unlock-Ablauf des Windows-Treibers. **Er enthaelt weder
`d4 00 00` noch `36 00 00` noch `08 01 00` noch `20 00 00`** — die Sequenz in
Abschnitt 2 ist damit ebenfalls hinfaellig.

| # | Host → Sensor | Payload | Sensor → Host |
|---|---|---|---|
| 33  | `e1 04 00` | `00` | `00000000` |
| 45  | `e3 02 00` | 256 B (`len=230` + Nonce + Body) | `00 4f030000` → Status 0, 847 |
| 57  | `e3 00 00` | 256 B (gleicher Body, **neue Nonce**) | 1431 B |
| 69  | `b0 02 00` | `00` | 65 B (sieht nach Kalibrierwerten aus) |
| 81  | `e0 01 00` | `00` | `00000093` |
| 93  | `a2 00 00` | `01 00 23 01` | `005c64001f003b00` |
| 105 | `a5 00 00` | 32 B Key | **1110 B** |
| 117 | `e0 00 00` | `00` | `00000000` |
| 129 | `a5 01 00` | `01 00 00 00` | `00` |
| 141 | `e3 02 00` | 256 B (`len=102`) | `00 4f030000` |
| 153 | `e3 01 00` | 256 B (gleicher Body) | 33 B (Status + 32 B, vermutlich MAC) |
| 165 | `b0 02 00` | `00` | 65 B |
| 177 | `a2 00 00` | `01 00 23 00` | nur ACK |
| 185 | `b3 02 00` | `00` | nur ACK |

Observations:
- `e3 02 00` **schreibt**, `e3 00 00` / `e3 01 00` **lesen** — jeweils mit
  demselben Body, aber jedes Mal einer frischen 32-Byte-Nonce.
- Der Sensor meldet auf jedes `e3 02 00` dieselbe Laenge 847 (Zertifikat).
- `a5 00 00` mit 32-Byte-Key liefert 1110 B zurueck — das ist der interessante
  Kandidat fuer Template-/Bilddaten.
- `b0 02 00` und `b3 02 00` sind im aktuellen Treiber ueberhaupt nicht bekannt.

### New Analysis Tools
- **`scratch/sdcp_replay.py`** — spielt diese Host-Frames byte-identisch ein und
  vergleicht jede Antwort mit dem Mitschnitt. Meldet praezise, ab welchem Frame
  der Sensor abweicht (= wo Nonce-Frische/Schluesselableitung noetig wird).
  ```bash
  python3 scratch/sdcp_replay.py --dry-run     # ohne Hardware, prueft nur den Mitschnitt
  sudo python3 scratch/sdcp_replay.py          # echter Replay
  sudo python3 scratch/sdcp_replay.py --until 65
  ```
- **`scratch/poc_driver_tls.py`** meldet jetzt nicht mehr bedingungslos Erfolg:
  jeder Flight wird als TLS-Record geparst, OpenSSLs stderr wird ausgelesen und
  am Ende steht ein ehrliches Fazit. Gegen die echten Sensor-Bytes getestet:
  „KEIN gueltiger TLS-Record".

---

## 13. Replay Results (Hardware): Sensor Accepts Replays

`sudo python3 scratch/sdcp_replay.py --until 65` gegen den echten Sensor.
Die erste Fassung des Skripts hat das Result falsch zusammengefasst („weicht
ab Frame 33 ab") — sie hat rein byteweise verglichen. Fachlich gelesen:

| Frame | Result | Evaluation |
|---|---|---|
| 33 `e1 04 00` | Antwort `00000000` **byte-identisch** | ✅ |
| 45 `e3 02 00` | Antwort `00 4f030000` **byte-identisch** | ✅ Sensor akzeptiert den replayten Nonce+Body |
| 57 `e3 00 00` | 1431 B, **gleiche Länge**, `01 ff`-Marker gleich, deklarierte Body-Länge **1366 identisch**, Body-Anfang identisch | ✅ strukturell identisch |
| 69 `b0 02 00` | 65 B, 24 B abweichend | ✅ das sind 16-Bit-**Live-Messwerte** des Sensors |
| alle ACKs | 1 Byte abweichend, immer Offset 3 (`…00` statt `…01`) | ✅ Flagbyte, kein Nutzinhalt |

**Es gibt keine Nonce-Freshness-Prüfung, die den Replay ablehnt.** Von den
1431 Byte der Frame-57-Antwort sind 937 identisch; die 494 abweichenden sind
die frische 32-Byte-Geräte-Nonce, der 26-Byte-Trailer und ~436 Byte im Body.

### Body is Encrypted
Blockweise Byte-Entropie des 1366-Byte-Bodys aus dem Windows-Mitschnitt liegt
durchgehend bei ~0,88–1,00 (zufällig). Weder das Zertifikat noch irgendeine
DER-Struktur ist darin zu finden. Zum Vergleich: unsere ClientHello-Antwort aus
Abschnitt 11 hat Blöcke mit 0,41–0,64 — dort lag das Zertifikat im Klartext.

Daraus folgt die Arbeitshypothese: der Sensor returns seine SDCP-Identität
**verschlüsselt**, wenn die Anfrage wohlgeformt ist, und fällt bei einer
unverständlichen Anfrage (unser ClientHello) auf eine Klartext-Antwort mit dem
Zertifikat zurück.

### Nächster Schritt: Felder kartieren ohne Kryptoanalyse
Zwei Läufe **derselben** Anfrage gegeneinander diffen. Was sich ändert, ist
frischer Zufall des Sensors; was gleich bleibt, sind statice Gerätedaten:

```bash
sudo python3 scratch/sdcp_replay.py --until 65      # Lauf 1
sudo python3 scratch/sdcp_replay.py --until 65      # Lauf 2
python3 scratch/sdcp_replay.py --diff scratch/replay_out/run_A scratch/replay_out/run_B
```

Das Skript speichert jetzt jede Antwort unter `scratch/replay_out/run_<zeit>/`
und `--diff` gibt eine Offset-Karte „static vs. frisch" aus. Damit steht das
Body-Layout fest, bevor auch nur ein Byte Krypto verstanden sein muss.

### Weitere Beobachtung
`b0 02 00` liefert 32 × 16-Bit-Werte (Status + 64 B). Werte um 0x0076–0x009b
bei uns, 0x0062–0x0095 bei Windows. Das ist der erste direkte Sensormesswert,
den wir sehen — Kandidat für die Kalibrierung und damit später für die
Bildgeometrie.

---

## 14. Field Layout Map of `e3 00 00` Response (aus zwei Replay-Läufen, 2026-07-28)

Zwei Läufe mit **byte-identischer** Anfrage, Sekunden Abstand. Was sich
unterscheidet, ist frischer Zufall des Sensors; was gleich bleibt, sind
statice Gerätedaten. Result für die 1431-Byte-Antwort:

```
  Offset      Größe   Art        Interpretation
  ----------------------------------------------------------------
       0        1 B   static   Status (0x00)
    1.. 32     32 B   FRESH/DYNAMIC     Device Nonce
   33.. 34      2 B   static   Marker 01 ff
   35.. 38      4 B   static   deklarierte Body-Länge (1366)
   39..1318   1280 B  static   Body[0..1279] — Device Identity
 1319..1430    112 B  FRESH/DYNAMIC     Body[1280..] + Rest, zusammenhängend
```

**1287 von 1431 Byte sind über Läufe hinweg bit-identisch.** Frisch sind nur
die 32-Byte-Nonce am Anfang und ein zusammenhängender 112-Byte-Schwanz am Ende.

### Korrektur zu Abschnitt 13
Die dortige Aussage „der Body ist verschlüsselt" war voreilig. Hohe Entropie
**plus** Bit-Gleichheit über mehrere Antworten heißt: es ist statices
hochentropes Material (Schlüssel, Hashes, ein fest verpackter Identitäts-Blob),
**keine frische Verschlüsselung pro Sitzung**. Sonst müsste sich alles ändern.

### Drei Geltungsbereiche
Der Vergleich Lauf ↔ Windows-Mitschnitt (völlig andere Sitzung) zeigt eine
feinere Staffelung:

| Bereich (innerer Puffer) | Größe | Verhalten |
|---|---|---|
| `inner[0..31]` | 32 B | ändert sich **bei jeder Antwort** → Nonce |
| `inner[32..965]` | 934 B | gleich **auch gegenüber Windows** → gerätekonstant (Zertifikat/Schlüssel) |
| `inner[966..1317]` | 352 B | gleich innerhalb unserer Läufe, ≠ Windows → **sitzungs-/reset-gebunden** |
| `inner[1318..1429]` | 112 B | ändert sich **bei jeder Antwort** → Signature / MAC / Ephemeral Key |

Die 112 Byte sind der interessante Teil. Größenordnung passt z. B. auf
ECDSA-P-256-Signatur (64 B roh) + 48 B, oder auf einen AES-GCM-verpackten
32-Byte-Sitzungsschlüssel (32+16) + 64 B Signatur. **Noch nicht belegt.**

### Nächstes Experiment
Der Bereich `inner[966..1317]` ist der Schlüssel zur Frage „woran hängt die
Sitzung?". Ein Lauf mit USB-Reset dazwischen trennt das:

```bash
sudo python3 scratch/sdcp_replay.py --until 65            # Lauf ohne Reset
sudo python3 scratch/sdcp_replay.py --until 65 --reset    # Lauf mit Reset davor
python3 scratch/sdcp_replay.py --diff                     # beide neuesten vergleichen
```

Wächst der frische Bereich nach einem Reset von 112 auf ~464 Byte, ist
`inner[966..1317]` an den Power-Zyklus gebunden (Boot-Random / ephemerer
Geräteschlüssel). Bleibt er bei 112, hängt er an etwas anderem — dann kommt als
nächstes das Variieren einzelner Felder in der Anfrage.

### Werkzeug-Korrekturen
- `--diff` **ohne Argumente** nimmt jetzt die beiden neuesten Läufe. (Die
  Platzhalter `run_A`/`run_B` in Abschnitt 13 waren als solche nicht erkennbar —
  entschuldige.)
- Neu: `--reset` löst vor dem Lauf `USBDEVFS_RESET` aus.
- `classify_diff()` kennt jetzt auch die 4-Byte-Statusantworten von `e1 04 00` /
  `e0 01 00`: dort ist das letzte Byte ein Gerätezustandswert (bei uns `0x9b`,
  im Windows-Mitschnitt `0x00`) und kein Fehlercode. Damit ist auch das
  Schlussfazit des Skripts endlich korrekt.

---

## 15. Reset Experiment: USB Reset Makes No Difference

Vier Läufe: zwei ohne Reset (Sekunden Abstand), einer 6 Minuten später, einer
direkt nach `USBDEVFS_RESET`. Frischer Anteil der 1431-Byte-`e3 00 00`-Antwort:

| Vergleich | frisch |
|---|---|
| Lauf1 ↔ Lauf2 (kein Reset, Sekunden) | 32 B Nonce + 112 B Schwanz |
| Lauf2 ↔ Lauf3 (kein Reset, 6 Min) | 32 B Nonce + 112 B Schwanz |
| Lauf3 ↔ Lauf4 (**mit USB-Reset**) | 32 B Nonce + 112 B Schwanz |

**USB Reset makes no difference.** Damit ist die Hypothese aus Abschnitt 14
widerlegt: `inner[966..1317]` (352 B) ist **nicht** an den Power-/Reset-Zyklus
gebunden, sondern **gerätepersistent**. Es überlebt Reset und Zeit.

Warum es sich dann vom Windows-Mitschnitt unterscheidet, ist offen. Die
naheliegendste Erklärung: persistenter Zustand, der sich seit dem Mitschnitt
geändert hat — am ehesten der **Enrollment-/Template-Stand** (im Projekt liegt
`goodix_delete_templates.pcapng`, es wurden also irgendwann Templates gelöscht).

### Practical Significance — Good News
Von 1431 Byte sind **1287 replaybare Konstanten**. Pro Antwort variieren nur:
- 32 B Nonce (erzeugt der Sensor selbst)
- 112 B Schwanz (Signatur/MAC, erzeugt der Sensor selbst)

Beides erzeugt der **Sensor**, nicht der Host. Für einen funktionierenden
Treiber müssen wir diese Felder also gar nicht berechnen können — wir müssen nur
**gültige Anfragen senden**, und eine solche haben wir aus dem Mitschnitt.

### Korrektur zu Abschnitt 13
`b0 02 00` liefert 32 × 16-Bit-Werte. Ich hatte sie als „Live-Messwerte"
eingeordnet — falsch. Über alle vier Läufe sind sie **bis auf ein einziges Byte
identisch** (152, 155, 131, 118, 154, 154, …). Gegenüber Windows weichen sie ab
(143, 147, 114, 98, …). Es sind also **Kalibrierwerte**, die vom Gerätezustand
abhängen, nicht vom Zufall. Wert­bereich in beiden Fällen 0..203.
Die Evaluation in `classify_diff()` ist entsprechend korrigiert.

### Nächster Schritt
Den Replay **über Frame 65 hinaus** bis zum Ende der Unlock-Sequenz laufen
lassen. Damit klärt sich die entscheidende Frage: nimmt der Sensor eine
vollständig replayte Sitzung end-to-end an?

```bash
sudo python3 scratch/sdcp_replay.py        # ohne --until = kompletter Ablauf
```

Besonders interessant ist Frame 105/113: `a5 00 00` mit 32-Byte-Key liefert
**1110 Byte** zurück, deren Kopf strukturiert ist
(`5c 64 45 00 00 00 00 62 00 43 04 f5 …`, danach 16 Nullbytes, dann hochentrop).
Die ersten beiden Bytes `5c 64` tauchen auch in der `a2 00 00`-Antwort auf
(`00 5c 64 00 1f 00 3b 00`) — dort, wo laut Abschnitt 2 das Finger-Event steht.

**Risiko:** Die Sequenz enthält `a5 01 00` (`01 00 00 00`) und `e0 00 00`, die
Gerätezustand schreiben könnten. Es ist ein Unlock-/Verify-Ablauf, kein Enroll
und kein Delete (dafür gibt es eigene Captures), das Risiko ist also gering —
aber nicht null.

---

## 16. Complete Replay + Alignment with `walkthrough.md`

### Complete Replay Results
Von 12 erwarteten Antworten kamen 10 strukturell korrekt zurück:

| Frame | Command | Result |
|---|---|---|
| 41 | `e1 04 00` | ✅ (nur Gerätezustandsbyte) |
| 53 | `e3 02 00` | ✅ byte-identisch |
| 65 | `e3 00 00` | ✅ 1431 B, gleiche Struktur |
| 77 | `b0 02 00` | ✅ Kalibrierwerte |
| 89 | `e0 01 00` | ✅ |
| **101** | `a2 00 00` (`01 00 23 01`) | ❌ **gar keine Antwort**, nur ACK. Windows: `00 5c 64 00 1f 00 3b 00` |
| **113** | `a5 00 00` | ❌ **`ff`** statt 1110 B |
| 125 | `e0 00 00` | ✅ byte-identisch |
| 137 | `a5 01 00` | ✅ byte-identisch (`00`) |
| 149 | `e3 02 00` | ✅ byte-identisch |
| 161 | `e3 01 00` | ✅ 33 B, Status `00` + 32 B frischer MAC |
| 173 | `b0 02 00` | ✅ |

Der gesamte Handshake ist also replaybar. Die Grenze liegt bei `a2 00 00`
mit Payload `01 00 23 01` — dort liefert der Sensor bei uns keine Scan-Status-
Daten, und in der Folge gibt `a5 00 00` nur `ff` zurück.

Nebenbefund: `a2 00 00` mit `01 00 23 01` (Frame 93) liefert im Mitschnitt
Daten, mit `01 00 23 00` (Frame 177) nur ein ACK — das letzte Byte schaltet
also offenbar etwas ein bzw. aus.

### Alignment with `walkthrough.md` — Wire format confirmed
`walkthrough.md` dokumentiert (aus früherer Arbeit im Projekt):

> `MAC (32 Bytes) + Header (01 FF) + Length (4 Bytes) + IV (16 Bytes) + Ciphertext`

Das ist **exakt** die Struktur, die in Abschnitt 12–14 unabhängig aus dem
Draht abgeleitet wurde (`[32 B][01 ff][4 B Länge][Body]`). Zwei unabhängige
Herleitungen, gleiches Result — das Format gilt damit als bestätigt.
Meine Bezeichnung „Nonce" für die ersten 32 Byte war falsch: es ist ein
**HMAC-SHA256**. Und der „Body" beginnt mit einem **16-Byte-IV**.

Das erklärt auch die Feldkarte aus Abschnitt 14 zwanglos: AES-CTR ist eine
Stromchiffre. Bei identischem Schlüssel, identischem IV und einem Klartext,
der sich nur am Ende unterscheidet, unterscheidet sich auch der Ciphertext nur
am Ende — genau die beobachteten 1287 staticen + 112 frischen Byte. Der MAC
ändert sich mit, weil der Ciphertext sich ändert.

### Stand der Technik im Projekt
`test_get_image.py` (718 Zeilen) implementiert laut `walkthrough.md` bereits:
ECDH P-256, Ableitung der AES-/HMAC-Schlüssel (verifiziert: der **reine**
Shared Secret dient direkt als Schlüssel, ohne Key Expansion), verschlüsseltes
Client-Identity-Paket, Authentifizierung, Finger-Erkennung und Auslesen des
`b0 02 00`-Arrays. `find_ec_pubkey_in_server_hello()` dokumentiert das Layout
der Server-Antwort:

```
    0.. 63   Session-Header / Nonce-Material
   64..910   X.509-Zertifikat (847 B)  -> staticer Sensor-Schlüssel
  911..975   ephemerer ECDH-Public-Key #1 (65 B, unkomprimiert)
  976..1040  EC-Punkt #2 / Proof-of-Possession (65 B)
 1041..Ende  HMAC / Signatur
```

Das deckt sich exakt mit dem, was in Abschnitt 11 an unserer eigenen Antwort
gemessen wurde (64 B Vorspann, 847 B Zertifikat, dann `04`-Präfix bei 911).

### Konsequenz für den C-Treiber
Der `openssl s_client`-Subprozess in `goodixtls.c` und die vierstufige
TLS-Handshake-SSM in `goodix.c` sind **konzeptionell falsch** und müssen durch
den ECDH-Ablauf aus `test_get_image.py` ersetzt werden. Die Arbeiten aus
Abschnitt 10 (Puffer-Resync, CRC8-Validierung, Padding-Behandlung,
`data_to_str`-Fix, Commandverkettung) bleiben davon unberührt und weiterhin
gültig — sie betreffen die Transportschicht, nicht die Krypto.

### Nächster Schritt
`test_get_image.py` gegen die Hardware laufen lassen. `cryptography` ist
vorhanden. Das zeigt, wie weit der Live-ECDH-Handshake heute tatsächlich kommt
— und ist aussagekräftiger als jeder weitere Replay.

---

## 17. Breakthrough: Cryptography is mbedTLS with `TLS-PSK-WITH-AES-128-CBC-SHA256`

### Measurement Results
- **Reihenfolge war es nicht.** `win_order_probe.py` bildet den Windows-Ablauf
  exakt nach (`e1 04 00` zuerst, `b0 02 00` mit 1 Byte `00`, `e0 01 00` mit
  1 Byte, `a2 00 00` mit `01 00 23 01`). Alle Antworten stimmen jetzt mit dem
  Mitschnitt überein — `b0 02 00` → 65 B, `a2` → `005d64001f003900`
  (Windows `005c64001f003b00`), `e0 00 00` → `00000000`, `a5 01 00` → `00`.
  Nur `a5 00 00` bleibt bei `04`.
- **EC-Punkt war es auch nicht.** `key_sweep.py` hat alle drei Punkte aus dem
  Server-Hello × Key-Expansion an/aus durchprobiert. Alle sechs → `04`.
- **Und der eigentliche Befund:** in keiner der 24 geprüften Kombinationen
  (6 Ableitungen × 4 MAC-Formeln) ließ sich die 32-Byte-Antwort des Sensors
  auf `e3 01 00` verifizieren.

### Central Assumption Refuted
`test_get_image.py` wertet `len == 33 and resp[0] == 0x00` als
„[SUCCESS] Handshake Completed! Server Identity verified." Der Sensor antwortet
aber **immer** so — auch mit nachweislich falschen Schlüsseln. Diese
Erfolgsmeldung hat nie etwas belegt, und `walkthrough.md` Abschnitt 3
(„Successfully authenticates the host with the sensor!") beruht darauf.

### Binary Inspection Findings
`windows_driver_binaries/GoodixMocWbdi.dll` (3,9 MB) enthält:

```
  ..\CODE\mbedtls\Src\ssl_tls.c          mbedTLS, statically linked
  ..\CODE\mbedtls\Src\ssl_cli.c
  TLS-PSK-WITH-AES-128-CBC-SHA256        die Cipher-Suite
  mbedtls_ssl_psk_derive_premaster
  mbedtls_ssl_derive_keys
  => calc finished tls sha256
  gf_sha256 / gf_hmac_sha256             Goodix-Wrapper
  secp256r1, alle vier P-256-Konstanten (als mbedTLS-Limbs)
```

Keine BCrypt-/NCrypt-Importe — die Krypto ist static gelinkt. Die Suite
erklärt die Beobachtungen am Draht lückenlos: **AES-128-CBC** (16-Byte-IV,
Ciphertext auf 16 gepolstert) und **HMAC-SHA256** (32-Byte-MAC vorn).

### Die vermutete Ursache
`mbedtls_ssl_psk_derive_premaster` baut den Premaster nach RFC 4279:

```
  reines PSK :  premaster = uint16(N) || N Nullbytes || uint16(N) || psk
  ECDHE-PSK  :  premaster = uint16(|Z|) || Z        || uint16(N) || psk
  danach:  master_secret = PRF(premaster, "master secret", cr||sr, 48)
           key_block     = PRF(master_secret, "key expansion", sr||cr, n)
```

`derive_goodix_gtls_keys()` steckt stattdessen das **rohe ECDH-Result** als
Secret hinein. Die Suite heißt zudem `TLS-PSK-…`, nicht `TLS-ECDHE-PSK-…` —
wenn das zutrifft, spielt das ECDH-Result für die Sitzungsschlüssel gar keine
Rolle. Das erklärt zwanglos, warum alle sechs EC-Kandidaten identisch scheiterten.

### Neues Werkzeug
`scratch/kdf_sweep.py` probiert 12 Kombinationen durch:
3 Premaster-Varianten (reines PSK / ECDHE-PSK / rohes Z) × Key-Expansion an+aus
× 2 Key-Block-Layouts (Goodix `aes16|iv16|hmac32` und TLS-Standard
`cMAC32|sMAC32|cKey16|sKey16|cIV16|sIV16`). Zusätzlich wird die Server-Antwort
gegen vier MAC-Formeln geprüft, darunter die TLS-`finished`-PRF.

```bash
sudo python3 scratch/kdf_sweep.py 2>&1 | tee kdf_sweep.log
```

### Korrigierte Feldkarte
Der in Abschnitt 14 vermutete „Trailer" existiert nicht. Bei allen fünf
`e3`-Frames des Mitschnitts geht die Rechnung auf:

```
  MAC(32) || 01 ff || Klartextlänge(LE32) || IV(16) || AES-CBC(pad16(Klartext))
       162 -> 176        1366 -> 1376          32 -> 48
```

Außerdem beginnt `unlock_success_flow.txt` bei Frame 33 **mitten in einer
laufenden Sitzung** — Frame 45 ist bereits verschlüsselt. Der eigentliche
Handshake dieser Aufzeichnung fehlt darin.

---

## 18. Crypto Status: Black-Box Limit Reached, Ghidra Tools Ready (2026-07-28)

### Was jetzt sicher ist
- **`01` = kein Match, `04` = anderer Fehler, `1110 B` = Auth-Token.** Aus den
  pcaps direkt abgelesen: `goodix_unlock_success` → `a5 00 00` liefert 1110 B;
  `goodix_unlock_fail` → `01`; unser Live-Versuch → `04`. Unsere Sitzung
  authentifiziert also nicht einmal so weit wie ein *fehlgeschlagener* Windows-
  Unlock. Der Handshake ist der Bruchpunkt, nicht der Finger-Match.
- **Der Sitzungsschlüssel ist nicht aus dem PSK allein ableitbar.** Ein
  Offline-Angriff mit 163 Schlüsselkandidaten (PSK, SHA256(PSK), sämtliche
  PRF-Ausgaben mit „master secret"/„key expansion"/„client finished"/
  „server finished" über cr‖sr, sr‖cr, …) gegen das PKCS7-Padding-Orakel der
  ersten Nachricht: **kein Treffer**.
- **Standard-TLS-Ableitung reproduziert die Server-Antwort nicht.** Selbst mit
  bekanntem ECDH-Z (aus unseren Live-Läufen) ergab keine der 24 Kombinationen
  aus `key_sweep.py`/`kdf_sweep.py` die 32-Byte-Antwort des Sensors auf
  `e3 01 00`. Die Ableitung ist nicht Lehrbuch-mbedTLS.
- **Windows sendet nie einen Klartext-ECDH-Hello.** In allen Captures ist schon
  die erste `e3 02 00` verschlüsselt. Der Schlüssel wird also nicht sichtbar
  über USB ausgehandelt.

### Nebenbefund: IV-Wiederverwendung
Der Treiber verwendet IVs mehrfach (`goodix_unlock_success`: 29 von 50
Nachrichten teilen sich einen IV mit einer anderen). Mehrere Paare sind sogar
**byte-identisch** (gleicher IV + gleicher Ciphertext = wortgleiche Nachricht
zweimal gesendet). Das ist kryptografisch unsauber, hilft aber nicht beim
Schlüssel, weil der IV ohnehin im Klartext mitgeschickt wird.

### Neues Werkzeug: `scratch/pcap_crypto.py`
Eigenständiger pcapng-Parser + Entschlüsselungs-Orakel. Lädt alle 159
verschlüsselten Nachrichten aus den Captures und prüft einen Schlüsselkandidaten
gegen zwei unabhängige Orakel (PKCS7-Padding und HMAC-SHA256 über
`01ff|len|IV|CT`). Selbsttest bestanden: Zero-Key → 0 Fehltreffer bei 159
Nachrichten, das Orakel ist also trennscharf.

```bash
python3 scratch/pcap_crypto.py                  # Übersicht
python3 scratch/pcap_crypto.py --key <hex16>    # Kandidat testen
# als Bibliothek: from pcap_crypto import try_key, try_derivation
```

Sobald die Ableitung aus Ghidra bekannt ist, verifiziert dieses Skript sie in
Sekunden gegen echte Daten — ohne Hardware.

### Klare Empfehlung: jetzt Ghidra
Der Black-Box-Weg ist erschöpft. Das Ziel in `GoodixMocWbdi.dll`:

1. **`gf_hmac_sha256`** — der String steht bei Offset 777912. Von dort die
   Aufrufer zurückverfolgen: welcher Puffer wird als Schlüssel übergeben und
   woraus entsteht er? Das ist der kürzeste Weg zum `mac_key`.
2. **`mbedtls_ssl_psk_derive_premaster`** (String bei ~0x3AF...) — zeigt, wie
   der Premaster zusammengesetzt wird (RFC 4279 oder abgewandelt).
3. **`mbedtls_ssl_derive_keys`** — Standard oder gepatcht?

Ghidra + JDK liegen bereits im Projekt (`ghidra_11.0.3_PUBLIC/`, `jdk/`).

### Ehrliche Gesamteinschätzung
Transport, Framing und Krypto-Suite sind vollständig verstanden und in
lauffähigen Python-Werkzeugen abgebildet. Was fehlt, ist die **eine**
Schlüsselableitungsfunktion. Die ist per Black-Box nicht mehr zu erraten — sie
muss aus dem Binary gelesen werden. Ohne sie kann der Linux-Treiber keine
gültige verschlüsselte Nachricht erzeugen und damit den MoC-Sensor nicht zum
Auth-Token bewegen. Das ist keine Sackgasse, aber die nächste Etappe ist
statice Reverse-Analyse, kein weiteres Hardware-Probing.

---

## 19. Binary Analysis + Sister Chips: Complete Picture (2026-07-28)

### objdump statt Ghidra
Ghidra läuft im Sandbox nicht (gebündelter JDK ist Windows-only, System-JDK ist
11, Ghidra 11 braucht 17). Ersatz: `objdump -b pei-x86-64` plus selbst
geschriebene PE-/.pdata-Parser (`/tmp/pe.py`, `/tmp/pdata.py`, `/tmp/xref.py`).
Damit exakte Funktionsgrenzen (2030 Funktionen aus `.pdata`) und
RIP-relative Xrefs — ausreichend für gezielte Analyse.

### Was die DLL verrät
- `GoodixMocWbdi.dll` linkt **mbedTLS** static, Suite
  **`TLS-PSK-WITH-AES-128-CBC-SHA256`** (Abschnitt 17).
- Der einzige Aufrufer des `gf_hmac_sha256`-Wrappers ist die Funktion
  **`ProcessPsk`** (VA 0x18008edc0) — das ist die **PSK-Provisionierung**, nicht
  der Sitzungs-KDF. Strings dort: `1.check psk if valid`, `3.write psk to mcu`,
  `sgxPskLen`, `GfSealData`, `PresetPskWriteKey`, `production_write_key`.
- Der Sitzungs-KDF nutzt also mbedTLS' eigene HMAC-Funktion, nicht den
  Goodix-Wrapper — er ist im Binary schwerer zu isolieren.

### Der Schwester-Chip liefert die fehlende Referenz
`goodix-fingerprint-reversing/capture.py` ist ein **funktionierender** Treiber
für den Goodix 55a2 (GF3206) und war bisher unbeachtet. Kernpunkte, die direkt
auf den GF3268 übertragen:

- **Der TLS-PSK ist Zero (32 Nullbytes).** Bestätigt durch die laufende
  openssl-Zeile: `openssl s_server -nocert -psk 0000…0`. Der 144-Byte-`PSK_WB`
  ist nur ein Provisionierungs-Blob, der einmalig in den MCU geschrieben wird —
  er ist **nicht** der Sitzungsschlüssel. Dieselben `ProcessPsk`/`PresetPsk`-
  Funktionen finden sich in unserer GF3268-DLL wieder.
- **Rollenverteilung:** das Gerät ist der TLS-**Client**, openssl ist der
  **`s_server`**. Der natasha-C-Treiber und `test_get_image.py` benutzen
  dagegen `s_client` bzw. rollen ein eigenes ECDH — **falsche Rolle**.
- **Ablauf 55a2:** `d0` (REQUEST_TLS) → Gerät sendet ClientHello →
  an s_server → ServerHello zurück ans Gerät → Gerät sendet
  ClientKeyExchange+CCS+Finished → an Server → ServerFinished ans Gerät. Reines
  Standard-TLS-PSK.

### Der GF3268 ist kein reiner 55a2
Zwei harte Unterschiede in den Captures:
1. **Kein einziger TLS-Record-Marker** (`16 03 xx`, `14 03 03`) im gesamten
   USB-Verkehr aller neun pcaps. Der GF3268 verpackt die mbedTLS-Crypto in ein
   **eigenes** Record-Format (`MAC32 | 01ff | len | IV | CT`), nicht in
   Standard-TLS-Records. Der s_server-Proxy-Trick des 55a2 funktioniert daher
   nicht unverändert.
2. Der GF3268 hat ein `d0`-Command, dessen Antwort mit `…0002 fe41 5050…`
   beginnt (in `goodix_init` und `goodix_handshake_and_enroll`, **nicht** im
   Unlock — der Handshake wird also nur einmal pro Power-Zyklus gemacht und
   dann wiederverwendet).

### Damit ist die Lage präzise
Alles ist verstanden **außer** der einen Schlüsselableitung aus den
Handshake-Nonces. Fakten:
- Crypto = mbedTLS, `TLS-PSK-WITH-AES-128-CBC-SHA256`, **Zero-PSK** (jetzt durch
  den 55a2-Beleg gestützt, nicht mehr nur Annahme).
- Standard-TLS-PSK-KDF mit Zero-PSK reproduziert die Sitzung aber nicht
  (`kdf_sweep.py`, 12 Varianten). Es kommt also ein zusätzlicher Faktor hinzu —
  am wahrscheinlichsten der ECDHE-Anteil (die Server-Hello enthält ephemere
  EC-Punkte), d.h. **ECDHE-PSK-Premaster** `Z || PSK-Struktur`, aber mit einer
  Nonce-/Seed-Belegung, die noch nicht getroffen wurde.

### Zwei Wege zum Ziel — Entscheidung nötig
**A. Frida-Hook auf Windows (schnellster sicherer Weg).**
Den Windows-Treiber laufen lassen und `mbedtls_ssl_derive_keys` bzw. die
AES-Setup-Funktion hooken, um `master_secret` / `key_block` **direkt** zu
dumpen. Eingaben (Nonces, Z) sind aus unseren Live-Läufen bekannt → die exakte
KDF-Formel ergibt sich aus einem einzigen Input/Output-Paar. `pcap_crypto.py`
verifiziert sie sofort. Voraussetzung: Windows-Installation mit dem Sensor.

**B. Statische RE weiter (kein Windows nötig, aber langwierig).**
Die mbedTLS-Handshake-Funktion im Binary vollständig lesen. Ohne Ghidra/JDK17
nur mit objdump machbar, aber aufwändig. Braucht als Ersatz einen lauffähigen
Ghidra (JDK 17 installieren) oder Radare2/Cutter.

Beides führt zum selben Ziel: sobald die KDF bekannt ist, ist der Treiber
geradeaus fertigstellbar — Transport, Framing, Commandsequenz und Bild-
Dekodierung (aus `capture.py`/`goodix5xx.c`) liegen bereits vor.

### Werkzeuge dieses Schritts (alle offline, im Repo)
- `/tmp`-Parser sind flüchtig; die dauerhaften liegen als `scratch/pcap_crypto.py`.
- Empfehlung: die PE-/pdata-/xref-Helfer nach `scratch/` kopieren, falls die
  RE offline fortgesetzt wird (siehe unten, werden mit angelegt).

---

## 20. Session Crypto Located + Frida Script Ready (2026-07-28)

### Wichtige Modul-Aufteilung (per objdump/Export-Analyse)
- **`GoodixMocWbdi.dll`** — Algorithmus/Templates (enrol*, identify*, template*,
  preprocess*). Enthält mbedTLS, aber die HMAC-Wrapper (`gf_hmac_sha256`) werden
  dort nur von `ProcessPsk` (PSK-Provisionierung) benutzt.
- **`GoodixMocSensorAdapter.dll`** — **Transport-Adapter, hier sitzt die
  Session-Krypto.** Enthält die mbedTLS-Cipher-Strings `AES-128-CBC` … und die
  SHA256-Init-Konstante in **8 Funktionen** (SHA256 + HMAC-Schichten).
- `GoodixMocStorageAdapter.dll` — Template-Speicherverschlüsselung (volle
  mbedTLS-Cipherliste inkl. GCM/CCM; für die Session irrelevant).

### AES ist weder tabellen- noch AES-NI-basiert
Weder AES-S-Box noch AES-NI-Instruktionen in irgendeiner DLL. mbedTLS ist also
mit laufzeit-generierten Tabellen gebaut. Der AES-Schlüssel ist damit static
nicht per Konstante auffindbar — aber er stammt ohnehin aus der HMAC-SHA256-PRF,
und **SHA256 ist auffindbar**. Deshalb zielt der Hook auf die SHA256/HMAC-Ebene.

### SHA256-/HMAC-Funktionen in GoodixMocSensorAdapter.dll (RVA, image_base 0x180000000)
```
  0x25580 (266 B)    0x26630 (198 B)    0x30bc0 (1175 B, PRF-Kandidat)
  0x324a2 (125 B)    0x326a7 (612 B, HMAC-Kandidat)   0x32a10 (237 B)
  0x34880 (296 B)    0x34a26 (180 B)
```

### Deliverable: `scratch/frida_kdf_dump.js`
Hookt diese acht Funktionen in **GoodixMocSensorAdapter.dll** und dumpt ihre
Zeiger-Argumente. Der Session-KDF ist eine Kette von HMAC-SHA256; im Trace ist
der `master_secret`-Schritt (Key = Zero-PSK-Struktur) und der `key expansion`-
Schritt (liefert AES-Key ‖ HMAC-Key) direkt erkennbar.

**Ablauf auf Windows:**
```
pip install frida-tools
frida-ps -ai                         # Prozess mit GoodixMocSensorAdapter.dll finden
                                     # (Windows Hello = Dienst WbioSrvc in svchost.exe)
frida -p <PID> -l scratch/frida_kdf_dump.js
# dann Fingerabdruck-Unlock/Enroll auslösen
```
Ausgabe: Konsole + `goodix_kdf_trace.txt`.

**Feinschliff:** Ist im Trace die mbedTLS-Einweg-HMAC erkennbar (6 Argumente:
md_info, key, keylen, in, ilen, out), ihren RVA in `HMAC_ONESHOT_RVA` eintragen —
dann werden Key/Daten/MAC sauber isoliert geloggt statt heuristisch.

### Verification
Der gedumpte AES-Key wird sofort geprüft:
```
python3 scratch/pcap_crypto.py --key <16-Byte-Hex>
```
Bei >50 % sauber entschlüsselter Nachrichten ist die KDF geknackt und der
Linux-Treiber kann die Ableitung nachbauen.

### Damit ist die Analyse abgeschlossen übergeben
Alle Componente für einen lauffähigen Treiber liegen vor und sind dokumentiert:
Transport, Framing (`MAC|01ff|len|IV|CT`), Commandsequenz (Abschnitt 16),
Statuscodes (`01`=kein Match, `04`=nicht auth, 1110 B=Token), Krypto-Suite,
Zero-PSK, Bild-Dekodierung (`capture.py`/`goodix5xx.c`) sowie die RE-Werkzeuge
(`scratch/re_tools/`, `scratch/pcap_crypto.py`) und der Frida-Extraktor. Die
einzige verbleibende Unbekannte — die genaue KDF — wird durch den Frida-Trace
auf echter Windows-Hardware in einem Lauf sichtbar.

---

## 21. Offline Methods Exhausted — Ghidra Analysis (2026-07-28)

### Was noch getestet und ausgeschlossen wurde
- **OTP als Schlüssel:** `a6 00` (READ_OTP) liefert 16 strukturierte Bytes, aber
  sie sind **kein** AES-Key (0-2/159 Padding-Treffer = Zufall). Der Wert ändert
  sich zudem zwischen Captures (Zähler `0001`→`0002`); er ist eine **Challenge**,
  die in der 1110-Byte-`a5`-Antwort zurückgespiegelt wird (das `62 00 43 04 f5 …
  c2b3231e…`-Muster in beiden).
- **Zertifikatsbasierte Schlüssel:** SHA256(cert), SHA256(pubkey), HMAC(PSK,·),
  alle EC-Punkt-Fenster und 786 gleitende 16-Byte-Fenster aus dem
  Handshake-Material — **kein Treffer**.
- **Kein Klartext-Handshake im e3-Kanal:** Vor der ersten verschlüsselten
  `e3 02 00` stehen nur `d0` (Geräte-Identität „RONGYAO/GM188…"), `d6`, `c0`
  (MCU-Config), `e1`, `a6` (OTP). Es gibt **keinen** sichtbaren Nonce-/Schlüssel-
  Austausch — die Schlüsselableitung ist rein im Treiber, nicht auf dem Draht.

Fazit: Der Session-Key lässt sich **nicht** aus den Captures rekonstruieren.
Er braucht die KDF-Funktion aus `GoodixMocSensorAdapter.dll`.

### Warum Frida hier nicht greift
Frida müsste **auf Windows** laufen, wo der Goodix-Treiber aktiv ist. Auf dem
Linux-Zielrechner läuft der Windows-Treiber nicht. Das `frida_kdf_dump.js`
bleibt gültig — aber nur, falls eine Windows-Installation/VM mit dem Sensor
verfügbar ist (die `goodix_vm_traffic.pcapng` legt nahe, dass es mal eine VM gab).

### Empfohlener Weg: Ghidra headless auf dem Linux-Rechner
Vollständig lokal, kein Windows nötig. Ghidra liegt bereits im Projekt.

```bash
# 1. JDK 17 installieren (CachyOS/Arch):
sudo pacman -S jdk17-openjdk
# 2. Dekompilierung starten:
./run_ghidra.sh
```

`run_ghidra.sh` importiert `GoodixMocSensorAdapter.dll`, lässt Ghidra
analysieren und ruft `scratch/ghidra_dump_kdf.py` auf, das die acht
SHA256-/HMAC-Funktionen (RVA 0x25580, 0x26630, **0x30bc0**, 0x324a2,
**0x326a7**, 0x32a10, 0x34880, 0x34a26) als C nach **`kdf_decompiled.c`**
schreibt. Die beiden fett markierten sind die Haupt­verdächtigen (PRF/HMAC).

Aus `kdf_decompiled.c` lässt sich die Ableitung direkt ablesen und als Python
nachbauen; `scratch/pcap_crypto.py --key <hex>` verifiziert sie sofort gegen die
Captures. Danach ist der Treiber geradeaus fertigstellbar.

### Alle heute erstellten Werkzeuge (im Repo)
| Datei | Zweck |
|---|---|
| `scratch/sdcp_replay.py` | Windows-Frames replayen, Antworten vergleichen |
| `scratch/moc_probe.py`, `win_order_probe.py` | a5-/Reihenfolge-Tests |
| `scratch/key_sweep.py`, `kdf_sweep.py` | ECDH-/KDF-Varianten am Sensor |
| `scratch/pcap_crypto.py` | **Offline-Schlüsselorakel** gegen alle Captures |
| `scratch/re_tools/` | PE-/pdata-/pcapng-Parser (objdump-basierte RE) |
| `scratch/frida_kdf_dump.js` | KDF-Live-Dump (nur Windows) |
| `run_ghidra.sh` + `scratch/ghidra_dump_kdf.py` | **KDF-Dekompilierung (Linux)** |

---

## 22. BREAKTHROUGH: Session Crypto Fully Decompiled (2026-07-28)

Ghidra headless lief auf `GoodixMocSensorAdapter.dll` (`kdf_decompiled.c`, 1007
Zeilen). Die gesamte Verschlüsselung ist damit rekonstruiert.

### Paket-Verschlüsselung: `FUN_180030bc0`
Baut exakt das beobachtete Wire-Format. Ausgabe-Layout (Offsets in param_3):
```
  +0x00  MAC (32 B, HMAC-SHA256, zuletzt berechnet)
  +0x20  01 ff            (Marker)
  +0x22  plaintext_len    (4 B LE)
  +0x26  IV (16 B)        <- NICHT zufällig: aus dem Klartext gehasht!
  +0x36  AES-128-CBC(PKCS7(plaintext))
```
Ablauf:
1. **IV** = HMAC-SHA256 über (`01ff` ‖ len ‖ plaintext ‖ 16×counter), erste 16 B.
   → deshalb die beobachtete IV-Wiederverwendung bei gleichem Klartext.
2. AES-Key + MAC-Key via KDF (siehe unten).
3. `FUN_180031600(ctx, keymat, 0x80)` = AES-128 setkey, `keymat[0:16]`.
4. PKCS7-Pad, AES-128-CBC verschlüsseln.
5. HMAC-SHA256 über (`01ff` ‖ len ‖ ciphertext) mit MAC-Key → MAC an +0x00.

### Schlüsselableitung: `FUN_1800325d0` = NIST SP 800-108 Counter-Mode-KDF
```
  Für jeden 32-B-Block i (counter startet bei 1):
    block_i = HMAC-SHA256(KI,  BE32(i) ‖ Label ‖ Context ‖ BE32(L_in_bits))
  Ausgabe = erste L Bytes der aneinandergehängten Blöcke.
```
- **KI** = 32-B-Master (aus `FUN_180034be0`, Herkunft = offene Frage, Runde 2).
- **Label**   = Bytes `6b676f6f6477697867 00` = `"kgoodwixg\0"` (10 B).
- **Context** = Bytes `6b61656c72676e6f65726c6974686d` = `"kaelrgnoerlithm"` (15 B).
  (verschleiertes „goodix" bzw. „kernel"+„algorithm"; **gehasht werden die
  Literalbytes**, nicht die entschleierte Form.)
- **L** = 0x30·8 = 384 Bit → 48 B Ausgabe: `[0:16]` = AES-Key, `[16:48]` = MAC-Key.

### `FUN_180034880` = HMAC-SHA256-Init (bestätigt: Standard-HMAC, Key>64B wird gehasht)

### Was noch fehlt: der Master-Key KI
`FUN_180034be0(local_c0)` füllt den 32-B-KI. Sein Aufrufbaum nutzt AES-setkey
(0x31600) und SHA (0x32480) — sieht nach einem **Key-Unwrap** aus (staticer
Schlüssel entpackt ein gespeichertes Blob?). Das entscheidet, ob KI
**gerätestatic** (dann offline berechenbar) oder handshake-abhängig ist.

**Runde 2 läuft:** `scratch/ghidra_dump_kdf.py` zielt jetzt auf `FUN_180034be0`
und seinen Aufrufbaum (0x34be0, 0x33960, 0x34720, 0x35790, 0x32940, 0x32280,
0x31600). Ausgabe → `kdf_master.c`.

```bash
./run_ghidra.sh      # erzeugt jetzt kdf_master.c
```

Sobald KI geklärt ist, ist die komplette Verschlüsselung in Python nachbaubar
und mit `scratch/pcap_crypto.py --key <hex>` sofort gegen die Captures
verifizierbar. Der KDF-Nachbau (Format + SP800-108) steht schon; nur die
KI-Quelle fehlt.

---

## 23. Master Key KI is an Obfuscated Constant — Extracted via Emulation (2026-07-28)

### FUN_180034be0 ist ein White-Box-Konstanten-Generator
`kdf_master.c` zeigt: `FUN_180034be0(out)` nimmt **keine** Eingabe. Es baut den
32-Byte-KI aus bit-rotierten „Goodix"-Bytes, die durch AES/HMAC/CRC mit
**hartcodierten** Schlüsseln (`DAT_18004b2f0`, `DAT_18004b340`) laufen
(`FUN_180032280` = AES-CMAC-artig, `FUN_180032940` = HMAC, `FUN_180034720` =
CRC-32, Poly 0x04C11DB7). **KI ist damit eine feste Konstante** — geräte- und
sitzungsunabhängig. Folglich sind auch AES- und MAC-Key **fix** und
entschlüsseln *alle* Captures.

Das erklärt rückblickend, warum kein Handshake-Material auf dem Draht nötig war:
die Sitzung ist von Anfang an mit einem im Treiber versteckten Konstant-Key
verschlüsselt.

### KDF verifiziert
Der Python-Nachbau der SP800-108-KDF stimmt Byte für Byte mit dem Dekompilat:
```python
label, context, L = b"kgoodwixg\x00", b"kaelrgnoerlithm", 48
block_i = HMAC_SHA256(KI, BE32(i) + label + context + BE32(L*8))
keyblock = (block_1 || block_2)[:48]
aes_key, mac_key = keyblock[:16], keyblock[16:48]
```
Sobald KI vorliegt, sind die Keys damit ohne weitere RE bestimmt.

### `scratch/emulate_ki.py` — KI per Emulation
Statt die Obfuskation nachzubauen, führt das Skript die Original-Funktionen
mit **Unicorn** aus (malloc/free gehookt, Stack-Cookie gestubbt, alle Sektionen
gemappt): `FUN_180034be0` → KI, dann `FUN_1800325d0` → 48-Byte-Keyblock. Es
vergleicht Emulator- und Python-KDF und verifiziert die Keys sofort gegen die
Captures via `pcap_crypto.py`.

```bash
# Unicorn installieren:
sudo pacman -S python-unicorn        # CachyOS/Arch
#   oder:  python3 -m pip install --user unicorn
python3 scratch/emulate_ki.py
```

Erwartete Ausgabe: `KI`, `AES-128-Key`, `HMAC-Key`, „Python-KDF stimmt überein:
True", und „*** TREFFER — die Keys entschlüsseln die echten Captures! ***".

### Danach ist der Treiber fertigstellbar
Mit den festen Keys steht die komplette Verschlüsselung:
- **Verschlüsseln** (Host→Sensor): IV = HMAC-SHA256(01ff‖len‖plaintext‖16×ctr)[:16],
  AES-128-CBC(PKCS7(plaintext)), MAC = HMAC-SHA256(01ff‖len‖CT).
- **Entschlüsseln** (Sensor→Host): AES-128-CBC-Decrypt mit IV aus dem Paket,
  MAC prüfen.
Das ersetzt den `openssl s_client`-Subprozess im C-Treiber vollständig durch
wenige Zeilen mbedTLS/Python-Krypto. Commandsequenz, Framing, Statuscodes und
Bild-Dekodierung liegen bereits vor (Abschnitte 16, 22).

---

## 24. ✅ SESSION CRYPTO FULLY BROKEN (2026-07-28)

`scratch/emulate_ki.py` hat per Unicorn-Emulation den Master-Key erzeugt, die
KDF gerechnet und die Keys gegen **alle 159** mitgeschnittenen Nachrichten
verifiziert:

```
  AES 159/159 valid padding   +   HMAC 159/159   =   Crypto 100% Correct
```

### The Keys (Fixed Constants in Driver, Device-Independent)
```
  KI      = <KI_KEY_PART1> <KI_KEY_PART2>
  AES_KEY = <AES_128_SESSION_KEY_16B_PLACEHOLDER>                       (AES-128-CBC)
  MAC_KEY = <MAC_KEY_PART1> <MAC_KEY_PART2>
```
- KI = `FUN_180034be0()` ‖ `FUN_180033960()` (zwei obfuskierte 16-B-Konstanten,
  Stack-benachbart → 32 B). Per Emulation gewonnen, nicht geraten.
- `AES_KEY, MAC_KEY = SP800-108-KDF(KI, "kgoodwixg\0", "kaelrgnoerlithm", 384bit)`.

### Verified Wire Format (Inner e3 Payload)
```
  MAC(32) || 01 ff || plaintext_len(LE32) || IV(16) || AES-128-CBC(PKCS7(plaintext))
  MAC = HMAC-SHA256(MAC_KEY, 01ff || plaintext_len(LE32) || ciphertext)   [159/159]
  IV  = SHA256(01ff||len||plaintext||16×BE32(3))[:16]  beim Senden;
        Empfänger nutzt den Paket-IV (IV ist nicht im MAC → beliebiger IV zulässig)
```

### New Reference Module: `scratch/goodix_crypto.py`
Fertige `encrypt()` / `decrypt()` / `derive_keys()` mit den festen Keys.
Selbsttest grün (KDF reproduziert die Keys, Round-trip passt). Das ersetzt den
kompletten `openssl s_client`-Subprozess im C-Treiber durch ~20 Zeilen.

### Readable MoC Protocol (Previously the Cryptographic Wall) (bisheriger „Cryptographic Wall")
Die entschlüsselte Unlock-Sitzung zeigt eine **zweite, innere Schicht**:
- Sensor→Host `e3 00 00` (1366 B) → entschlüsselt zu `71040000 3082034b…` =
  Handshake-Flight mit dem **Zertifikat** (byte-genau `sensor_cert.der`).
- Host `e3 02/00` (162 B) → innerer **ECDH-Handshake** (Microsoft SDCP).
- Host `e3 02/01` (32 B) → SDCP-Identity/MAC-Token.

Die äußere Transportschicht ist damit erledigt; die innere SDCP-Schicht ist
jetzt **im Klartext lesbar** und kann Schritt für Schritt nachgebaut werden —
das war laut `walkthrough.md` Abschnitt 6 der eigentliche Endgegner.

### Status for Driver Implementation
| Component | Status |
|---|---|
| USB Transport, Packet Framing, CRCs | ✅ (C-Treiber + Python) |
| Commandsequenz, Statuscodes | ✅ (Abschnitt 16) |
| **Session Encryption** | ✅ **Resolved** (`goodix_crypto.py`) |
| Inner SDCP Layer (ECDH/Token) | ⏳ Decrypted, Host Bind implemented |
| Image/Template Decoding | teils (5xx-Code + `capture.py`) |

Nächster Schritt: die entschlüsselte SDCP-Sequenz aus den pcaps vollständig
kartieren (Client/Server-ECDH, Identity, Enroll/Verify-Token) und im Treiber
nachbilden. Der schwierigste Teil — der undurchsichtige Transport — ist Resolved.

---

# 25. OVERALL SUMMARY & FILE INDEX (Stand 2026-07-28)

This section serves as the primary reference. Er fasst den kompletten Weg und den
aktuellen Stand zusammen; die Abschnitte 10–24 enthalten die Details in
chronologischer Reihenfolge.

## 25.1 What Was Achieved (Executive Summary)
1. **C-Treiber-Transportfehler behoben** (Abschnitt 10): Puffer-Resync,
   CRC8-Header-Validierung, 64-Byte-Padding, `data_to_str`-Uninitialisiert-Bug,
   Commandverkettung `36`→`a2`, Post-TLS-SSM (`a5`/`08`), MoC-Finger-Down-Pfad.
2. **TLS-Irrweg widerlegt** (Abschnitte 11–17): Der Sensor spricht KEIN TLS auf
   dem Draht; der `openssl s_client`-Proxy war konzeptionell falsch. Der Python-
   PoC prüfte den Handshake nie und meldete blind Erfolg.
3. **Protokoll kartiert** (Abschnitte 12–16): vollständige Windows-Unlock-
   Sequenz, Wire-Framing, Statuscodes (`01`=kein Match, `04`=nicht auth,
   1110 B = Auth-Token).
4. **Krypto-Bibliothek identifiziert** (Abschnitt 17): mbedTLS,
   `TLS-PSK-WITH-AES-128-CBC-SHA256`, in `GoodixMocSensorAdapter.dll`.
5. **Session-Krypto vollständig gebrochen** (Abschnitte 22–24): per Ghidra
   dekompiliert, KDF rekonstruiert (SP800-108/HMAC-SHA256), Master-Key per
   Unicorn-Emulation extrahiert, gegen **159/159** Nachrichten verifiziert.

## 25.2 Die Resolveden Schlüssel (feste Konstanten, geräteunabhängig)
```
  AES_KEY = <AES_128_SESSION_KEY_16B_PLACEHOLDER>
  MAC_KEY = <HMAC_SHA256_SESSION_KEY_32B_PLACEHOLDER>
  KI      = <KDF_MASTER_KEY_32B_PLACEHOLDER>
```
Wire-Format (innerer e3-Payload):
`MAC(32) ‖ 01ff ‖ len(LE32) ‖ IV(16) ‖ AES-128-CBC(PKCS7(pt))`,
`MAC = HMAC-SHA256(MAC_KEY, 01ff ‖ len ‖ CT)`.

## 25.3 File Index (Repository Structure)
| Datei | Zweck | Läuft wo |
|---|---|---|
| `scratch/goodix_crypto.py` | **Referenz-Krypto**: encrypt/decrypt/KDF, feste Keys | überall |
| `scratch/emulate_ki.py` | Master-Key per Unicorn-Emulation der DLL gewinnen | Linux, `python-unicorn` |
| `scratch/pcap_crypto.py` | Offline-Schlüsselorakel gegen die Captures | überall |
| `scratch/sdcp_replay.py` | Windows-Frames replayen/vergleichen | Sensor-Hardware |
| `scratch/moc_probe.py`, `win_order_probe.py` | a5-/Reihenfolge-Tests | Sensor-Hardware |
| `scratch/key_sweep.py`, `kdf_sweep.py` | (historisch) KDF-Varianten am Sensor | Sensor-Hardware |
| `scratch/frida_kdf_dump.js` | (Alternativweg) KDF live dumpen | Windows + Frida |
| `scratch/re_tools/` | PE-/pdata-/pcapng-Parser (objdump-basierte RE) | überall |
| `run_ghidra.sh` + `scratch/ghidra_dump_kdf.py` | DLL-Funktionen dekompilieren | Linux + JDK17 |
| `kdf_decompiled.c`, `kdf_master.c` | Dekompilate der Krypto-/KDF-Funktionen | — |
| `run_enroll_test.sh` | C-Treiber bauen + gegen Sensor testen | Sensor-Hardware |
| `HANDOVER_COWORK.md` | **dieses Dokument** | — |

Nicht im Git (siehe `.gitignore`): `ghidra_11.0.3_PUBLIC/`, `jdk/`,
`ghidra_headless_proj/`, `*.pcapng`, `*.bin`, `*.log`, Emulations-Ausgaben.

## 25.4 Reproduction of Cryptographic Break (Linux)
```bash
sudo pacman -S jdk17-openjdk python-unicorn      # Voraussetzungen
./run_ghidra.sh                                  # dekompiliert -> kdf_master.c
python3 scratch/emulate_ki.py                    # KI -> Keys -> 159/159 Treffer
python3 scratch/goodix_crypto.py                 # Selbsttest der Referenz-Krypto
```

## 25.5 Steps to Production Driver
1. **Innere SDCP-Schicht kartieren:** Die äußere Verschlüsselung ist Resolved, die
   MoC-Commands sind jetzt entschlüsselbar. Aus den pcaps die Klartext-Sequenz
   von ECDH-Handshake, Identity und Enroll/Verify-Token extrahieren.
2. **Treiber-Krypto ersetzen:** Den `openssl s_client`-Subprozess im C-Treiber
   (bzw. den Python-Ansatz) durch `goodix_crypto.py`-Logik ersetzen (AES-128-CBC
   + HMAC-SHA256 mit den festen Keys).
3. **Enroll/Verify implementieren:** Die nun lesbare SDCP-Sequenz nachbilden;
   MoC liefert Auth-Token (1110 B) statt Rohbild — für libfprint-Integration
   klären, ob ein Match-Result genügt.
4. **Bild-/Template-Pfad:** Für Bilddaten `capture.py` (55a2) und `goodix5xx.c`
   als Referenz; Sensor ist Match-on-Chip, echtes Rohbild verlässt den Chip evtl.
   nie.

**Der schwierigste, jahrelang blockierende Teil — die undurchsichtige
Session Encryption — ist ab jetzt vollständig Resolved und reproduzierbar.**

---

# 26. Decrypted Protocol & Driver Architecture (2026-07-28)

Mit den festen Session-Keys ist der gesamte Windows-Verkehr im Klartext lesbar.
Werkzeug: `scratch/decode_protocol.py <capture.pcapng>`. Resultse als
`protocol_unlock.txt` und `protocol_enroll.txt` im Repo.

## 26.1 Key Architectural Findings
- **No transport handshake required:** Der erste verschlüsselte `e3`
  kommt direkt nach `e1 04 00`; der Sensor akzeptiert die festen Keys sofort.
  → Der Linux-Treiber kann von Anfang an verschlüsselt sprechen.
- **Two Layers:** Außen die geknackte AES/HMAC-Transportkrypto; innen ein
  **SDCP-Handshake** (Microsoft Secure Device Connection Protocol).
- **Innerer SDCP-ClientHello** (162 B, entschlüsselt):
  `nonce(32) ‖ EC-Punkt(65, 0x04…) ‖ EC-Punkt(65, 0x04…)` — ephemerer
  ECDH-Public-Key des Hosts, wechselt pro Sitzung.
- **SDCP-ServerHello** (1366 B): `71 04 00 00 ‖ Zertifikat(847=sensor_cert.der)
  ‖ Server-EC-Punkt ‖ Signatur`.
- **SDCP-Identity** (32 B → 33 B Antwort): HMAC-Token über den Transcript.

## 26.2 Enroll Flow (aus goodix_handshake_and_enroll, entschlüsselt)
```
  Transport-Krypto hoch (e3-Handshake, feste Keys)
  a7 02 00  (102 B, OTP/Config: enthält den READ_OTP-Wert)
  a5 00 00  (32 B SDCP-Key) -> 1110 B Token   [oder 0x01 bei Fehlschlag]
  a5 01 00  (01000000)      -> 00
  a1 00 00  (Enroll begin)  -> 33 B Token
  Schleife pro Finger-Sample (13x):
     a0 00 00  Payload 01 64 64   ->  00 <fortschritt> <qualität>
        (Antwort z.B. 00 32 xx, 00 61 xx … = Enroll-Fortschritt/Coverage)
  a3 00 00 / a4 00 00  (Enroll commit/finalize)
```
`a0 00 00` ist damit das **Enroll-Sample-Command mit Fortschritts-Feedback** —
genau das, was libfprint für die Enroll-Stufen braucht. `a0/a1/a3/a4` sind
Klartext-Protokollkommandos (nicht verschlüsselt).

## 26.3 Verify Flow (aus goodix_unlock_success)
Pro Scan-Zyklus: `e3`-SDCP-Handshake → `b0 02` (Kalibrier-/Sensorwerte, 65 B)
→ `a2 00 00 01002301` (Finger-Region `5c 64 …`) → `a5 00 00` (32 B) → 1110 B
Token bei Match bzw. `01` bei kein-Match → `e3 01` SDCP-Identity.
Statuscodes bestätigt: `a5`-Antwort **1110 B = Match/Token**, **`01` = kein Match**.

## 26.4 Driver Infrastructure: `scratch/goodix_gf3268.py`
Vollständiger USB-Transport (Bulk, Goodix-Framing mit CRC8/CRC32/64-B-Padding,
Framing gegen echte Pakete verifiziert 12/12) + integrierte Session-Krypto.
Bietet `send()/recv()` (Klartext-Commands) und `send_enc()/recv_enc()`
(verschlüsselter e3-Kanal). Enthält `verify_crypto_live()`: sendet einen
inneren e3 und entschlüsselt die Sensor-Antwort — **End-to-End-Beweis auf der
Hardware**.

```bash
sudo python3 scratch/goodix_gf3268.py
```
Erwartung: „*** ERFOLG: Sensor-Zertifikat live entschlüsselt … ***" — dann ist
die komplette Kette (USB → Framing → Krypto) auf dem Gerät bestätigt.

## 26.5 Status & Remaining Work
**Gelöst und nutzbar:** USB-Transport, Framing, Session Encryption,
Command-Landkarte, Enroll-/Verify-Commands identifiziert.

**Noch offen für vollen Enroll/Verify:** die innere SDCP-Schicht. Zwei Wege:
1. **SDCP umgehen (bevorzugt):** Prüfen, ob der Sensor `a1`/`a0`-Enroll und
   `a5`-Verify auch mit einem *Dummy*- oder *ohne* vollständigen SDCP-Handshake
   ausführt. Das ist jetzt mit `goodix_gf3268.py` direkt an der Hardware
   testbar. Wenn ja, ist ein libfprint-Treiber ohne Krypto-Attestierung möglich.
2. **SDCP nachbauen:** ephemeres ECDH (P-256) + die SDCP-KDF (weitere kleine
   RE-Aufgabe in `GoodixMocSensorAdapter.dll`, analog zur schon Resolveden
   Transport-KDF) + Identity-Token. Nötig nur, falls der Sensor SDCP erzwingt.

Der jahrelange Hauptblocker — die undurchsichtige Transportverschlüsselung — ist
Resolved. Enroll/Verify ist jetzt ein klar umrissenes, an der Hardware testbares
Problem statt einer Blackbox.

---

# 27. ✅ HARDWARE-BESTÄTIGUNG: Transport+Krypto laufen end-to-end (2026-07-29)

`sudo python3 scratch/goodix_gf3268.py` auf dem echten GF3268:
```
  Interface 0 beansprucht. Sensor bereit.
  --- Init-Sequenz ---   e1 04 -> 00000000
  --- Krypto-Kanal live verifizieren ---
     e3 02 -> Status/Len: 004f030000
     e3 00 -> 1366 B entschlüsselt: 710400003082034b308202f1a0030201…
  *** ERFOLG: Sensor-Zertifikat live entschlüsselt ***
```
Damit ist die komplette Kette **auf der Hardware** bewiesen: USB-Bulk →
Goodix-Framing (CRC8/CRC32/64B-Padding) → Session Encryption (feste Keys)
→ Entschlüsselung der 1366-B-Sensorantwort (Zertifikats-Flight). Der Sensor
akzeptiert die festen Keys ohne jeden Handshake.

Behobene Startfehler: fehlende ctypes-`argtypes` (64-Bit-Zeiger-Kürzung) und ein
`log()`-Aufruf. `goodix_gf3268.py` läuft jetzt sauber.

## 27.1 Live Fingerprint Oracle Tests
```bash
sudo systemctl stop fprintd        # Interface freigeben
sudo python3 scratch/goodix_gf3268.py finger
```
Der `finger`-Modus pollt 20 s lang `a2 00 00` (Wait-Finger) und `b0 02`
(Kalibrier-/Sensorwerte) und zeigt Änderungen an. Beim Auflegen/Abheben des
Fingers sollten sich die Werte sichtbar ändern → Beleg, dass wir Fingerpräsenz
und Sensorwerte live lesen können (Grundlage für Verify).

## 27.2 Roadmap to Complete Enroll/Verify
1. **Finger-Probe** (oben): bestätigen, dass a2/b0 auf Fingerkontakt reagieren.
2. **Verify ohne SDCP testen:** `a5 00 00` mit 32-B-Wert senden, prüfen ob der
   Sensor 1110 B (Match) / 0x01 (kein Match) liefert — auch ohne gültige
   innere SDCP-Sitzung. Falls ja: Verify gegen Windows-Templates möglich.
3. **Falls SDCP erzwungen:** die innere SDCP-KDF in GoodixMocSensorAdapter.dll
   reversen (gleiche Methode wie bei der schon Resolveden Transport-KDF:
   Ghidra-Dekompilat + ggf. Unicorn-Emulation) und ECDH P-256 + Identity-Token
   nachbauen.
4. **Enroll:** `a1 00 00` (begin) → `a0 00 00` (Sample, Fortschritts-Feedback)
   ×N → `a3/a4` (commit); Template on-chip.
5. **libfprint-Integration:** die bewährte Commandfolge + `goodix_crypto` in
   den C-Treiber übernehmen (ersetzt den openssl-Subprozess vollständig).

---

# 28. ✅✅ VERIFY FUNKTIONIERT AUF HARDWARE — OHNE SDCP (2026-07-29)

`sudo python3 scratch/goodix_gf3268.py verify` mit enrolltem Finger:
```
   a2=005a64001f003800  a5-> 1110 B  *** MATCH-TOKEN! ***
        005a64470000000062004304f500cd00cc0fe95f7fcf760503889a36c8e6…
```

**Der Sensor macht den Match-on-Chip und liefert das 1110-B-Token — ganz ohne
gültige innere SDCP-Sitzung.** Nötig war nur: Transportkrypto (feste Keys) +
Vorsequenz (`b0 02`, `e0 01`, `a2 00 00`) + `a5 00 00` mit 32-B-Zufalls-Challenge.

### Das ist der Durchbruch für einen lauffähigen Verify-Treiber
- `a5 00 00` Antwort **1110 B = Match**, **0x01 = kein Match** (verifiziert).
- Kein ECDH, kein SDCP-Identity-Token, keine Attestierung nötig.

### Struktur des Match-Tokens (1110 B, aus 10 Captures analysiert)
```
  [  0]      Status 00
  [1:3]      Finger-Region (z.B. 5a64, = a2-Region)
  [3]        Zähler
  [4:112]    108 B  STATISCH über Matches  -> Template-/Geräte-Identität
                    (enthält 62004304f5 = OTP). Unterscheidet die enrollten
                    Finger -> Grundlage für IDENTIFY.
  [112:144]  32 B   wechselt  -> Match-Nonce
  [144:150]  6 B    static
  [150:1110] 960 B  wechselt  -> SDCP-Signatur/Attestierung (für Linux irrelevant)
```
Für libfprint genügt: 1110 B = Match, `[4:112]` identifiziert den Finger.

### Damit ist der Stand
| Funktion | Status |
|---|---|
| USB-Transport + Framing | ✅ Hardware |
| Session Encryption | ✅ Hardware |
| Fingererkennung (a2/b0) | ✅ Hardware |
| **Verify / Match-on-Chip** | ✅ **Hardware, ohne SDCP** |
| Enroll (a1/a0/a3/a4) | ⏳ als Nächstes testen |
| libfprint-Integration | offen (Commandfolge steht) |

Nur noch Enroll fehlt für einen vollständigen Treiber — und die Enroll-Commands
(`a1` begin, `a0` sample mit Fortschritt, `a3/a4` commit) sind bereits
identifiziert und werden als Nächstes an der Hardware getestet.

---

# 29. Verify rigoros bestätigt (Positiv- + Negativtest, 2026-07-29)

Kontrolltest auf echter Hardware:
- **Enrollter Finger** → `a5 -> 1110 B  *** MATCH-TOKEN ***`
- **Nicht-enrollter Finger** → durchgehend `a5 -> 01 (kein Match)`

Damit ist zweifelsfrei belegt: der Sensor führt einen **echten Match-on-Chip**
aus, und `01` vs `1110 B` ist das reale Result (nicht bloß Fingerpräsenz).
**Verify ist damit vollständig und wissenschaftlich sauber verifiziert.**

Robustheitsfix: `Device._drain()` verwirft beim Start liegengebliebene IN-Pakete
einer Vorsession — behebt das „erster Lauf hakt"-Verhalten.

## 29.1 Nächster Schritt: Enroll (Trockenlauf)
```bash
sudo systemctl stop fprintd
sudo python3 scratch/goodix_gf3268.py enroll
```
Der `enroll`-Modus macht Setup (`a6` OTP → `a7` → `a1` begin) und die
`a0`-Sample-Schleife mit Fortschritts-Anzeige — **ohne `a4`-Commit**, es wird
also **kein Template gespeichert** und der Sensor bleibt unverändert. Finger
wiederholt leicht versetzt auflegen. Steigt `Byte1` der `a0`-Antwort Richtung
`0x64` (100 %), läuft Enroll ohne SDCP und wir ergänzen den Commit (`a3`/`a4`)
für echtes Speichern.

---

# 30. Enroll-Befund: braucht gültiges SDCP; Verify nicht (2026-07-29)

Hardware-Tests des `enroll`-Trockenlaufs (mehrere Durchläufe):
- `a1 00` (begin) liefert stets `00…` (33 B) = **Erfolg**.
- Frame-Erfassung läuft: `a2 00 00 000f4101` liefert wechselnde Finger-Regionen
  (`585a`, `5d5e`, `565b`, `4d56`, `5350` …) — das Sampling funktioniert.
- **`a0 00 00` gibt aber durchweg `000000`** = Frame akzeptiert, **aber nicht
  angerechnet**. Auch **mit** vorangestelltem `e3 01`-Identity-Schritt (Dummy-32 B)
  bleibt der Fortschritt bei 0.

**Schlussfolgerung:** Enroll rechnet ein Sample nur an, wenn die `e3 01`-SDCP-
Identity **inhaltlich gültig** ist (nicht nur transportiert). Eine Zufalls-
Identity genügt nicht. Verify dagegen liefert das Match-Token unabhängig von der
SDCP-Identity — deshalb funktioniert Verify vollständig, Enroll (noch) nicht.

## 30.1 Status Table
| Funktion | Ohne SDCP | Status |
|---|---|---|
| Transport/Krypto/Framing | — | ✅ Hardware |
| Fingererkennung (a2/b0) | ✅ | ✅ Hardware |
| **Verify / Match-on-Chip** | ✅ **ja** | ✅ **funktioniert (Match vs. 01)** |
| **Enroll (a0 Anrechnung)** | ❌ **nein** | ⏳ braucht gültige SDCP-Identity |

## 30.2 Two Enrollment Paths
1. **SDCP nachbauen (der saubere Weg):** die innere Schicht in
   GoodixMocSensorAdapter.dll reversen — ECDH P-256 (ClientHello:
   nonce(32)+EC(65)+EC(65)) + die SDCP-Schlüssel-/Identity-KDF. Methodik ist
   identisch zur bereits Resolveden Transport-KDF: Ghidra-Dekompilat der SDCP-
   Funktionen + ggf. Unicorn-Emulation, dann Identity-Token pro Sample berechnen.
   Danach ist Enroll vollständig.
2. **Pragmatisch (sofort nutzbar):** In Windows enrollen, unter Linux nur
   verifizieren. Da Verify gegen die vorhandenen Templates funktioniert, ist ein
   Unlock-Only-Betrieb (Dual-Boot) bereits jetzt möglich.

Robustheit: `_bulk_out` setzt bei Stall den Endpunkt zurück und wiederholt; die
Sample-Schleife fängt USB-Stalls ab und läuft weiter (die `-1/-4`-Abbrüche der
ersten Läufe treten dadurch nicht mehr auf).

## 30.3 Next Concrete Step (falls Enroll gewünscht)
SDCP-Funktionen in `GoodixMocSensorAdapter.dll` lokalisieren und dekompilieren
(gleiche Werkzeuge: `run_ghidra.sh`, `scratch/re_tools/`, `scratch/emulate_ki.py`).
Einstieg: die e3-01-Identity-Erzeugung und die ECDH-Verarbeitung des
ServerHello (Zertifikat + Server-EC-Punkt) im Binär rückverfolgen.

---

# 31. SDCP-Schlüsselschema vollständig dekompiliert (2026-07-29)

Sechs Ghidra-Runden auf GoodixMocSensorAdapter.dll haben die komplette
Host-Seite der SDCP-Schicht offengelegt (Quellpfad im Binär:
`…\GoodixSdcp\GoodixSdcpCmd.cpp`). Die Krypto folgt dem Microsoft-SDCP-Schema.

## 31.1 Function Address Map (RVA in GoodixMocSensorAdapter.dll) (RVA in GoodixMocSensorAdapter.dll)
```
  0x7050   GoodixSdcpConnectSecure   Haupt-Connect
  0xf020   host generate connect params  -> ClientHello (nonce + EC + EC)
  0x12040  sdcpcli_keygen            ephemeres P-256-Keypair (pub 65B @+0, priv 32B @+0x41)
  0x113e0  sdcpcli_gen_rand          DRBG (Personalisierung "sdcpcli_gen_rand")
  0x10320  parse_connect_data        ServerHello parsen + ECDH + Keys + MAC-Check
  0x10c30    +-> ECDH-Keymaterial    (server_pub, client_priv, nonces)
  0x10ef0    |     FUN: ECDH-Punktmult (P-256)
  0x10bd0    +-> Session-Keys        (application keys)
  0x11de0  KDF-PRIMITIVE             SP800-108 Counter-Mode HMAC-SHA256
  0x124b0  HMAC-SHA256 (mit Label)   Identity/MAC
  0x10a90  AES (SDCP-Datenkanal)     key @0x571d0
```

## 31.2 Key Derivation Scheme (Labels sind die Literalbytes)
```
  Z            = ECDH_P256(client_priv, server_pub)              (32 B)
  master_mat   = KDF(Z,          "master secret",  nonce_c‖nonce_s, 32 B)
  session_keys = KDF(master_mat, "application keys", (leer),         64 B)
                 -> AES-Key(32) ‖ MAC-Key(32)  (genaue Aufteilung noch zu pruefen)
  identity/MAC = HMAC-SHA256(session_key, "connect"|"reconnect" ‖ transcript)
```
Labels (RVA): `master secret`@0x48b78, `application keys`@0x48b88,
`connect`@0x48ba0, `connect2`@0x48ba8, `reconnect`@0x48bb8, `cert_m: `@0x48bc8.

## 31.3 KDF Primitives (SP 800-108) `FUN_180011de0` = SP800-108, wie die Transport-KDF
Signatur `kdf(key, keylen, label, data, datalen, out, outlen)`. Struktur
identisch zur bereits verifizierten Transport-KDF (`FUN_1800325d0`):
pro 32-B-Block `HMAC-SHA256(key, BE32(counter) ‖ label ‖ … ‖ data ‖ BE32(outlen·8))`.
Die exakte Feldreihenfolge (Trenner `0x00`, Position von counter/bitlen) muss
noch am Draht bestaetigt werden, da sie offline nicht pruefbar ist (der
ephemere Client-Privkey der Windows-Captures fehlt).

## 31.4 Wichtige Einschraenkung fuer die Verification
Anders als bei Transport-KDF und Master-Key laesst sich die SDCP-KDF **nicht
offline gegen die Captures pruefen**: dort fehlt der ephemere Client-Private-Key
(er wurde pro Windows-Sitzung neu erzeugt und nie uebertragen). Verification
geht daher nur auf der Hardware: eigenen Handshake fahren und pruefen, ob der
Sensor unsere Identity akzeptiert (Enroll-Frames werden angerechnet, `a0` > 0).
Deshalb sind fuer die exakte Feldreihenfolge 1–2 Hardware-Iterationen realistisch.

---

# 32. Alltags-Entsperren via PAM (Verify-only) — 2026-07-29

Da Verify auf der Hardware funktioniert (Abs. 28/29), ist ein im Alltag
nutzbares Fingerabdruck-Entsperren möglich, OHNE Linux-Enroll und ohne die
große libfprint-C-Integration — über PAM (`pam_exec`), das gegen die bereits
im Chip liegenden (Windows-)Templates matcht.

## Dateien
- `scratch/goodix_verify.py` — Standalone-Verify. Fährt den Transportkanal hoch,
  wartet auf Finger, `a5`-Match. Exit: **0=Match, 1=kein Match, 2=Timeout,
  3=Fehler**. `--quiet` für PAM. CRC8/Transport gegen echte Pakete verifiziert.
- `install_fingerprint_unlock.sh` — Installer: kopiert nach `/opt/goodix-fp`,
  legt `/usr/local/bin/goodix-fp-verify` an, schreibt udev-Regel, Selbsttest,
  optional PAM-Aktivierung.

## Installation
```bash
sudo ./install_fingerprint_unlock.sh          # installieren + testen
sudo ./install_fingerprint_unlock.sh --sudo   # Fingerabdruck für 'sudo' aktivieren
sudo ./install_fingerprint_unlock.sh --remove # alles rückgängig
```
Der Fingerabdruck wird als **`sufficient`** eingetragen: das Passwort
funktioniert immer weiter, nichts wird ersetzt.

## Security & Limitations (Honest Assessment)
- **Passwort-Fallback bleibt immer aktiv** — kein Lockout-Risiko.
- `pam_exec` ist **sequentiell**: `sudo` wartet bis zu `TIMEOUT_S` (6 s) auf
  einen Finger, bevor es zum Passwort durchfällt. Finger zügig auflegen, sonst
  kurz warten und Passwort tippen.
- Kein Prompt im Sperrbildschirm: `pam_exec` kann nicht sauber „Finger auflegen"
  anzeigen. Für Terminal/`sudo`/Konsolen-Login ist das ok.
- **Grafische Sperrbildschirme (GDM/SDDM/KDE)** brauchen einen Eintrag in deren
  PAM-Stack (z.B. `/etc/pam.d/system-auth` oder der Greeter). Das automatische
  Editieren ist riskant (Aussperr-Gefahr) und daher NICHT im Installer — bei
  Bedarf manuell und mit offener Root-Shell als Absicherung.
- Dies ist **keine** SDCP-Attestierung wie unter Windows Hello. Der Sensor
  matcht real on-chip, aber die PAM-Ebene hat keine Anti-Replay-Absicherung auf
  Protokollebene. Für einen persönlichen Laptop eine pragmatische Lösung; für
  Hochsicherheitsanforderungen wäre die volle libfprint/SDCP-Integration nötig.

## Prerequisites
`python-cryptography`, `libusb`. fprintd darf den Sensor nicht belegen
(Installer stoppt es für den Test; bei Dauerbetrieb ggf. `systemctl disable
fprintd`, falls es stört).

---

# 33. SDCP-Enroll: Live-Handshake gefangen, KDF noch nicht geknackt (2026-07-29)

## Progress
- **`scratch/sdcp_capture.py`** fährt einen echten SDCP-Handshake mit SELBST
  erzeugten Schlüsseln und speichert alles nach `scratch/sdcp_capture.json`.
  Auf der Hardware bestätigt: der Sensor akzeptiert unseren ClientHello
  (`nonce(32)+EC1(65)+EC2(65)`) und antwortet mit vollem ServerHello (1366 B).
  Damit haben wir eine Live-Sitzung mit **bekanntem** Client-Private-Key.
- ServerHello-Struktur (nach dem 847-B-Zertifikat, 515 B):
  ```
    +0    EC static (65 B)   0437fb51…  = Geraete-Attestierungsschluessel (== Windows)
    +65   EC server-eph(65)  04e9c7bd…  = Server-Ephemeral (pro Sitzung)
    +130  96 B  STATISCH
    +226  64 B  SITZUNG   (Nonce? MAC?)
    +291  104 B SITZUNG   (weitere EC-Punkte @+290,+406)
    +396  119 B SITZUNG   (Signatur)
  ```

## What Did NOT Work
Breiter Offline-Angriff (75600 Kombinationen: 4 ECDH-Kandidaten × 5 SP800-108-
Feldordnungen × ~20 nonce_s-Fenster × 2 Kontext-Ordnungen × 3 Keys × 10
Transcripts, plus HKDF-Varianten): **0 Treffer**. Der Server-MAC ist also nicht
`HMAC(abgeleiteter_key, simpler_transcript)` — der MAC signiert einen **komplexen
Transcript-Hash**, der in `FUN_180011870` berechnet wird (Eingang: Zertifikat +
beide EC-Punkte + Nonces). Diese Funktion ist noch nicht dekompiliert.

## Ehrliche Analysis & Classification
Anders als Transport-KDF und Master-Key (die sich nach dem Dekompilieren zügig
offline verifizieren ließen) ist SDCP mehrstufig verzahnt: Transcript-Hash →
KDF → MAC, plus die Wire→Struktur-Parsung. Zum Knacken fehlen noch:
1. `FUN_180011870` — der genaue Transcript-Hash (nächster Dekompilier-Schritt).
2. Bestätigung der KDF-Feldreihenfolge (`FUN_180011de0`) an echten Werten.
3. Die exakte Wire-Position von server_nonce/server_MAC (Parse-Funktion).

Das ist machbar, aber realistisch mehrere weitere Dekompilier-Runden. Nächster
Schritt: `./run_ghidra.sh` (Ziel jetzt `FUN_180011870`) → `sdcp6.c`.

---

# 34. SDCP-Transcript geklärt, aber Framing-Diskrepanz blockiert Offline-Crack (2026-07-29)

## Neue Erkenntnisse (sdcp6.c)
- **`FUN_180011870` = SHA256** (md-Typ 6, init + 7 Updates + finish) über die
  Server-Handshake-Felder. Der Server-MAC ist damit:
  `server_MAC = HMAC-SHA256(session_key, SHA256(cert ‖ EC-Punkte ‖ nonce ‖ Blöcke))`.
- Verifications-Flow in `FUN_180010320`: ECDH → master-KDF ("master secret") →
  app-KDF ("application keys") → SHA256-Transcript → `HMAC(session_key, transcript)`
  == server_MAC (Vergleich per memcmp).
- `FUN_1800127a0` prüft die **Zertifikatskette** ("cert_m: ", "Client Certs: ")
  gegen zwei eingebettete Root-Zertifikate (`DAT_180055b30`, `DAT_180054f80`).

## Warum der Offline-Crack (noch) scheitert — die Kernursache
Der DLL-SDCP-Code liest MAC/Nonce/Cert aus einer Struktur mit Offsets
`+0x14`/`+0x34`/`+0x54` — das ist die **IOCTL-Rahmung** zwischen DLL und
Kerneltreiber. Unser entschlüsseltes **e3-ServerHello** hat aber eine ANDERE
Rahmung (Header `71040000`, Zertifikat bei `+4`). Beide tragen denselben
SDCP-Inhalt, aber an unterschiedlichen Positionen. Ohne die genaue
Wire↔IOCTL-Abbildung rate ich gegen die falschen Byte-Offsets → alle
Brute-Force-Läufe (78000+ Kombinationen) treffen nicht.

## Ehrliche Lage & realistische Optionen
SDCP-Enroll ist damit die mit Abstand zäheste Ebene: mehrstufig (ECDH → 2× KDF →
SHA256 → HMAC), mit Zertifikatsketten-Prüfung und zwei verschiedenen Rahmungen.
Anders als alle bisherigen Schichten lässt es sich **nicht** durch
Offline-Brute-Force gegen die Captures knacken.

Drei mögliche Wege:
1. **Emulation (aussichtsreichster Weg):** `FUN_18000f020` (ClientHello+Keygen)
   und `FUN_180010320` (ServerHello→Session-Key) mit Unicorn ausführen — DRBG
   auf bekannte Werte gehookt. Dann liefert die Emulation den Session-Key direkt
   aus UNSEREM Live-ServerHello, ohne Raten. Die vtable-/mbedtls-Aufrufe laufen
   im Emulator (Code ist gemappt). Aufwändiger Aufbau, aber umgeht die
   Framing-Frage komplett. **Empfohlen.**
2. **Weiter dekompilieren:** die IOCTL-/Parse-Schicht (`FUN_180007da0` &
   Umfeld) reversen, um Wire↔Struktur zu mappen. Mehrere Runden, unsicher.
3. **Konsolidieren:** Verify-Unlock läuft (Alltagsziel erreicht). SDCP-Enroll
   als offenes Forschungsthema zurückstellen.

Der praktische Alltagsnutzen (Fingerabdruck-Entsperren) ist unabhängig davon
bereits erreicht und einsatzbereit.

---

# 35. DURCHBRUCH: komplette SDCP-Kette per Disassembly rekonstruiert (2026-07-29)

Statt Ghidra/Emulation (Sandbox kann beides nicht) wurde die DLL mit **objdump**
disassembliert und die gesamte SDCP-Kryptokette von Hand aus dem Maschinencode
rekonstruiert. Alle Werte sind damit binär-belegt, nicht geraten.

## KDF (FUN_180011de0) — exakt NIST SP800-108 Counter Mode
    K(i) = HMAC-SHA256(key, BE32(i) || label||0x00 || context || BE32(outlen*8))
- Counter i 1-basiert, 4B big-endian
- Label wird INKLUSIVE Nullterminator gehasht ("master secret\0")
- L = outlen in BITS, 4B big-endian
- output = K(1)||K(2)||… truncate outlen
=> bestätigt exakt die bisherige sp800_108-Formel.

## Session-Key-Ableitung (FUN_180010320 / _c30 / _bd0)
    Z        = ECDH(client_priv, EC_B)              # EC_B = Server-Ephemeral
    master   = KDF(Z,      "master secret\0",   nonce_c || nonce_s, 32)
    session  = KDF(master, "application keys\0", <leer>,            64)  # 2×32B
- nonce_c = unsere Client-Nonce (global 0x57188)
- nonce_s = Server-Nonce (struct+0x34)
- ECDH-Punkt ist EC_B (arg1 = [rbp-0x50] = zweiter EC-Punkt nach Zertifikat)

## Transcript (FUN_180011870) = SHA256
    transcript = SHA256(cert || EC_A(65) || EC_B(65) || 32B@130 || 64B@162 || 64B@226)
- alle Felder aus dem ServerHello-Tail (nach dem Zertifikat)

## MAC-Verification (FUN_1800121d0 + memcmp)
    server_MAC (struct+0x14) == HMAC-SHA256(session_key, transcript)

## ClientHello (FUN_18000f020) — 105 Bytes, EXAKT rekonstruiert
    [len u32=0x69] [ver u16=1] [type u16] [nonce_c 32B] [ephemeral_pubkey 65B]
- nur EIN Ephemeral-Key (nicht zwei!). Unser altes Capture (nonce+pub1+pub2, kein
  Header) war deshalb FALSCH strukturiert -> Sensor interpretierte die Bytes falsch
  -> ECDH passte nie -> alle bisherigen Offline-Cracks (100k+ Kombinationen) mussten
  scheitern. DAS war die eigentliche Ursache, nicht die Krypto.

## Identity-Labels (FUN_1800124b0): "enroll", "identify"
Für den Enroll-Finish nach erfolgreichem Connect.

## Nächster Schritt
scratch/sdcp_capture.py NEU: sendet korrektes 105B-ClientHello mit bekanntem
Ephemeral-Key und verifiziert den Server-MAC sofort offline (brute-forced nur noch
die nonce_s-Position über 32B-Fenster). Ein Treffer bestätigt die GESAMTE Kette und
liefert den Session-Key -> danach Identity berechnen und Enroll.

---

# 36. ★ SDCP-SESSION-KRYPTO GEKNACKT (2026-07-29) ★

Live auf der Hardware reproduziert und offline verifiziert (Server-MAC nachgerechnet).

## Draht-Format (bestätigt via Windows-Mitschnitt + eigenem Handshake)
ClientHello (e3 00, transport-verschlüsselt):
    nonce_c(32) || EC1(65) || EC2(65)                    = 162 Bytes
ServerHello-Flight (Antwort):
    [71 04 00 00] || cert(847) || tail(515)              = 1366 Bytes

## ServerHello-Tail-Layout (nach dem Zertifikat, Offsets relativ Tail)
    @0   EC_A(65)   staticer Geräteschlüssel (konstant)
    @65  EC_B(65)   Server-Ephemeral  ← ECDH-Punkt
    @130 32B        \
    @162 64B         > Transcript-Material (tail[0:290])
    @226 64B        /
    @290 EC_C(65)   weiterer Punkt
    @355..515       Session-Blöcke, darunter:
    @419 MAC(32)    Server-Key-Confirmation-MAC
    @451 nonce_s(32) Server-Nonce

## Vollständige verifizierte Ableitung (1:1 aus GoodixMocSensorAdapter.dll)
    Z          = ECDH(client_priv, EC_B)                        # X-Koord, 32B
    master     = SP800-108(Z,      "master secret\0",   nonce_c||nonce_s, 32)
    session    = SP800-108(master, "application keys\0", <leer>,          64)
    transcript = SHA256(cert || tail[0:290])
    server_MAC = HMAC-SHA256(session[0:32], "connect\0" || transcript)
Prüfung: server_MAC == ServerHello-Feld @ (cert_ende+419).  ★ bestätigt ★

## SP800-108 (FUN_180011de0), exakt
    K(i) = HMAC-SHA256(key, BE32(i) || label||0x00 || context || BE32(outlen*8))
    label INKLUSIVE Nullterminator; Counter 1-basiert; L in Bits.

## Wichtige Irrwege (dokumentiert, damit nicht wiederholt)
- FUN_18000f020 erzeugt das INTERNE 105B-DLL/IOCTL-Format
  ([len][ver][type][nonce][1×pubkey]); der Kerneltreiber übersetzt es ins
  162B-Draht-Format. Direkt an den Sensor gesendet ergibt es einen falschen Pfad
  (1201B-Antwort) — NICHT verwenden. Draht = nonce+EC+EC.
- connect_type-Feld ist NICHT im Draht-ClientHello (das ist rein DLL-intern).

## Session-Key nutzbar für
Ab hier ist der authentifizierte Session-Key verfügbar. Nächster Schritt:
Host-Identity/Finish (Labels "connect"/"enroll"/"identify" via FUN_1800124b0)
berechnen und für den SDCP-Enroll senden.

---

# 37. Enroll-Protokoll: Struktur verstanden (2026-07-29)

## Geräte-Antwort-MAC (live geknackt)
Auf jedes e3 01 <host_identity> antwortet der Sensor mit '00' + 32B:
    device_MAC = HMAC-SHA256(session_key, "reconnect\0" || host_identity)
=> beidseitige Schlüsselbestätigung; der Sensor prüft X bei e3 01 NICHT
   (bestätigt nur). Beide Seiten nutzen dasselbe gelabelte HMAC (FUN_1800124b0).

## Host-Identity
    identity = HMAC-SHA256(session_key, "enroll\0"|"identify\0" || X)
X = 32B (Puffer 0x57258, gesetzt via FUN_18000f140 aus dem Engine-Adapter).
Hypothese: X ist eine frei wählbare Host-Nonce (Frische) — da der Sensor die
Identity nur als gültige Session-Key-HMAC prüft, nicht deren Inhalt.

## Enroll-Choreografie (aus Windows-Mitschnitt)
    e0 01 (PSK) -> a2 (arm) -> a5 (identify, 1110B) -> e3 02/e3 01 (identity)
    -> b0 02 (Kalibrierung) -> [a1 Enroll-Init, 33B] -> Schleife:
        e3 02/e3 01 (neue identity) -> b0 02 -> a2 000f4101 -> a0 016464
        -> Fortschritt 00 XX YY  (XX steigt 0x00->0x32->0x61->...->0x64)
    Bei 100%: a3/a4 committen den Template.
'000000' beim a0 = "noch kein Finger-Frame", KEINE Identity-Ablehnung.

## Nächster Schritt
scratch/enroll_attempt.py: repliziert die Sequenz mit unserem Session-Key und
X=Host-Nonce; Fortschritt wird live angezeigt. Bei Erfolg -> Template-Commit.

---

# 38. Enroll-Stand: alle Krypto-Teile ok, a0 erfasst keinen Frame (2026-07-29)

## Was funktioniert (live verifiziert)
- SDCP-Handshake + Session-Key + Server-MAC  ✓
- Beidseitige Schlüsselbestätigung (device_MAC = HMAC(sk,"reconnect\0"||id))  ✓
- Finger-Erkennung: a2 liefert Finger-Region, b0 liefert wechselndes Bild  ✓
- a5 (identify) akzeptiert JEDE gültige Session-Key-HMAC (X-Inhalt wird NICHT
  geprüft) und liefert bei aufliegendem Finger einen Match-Token; 'ff' = kein
  Finger (nicht: Identity ungültig)  ✓
- a1 (Enroll-Init) liefert 33B  ✓

## Was NICHT funktioniert
- a0 016464 liefert IMMER 000000 (kein Frame), während Windows pro Frame
  wechselnde Metriken liefert (003232, 00612a, 002f10, 005524 = Abdeckung/Qualität,
  KEIN monotoner Fortschritt). Enroll akkumuliert intern; a0-Payload variiert auch
  (016464 -> 016450).

## Wahrscheinlichste Ursachen (offen)
1. Fehlender Imaging-/FDT-Modus: der funktionierende VERIFY-Pfad
   (goodix_gf3268.py) setzt vor dem Capture FDT/POV-Imaging; unser Enroll nicht.
   a0 könnte den von b0/FDT vorbereiteten Frame lesen.
2. Finger bereits registriert: a5 liefert Match-Token statt '01'. Windows-Enroll
   lief mit frischem Finger (a5->01). Sensor enrollt evtl. keinen bekannten Finger.
3. Feinsequenz/Timing zwischen a2 (arm) und a0 (read).

## Erreichtes (praktisch)
Das Alltagsziel (Fingerabdruck-Entsperren) ist über den Verify-Pfad bereits
erfüllt und ausgerollt. Die kryptografische Kernaufgabe (SDCP-Session) ist
vollständig Resolved und live bestätigt.

---

# 39. Enroll-Blockade eingegrenzt — Stand für Übergabe (2026-07-29)

## Definitiv bestätigt (live, mehrfach reproduziert)
- SDCP-Session-Krypto vollständig Resolved, Server-MAC nachgerechnet ✓ (Abschnitt 36)
- Der Sensor validiert die SDCP-Identity INHALTLICH NICHT: der produktive
  Verify-Pfad läuft mit `a5 00 <os.urandom(32)>` und matcht korrekt.
  => X-Suche (Abschnitt 37) war gegenstandslos. Enroll ist KEIN Auth-Problem.
- a5-Match-Orakel funktioniert einwandfrei (check_finger.py):
  registrierte Finger -> 1110B Token, frische Finger -> 0x01.
- REIHENFOLGE-REGEL: vor jedem `a5` MUSS ein `a2 00 01002301` stehen
  (Finger-Detektion, macht den Sensor scharf). Ohne das liefert a5 immer 'ff'
  (= kein Finger), unabhängig vom Finger. War die Ursache falscher
  "REGISTRIERT"-Meldungen in enroll_v5 (behoben).
- Mit frischem Finger: a5 -> 01 ✓, a1 (Enroll-Init) -> 33B ✓

## Die eigentliche Blockade
`a0 00 016464` liefert IMMER `000000` (kein Frame erfasst), obwohl
  - der Finger erkannt wird (a2 liefert Region, b0 wechselnde Bilddaten)
  - der Finger frisch ist (a5 -> 01)
  - a1 initialisiert hat
Kurz danach bricht der USB-Transfer ab (-4 Gerät weg / -7 Timeout), d.h. der
Sensor resettet sich. Windows liefert an dieser Stelle pro Frame wechselnde
Metriken (003232, 00612a, 002f10, 005524 — Abdeckung/Qualität, KEIN monotoner
Fortschritt) und variiert auch die a0-Payload (016464 -> 016450).

## Wahrscheinlichste verbleibende Ursache
Ein fehlender Imaging-/FDT-Schritt zwischen a2 und a0. Der Windows-Mitschnitt
zeigt zwischen den Enroll-Frames zusätzliche Commands, die wir noch nicht
replizieren (FDT-Modus 0x32/0x34/0x36, POV_IMG 0xd2). Der Verify-Pfad braucht
sie nicht, weil `a5` Capture+Match intern in einem Schritt macht — der Enroll
dagegen liest offenbar einen VORHER von FDT/Imaging bereitgestellten Frame.
Empfehlung für den nächsten Schritt: im pcapng-Mitschnitt ALLE Commands
zwischen zwei kreditierten a0 vollständig auflisten (auch die im annotierten
Dump gefilterten) und 1:1 nachbauen.

## Praktischer Stand
Fingerabdruck-Entsperren (Verify) läuft produktiv und ist ausgerollt (KDE
Lockscreen + LightDM). Der Enroll bleibt offen; für neue Finger derzeit
Windows/Werkseinrichtung nötig.

## Relevante Skripte
- scratch/sdcp_session.py   Handshake + Session-Key (verifiziert)  ← Kern
- scratch/check_finger.py   a5-Orakel: welche Finger sind registriert  ← funktioniert
- scratch/goodix_verify.py  produktiver Verify (PAM)                ← funktioniert
- scratch/enroll_v5.py      aktueller Enroll-Versuch (a0 bleibt 000000)

---

# 40. ★ ENROLL FUNKTIONIERT — Frames werden erfasst (2026-07-29)

DURCHBRUCH: Aus dem ROHEN pcapng (jedes Paket zwischen zwei a0) kam die fehlende
Zutat: VOR JEDEM a0 steht ein e3 02/e3 01-Identity-Paar (32B, Inhalt egal).
enroll_v4/v5 hatten das weggelassen -> Sensor-Reset (-4). enroll_v6 mit dem
e3-Paar erfasst Frames (a0 -> 004949, 003232-artige Werte).

## a0-Antwortformat (Enroll-Frame)
    00 00 00   kein neuer Frame (neu auflegen)
    00 XX YY   Frame erfasst, XX = Abdeckung, Ziel 0x64=100%
    74../ff..  Frame zu ähnlich -> anderen Fingerbereich auflegen
Abschluss: 00 64 00 -> a3 00 (commit) -> a4 <template> -> 00.
Windows brauchte ~14 Frames mit VERSCHIEDENEN Fingerbereichen.

## Vollständige Enroll-Sequenz (funktioniert)
  Präambel (festes HELLO, b0, e0)
  a2 01002301 -> a5 identify (frisch=01) -> a5 01 -> e3-Paar -> b0 -> a1
  Schleife pro Frame: e3 02/e3 01 (32B) -> b0 02 -> a2 000f4101 -> a0 016464
  bei Abdeckung 0x64: a3 00 -> a4 (Template)

## Offen
Nur noch: genug VERSCHIEDENE Fingerbereiche auflegen, bis Abdeckung 0x64 -> commit.
enroll_v7.py führt durch und committet automatisch.

---

# 41. ★ Enroll-Capture GELÖST — a3 finalisiert (2026-07-29)

- Payload-Phasenwechsel 016464 -> 016450 (nach 5 a0) durchbricht die erste
  '74'-Wand. Danach 2. Wand bei ~11-12 Frames = "genug erfasst".
- An der Wand a3 00 gesendet -> Gerät antwortet 00 = CAPTURE VOLLSTÄNDIG.
  Die '74'-Wand bedeutet also "fertig, committen", nicht "mehr nötig".
- a4 (Template-Commit, 100B) mit Windows-Payload -> 9f (abgelehnt). Die Payload
  enthält 16B Template-ID + 33B Feld (ec02..) + Windows-SID (S-1-5-21-..-1001).
  Herkunft der Felder: 33B + SID tauchen in a6(READ_OTP)-Antworten auf (Gerät),
  16B Template-ID nur in a4 (host-generiert).
- OFFEN: korrekte a4-Payload für Linux. Test in enroll_v12: prüft, ob a3 allein
  das Template schon speichert (a5-Match nach a3). Wenn ja -> a4 = nur
  Windows-Identitäts-Metadaten, für Verify/Unlock nicht nötig.

## Vollständige funktionierende Capture-Sequenz
  Präambel (HELLO, b0, e0) -> a2 01002301 -> a5(frisch=01) -> a5 01 -> e3 -> b0
  -> a1 -> pro Frame [e3 02/e3 01 (32B) -> b0 -> a2 000f4101 -> a0 <016464|016450>]
  -> bei 74-Wand a3 00 (=> 00) -> a4 <100B> (Payload noch offen).

---

# 42. ★★ a4-Struktur geknackt: Template-Record = Identity-MAC pro User (2026-07-29)

a6 (READ_OTP) liefert die gespeicherten Records (je 100B = a4-Format):
    [62004304f5XX][16B TemplateID][16B 0][33B Identity-MAC][28B SID][00]
Der 33B-Identity-MAC ist PRO USER (gleich für alle Templates eines Users,
via GoodixSdcpMacEnroll berechnet) — NICHT pro Template. SID = Windows-SID.
Storage-Adapter-Strings bestätigen: GoodixSdcpMacEnroll, CommitTemplate,
GoodixSdcpVerifyAuthorizedIdentity, CreateTemplateId.

STRATEGIE (enroll_v13): existierenden gültigen 33B-MAC + SID aus a6 wiederverwenden,
nur neue 16B-Template-ID -> a4 sollte akzeptiert werden (Sensor verifiziert eine
echte Identität). Damit Enroll OHNE GoodixSdcpMacEnroll-Nachbau.
Danach a5-Match-Test: wird der neue Finger erkannt?

---

# 43. Enroll-CAPTURE vollständig Resolved; a4-Commit-MAC ist der letzte Component (2026-07-29)

## ★ GELÖST: Enroll-Capture (der schwierige Sensor-Teil)
Vollständige, reproduzierbare Sequenz (enroll_v10..v15):
  Präambel(HELLO,b0,e0) -> a2 01002301 -> a5(frisch=01) -> a5 01 -> e3-Paar -> b0
  -> a1 -> pro Frame: [e3 02/e3 01 (32B, Inhalt egal) -> b0 -> a2 000f4101
           -> a0 <016464 die ersten 5, danach 016450>]
  -> nach ~11-13 Frames '74'-Wand -> a3 00 = CAPTURE FERTIG.
Wichtig: e3-Paar VOR jedem a0 nötig; Payload-Wechsel 016464->016450 durchbricht
die 1. Wand; die 2. '74'-Wand bedeutet "genug -> committen".

## a4-Record-Struktur (100 B), vollständig verstanden
  [62004304f500][16B TemplateID][16B 0][32B MAC][1B SID_len=0x1c][28B SID][00]
  (a6 READ_OTP liefert genau diese Records; MAC ist PRO TEMPLATE.)

## OFFEN: die 32B-a4-MAC (GoodixSdcpMacEnroll)
- Storage-Adapter berechnet sie über ein SDCP-Interface-Objekt (global 0x18007b870)
  -> vtable in den Sensor-Adapter (dort FUN_1800124b0 = HMAC(session_key,label||data)).
- a4 ist BELIEBIG WIEDERHOLBAR (Zustand bleibt nach a3) -> viele Kandidaten pro
  Enroll testbar.
- AUSGESCHLOSSEN (alle -> 9f):
  * geräte-statice Keys (KI, MAC_KEY, MAC_KEY[:16], AES_KEY)
  * echter Session-Key + session_key2 + master
  * je × Labels {"", enroll, identify, connect} × Eingaben
    {tid, sid, tid+sid, sid+tid, tid+zeros, tid+zeros+sid, hdr+..., ganzer Record}
- VERMUTUNG: Eingabe ist ein 32-Byte-Wert (wie X in FUN_18000f170), nicht rohe
  tid/sid — z.B. SHA256(template/identity) oder ein geräte-geliefertes Nonce
  (a1-Antwort 33B? variiert pro Enroll). Nächster Schritt: GoodixSdcpMacEnroll
  im Storage-Adapter sauber tracen (vtable-Methode + Input-Buffer) ODER
  a1-Antwort/Templatehash als MAC-Eingabe testen.

## Skripte
- enroll_v15.py  echter Handshake + Capture + a4-MAC-Suche (Session-Key)
- enroll_v14.py  a4-MAC-Suche (geräte-statice Keys); belegt a4-Wiederholbarkeit
- check_finger.py  welche Finger sind registriert (a5 Token vs 01)  [funktioniert]

---

# 44. ★★ a4-MAC-Formel gefunden + a7-Identitätsregistrierung (2026-07-29)

DURCHBRUCH: Unter allen Kandidaten gibt GENAU EINE eine andere Antwort (ff statt
9f) -> die MAC-Prüfung besteht:
    a4-MAC (32B) = HMAC-SHA256(session_key, "enroll\0" || a1_response[1:33])
- a1_response = 33B Geräte-Nonce aus a1 00 (variiert pro Enroll).
- a1[1:33] (32B, ohne Status-Byte) ist korrekt; a1[0:32]/a1[:33] -> 9f.
- ff (nicht 9f) = MAC ok, aber Identität nicht autorisiert.

Fehlender Schritt: a7 02 (Payload 0100 + 100B-Record) REGISTRIERT einen User in
der Session (Windows: a7 registriert User 6a88b616, dann Enroll FÜR diesen User).
a4-SID muss = registrierte SID sein.

enroll_v18: a6 -> a7(Record registrieren) -> Handshake -> Capture -> a3 ->
a4 mit HMAC(sk,"enroll\0"||a1v) + registrierter SID -> Match-Test.

---

# 45. a5=03 = hängender Enroll-Zustand; a7 0100 pollutet Arbeitsspeicher (2026-07-29)

- Wiederholte abgebrochene Enrolls (a3=00 ohne gültiges a4) UND a7 0100-Aufrufe
  bringen den Sensor in Zustand a5->03 (Enroll offen / falscher Zustand).
- USB-Reset (libusb_reset_device) räumt das NICHT. Nur REBOOT.
- a7-Präfixe: 0100 = registrieren/hinzufügen, 0200 = löschen
  (aus goodix_delete_templates.pcapng).
- Konsequenz für a4-Suche: KEIN a7; a4 innerhalb einer Session wiederholbar,
  aber endet die Session ohne gültiges a4 -> 03 -> reboot nötig. Also wenige
  Kandidaten pro Session, beste zuerst (a1v).
- Beste MAC bleibt HMAC(sk,"enroll\0"||a1[1:33]) (gab 'ff'=MAC ok). Evtl. war
  'ff' Folge des schon angeschlagenen Zustands -> im sauberen Zustand testen.
- enroll_v20.py: sauber, ohne a7, a1v + enge Nachbarschaft.

---

# 46. Template-Store durch Experimente GELEERT (0 Records) — Recovery (2026-07-29)

- diag_state.py nach Reboot: a6 = 0 Records (Store LEER), a5 = ff (kein Finger).
  Der 03-Hänger ist weg -> Sensor sauber, aber alle Abdrücke gelöscht
  (durch a7-0100/a3-Experimente + Reboot). Deshalb kein Login mehr.
- Recovery-Wege: (A) Windows-Hello neu einrichten [zuverlässig];
  (B) Linux-Enroll auf sauberem Store fertigstellen [enroll_v21, a1v-MAC +
  synthetische 28B-SID, da kein Record zum Reuse].
- WICHTIG gelernt: a7 0100 / a3-ohne-a4 verändern den persistenten Store ->
  künftig NUR mit Enroll-Abbruch/Recovery-Plan testen.

---

# 47. FINAL-Stand Enroll: Capture + MAC Resolved, a4-Commit-Autorisierung offen (2026-07-29)

## Auf sauberem/leerem Store bestätigt
- a4 [HMAC(sk,"enroll\0"||a1[1:33])] -> ff (als EINZIGE Formel; alle anderen 9f).
  => MAC-Formel korrekt (ff=MAC ok). ff ist eine Commit-Nachbedingung, NICHT
  Folge des früher verschmutzten Zustands.
- a1_response = a1 00 -> 33B; a1[1:33] (ohne Status-Byte) ist die MAC-Eingabe.
- Synthetische UND reale SID -> beide ff. Also nicht das SID-Format.
- Vermutete ff-Ursache: Identitäts-Autorisierung (GoodixSdcpVerifyAuthorizedIdentity)
  bzw. Template-Vollständigkeit (unsere byte1-Werte blieben ~0x01, Windows 0x32-0x64;
  a3 wurde an der 74-Wand ausResolved, evtl. vor voller Coverage 0x64).

## GELÖST
- SDCP-Session-Krypto (Abschnitt 36), Enroll-Capture (a3=00), a4-Record-Struktur,
  a4-MAC-Formel (HMAC(sk,"enroll\0"||a1[1:33])).

## OFFEN (letzter Component)
- a4-Commit-Autorisierung (ff). Am besten lösbar durch einen FRESH/DYNAMICEN
  Windows-Enroll-Mitschnitt auf LEEREM Store (zeigt exakte a4-Payload + Identitäts-
  schritte für Erst-Enrollment). Alternativ: byte1 bis 0x64 capturen (volle Coverage)
  vor a3, statt an der 74-Wand abzubrechen.

## WICHTIG / Recovery
- Store wurde durch die Experimente geleert (0 Records) -> Login kaputt.
  Wiederherstellung: Finger in Windows Hello neu einrichten (stellt Win+Linux her).
- a7 0100 / a3-ohne-a4 verändern persistenten Store -> künftig nur mit
  Recovery-Plan testen.

---

# 48. ★★★ NATIVER libfprint-TREIBER FUNKTIONIERT (2026-07-30)

scratch/libfprint_natasha/libfprint/drivers/goodixsdcp/ — neuer Treiber
`goodixsdcp` (27c6:6f94), gebaut auf dem goodixmoc-Skelett, mit unserer
SDCP-Transport-Krypto (goodixsdcp_crypto.c, OpenSSL). Live verifiziert:
- open/init (e1 04, e3-HELLO, b0, e0, a6-Liste) -> "open completion" ✓
- Enroll-Bind: Windows-Hello-Finger auflegen -> a5 1110B-Token -> gebunden ✓
- Verify/Identify: a5-Match -> "MATCH!" ✓ (kein Crash nach Double-Free-Fix)
- delete/clear_storage: nur Host-Bindung, on-chip-Template bleibt.

Enroll = "Bind": neue Finger sind TPM-gebunden nicht anlernbar; man legt einen
in Windows Hello angelernten Finger auf, der Chip matcht ihn, und der Treiber
registriert das on-chip-Template als FpPrint. Danach Verify systemweit.

Build (nur dieser Treiber):
  meson setup build -Ddrivers=goodixsdcp -Ddoc=false -Dintrospection=false -Dgtk-examples=false
  ninja -C build
Test ohne fprintd: build/examples/enroll, build/examples/verify.

Nächster Schritt: systemweite Installation + fprintd/KDE-Einbindung + PAM.

---

# 49. ★★★ FERTIG: nativer Treiber systemweit + KDE/PAM integriert (2026-07-30)

Voll funktionsfähig und live bestätigt:
- libfprint mit goodixsdcp nach /usr installiert (build-install, prefix /usr).
- fprintd nutzt den Treiber: fprintd-enroll -> enroll-completed,
  fprintd-verify -> verify-match.
- KDE-Systemeinstellungen -> Benutzer -> Fingerabdruck: Registrierung + Nutzung
  über die GUI funktioniert (bindet den Windows-Hello-Finger).
- Sperrbildschirm (Super+L) entsperrt per Finger ✓
- sudo per Finger ✓ (pam_fprintd in /etc/pam.d/sudo)
- LightDM-Login: pam_fprintd in /etc/pam.d/lightdm eingetragen.
- Altes Python-pam_exec-Entsperren entfernt (sonst USB-Konflikt mit fprintd).

## Modell / Grenzen
- Enroll neuer Finger ist TPM-gebunden -> nur in Windows Hello moeglich.
  Der Treiber-"Enroll" ist ein BIND: on-chip-Template via a5-Match an FpPrint
  binden. Verify/Identify/Match funktionieren nativ.
- Der fprintd-Finger-Slot ist nur ein Etikett; der Sensor matcht jeden
  registrierten on-chip-Finger (per-Finger-Unterscheidung ist lose).

## WARTUNG (wichtig)
- Unser libfprint ersetzt das Distro-Paket in /usr. Ein pacman-Update von
  'libfprint' ueberschreibt es -> danach neu bauen+installieren:
    cd ~/Projekte/Fingerprint/scratch/libfprint_natasha
    ninja -C build-install && sudo ninja -C build-install install
    sudo udevadm control --reload-rules && sudo udevadm trigger
    sudo systemctl restart fprintd
  (Optional: 'libfprint' in /etc/pacman.conf unter IgnorePkg setzen.)

## Offene Politur (optional)
- Verify-Retry im Fehlerfall feuert schnell (~250ms); Abhilfe: nach No-Match
  auf Finger-Anheben warten, bevor der naechste a5 laeuft.

---

# 50. Politur: No-Match wartet auf Finger-Anheben (2026-07-30)

Verify-SSM um Zustand GSDCP_VER_WAIT_LIFT erweitert: bei Match sofort fertig,
bei No-Match wird FAIL gemeldet und dann per a2 (200ms-Poll) auf Finger-Anheben
gewartet, bevor die Operation endet. Damit startet die nächste fprintd-Verify
frisch, statt im Fehlerfall alle ~250ms zu feuern.
Neu bauen+installieren nötig:
    cd ~/Projekte/Fingerprint/scratch/libfprint_natasha
    ninja -C build-install && sudo ninja -C build-install install
    sudo systemctl restart fprintd

---

# 51. NEUE HOFFNUNG fuer Enroll: TPM nur INITIAL noetig (2026-07-30)

Nutzer-Erkenntnis: Nur die ERSTE Fingerregistrierung braucht TPM; FOLGE-Finger
gingen auch in der Windows-VM OHNE TPM. => 'ff' beim a4 ist keine harte
TPM-Wand, sondern "Identitaet nicht als autorisiert erkannt". Sobald eine
gueltige Identitaet on-chip existiert, sollte Hinzufuegen ohne TPM klappen.
Der geleerte Speicher war vermutlich ein Sicherheits-Lockout nach zu vielen
Fehlversuchen (keine Beschaedigung).

Nie sauber getestete Kombination: a7-Registrierung der ECHTEN Identitaet +
HMAC(sk,"enroll\0"||a1[1:33]) + ECHTE SID auf BEFUELLTEM Speicher.
enroll_v22.py macht genau das mit EINEM a4-Versuch (Lockout-Schutz).

---

# 52. Enroll-Versuch beendet + Recovery; Projekt abgeschlossen (2026-07-30)

## Result des letzten Enroll-Versuchs (enroll_v22)
Mit der Kombination a7-Identitaet + a1v-MAC + echte SID auf befuelltem Speicher:
- Der Enroll-CAPTURE lief NICHT an (a0 blieb 000000), obwohl fprintd gestoppt
  und der Finger frisch war (a5 -> 01).
- Die a6-Record-Zahl schwankte (3 -> 2) -> unsere a7/a4-Schreibzugriffe
  veraendern den persistenten Template-Speicher; wiederholte Versuche loesen
  einen Sicherheits-LOCKOUT aus (bestaetigt die Nutzer-Hypothese).
=> In diesem Zustand ist der native Enroll nicht durchfuehrbar, und jeder
   weitere Versuch gefaehrdet die funktionierenden (Windows-)Registrierungen.
   ENTSCHEIDUNG: nativen Enroll nicht weiter verfolgen.

## Wichtige Betriebs-Erkenntnis
- Sobald fprintd installiert/aktiv ist (fuer sudo/Login), GREIFT es auf den
  Sensor zu und konkurriert mit den Python-Tools um das USB-Geraet -> wackelige
  Resultse, -4-Fehler. Fuer Python-Experimente vorher: `sudo systemctl stop fprintd`,
  danach wieder starten.

## Recovery (funktioniert zuverlaessig)
Wenn der Speicher durch Experimente geleert/gesperrt wurde:
1. Finger in Windows Hello neu anlernen (stellt on-chip-Templates wieder her).
2. Unter Linux via KDE/fprintd erneut "registrieren" (= Bind an on-chip-Template).
-> Sperrbildschirm-Entsperren + sudo per Finger wieder funktionsfaehig.

## Projekt-Endstand
- Nativer libfprint-Treiber goodixsdcp: FERTIG (Verify/Identify/Bind + KDE/PAM).
- Enroll neuer Finger: aus Linux nicht praktikabel (Lockout/Identitaets-
  Autorisierung); Registrierung erfolgt in Windows Hello, danach Linux-Bind.
- Alles dokumentiert (Abschnitte 1-52), Release-Paket unter release/.
