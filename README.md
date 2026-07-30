# Goodix GF3268 (Windows Hello / SDCP) — nativer Linux-Fingerabdrucktreiber

Sauberes, reproduzierbares Paket für den nativen libfprint-Treiber `goodixsdcp`
für den Goodix GF3268 (USB `27c6:6f94`), den SDCP/Windows-Hello-Sensor u.a. im
Honor MagicBook Art 14.

Der Treiber klinkt sich in **fprintd** ein und funktioniert damit systemweit
(KDE/GNOME-Einstellungen, Sperrbildschirm, Login, sudo).

---

## Was funktioniert

| Funktion              | Status | Weg                                              |
|-----------------------|--------|--------------------------------------------------|
| Verify / Identify     | ✅     | `a5` SDCP-Match on-chip                           |
| Enroll (Bind)         | ✅     | Windows-Hello-Finger auflegen → on-chip gematcht → als FpPrint gebunden |
| List / Delete         | ✅     | `a6` Template-Liste / nur Host-Bindung entfernen |
| KDE/fprintd/PAM       | ✅     | Sperrbildschirm, sudo, Login, GUI-Enrollment     |
| Enroll NEUER Finger   | ❌     | TPM-gebunden — nur in Windows Hello möglich (siehe unten) |

**Modell:** Neue Finger anzulernen ist TPM-gebunden und nur unter Windows Hello
möglich. Der Treiber-„Enroll" ist deshalb ein **Bind**: man legt einen in
Windows angelernten Finger auf, der Chip erkennt ihn, und der Treiber
registriert das on-chip-Template als fprintd-Abdruck. Danach läuft Verify nativ.

---

## Inhalt

```
release/
├── README.md                 dieses Dokument
├── HANDOVER_COWORK.md         vollständiges Reverse-Engineering-Log (50 Abschnitte)
├── driver/                    der libfprint-Treiber (der Deliverable)
│   ├── goodixsdcp.c           Device-Klasse, SSMs, verify/enroll/list
│   ├── goodixsdcp.h           Struct + Zustände
│   ├── goodixsdcp_crypto.c    Transport-Krypto (AES/HMAC) + Goodix-Framing
│   └── goodixsdcp_crypto.h
├── protocol/                  Referenz-/Reproduktions-Tools (Python)
│   ├── goodix_crypto.py       feste Session-Keys + AES/HMAC (Ground Truth)
│   ├── goodix_gf3268.py       USB-Transport + Framing (CRC8/CRC32)
│   ├── sdcp_session.py        SDCP-Handshake + Session-Key
│   ├── sdcp_capture.py        Live-Handshake fahren + verifizieren
│   ├── check_finger.py        welche Finger sind registriert (a5-Orakel)
│   ├── goodix_verify.py       eigenständiges Verify (ohne libfprint)
│   ├── emulate_ki.py          Master-Key/Session-Keys per Unicorn-Emulation
│   └── re_tools/              PE-/pcapng-/pdata-Parser
├── captures/                  Schlüssel-Mitschnitte (entschlüsselbar mit den Keys)
│   ├── goodix_handshake_and_enroll.pcapng
│   └── goodix_unlock_success.pcapng
└── windows_binaries/          Basis der Reverse-Analyse
    ├── GoodixMocSensorAdapter.dll
    └── GoodixMocStorageAdapter.dll
```

---

## Treiber bauen & installieren

Der Treiber wird in einen libfprint-Quellbaum eingebaut.

### 1. libfprint-Quellen holen
```bash
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
cd libfprint
```
(Getestet gegen libfprint 1.94.5. Bei stark abweichender Version ggf. kleine
API-Anpassungen nötig.)

### 2. Treiber einlegen
```bash
mkdir -p libfprint/drivers/goodixsdcp
cp /pfad/zu/release/driver/*.c libfprint/drivers/goodixsdcp/
cp /pfad/zu/release/driver/*.h libfprint/drivers/goodixsdcp/
```

### 3. Meson-Verdrahtung (4 Änderungen)

**`meson.build`** — in `default_drivers` ergänzen:
```meson
    'goodixsdcp',
```
**`meson.build`** — in `driver_helper_mapping` ergänzen:
```meson
    'goodixsdcp' : [ 'goodixsdcp_crypto' ],
```
**`meson.build`** — in der Abhängigkeits-Schleife (`foreach i : driver_helpers`)
einen Zweig für OpenSSL ergänzen:
```meson
    elif i == 'goodixsdcp_crypto'
        openssl_dep = dependency('openssl', required: false)
        if not openssl_dep.found()
            error('openssl is required for @0@'.format(driver))
        endif
        optional_deps += openssl_dep
```
**`libfprint/meson.build`** — in `driver_sources` und `helper_sources` ergänzen:
```meson
    'goodixsdcp' :
        [ 'drivers/goodixsdcp/goodixsdcp.c' ],
```
```meson
    'goodixsdcp_crypto' :
        [ 'drivers/goodixsdcp/goodixsdcp_crypto.c' ],
```

### 4. Bauen & testen (ohne fprintd)
```bash
meson setup build -Ddrivers=goodixsdcp -Ddoc=false -Dintrospection=false -Dgtk-examples=false
ninja -C build
sudo ./build/examples/enroll     # Windows-Hello-Finger auflegen → bindet
sudo ./build/examples/verify     # Finger auflegen → "verify-match"
```

### 5. Systemweit installieren (fprintd/KDE)
```bash
sudo pacman -S --needed fprintd
meson setup build-install -Dprefix=/usr --libdir=lib \
      -Ddrivers=goodixsdcp -Ddoc=false -Dintrospection=false -Dgtk-examples=false
ninja -C build-install
sudo ninja -C build-install install
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl restart fprintd
```
Danach in KDE **Systemeinstellungen → Benutzer → Fingerabdruck** registrieren,
oder `fprintd-enroll` / `fprintd-verify`. Für sudo/Login `pam_fprintd.so` in die
jeweiligen `/etc/pam.d/`-Dateien eintragen (`auth sufficient pam_fprintd.so`).

---

## Wartung

- **Distro-Update von `libfprint`** überschreibt unsere Version in `/usr`.
  Danach neu bauen+installieren (Schritt 5) und `fprintd` neu starten.
  Optional `libfprint` in `/etc/pacman.conf` unter `IgnorePkg` setzen.
- Abgebrochene Enroll-Experimente können den on-chip Template-Speicher leeren
  → dann Finger in Windows Hello neu einrichten (stellt Win- und Linux-Login her).

---

## Reproduktion der Reverse-Analyse

Der komplette Weg ist in `HANDOVER_COWORK.md` chronologisch dokumentiert
(Abschnitte 1–50). Kurzform:

1. **Transport-Krypto:** feste AES/HMAC-Session-Keys (aus der DLL via Unicorn
   emuliert, `emulate_ki.py`), Wire-Format in `goodix_crypto.py`. Verifiziert
   159/159 gegen die Mitschnitte.
2. **SDCP-Handshake:** ECDH(P-256) + SP800-108-KDF, Transcript=SHA256,
   MAC=HMAC. Rekonstruiert per objdump aus `GoodixMocSensorAdapter.dll`,
   live bestätigt (`sdcp_capture.py`, `sdcp_session.py`).
3. **Verify:** `a2` Finger-Detektion + `a5` SDCP-Match (`goodix_verify.py`,
   `check_finger.py`).
4. **Treiber:** `driver/` portiert das alles nach C/libfprint.

Die DLLs disassembliert man mit `objdump -d -M intel`; die Mitschnitte
entschlüsselt `protocol/re_tools/` + `goodix_crypto.py`.

---

## Betrieb / Wichtiger Hinweis

Ist `fprintd` aktiv (für sudo/Login), greift es selbst auf den Sensor zu und
konkurriert mit den Python-Tools aus `protocol/` um das USB-Gerät. Für eigene
Experimente vorher `sudo systemctl stop fprintd`, danach wieder starten.

## Grenzen (ehrlich)

Enroll **neuer** Finger ist aus Linux heraus praktisch nicht möglich:
- Der `a4`-Commit besteht die MAC-Prüfung
  (`HMAC(session_key,"enroll\0"||a1[1:33])`), scheitert aber an einer
  nachgelagerten **Identitäts-Autorisierung** (`ff`).
- Nur die INITIALE Registrierung braucht TPM; Folge-Finger gingen in Windows
  auch ohne TPM. Ein nativer Linux-Versuch mit registrierter Identität kam aber
  nicht durch: der Enroll-Capture lief nicht an, und wiederholte Versuche lösen
  einen **Sicherheits-Lockout** aus, der den on-chip Template-Speicher leert.
- Praktikabler Weg: Finger **in Windows Hello anlernen**, danach unter Linux
  via KDE/fprintd „registrieren" (= Bind an das on-chip-Template).

Details in `HANDOVER_COWORK.md` Abschnitte 40–52.
