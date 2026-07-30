#!/usr/bin/env python3
"""
goodix_gf3268.py — Linux-Treibergerüst für den Goodix GF3268 (27c6:6f94).

Setzt auf dem gelösten Transport auf: USB-Bulk + Goodix-Paket-Framing
(CRC8-Header, CRC32, 64-B-Padding) + der geknackten Session-Verschlüsselung
(scratch/goodix_crypto.py, feste AES-/HMAC-Keys, KEIN Handshake nötig).

Was funktioniert / getestet werden kann:
  - USB öffnen, Init-Sequenz senden
  - Verschlüsselte e3-Kommandos senden und Antworten entschlüsseln
  - End-to-End-Beweis: der Sensor liefert live seinen Zertifikats-Flight,
    den wir mit den festen Keys entschlüsseln (bestätigt die ganze Kette).

Noch offen (SDCP-Enroll/Verify): die innere ECDH-/Token-Schicht — siehe
HANDOVER_COWORK.md Abschnitt 26.

    sudo python3 scratch/goodix_gf3268.py            # Krypto-Kanal live verifizieren
"""

import binascii
import ctypes
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import goodix_crypto as GC

VID, PID = 0x27C6, 0x6F94
EP_OUT, EP_IN = 0x01, 0x83

libusb = ctypes.CDLL("libusb-1.0.so.0")

# WICHTIG: ohne argtypes/restype kürzt ctypes 64-Bit-Zeiger auf 32 Bit -> Absturz.
_vp = ctypes.c_void_p
_ub = ctypes.POINTER(ctypes.c_ubyte)
libusb.libusb_init.argtypes = [ctypes.POINTER(_vp)]
libusb.libusb_init.restype = ctypes.c_int
libusb.libusb_open_device_with_vid_pid.argtypes = [_vp, ctypes.c_uint16, ctypes.c_uint16]
libusb.libusb_open_device_with_vid_pid.restype = _vp
libusb.libusb_kernel_driver_active.argtypes = [_vp, ctypes.c_int]
libusb.libusb_detach_kernel_driver.argtypes = [_vp, ctypes.c_int]
libusb.libusb_claim_interface.argtypes = [_vp, ctypes.c_int]
libusb.libusb_release_interface.argtypes = [_vp, ctypes.c_int]
libusb.libusb_close.argtypes = [_vp]
libusb.libusb_exit.argtypes = [_vp]
libusb.libusb_bulk_transfer.argtypes = [_vp, ctypes.c_ubyte, _ub, ctypes.c_int,
                                        ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
libusb.libusb_bulk_transfer.restype = ctypes.c_int
libusb.libusb_clear_halt.argtypes = [_vp, ctypes.c_ubyte]
libusb.libusb_clear_halt.restype = ctypes.c_int


# ----------------------------------------------------------------- Framing

def crc8(data):
    crc = 0
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc ^= (0x1070 << 3)
            crc = (crc << 1) & 0xFFFF
    return (~(crc >> 8)) & 0xFF


def pack(cmd0, cmd1, seq, payload):
    length = len(payload) + 4
    hp = bytes([cmd0, cmd1, 0x00, seq & 0xFF]) + struct.pack("<H", length)
    c = crc8(hp)
    header = hp + bytes([c, (~c) & 0xFF])
    body = header + payload
    return body + struct.pack("<I", binascii.crc32(body) & 0xFFFFFFFF)


def pad64(d):
    if len(d) % 64:
        d += b"\x00" * (64 - len(d) % 64)
    return d


def parse(raw):
    """Zerlegt ein Geräte-Paket -> (cmd0, cmd1, seq, payload) oder None."""
    if len(raw) < 12:
        return None
    plf = raw[4] | (raw[5] << 8)
    if plf < 4 or len(raw) < 8 + plf:
        return None
    return raw[0], raw[1], raw[3], raw[8:8 + plf - 4]


# ----------------------------------------------------------------- USB

class Device:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.seq = 0
        self.ctx = ctypes.c_void_p()
        if libusb.libusb_init(ctypes.byref(self.ctx)) != 0:
            raise RuntimeError("libusb_init fehlgeschlagen.")
        h = libusb.libusb_open_device_with_vid_pid(self.ctx, VID, PID)
        if not h:
            raise RuntimeError("Sensor 27c6:6f94 nicht gefunden (sudo?).")
        self.h = ctypes.c_void_p(h)
        if libusb.libusb_kernel_driver_active(self.h, 0) == 1:
            libusb.libusb_detach_kernel_driver(self.h, 0)
        if libusb.libusb_claim_interface(self.h, 0) != 0:
            raise RuntimeError("Interface 0 belegt (fprintd/alter Test läuft?).")
        self._drain()

    def _drain(self):
        """Verwirft Reststatus/liegengebliebene IN-Pakete einer Vorsession.
           Behebt das 'erster Lauf hakt'-Verhalten."""
        for _ in range(8):
            if self._bulk_in(timeout=120) is None:
                break

    def _bulk_out(self, data):
        arr = (ctypes.c_ubyte * len(data))(*data)
        n = ctypes.c_int()
        r = libusb.libusb_bulk_transfer(self.h, EP_OUT, arr, len(data),
                                        ctypes.byref(n), 2000)
        if r != 0:
            # Bei Stall/IO-Fehler Endpunkt zurücksetzen und einmal wiederholen
            libusb.libusb_clear_halt(self.h, EP_OUT)
            libusb.libusb_clear_halt(self.h, EP_IN)
            r = libusb.libusb_bulk_transfer(self.h, EP_OUT, arr, len(data),
                                            ctypes.byref(n), 2000)
            if r != 0:
                raise RuntimeError("Bulk-OUT fehlgeschlagen: %d" % r)

    def _bulk_in(self, timeout=2000, size=4096):
        buf = (ctypes.c_ubyte * size)()
        n = ctypes.c_int()
        r = libusb.libusb_bulk_transfer(self.h, EP_IN, buf, size,
                                        ctypes.byref(n), timeout)
        if r != 0:
            return None
        return bytes(buf[:n.value])

    def send(self, cmd0, cmd1, payload=b""):
        pkt = pad64(pack(cmd0, cmd1, self.seq, payload))
        self.seq = (self.seq + 1) & 0xFF
        for i in range(0, len(pkt), 64):
            self._bulk_out(pkt[i:i + 64])

    def recv(self, timeout=2000, want=None):
        """Liest Pakete bis eines mit cmd0==want (oder irgendeins) kommt.
           Überspringt ACKs (aa 00). Setzt fragmentierte Transfers zusammen."""
        buf = b""
        import time
        deadline = time.time() + timeout / 1000.0
        while time.time() < deadline:
            chunk = self._bulk_in(timeout=500)
            if chunk:
                buf += chunk
            p = parse(buf)
            if p is None:
                continue
            cmd0, cmd1, seq, payload = p
            consumed = 8 + (buf[4] | buf[5] << 8)
            if consumed % 64:
                consumed += 64 - consumed % 64
            buf = buf[consumed:] if consumed < len(buf) else b""
            if cmd0 == 0xAA:      # ACK überspringen
                continue
            if want is None or cmd0 == want:
                return cmd0, cmd1, payload
        return None

    def close(self):
        try:
            libusb.libusb_release_interface(self.h, 0)
            libusb.libusb_close(self.h)
            libusb.libusb_exit(self.ctx)
        except Exception:
            pass

    # ---- verschlüsselter e3-Kanal ----
    def send_enc(self, cmd1, plaintext):
        """Sendet plaintext verschlüsselt via e3 <cmd1> 00 (mit 4-B-Längenpräfix)."""
        inner = GC.encrypt(plaintext)
        payload = struct.pack("<I", len(inner)) + inner
        self.send(0xE3, cmd1, payload)

    def recv_enc(self, timeout=3000):
        """Empfängt eine e3-Antwort und entschlüsselt sie. -> Klartext oder None."""
        r = self.recv(timeout=timeout, want=0xE3)
        if not r:
            return None
        _, _, payload = r
        inner = payload[1:]     # Status-Byte weg
        if len(inner) < 54 or inner[32:34] != b"\x01\xff":
            return ("RAW", payload)
        return GC.decrypt(inner)


# ----------------------------------------------------------------- Ablauf

def log(*args):
    print(*args, flush=True)


def bringup(dev):
    """Init-Sequenz wie im Windows-Mitschnitt bis zum ersten verschlüsselten e3."""
    log("--- Init-Sequenz ---")
    dev.send(0xE1, 0x04, b"\x00")            # POV_CONFIG
    r = dev.recv(want=0xE1)
    log("   e1 04 ->", r[2].hex() if r else "keine Antwort")


def verify_crypto_live(dev):
    """End-to-End-Beweis: inneren SDCP-ClientHello (162 B) senden, Zertifikats-
       Flight empfangen und mit den festen Keys entschlüsseln.

       Der 162-B-Klartext ist ein SDCP-ClientHello (nonce32 + EC-Punkt + EC-Punkt).
       Für den reinen Krypto-Beweis genügt ein beliebiger 162-B-Block: der Sensor
       antwortet auf e3 00 00 mit seinem (statischen) Zertifikats-Flight, den wir
       entschlüsseln. Ob der Sensor den ClientHello inhaltlich akzeptiert, ist für
       den Transport-Beweis unerheblich."""
    log("\n--- Krypto-Kanal live verifizieren ---")
    # Echter, vom Sensor bereits akzeptierter SDCP-ClientHello (aus dem
    # Mitschnitt entschlüsselt). Ephemerer Key ist alt, aber der Sensor liefert
    # seinen (statischen) Zertifikats-Flight zurück -> reicht als Krypto-Beweis.
    hello = bytes.fromhex(
        "f1570b5c76e5609ecd6e948407c6edab35d9dedec6f6e4a5fb7a5a3ad452b04d"
        "047a7cffa5406c3b1d3366efdb66caf0c1b7d9395def51df57266f4726ce4a429"
        "7871d51e38fa824f9156e8fda5d32831d7c20562d901d27e60ddc16eb15752c05"
        "04402c6e42271d92f6ccd0a3f60e901dfa947d19b65be878f9723b337fbc1cd04"
        "9453be4e23a61ebac0569d2487fb81353e2b83d72224314c5cf02a7f40d901335")
    dev.send_enc(0x02, hello)               # e3 02 00 (write)
    r = dev.recv(want=0xE3)
    log("   e3 02 -> Status/Len:", r[2].hex() if r else "-")
    dev.send_enc(0x00, hello)               # e3 00 00 (read server flight)
    pt = dev.recv_enc()
    if isinstance(pt, tuple):
        log("   e3 00 -> unverschlüsselte/kurze Antwort:", pt[1][:16].hex())
        return
    if pt is None:
        log("   keine Antwort auf e3 00.")
        return
    log("   e3 00 -> %d B entschlüsselt: %s…" % (len(pt), pt[:16].hex()))
    if pt[:4] == b"\x71\x04\x00\x00" or b"\x30\x82\x03\x4b" in pt:
        log("\n   *** ERFOLG: Sensor-Zertifikat live entschlüsselt — "
            "Transport+Krypto funktionieren end-to-end auf der Hardware! ***")
    else:
        log("   (Antwort entschlüsselt, aber kein Zertifikat erkannt — Struktur prüfen.)")


HERE_ROOT = os.path.dirname(os.path.abspath(__file__))


def finger_probe(dev, seconds=20):
    """Liest live Sensor-/Fingerdaten: pollt a2 00 00 (Wait-Finger) und b0 02
       (Kalibrier-/Sensorwerte). Zeigt, ob wir Fingerpräsenz erkennen können.
       Finger während des Laufs auflegen und wieder abheben."""
    import time
    log("\n--- Finger-Probe: %d s lang a2/b0 pollen ---" % seconds)
    log("    >>> Finger mehrfach auf den Sensor legen und abheben <<<\n")
    end = time.time() + seconds
    last = None
    while time.time() < end:
        dev.send(0xA2, 0x00, bytes.fromhex("01002301"))    # Wait/Query Finger
        a2 = dev.recv(want=0xA2, timeout=1500)
        dev.send(0xB0, 0x02, b"\x00")                      # Kalibrier-/Sensorwerte
        b0 = dev.recv(want=0xB0, timeout=1500)
        a2h = a2[2].hex() if a2 else "-"
        # b0: erste paar 16-Bit-Werte als grober "Aktivitäts"-Indikator
        vals = ""
        if b0 and len(b0[2]) >= 8:
            import struct as _s
            vals = " ".join(str(v) for v in _s.unpack("<4H", b0[2][:8]))
        line = "a2=%s  b0[:4]=%s" % (a2h, vals)
        if line != last:
            log("   " + line)
            last = line
        time.sleep(0.2)
    log("\n   Wenn sich a2/b0 beim Auflegen sichtbar geändert haben, können wir")
    log("   Fingerpräsenz und Sensorwerte live lesen — die Basis für Verify.")


def verify_probe(dev, seconds=25):
    """Testet, ob Verify OHNE vollständiges SDCP funktioniert: pollt auf Finger
       und sendet dann a5 00 00 (SDCP-Key/Verify). 1110 B Antwort = Match-Token,
       0x01 = kein Match, anderes = Sensor erzwingt evtl. gültiges SDCP.
       Finger auf einen bei Windows enrollten Sensor legen."""
    import os as _os
    import time
    log("\n--- Verify-Probe (ohne SDCP): a5 00 00 mit Finger ---")
    log("    >>> Enrollten Finger auflegen und liegen lassen <<<\n")
    # Vorsequenz wie im Mitschnitt vor a5
    dev.send(0xB0, 0x02, b"\x00"); dev.recv(want=0xB0, timeout=1000)
    dev.send(0xE0, 0x01, b"\x00"); dev.recv(want=0xE0, timeout=1000)
    end = time.time() + seconds
    tries = 0
    while time.time() < end and tries < 12:
        dev.send(0xA2, 0x00, bytes.fromhex("01002301"))
        a2 = dev.recv(want=0xA2, timeout=1500)
        if not a2:
            continue
        # a5 00 00 mit 32-B-Challenge (Host-Nonce); Inhalt scheint frei wählbar
        dev.send(0xA5, 0x00, _os.urandom(32))
        a5 = dev.recv(want=0xA5, timeout=2000)
        tries += 1
        if not a5:
            log("   a2=%s  a5-> keine Antwort" % a2[2].hex())
            continue
        payload = a5[2]
        if len(payload) >= 100:
            log("   a2=%s  a5-> %d B  *** MATCH-TOKEN! ***" % (a2[2].hex(), len(payload)))
            log("        %s…" % payload[:48].hex())
            _os.makedirs(os.path.join(HERE_ROOT, "hw_out"), exist_ok=True)
            open(os.path.join(HERE_ROOT, "hw_out", "a5_match.bin"), "wb").write(payload)
            log("        gespeichert: scratch/hw_out/a5_match.bin")
            break
        else:
            log("   a2=%s  a5-> %s (%s)"
                % (a2[2].hex(), payload.hex(),
                   {b"\x01": "kein Match", b"\x04": "nicht authentifiziert/kein SDCP"}
                   .get(payload, "?")))
        time.sleep(0.3)
    log("\n   1110 B = Match, 0x01 = kein Match, 0x04 = SDCP erzwungen.")


def enroll_probe(dev, seconds=40):
    """TROCKENLAUF Enroll: Setup (OTP -> a7 -> a1 begin) + a0-Sample-Schleife mit
       Fortschritts-Anzeige. KEIN a4-Commit -> es wird KEIN Template gespeichert,
       der Sensorzustand bleibt unverändert. Zeigt, ob Enroll ohne SDCP läuft.

       Finger WIEDERHOLT auflegen/abheben (leicht versetzt), bis der Fortschritt
       Richtung 0x64 (100 %) geht."""
    import time
    log("\n--- Enroll-Probe (Trockenlauf, KEIN Commit/kein Template) ---")
    # 1. OTP lesen
    dev.send(0xA6, 0x00, b"\x00")
    otp = dev.recv(want=0xA6, timeout=1500)
    if not otp:
        log("   a6 (READ_OTP) keine Antwort — Abbruch."); return
    ob = otp[2]
    log("   OTP: %s" % ob[:24].hex())
    # a7-Payload aus dem OTP bauen: 01 00 62004304f5 00 <16B> + Padding auf 102B
    # Struktur aus dem Mitschnitt: 01 00 62004304f5 00 <16B OTP-Nonce> ...
    otp16 = ob[8:24] if len(ob) >= 24 else ob[:16].ljust(16, b"\x00")
    a7 = bytes.fromhex("010062004304f500") + otp16
    a7 = a7.ljust(102, b"\x00")
    dev.send(0xA7, 0x02, a7)
    r = dev.recv(want=0xA7, timeout=1500)
    log("   a7 02 -> %s" % (r[2].hex() if r else "-"))
    import os as _os
    # a1 begin
    dev.send(0xA1, 0x00, b"\x00")
    r = dev.recv(want=0xA1, timeout=1500)
    log("   a1 00 (begin) -> %s%s" % (r[2][:16].hex() if r else "-",
                                      "…" if r and len(r[2]) > 16 else ""))

    def sdcp_identity():
        """e3 02 / e3 01 mit Dummy-32B-Identity — wie im Mitschnitt vor jedem
           angerechneten a0. Testet, ob die Identity nur transportiert oder
           inhaltlich geprüft wird."""
        ident = _os.urandom(32)
        dev.send_enc(0x02, ident); dev.recv(want=0xE3, timeout=1500)
        dev.send_enc(0x01, ident); dev.recv(want=0xE3, timeout=1500)

    log("\n   >>> Finger jetzt wiederholt auflegen/abheben (leicht versetzt) <<<\n")
    end = time.time() + seconds
    n = 0
    best = 0
    while time.time() < end and n < 30:
        try:
            sdcp_identity()                                   # e3 02/e3 01 Identity
            dev.send(0xB0, 0x02, b"\x00")                     # Kalibrierwerte
            dev.recv(want=0xB0, timeout=1000)
            dev.send(0xA2, 0x00, bytes.fromhex("000f4101"))   # Frame erfassen
            a2 = dev.recv(want=0xA2, timeout=1500)
        except RuntimeError as e:
            log("   USB-Stall (%s), setze fort…" % e)
            time.sleep(0.3)
            continue
        if not a2:
            continue
        if a2[2][:1] == b"\xc0":
            time.sleep(0.15)
            continue
        try:
            dev.send(0xA0, 0x00, bytes.fromhex("016464"))     # Frame verarbeiten
            r = dev.recv(want=0xA0, timeout=1500)
        except RuntimeError as e:
            log("   USB-Stall bei a0 (%s), setze fort…" % e)
            continue
        n += 1
        if r:
            b = r[2]
            st = b[0] if b else 0xff
            prog = b[1] if len(b) > 1 else 0
            best = max(best, prog)
            tag = "" if st == 0 else "  <status 0x%02x>" % st
            log("   Sample %02d: a2=%s  a0=%s  Fortschritt=0x%02x(%d)%s"
                % (n, a2[2].hex(), b.hex(), prog, prog, tag))
        else:
            log("   Sample %02d: a0 keine Antwort" % n)
        time.sleep(0.1)
    log("\n   Höchster Fortschritt: 0x%02x (%d von 100)" % (best, best))
    log("   Kein Commit (a3/a4) gesendet — Sensor bleibt unverändert.")
    if best >= 0x40:
        log("   >>> Enroll-Sampling läuft ohne SDCP! Nächster Schritt: a3/a4-Commit. <<<")


def main():
    import sys as _sys
    mode = _sys.argv[1] if len(_sys.argv) > 1 else "crypto"
    try:
        dev = Device()
    except RuntimeError as e:
        log("FEHLER: %s" % e)
        return 1
    log("Interface 0 beansprucht. Sensor bereit.\n")
    try:
        bringup(dev)
        verify_crypto_live(dev)
        if mode == "finger":
            finger_probe(dev)
        elif mode == "verify":
            verify_probe(dev)
        elif mode == "enroll":
            enroll_probe(dev)
    finally:
        dev.close()
        log("\nGerät geschlossen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
