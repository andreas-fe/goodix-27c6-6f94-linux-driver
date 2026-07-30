#!/usr/bin/env python3
"""
goodix_verify.py — Fingerabdruck-Verify für PAM (Goodix GF3268, 27c6:6f94).

Wartet auf einen Finger, führt den On-Chip-Match aus und beendet sich mit:
    0  = Match       (Finger erkannt und akzeptiert)
    1  = kein Match  (Finger erkannt, aber kein passendes Template)
    2  = Timeout / kein Finger
    3  = Fehler (Sensor nicht erreichbar o.ä.)

Nutzt die geknackte Transport-Verschlüsselung (goodix_crypto). Es ist KEIN
Enroll nötig — es wird gegen die bereits im Chip registrierten Templates
(z.B. aus Windows) gematcht.

Gedacht für den Aufruf aus PAM via pam_exec (siehe install_pam.sh).
Aufruf-Test:   sudo python3 goodix_verify.py            # mit Ausgabe
               sudo python3 goodix_verify.py --quiet     # für PAM
"""

import ctypes
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import goodix_crypto as GC

VID, PID = 0x27C6, 0x6F94
EP_OUT, EP_IN = 0x01, 0x83

QUIET = "--quiet" in sys.argv or "quiet" in sys.argv


def _arg_timeout(default=6.0):
    for a in sys.argv[1:]:
        if a.startswith("--timeout="):
            try:
                return float(a.split("=", 1)[1])
            except ValueError:
                pass
    return default


TIMEOUT_S = _arg_timeout()
# Wenn nach dieser Zeit noch KEIN Finger anlag, früh aufgeben (schneller
# Rückfall auf Passwort, wichtig für den Sperrbildschirm).
GRACE_S = min(TIMEOUT_S, 2.5)


def log(*a):
    if not QUIET:
        print(*a, file=sys.stderr, flush=True)


# ---- libusb ----
_l = ctypes.CDLL("libusb-1.0.so.0")
_vp = ctypes.c_void_p
_ub = ctypes.POINTER(ctypes.c_ubyte)
_l.libusb_init.argtypes = [ctypes.POINTER(_vp)]
_l.libusb_open_device_with_vid_pid.argtypes = [_vp, ctypes.c_uint16, ctypes.c_uint16]
_l.libusb_open_device_with_vid_pid.restype = _vp
for fn in ("libusb_kernel_driver_active", "libusb_detach_kernel_driver",
           "libusb_claim_interface", "libusb_release_interface"):
    getattr(_l, fn).argtypes = [_vp, ctypes.c_int]
_l.libusb_close.argtypes = [_vp]
_l.libusb_exit.argtypes = [_vp]
_l.libusb_bulk_transfer.argtypes = [_vp, ctypes.c_ubyte, _ub, ctypes.c_int,
                                    ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
_l.libusb_clear_halt.argtypes = [_vp, ctypes.c_ubyte]


def crc8(d):
    c = 0
    for b in d:
        c ^= (b << 8)
        for _ in range(8):
            if c & 0x8000:
                c ^= (0x1070 << 3)
            c = (c << 1) & 0xFFFF
    return (~(c >> 8)) & 0xFF


def crc32(d):
    import binascii
    return binascii.crc32(d) & 0xFFFFFFFF


def pack(cmd0, cmd1, seq, payload):
    hp = bytes([cmd0, cmd1, 0, seq & 0xFF]) + struct.pack("<H", len(payload) + 4)
    c = crc8(hp)
    body = hp + bytes([c, (~c) & 0xFF]) + payload
    body += struct.pack("<I", crc32(body))
    if len(body) % 64:
        body += b"\x00" * (64 - len(body) % 64)
    return body


class Dev:
    def __init__(self):
        self.seq = 0
        self.ctx = ctypes.c_void_p()
        if _l.libusb_init(ctypes.byref(self.ctx)) != 0:
            raise RuntimeError("libusb_init")
        h = _l.libusb_open_device_with_vid_pid(self.ctx, VID, PID)
        if not h:
            raise RuntimeError("Sensor nicht gefunden")
        self.h = ctypes.c_void_p(h)
        if _l.libusb_kernel_driver_active(self.h, 0) == 1:
            _l.libusb_detach_kernel_driver(self.h, 0)
        if _l.libusb_claim_interface(self.h, 0) != 0:
            raise RuntimeError("Interface belegt")
        for _ in range(8):
            if self._in(120) is None:
                break

    def _out(self, data):
        arr = (ctypes.c_ubyte * len(data))(*data)
        n = ctypes.c_int()
        r = _l.libusb_bulk_transfer(self.h, EP_OUT, arr, len(data), ctypes.byref(n), 2000)
        if r != 0:
            _l.libusb_clear_halt(self.h, EP_OUT)
            _l.libusb_clear_halt(self.h, EP_IN)
            if _l.libusb_bulk_transfer(self.h, EP_OUT, arr, len(data),
                                       ctypes.byref(n), 2000) != 0:
                raise RuntimeError("bulk-out")

    def _in(self, timeout=2000, size=4096):
        buf = (ctypes.c_ubyte * size)()
        n = ctypes.c_int()
        if _l.libusb_bulk_transfer(self.h, EP_IN, buf, size, ctypes.byref(n), timeout) != 0:
            return None
        return bytes(buf[:n.value])

    def send(self, c0, c1, payload=b""):
        pkt = pack(c0, c1, self.seq, payload)
        self.seq = (self.seq + 1) & 0xFF
        for i in range(0, len(pkt), 64):
            self._out(pkt[i:i + 64])

    def recv(self, want=None, timeout=2500):
        buf = b""
        deadline = time.time() + timeout / 1000.0
        while time.time() < deadline:
            ch = self._in(500)
            if ch:
                buf += ch
            if len(buf) < 12:
                continue
            plf = buf[4] | buf[5] << 8
            if plf < 4 or len(buf) < 8 + plf:
                continue
            c0, c1, payload = buf[0], buf[1], buf[8:8 + plf - 4]
            consumed = 8 + plf
            if consumed % 64:
                consumed += 64 - consumed % 64
            buf = buf[consumed:] if consumed < len(buf) else b""
            if c0 == 0xAA:
                continue
            if want is None or c0 == want:
                return c0, c1, payload
        return None

    def send_enc(self, c1, pt):
        inner = GC.encrypt(pt)
        self.send(0xE3, c1, struct.pack("<I", len(inner)) + inner)

    def close(self):
        try:
            _l.libusb_release_interface(self.h, 0)
            _l.libusb_close(self.h)
            _l.libusb_exit(self.ctx)
        except Exception:
            pass


HELLO = bytes.fromhex(
    "f1570b5c76e5609ecd6e948407c6edab35d9dedec6f6e4a5fb7a5a3ad452b04d"
    "047a7cffa5406c3b1d3366efdb66caf0c1b7d9395def51df57266f4726ce4a429"
    "7871d51e38fa824f9156e8fda5d32831d7c20562d901d27e60ddc16eb15752c05"
    "04402c6e42271d92f6ccd0a3f60e901dfa947d19b65be878f9723b337fbc1cd04"
    "9453be4e23a61ebac0569d2487fb81353e2b83d72224314c5cf02a7f40d901335")


def main():
    try:
        dev = Dev()
    except RuntimeError as e:
        log("Fehler:", e)
        return 3
    try:
        # Transport-Kanal hochfahren
        dev.send(0xE1, 0x04, b"\x00"); dev.recv(want=0xE1, timeout=1500)
        dev.send_enc(0x02, HELLO); dev.recv(want=0xE3, timeout=1500)
        dev.send_enc(0x00, HELLO); dev.recv(want=0xE3, timeout=2500)
        dev.send(0xB0, 0x02, b"\x00"); dev.recv(want=0xB0, timeout=1000)
        dev.send(0xE0, 0x01, b"\x00"); dev.recv(want=0xE0, timeout=1000)

        log(">>> Finger auflegen …")
        start = time.time()
        deadline = start + TIMEOUT_S
        saw_finger = False
        while time.time() < deadline:
            dev.send(0xA2, 0x00, bytes.fromhex("01002301"))
            a2 = dev.recv(want=0xA2, timeout=1200)
            if not a2 or a2[2][:1] == b"\xc0":       # kein Finger
                # Wenn in der Grace-Zeit gar kein Finger kam: früh aufgeben.
                if not saw_finger and time.time() - start > GRACE_S:
                    break
                continue
            saw_finger = True
            dev.send(0xA5, 0x00, os.urandom(32))
            a5 = dev.recv(want=0xA5, timeout=2000)
            if a5 and len(a5[2]) >= 100:
                log("MATCH")
                return 0
            # 0x01 = kein Match -> weiter versuchen (Finger evtl. schlecht aufgelegt)
            time.sleep(0.2)
        log("kein Match" if saw_finger else "Timeout / kein Finger")
        return 1 if saw_finger else 2
    finally:
        dev.close()


if __name__ == "__main__":
    sys.exit(main())
