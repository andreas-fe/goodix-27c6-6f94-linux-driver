#!/usr/bin/env python3
"""
check_finger.py — ist der aufliegende Finger bereits registriert?

a5 (mit aufliegendem Finger) -> langer Token (>=100B) = MATCH (registriert)
                             -> '01'                    = kein Match (FRISCH)
Schnell: stabile Verify-Präambel, EIN Fingertest.

    sudo python3 scratch/check_finger.py
"""

import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from goodix_gf3268 import Device

HELLO = bytes.fromhex(
    "f1570b5c76e5609ecd6e948407c6edab35d9dedec6f6e4a5fb7a5a3ad452b04d"
    "047a7cffa5406c3b1d3366efdb66caf0c1b7d9395def51df57266f4726ce4a429"
    "7871d51e38fa824f9156e8fda5d32831d7c20562d901d27e60ddc16eb15752c05"
    "04402c6e42271d92f6ccd0a3f60e901dfa947d19b65be878f9723b337fbc1cd04"
    "9453be4e23a61ebac0569d2487fb81353e2b83d72224314c5cf02a7f40d901335")


def main():
    try:
        dev = Device()
    except RuntimeError as e:
        print("FEHLER:", e); return 1
    try:
        def cmd(c0, c1, p, to=2000):
            dev.send(c0, c1, p); r = dev.recv(want=c0, timeout=to)
            return r[2] if r else None
        cmd(0xE1, 0x04, b"\x00")
        dev.send_enc(0x02, HELLO); dev.recv(want=0xE3, timeout=1500)
        dev.send_enc(0x00, HELLO); dev.recv(want=0xE3, timeout=2500)
        cmd(0xB0, 0x02, b"\x00"); cmd(0xE0, 0x01, b"\x00")
        print("★ bereit.\n")

        print("  Teste mehrere Finger. Pro Finger: auflegen, Enter drücken.")
        print("  ('q' + Enter zum Beenden)\n")
        n = 0
        while True:
            s = input("  Finger %d auflegen, dann Enter (oder q): " % (n + 1))
            if s.strip().lower() == "q":
                break
            n += 1
            # kurz auf Finger warten
            a2 = cmd(0xA2, 0x00, bytes.fromhex("01002301"), to=1200)
            if not a2 or a2[:1] == b"\xc0":
                print("    -> kein Finger erkannt, nochmal.\n"); n -= 1; continue
            a5 = cmd(0xA5, 0x00, os.urandom(32), to=2500)
            if a5 and len(a5) >= 100:
                print("    -> REGISTRIERT (Match-Token, %dB)\n" % len(a5))
            elif a5 == b"\x01":
                print("    -> FRISCH (kein Match) — für Enroll geeignet!\n")
            else:
                print("    -> a5 = %s (%dB)\n" % (a5.hex()[:20] if a5 else "-", len(a5) if a5 else 0))
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
