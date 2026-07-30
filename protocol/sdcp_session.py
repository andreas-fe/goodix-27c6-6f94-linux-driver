#!/usr/bin/env python3
"""
sdcp_session.py — SDCP-Handshake + Session-Key-Ableitung (verifiziert).

Kern des nativen Treibers: fährt den SDCP-Handshake über den e3-Transportkanal,
leitet den Session-Key ab und verifiziert den Server-MAC. Ab da stehen
session_key und die identity()-Funktion für Enroll/Verify bereit.

Alle Formeln 1:1 aus GoodixMocSensorAdapter.dll disassembliert und live
gegen die Hardware verifiziert (siehe HANDOVER_COWORK.md Abschnitt 36).

    sudo python3 scratch/sdcp_session.py           # Handshake + Selbsttest
"""

import os
import sys
import struct
import hashlib
import hmac

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from goodix_gf3268 import Device
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ML = b"master secret\x00"
AL = b"application keys\x00"


def _eph():
    p = ec.generate_private_key(ec.SECP256R1())
    pub = p.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return pub, p.private_numbers().private_value.to_bytes(32, "big")


def _ecdh(priv, pub):
    prv = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1())
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    return prv.exchange(ec.ECDH(), peer)


def sp800_108(key, label, ctx, n):
    """NIST SP800-108 Counter Mode (FUN_180011de0). Label inkl. Nullterminator."""
    out, i = b"", 1
    while len(out) < n:
        out += hmac.new(key, struct.pack(">I", i) + label + ctx + struct.pack(">I", n * 8),
                        hashlib.sha256).digest()
        i += 1
    return out[:n]


class SdcpSession:
    """Ein etablierter SDCP-Session-Kontext (nach erfolgreichem Handshake)."""

    def __init__(self, dev):
        self.dev = dev
        self.session_key = None      # session[0:32]  (MAC/Identity-Key)
        self.session_key2 = None     # session[32:64]
        self.master = None
        self.nonce_c = None
        self.nonce_s = None
        self.cert = None
        self.server_hello = None

    # -- Handshake --------------------------------------------------------
    def connect(self):
        d = self.dev
        d.send(0xE1, 0x04, b"\x00"); d.recv(want=0xE1, timeout=1500)

        pub1, priv1 = _eph()
        pub2, priv2 = _eph()
        self.nonce_c = os.urandom(32)
        hello = self.nonce_c + pub1 + pub2         # 162B Wire-ClientHello
        assert len(hello) == 162

        d.send_enc(0x02, hello)
        d.recv(want=0xE3, timeout=2000)
        d.send_enc(0x00, hello)
        resp = d.recv_enc(timeout=3000)
        if resp is None:
            raise RuntimeError("kein ServerHello")
        sh = resp[1][1:] if isinstance(resp, tuple) else resp
        self.server_hello = sh

        ci = sh.find(bytes.fromhex("3082034b"))
        if ci < 0:
            raise RuntimeError("Zertifikat nicht im ServerHello")
        cert = sh[ci:ci + 847]
        tail = sh[ci + 847:]
        self.cert = cert
        EC_B = tail[65:130]                        # Server-Ephemeral
        self.nonce_s = tail[451:483]
        mac_field = tail[419:451]

        # Session-Key ableiten (priv1 ist der ECDH-Client-Key)
        Z = _ecdh(priv1, EC_B)
        self.master = sp800_108(Z, ML, self.nonce_c + self.nonce_s, 32)
        session = sp800_108(self.master, AL, b"", 64)
        self.session_key, self.session_key2 = session[:32], session[32:]

        # Server-MAC verifizieren (Key-Confirmation)
        transcript = hashlib.sha256(cert + tail[0:290]).digest()
        want = hmac.new(self.session_key, b"connect\x00" + transcript, hashlib.sha256).digest()
        if want != mac_field:
            # Fallback: priv2 (falls Sensor den zweiten Punkt nahm)
            Z2 = _ecdh(priv2, EC_B)
            m2 = sp800_108(Z2, ML, self.nonce_c + self.nonce_s, 32)
            s2 = sp800_108(m2, AL, b"", 64)
            w2 = hmac.new(s2[:32], b"connect\x00" + transcript, hashlib.sha256).digest()
            if w2 == mac_field:
                self.master, self.session_key, self.session_key2 = m2, s2[:32], s2[32:]
            else:
                raise RuntimeError("Server-MAC stimmt nicht — Handshake ungültig")
        return self

    # -- Identity/MAC (FUN_1800124b0) ------------------------------------
    def identity(self, label, *data_blocks):
        """HMAC-SHA256(session_key, label||0x00 || data_blocks...).
           label z.B. b'connect', b'enroll', b'identify'."""
        mac = hmac.new(self.session_key, label + b"\x00", hashlib.sha256)
        for b in data_blocks:
            mac.update(b)
        return mac.digest()


def main():
    try:
        dev = Device()
    except RuntimeError as e:
        print("FEHLER:", e); return 1
    try:
        s = SdcpSession(dev).connect()
        print("★ SDCP-Handshake erfolgreich — Server-MAC verifiziert.")
        print("  session_key : %s" % s.session_key.hex())
        print("  session_key2: %s" % s.session_key2.hex())
        print("  nonce_s     : %s" % s.nonce_s.hex())
        print("  Zertifikat  : %d B (Windows Hello Secure BIO Sensor)" % len(s.cert))
        print("\n  Bereit für Identity-basierte Enroll-/Verify-Kommandos.")
    except RuntimeError as e:
        print("FEHLER:", e); return 2
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
