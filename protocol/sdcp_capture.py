#!/usr/bin/env python3
"""
sdcp_capture.py — echten SDCP-Handshake im WIRE-Format fahren und die
Session-Krypto sofort offline verifizieren.

WICHTIG: Das Draht-ClientHello ist (aus dem Windows-Mitschnitt bestätigt):
    nonce_c(32) || EC1(65) || EC2(65)   = 162 Bytes
Der Sensor antwortet mit dem ServerHello-Flight:
    [71 04 00 00] || cert(847) || tail(515)
Der 515B-Tail enthält 3 EC-Punkte (@0 statisch, @65 ephemeral, @290) und mehrere
32B-Blöcke — darunter Server-Nonce und Server-MAC.

Verifikation (Formel 1:1 aus GoodixMocSensorAdapter.dll disassembliert):
    Z          = ECDH(client_priv, server_EC)
    master     = SP800-108(Z,      "master secret\\0",    nonce_c||nonce_s, 32)
    session    = SP800-108(master, "application keys\\0",  <leer>,           64)
    transcript = SHA256(cert || tail[0:290])
    server_MAC = HMAC-SHA256(session[0:32], "connect\\0" || transcript)

Da unklar ist, welcher der beiden Client-Punkte / welcher Server-Punkt / welches
32B-Fenster nonce_s bzw. MAC ist, wird umfassend gesucht. Ein Treffer bestätigt
die gesamte Kette und legt alle Positionen fest.

    sudo python3 scratch/sdcp_capture.py
"""

import json, os, sys, struct, hashlib, hmac

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from goodix_gf3268 import Device
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdcp_capture.json")
ML = b"master secret\x00"
AL = b"application keys\x00"
CONNECT = b"connect\x00"


def eph():
    p = ec.generate_private_key(ec.SECP256R1())
    pub = p.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return pub, p.private_numbers().private_value.to_bytes(32, "big")


def ecdh(priv, pub):
    prv = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1())
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    return prv.exchange(ec.ECDH(), peer)


def kdf(key, label, ctx, n):
    o, i = b"", 1
    while len(o) < n:
        o += hmac.new(key, struct.pack(">I", i) + label + ctx + struct.pack(">I", n * 8),
                      hashlib.sha256).digest()
        i += 1
    return o[:n]


def find_ec_points(buf):
    """Alle 0x04-präfixierten 65B-Punkte, die gültige P-256-Punkte sind."""
    pts = []
    for o in range(len(buf) - 65):
        if buf[o] == 0x04:
            try:
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), buf[o:o + 65])
                pts.append((o, buf[o:o + 65]))
            except Exception:
                pass
    return pts


def verify(privs, nonce_c, sh):
    ci = sh.find(bytes.fromhex("3082034b"))
    if ci < 0:
        return None, "cert nicht gefunden"
    cert = sh[ci:ci + 847]
    tail = sh[ci + 847:]
    if len(tail) < 290:
        return None, "tail zu kurz (%d)" % len(tail)
    transcript = hashlib.sha256(cert + tail[0:290]).digest()
    server_pts = find_ec_points(sh)
    windows = [sh[o:o + 32] for o in range(0, len(sh) - 31)]
    tested = 0
    for pi, priv in enumerate(privs):
        for sp_off, sp in server_pts:
            try:
                Z = ecdh(priv, sp)
            except Exception:
                continue
            for order in (0, 1):
                for ns_off in range(0, len(sh) - 31):
                    ns = sh[ns_off:ns_off + 32]
                    ctx = (nonce_c + ns) if order == 0 else (ns + nonce_c)
                    master = kdf(Z, ML, ctx, 32)
                    session = kdf(master, AL, b"", 64)
                    for kh, key in (("s0", session[:32]), ("s1", session[32:])):
                        mac = hmac.new(key, CONNECT + transcript, hashlib.sha256).digest()
                        tested += 1
                        if mac in sh:
                            return {"priv": pi, "server_ec_off": sp_off, "order": order,
                                    "nonce_s_off": ns_off, "key_half": kh,
                                    "mac_off": sh.find(mac), "tested": tested}, "TREFFER"
    return None, "kein Treffer (%d getestet)" % tested


def main():
    try:
        dev = Device()
    except RuntimeError as e:
        print("FEHLER:", e); return 1
    print("Sensor bereit. SDCP-Handshake im 162B-Wire-Format …")
    try:
        dev.send(0xE1, 0x04, b"\x00"); dev.recv(want=0xE1, timeout=1500)
        pub1, priv1 = eph()
        pub2, priv2 = eph()
        nonce_c = os.urandom(32)
        hello = nonce_c + pub1 + pub2
        assert len(hello) == 162

        dev.send_enc(0x02, hello)
        r1 = dev.recv(want=0xE3, timeout=2000)
        status = r1[2].hex() if r1 else None
        print("  e3 02 ->", status)

        dev.send_enc(0x00, hello)
        resp = dev.recv_enc(timeout=3000)
        if resp is None:
            print("  e3 00 -> keine Antwort"); return 2
        sh = resp[1][1:] if isinstance(resp, tuple) else resp
        print("  e3 00 -> ServerHello %d B: %s…" % (len(sh), sh[:16].hex()))

        data = {"nonce_c": nonce_c.hex(), "priv1": priv1.hex(), "pub1": pub1.hex(),
                "priv2": priv2.hex(), "pub2": pub2.hex(), "client_hello": hello.hex(),
                "e3_02_status": status, "server_hello": sh.hex()}
        with open(OUT, "w") as f:
            json.dump(data, f, indent=2)
        print("Gespeichert:", OUT)

        print("\n== Umfassende Offline-Verifikation ==")
        hit, msg = verify([priv1, priv2], nonce_c, sh)
        if hit:
            print("  *** TREFFER — SDCP-Session-Krypto rekonstruiert! ***")
            print("      client-priv : priv%d" % (hit["priv"] + 1))
            print("      server-EC @ : %d" % hit["server_ec_off"])
            print("      nonce-Reih. : %s" % ("nc||ns" if hit["order"] == 0 else "ns||nc"))
            print("      nonce_s @   : %d" % hit["nonce_s_off"])
            print("      session-key : %s" % hit["key_half"])
            print("      MAC @       : %d" % hit["mac_off"])
            data["solved"] = hit
            with open(OUT, "w") as f:
                json.dump(data, f, indent=2)
        else:
            print("  %s" % msg)
            print("  (ServerHello gespeichert — ich analysiere weiter.)")
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
