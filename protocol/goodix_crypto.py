#!/usr/bin/env python3
"""
goodix_crypto.py — Session-Verschlüsselung des Goodix GF3268 (27c6:6f94).

Vollständig aus GoodixMocSensorAdapter.dll rekonstruiert und gegen 159
mitgeschnittene Nachrichten verifiziert (AES 159/159, HMAC 159/159).

Die Schlüssel sind FESTE, im Treiber versteckte Konstanten (per Emulation der
Obfuskations-Funktionen gewonnen, siehe scratch/emulate_ki.py). Sie sind
geräte- und sitzungsunabhängig — es gibt keinen Handshake auf dem Draht.

Wire-Format des e3-Payloads (nach dem 8-Byte-Paketkopf, ohne Status-Byte):
    MAC(32) || 01 ff || plaintext_len(LE32) || IV(16) || AES-128-CBC(PKCS7(plaintext))
  - AES-128-CBC-Schlüssel: AES_KEY
  - MAC = HMAC-SHA256(MAC_KEY, 01ff || plaintext_len(LE32) || ciphertext)
  - IV: beim Senden aus dem Klartext abgeleitet (siehe derive_iv); der Empfänger
        nutzt den IV aus dem Paket, daher ist ein beliebiger IV auch zulässig.

Herkunft der Schlüssel (reproduzierbar):
    KI = FUN_180034be0() || FUN_180033960()   (je 16 B obfuskierte Konstante)
    keyblock = SP800-108-CounterKDF(KI, "kgoodwixg\\0", "kaelrgnoerlithm", 384 bit)
    AES_KEY, MAC_KEY = keyblock[:16], keyblock[16:48]
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- Feste Session-Schlüssel (verifiziert 159/159) ---
# --- Session-Schlüssel (Platzhalter für öffentliche Veröffentlichung) ---
# Für eigene Tests können die Schlüssel hier eintragen oder per Umgebungsvariablen übergeben werden.
AES_KEY = bytes.fromhex(os.environ.get("GOODIX_AES_KEY", "00" * 16))
MAC_KEY = bytes.fromhex(os.environ.get("GOODIX_MAC_KEY", "00" * 32))

# Master-Key und KDF-Parameter (Platzhalter)
KI = bytes.fromhex(os.environ.get("GOODIX_KI", "00" * 32))
KDF_LABEL = b"kgoodwixg\x00"
KDF_CONTEXT = b"kaelrgnoerlithm"


def derive_keys(ki=KI):
    """SP 800-108 Counter-Mode-KDF (HMAC-SHA256), wie im Treiber. -> (aes, mac)."""
    L = 48
    out, i = b"", 1
    while len(out) < L:
        msg = struct.pack(">I", i) + KDF_LABEL + KDF_CONTEXT + struct.pack(">I", L * 8)
        out += hmac.new(ki, msg, hashlib.sha256).digest()
        i += 1
    return out[:16], out[16:48]


def _mac(plaintext_len, ciphertext):
    body = b"\x01\xff" + struct.pack("<I", plaintext_len) + ciphertext
    return hmac.new(MAC_KEY, body, hashlib.sha256).digest()


def derive_iv(plaintext):
    """IV-Ableitung wie im Treiber (FUN_180030bc0): SHA256 über
       01ff || len(LE32) || plaintext || (16x 4-Byte-Zähler 0x00000003), erste 16 B.
       Für ausgehende Pakete nicht zwingend nötig (Empfänger nutzt Paket-IV),
       aber hier zur Originaltreue nachgebaut."""
    h = hashlib.sha256()
    h.update(b"\x01\xff")
    h.update(struct.pack("<I", len(plaintext)))
    h.update(plaintext)
    h.update(struct.pack("<I", 3) * 16)
    return h.digest()[:16]


def _pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    n = data[-1]
    if not (1 <= n <= 16) or data[-n:] != bytes([n]) * n:
        raise ValueError("ungültiges PKCS7-Padding")
    return data[:-n]


def encrypt(plaintext, iv=None):
    """Baut den inneren e3-Payload: MAC || 01ff || len || IV || CT."""
    if iv is None:
        iv = derive_iv(plaintext)
    ct = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv)).encryptor()
    ciphertext = ct.update(_pkcs7_pad(plaintext)) + ct.finalize()
    mac = _mac(len(plaintext), ciphertext)
    return mac + b"\x01\xff" + struct.pack("<I", len(plaintext)) + iv + ciphertext


def decrypt(payload, verify=True):
    """Zerlegt einen inneren e3-Payload und gibt den Klartext zurück."""
    mac, marker = payload[:32], payload[32:34]
    if marker != b"\x01\xff":
        raise ValueError("Marker 01ff fehlt (kein verschlüsselter e3-Payload)")
    plen = struct.unpack("<I", payload[34:38])[0]
    iv, ciphertext = payload[38:54], payload[54:]
    if verify and _mac(plen, ciphertext) != mac:
        raise ValueError("MAC-Prüfung fehlgeschlagen")
    pt = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv)).decryptor()
    plaintext = pt.update(ciphertext) + pt.finalize()
    return _pkcs7_unpad(plaintext)[:plen]


if __name__ == "__main__":
    # Selbsttest: Keys aus KI reproduzieren + Round-trip
    a, m = derive_keys()
    assert a == AES_KEY and m == MAC_KEY, "KDF reproduziert die Keys nicht!"
    msg = b"hello goodix, this is a test payload of some length"
    p = encrypt(msg)
    assert decrypt(p) == msg, "round-trip fehlgeschlagen"
    print("Selbsttest OK — KDF reproduziert die Keys, encrypt/decrypt round-trip passt.")
    print("AES_KEY =", AES_KEY.hex())
    print("MAC_KEY =", MAC_KEY.hex())
