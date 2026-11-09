"""Exercise the actual native C crypto implementation with an independent peer.

No USB access, vendor binaries, saved fingerprints or private key output.
"""
import ctypes as C
import hashlib
import hmac
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]


class Session(C.Structure):
    _fields_ = [("private_keys", C.c_void_p * 2), ("nonce", C.c_ubyte * 32),
                ("key", C.c_ubyte * 32), ("valid", C.c_int)]


def data(value):
    return (C.c_ubyte * len(value)).from_buffer_copy(value)


def kdf(key, label, context, size):
    return b"".join(hmac.new(key, struct.pack(">I", counter) + label + context +
                             struct.pack(">I", size * 8), hashlib.sha256).digest()
                    for counter in range(1, (size + 31) // 32 + 1))[:size]


class NativeCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="goodix-native-crypto-")
        output = Path(cls.temp.name) / "crypto.so"
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "glib-2.0", "openssl"], text=True))
        subprocess.run(["cc", "-shared", "-fPIC", "-Wno-deprecated-declarations",
                        str(ROOT / "driver/goodixsdcp_crypto.c"), "-o", str(output),
                        *flags], check=True, capture_output=True)
        cls.lib = C.CDLL(str(output))
        signatures = {
            "gsdcp_session_clear": ([C.POINTER(Session)], None),
            "gsdcp_session_start": ([C.POINTER(Session), C.c_void_p], C.c_int),
            "gsdcp_session_accept": ([C.POINTER(Session), C.c_void_p, C.c_size_t], C.c_int),
            "gsdcp_session_mac": ([C.POINTER(Session), C.c_char_p, C.c_void_p, C.c_size_t, C.c_void_p], C.c_int),
            "gsdcp_session_check_reconnect": ([C.POINTER(Session), C.c_void_p, C.c_void_p, C.c_size_t], C.c_int),
            "gsdcp_encrypt": ([C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t], C.c_size_t),
            "gsdcp_decrypt": ([C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t], C.c_ssize_t),
            "gsdcp_build_package": ([C.c_ubyte, C.c_ubyte, C.c_ubyte, C.c_void_p, C.c_size_t,
                                      C.c_void_p, C.c_size_t], C.c_size_t),
            "gsdcp_parse_packet": ([C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p,
                                    C.c_void_p, C.c_void_p, C.c_void_p], C.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(cls.lib, name)
            function.argtypes, function.restype = args, result

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.session = Session()

    def tearDown(self):
        self.lib.gsdcp_session_clear(C.byref(self.session))

    def encrypt(self, plaintext):
        out = (C.c_ubyte * 2048)()
        size = self.lib.gsdcp_encrypt(data(plaintext), len(plaintext), out, len(out))
        self.assertGreater(size, 0)
        return bytes(out[:size])

    def server_reply(self, *, second_client=False, bad_mac=False, bad_point=False):
        hello = (C.c_ubyte * 162)()
        self.assertTrue(self.lib.gsdcp_session_start(C.byref(self.session), hello))
        hello = bytes(hello)
        private = ec.generate_private_key(ec.SECP256R1())
        offset = 97 if second_client else 32
        client = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), hello[offset:offset+65])
        certificate = bytes.fromhex("3082034b") + b"c" * 843
        tail = bytearray(515)
        tail[65:130] = private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        tail[451:483] = b"s" * 32
        master = kdf(private.exchange(ec.ECDH(), client), b"master secret\0", hello[:32] + tail[451:483], 32)
        key = kdf(master, b"application keys\0", b"", 64)[:32]
        transcript = hashlib.sha256(certificate + tail[:290]).digest()
        tail[419:451] = hmac.new(key, b"connect\0" + transcript, hashlib.sha256).digest()
        if bad_mac:
            tail[419] ^= 1
        if bad_point:
            tail[65:130] = b"\0" * 65
        return b"\0" + self.encrypt(b"\x71\x04\0\0" + certificate + tail), key

    def accept(self, reply):
        return self.lib.gsdcp_session_accept(C.byref(self.session), data(reply), len(reply))

    def test_ecdh_kdf_and_server_mac_match_independent_python_peer(self):
        reply, expected = self.server_reply()
        self.assertTrue(self.accept(reply))
        self.assertEqual(bytes(self.session.key), expected)
        self.assertTrue(self.session.valid)
        self.assertEqual(list(self.session.private_keys), [None, None])

    def test_second_client_ec_point_fallback(self):
        reply, expected = self.server_reply(second_client=True)
        self.assertTrue(self.accept(reply))
        self.assertEqual(bytes(self.session.key), expected)

    def test_modified_server_mac_and_bad_point_fail_closed(self):
        for options in ({"bad_mac": True}, {"bad_point": True}):
            reply, _ = self.server_reply(**options)
            self.assertFalse(self.accept(reply))
            self.assertFalse(self.session.valid)
            self.assertEqual(bytes(self.session.key), b"\0" * 32)

    def test_reconnect_and_enrollment_labels_include_null_terminator(self):
        reply, key = self.server_reply()
        self.assertTrue(self.accept(reply))
        nonce = b"n" * 32
        expected = hmac.new(key, b"reconnect\0" + nonce, hashlib.sha256).digest()
        response = b"\0" + expected
        self.assertTrue(self.lib.gsdcp_session_check_reconnect(C.byref(self.session), data(nonce), data(response), 33))
        self.assertFalse(self.lib.gsdcp_session_check_reconnect(C.byref(self.session), data(b"x"*32), data(response), 33))
        out = (C.c_ubyte * 32)()
        self.assertTrue(self.lib.gsdcp_session_mac(C.byref(self.session), b"enroll", data(nonce), 32, out))
        self.assertEqual(bytes(out), hmac.new(key, b"enroll\0" + nonce, hashlib.sha256).digest())

    def test_session_restart_changes_nonce_and_explicit_clear_wipes_state(self):
        first, second = (C.c_ubyte * 162)(), (C.c_ubyte * 162)()
        self.assertTrue(self.lib.gsdcp_session_start(C.byref(self.session), first))
        self.assertTrue(self.lib.gsdcp_session_start(C.byref(self.session), second))
        self.assertNotEqual(bytes(first), bytes(second))
        self.lib.gsdcp_session_clear(C.byref(self.session))
        self.assertEqual(C.string_at(C.byref(self.session), C.sizeof(Session)), b"\0" * C.sizeof(Session))

    def test_truncated_or_corrupt_encrypted_response_is_rejected(self):
        reply, _ = self.server_reply()
        self.assertFalse(self.accept(reply[:-1]))
        reply, _ = self.server_reply()
        corrupted = bytearray(reply)
        corrupted[-1] ^= 1
        self.assertFalse(self.accept(corrupted))

    def test_transport_roundtrip_and_output_bound(self):
        message = b"test" * 40
        encrypted = self.encrypt(message)
        out = (C.c_ubyte * 2048)()
        length = self.lib.gsdcp_decrypt(data(encrypted), len(encrypted), out, len(out))
        self.assertEqual(bytes(out[:length]), message)
        self.assertEqual(self.lib.gsdcp_decrypt(data(encrypted), len(encrypted), out, 8), -1)

    def test_packet_crc_integrity_and_length_bound(self):
        out = (C.c_ubyte * 64)()
        size = self.lib.gsdcp_build_package(0xd0, 0, 0, data(b"\0"), 1, out, len(out))
        self.assertEqual(size, 64)
        self.assertTrue(self.lib.gsdcp_parse_packet(out, size, None, None, None, None, None))
        out[8] ^= 1
        self.assertFalse(self.lib.gsdcp_parse_packet(out, size, None, None, None, None, None))
        self.assertEqual(self.lib.gsdcp_build_package(0xd0, 0, 0, None, 65535, out, len(out)), 0)


if __name__ == "__main__":
    unittest.main()
