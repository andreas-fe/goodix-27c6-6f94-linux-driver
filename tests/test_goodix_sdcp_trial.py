"""Boundaries and trace-based SDCP enrollment policy; no hardware access."""

import hashlib
import hmac
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("goodix_sdcp_trial", Path(__file__).parents[1] / "experiments/goodix_sdcp_trial.py")
trial = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = trial
SPEC.loader.exec_module(trial)


def record(seed=1):
    return bytes.fromhex("62004304f500") + bytes([seed])*32 + bytes([seed+1])*32 + b"\x1c" + b"\x01"*28 + b"\0"


def version_reply():
    fields = (b"APP", b"01010032", b"RONGYAO", b"GM188B0", b"GF3268", b"1.04.05.")
    return (b"\0\x02\xfe" + b"".join(value.ljust(8, b"\0") for value in fields)).ljust(129, b"\0")


class PublicTransportKeyTests(unittest.TestCase):
    def test_placeholder_keys_are_rejected_before_live_sdcp(self):
        for aes, mac in ((b"\0"*16, b"\0"*32), (b"a"*16, b"\0"*32), (b"a"*15, b"b"*32)):
            with self.assertRaises(trial.TrialError):
                trial.validate_transport_keys(aes, mac)

    def test_configured_nonzero_keys_have_the_expected_sizes(self):
        trial.validate_transport_keys(b"a"*16, b"b"*32)


class PolicyTests(unittest.TestCase):
    def test_inspect_permits_only_metadata(self):
        policy = trial.CommandPolicy("inspect")
        for command in range(256):
            if command in (0xd0, 0xa6):
                policy.check(command, 0, b"\0")
            else:
                with self.assertRaises(trial.TrialError):
                    policy.check(command, 0, b"\0")

    def test_session_check_rejects_enrollment_even_with_reference(self):
        policy = trial.CommandPolicy("session-check")
        policy.reference_reserved = True
        for command, payload in ((0xa1, b"\0"), (0xa0, b"\x01\x64\x64"),
                                 (0xa3, b"\0"), (0xa4, record()), (0xa2, bytes.fromhex("000f4101"))):
            with self.assertRaises(trial.TrialError):
                policy.check(command, 0, payload)

    def test_c0_a7_and_unknown_subcommands_are_always_rejected(self):
        for mode in ("inspect", "session-check", "enroll"):
            policy = trial.CommandPolicy(mode)
            policy.reference_reserved = True
            for command in (0xc0, 0xa7):
                for subcommand in range(256):
                    with self.assertRaises(trial.TrialError):
                        policy.check(command, subcommand, b"\0"*128)
            for command in (0xd0, 0xa6, 0xe1, 0xb0, 0xe0, 0xa2, 0xa1, 0xa0, 0xa3, 0xa4, 0xe3):
                with self.assertRaises(trial.TrialError):
                    policy.check(command, 255, b"\0")

    def test_reference_required_before_a1(self):
        with self.assertRaises(trial.TrialError):
            trial.CommandPolicy("enroll").check(0xa1, 0, b"\0")

    def test_saved_windows_trace_policy_counts_zero_overlay_samples(self):
        # Actual A0 replies in goodix_handshake_and_enroll.pcapng.
        replies = [bytes.fromhex(value) for value in (
            "000000", "003232", "00612a", "002f10", "000000", "005524", "726451",
            "006200", "005600", "004200", "00641e", "00612b", "000000", "006400")]
        policy = trial.CommandPolicy("enroll")
        policy.reference_reserved = True
        policy.check(0xa1, 0, b"\0")
        requests = []
        for reply in replies:
            requests.append(policy.sample_payload)
            policy.check(0xa0, 0, policy.sample_payload)
            policy.accept_sample(reply)
        self.assertEqual(policy.accepted, 13)
        self.assertEqual(requests[:5], [bytes.fromhex("016464")]*5)
        self.assertEqual(requests[5:], [bytes.fromhex("016450")]*9)
        with self.assertRaises(trial.TrialError):
            policy.check(0xa0, 0, bytes.fromhex("016450"))
        policy.check(0xa3, 0, b"\0")
        policy.accept_duplicate_check(b"\0")
        policy.expected_commit = record()
        policy.check(0xa4, 0, policy.expected_commit)
        with self.assertRaises(trial.TrialError):
            policy.check(0xa4, 0, policy.expected_commit)

    def test_74_is_failure_and_never_completion(self):
        policy = trial.CommandPolicy("enroll")
        policy.begun = True
        with self.assertRaises(trial.TrialError):
            policy.accept_sample(bytes.fromhex("746400"))
        self.assertEqual(policy.accepted, 0)

    def test_wrong_phase_payload_is_rejected(self):
        policy = trial.CommandPolicy("enroll")
        policy.reference_reserved = policy.begun = True
        policy.accepted = 5
        with self.assertRaises(trial.TrialError):
            policy.check(0xa0, 0, bytes.fromhex("016464"))

    def test_reconnect_plaintext_sizes_are_bounded(self):
        policy = trial.CommandPolicy("session-check")
        policy.check(0xe3, 1, b"n"*32)
        for subcommand, payload in ((0, b"n"*32), (1, b"n"*162), (2, b"n"*10000), (2, b"n"*162)):
            with self.assertRaises(trial.TrialError):
                policy.check(0xe3, subcommand, payload)


class ReferenceTests(unittest.TestCase):
    def test_reference_is_private_durable_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "reference.json"
            trial.reserve_reference(destination, {}, (record(),))
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            original = destination.read_bytes()
            with self.assertRaises(FileExistsError):
                trial.reserve_reference(destination, {}, ())
            self.assertEqual(destination.read_bytes(), original)

    def test_reference_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("keep")
            link = Path(directory) / "reference"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                trial.reserve_reference(link, {}, ())
            self.assertEqual(target.read_text(), "keep")

    def test_record_comparison_requires_exact_original_bytes(self):
        old = (record(),)
        trial.compare_records(old, old+(record(5),), added=1)
        for changed in ((), (record(2),), (record(2), record(5)), old+(record(5), record(7))):
            with self.assertRaises(trial.TrialError):
                trial.compare_records(old, changed, added=1)

    def test_commit_uses_nonce_mac_and_reuses_only_known_identity_metadata(self):
        source = record()
        key, nonce = b"k"*32, b"n"*32
        body = trial.prepare_commit(source, key, nonce)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[:6], bytes.fromhex("62004304f500"))
        self.assertEqual(body[22:38], b"\0"*16)
        self.assertEqual(body[38:70], hmac.new(key, b"enroll\0"+nonce, hashlib.sha256).digest())
        self.assertEqual(body[70:], source[70:])


class SessionTests(unittest.TestCase):
    def test_reconnect_verifies_actual_nonce_mac(self):
        key = b"k"*32
        calls = []
        def exchange(command, subcommand, payload):
            calls.append((command, subcommand, payload))
            if subcommand == 2:
                return bytes.fromhex("004f030000")
            return b"\0" + hmac.new(key, b"reconnect\0"+payload, hashlib.sha256).digest()
        trial.Session(SimpleNamespace(exchange=exchange), key).reconnect()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][2], calls[1][2])
        self.assertEqual(len(calls[0][2]), 32)

    def test_reconnect_rejects_bad_mac(self):
        def exchange(command, subcommand, payload):
            return bytes.fromhex("004f030000") if subcommand == 2 else b"\0"*33
        with self.assertRaises(trial.TrialError):
            trial.Session(SimpleNamespace(exchange=exchange), b"k"*32).reconnect()

    def test_full_handshake_derives_key_from_actual_generated_client_ec_point(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            sys.path.insert(0, str(trial.ROOT / "protocol"))
            import goodix_crypto
        except ImportError:
            self.skipTest("cryptography unavailable")
        peer_private = ec.generate_private_key(ec.SECP256R1())
        expected_key = None
        tamper = False
        def exchange(command, subcommand, payload):
            nonlocal expected_key
            if command == 0xe1:
                return b"\0"*4
            if subcommand == 2:
                return bytes.fromhex("004f030000")
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), payload[32:97])
            certificate = bytes.fromhex("3082034b") + b"c"*843
            tail = bytearray(515)
            tail[65:130] = peer_private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            tail[451:483] = b"s"*32
            master = trial.kdf(peer_private.exchange(ec.ECDH(), peer), b"master secret\0", payload[:32]+tail[451:483], 32)
            expected_key = trial.kdf(master, b"application keys\0", b"", 64)[:32]
            transcript = hashlib.sha256(certificate + tail[:290]).digest()
            tail[419:451] = hmac.new(expected_key, b"connect\0"+transcript, hashlib.sha256).digest()
            if tamper:
                tail[419] ^= 1
            return b"\0" + goodix_crypto.encrypt(b"\x71\x04\0\0"+certificate+tail)
        session = trial.Session.connect(SimpleNamespace(exchange=exchange))
        self.assertEqual(session.key, expected_key)
        tamper = True
        with self.assertRaises(trial.TrialError):
            trial.Session.connect(SimpleNamespace(exchange=exchange))


class FakeTransport:
    instances = []
    commit_status = b"\0"
    lost_commit_reply = False
    cleanup_failure = False
    no_finger_replies = 0

    def __init__(self, policy):
        self.policy = policy
        self.records = [record()]
        self.calls = []
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def query(self, command, subcommand=0):
        return self.exchange(command, subcommand, b"\0")

    def exchange(self, command, subcommand, payload, **kwargs):
        self.policy.check(command, subcommand, payload)
        self.calls.append((command, subcommand, payload))
        if command == 0xd0:
            return version_reply()
        if command == 0xa6:
            return len(self.records).to_bytes(2, "big") + b"".join(self.records)
        if command == 0xa1:
            return b"\0"+b"n"*32
        if command == 0xa0:
            return b"\0\0\0"
        if command == 0xa2 and self.__class__.no_finger_replies:
            self.__class__.no_finger_replies -= 1
            return b"\xc0"
        if command == 0xa4:
            if self.commit_status == b"\0":
                self.records.append(payload)
            if self.lost_commit_reply:
                raise trial.TrialError("Simulated lost commit response")
            return self.commit_status
        if command == 0xe0 and subcommand == 0 and self.cleanup_failure:
            raise trial.TrialError("Simulated cleanup failure")
        return b"\0"


class EndToEndPolicyTests(unittest.TestCase):
    def setUp(self):
        FakeTransport.instances = []
        FakeTransport.commit_status = b"\0"
        FakeTransport.lost_commit_reply = False
        FakeTransport.cleanup_failure = False
        FakeTransport.no_finger_replies = 0

    def test_inspect_never_changes_sensor_mode(self):
        result = trial.run("inspect", transport_class=FakeTransport)
        self.assertTrue(result["original_records_preserved"])
        self.assertEqual([command for command, _, _ in FakeTransport.instances[0].calls], [0xd0, 0xa6, 0xd0, 0xa6])

    def run_enrollment(self, path):
        sessions = [SimpleNamespace(key=value*32, reconnect=lambda: None) for value in (b"a", b"b")]
        with patch.object(trial.Session, "connect", side_effect=sessions), patch.object(trial.time, "sleep"), patch("sys.stderr", io.StringIO()):
            return trial.run("enroll", path, transport_class=FakeTransport)

    def test_one_commit_after_13_accepted_zero_overlay_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_enrollment(Path(directory) / "reference")
        self.assertNotIn("error", result)
        self.assertTrue(result["new_record_confirmed"])
        self.assertEqual(result["templates_after"], result["templates_before"]+1)
        self.assertTrue(result["original_records_preserved"])
        self.assertEqual(result["new_finger_verification"], "not_run")
        calls = FakeTransport.instances[0].calls
        updates = [payload for command, _, payload in calls if command == 0xa0]
        self.assertEqual(updates, [bytes.fromhex("016464")]*5 + [bytes.fromhex("016450")]*8)
        self.assertEqual(sum(command == 0xa4 for command, _, _ in calls), 1)
        self.assertFalse(any(command in (0xc0, 0xa7) for command, _, _ in calls))

    def test_failed_commit_is_never_retried(self):
        FakeTransport.commit_status = b"\xff"
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_enrollment(Path(directory) / "reference")
        self.assertIn("error", result)
        self.assertNotIn("new_record_confirmed", result)
        self.assertTrue(result["original_records_preserved"])
        self.assertEqual(sum(command == 0xa4 for command, _, _ in FakeTransport.instances[0].calls), 1)

    def test_lost_commit_response_preserves_private_after_record_and_never_retries(self):
        FakeTransport.lost_commit_reply = True
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "reference"
            result = self.run_enrollment(reference)
            prepared = json.loads(Path(str(reference) + ".commit.json").read_text())
            after_path = Path(str(reference) + ".after.json")
            after = json.loads(after_path.read_text())
            self.assertEqual(stat.S_IMODE(after_path.stat().st_mode), 0o600)
            self.assertIn(prepared["prepared_record_hex"], after["records_hex"])
        self.assertIn("error", result)
        self.assertTrue(result["possible_commit_despite_missing_confirmation"])
        self.assertTrue(result["original_records_preserved"])
        self.assertEqual(sum(command == 0xa4 for command, _, _ in FakeTransport.instances[0].calls), 1)

    def test_cleanup_failure_is_not_reported_as_full_success(self):
        FakeTransport.cleanup_failure = True
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_enrollment(Path(directory) / "reference")
        self.assertTrue(result["commit_confirmed"])
        self.assertTrue(result["shield_cleanup_failed"])
        self.assertIn("error", result)

    def test_no_finger_wait_does_not_count_a_sample(self):
        FakeTransport.no_finger_replies = 1
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_enrollment(Path(directory) / "reference")
        self.assertNotIn("error", result)
        calls = FakeTransport.instances[0].calls
        self.assertEqual(sum(command == 0xa2 for command, _, _ in calls), 14)
        self.assertEqual(sum(command == 0xa0 for command, _, _ in calls), 13)


if __name__ == "__main__":
    unittest.main()
