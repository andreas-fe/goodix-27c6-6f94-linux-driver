#!/usr/bin/env python3
"""Controlled GF3268 SDCP experiment, for firmware 01010032 only.

--inspect reads metadata. --session-check additionally checks two fresh SDCP
sessions and reconnect MACs. --enroll enables a single experimental enrollment
and requires --reference NEW_FILE (private 0600 metadata snapshot).

No C0 configuration writes, A7 deletes, USB reset/detach/halt recovery, service
changes or automatic enrollment retries are implemented. Existing records are
never modified intentionally. Enrollment is experimental: 13 accepted A0
updates, including 000000, match the saved Windows traces, not a firmware API
guarantee. A3 is a duplicate check. A4 is attempted once. No A5 precheck is
performed here: use a separately verified new finger. New-finger verification
and fprintd binding must be performed separately after a successful commit.

The transport has strict CRC checks. SDCP verifies server key confirmation and
reconnect MACs; full certificate-chain/firmware attestation is NOT implemented.
Only bounded metadata, status codes and counts are printed, never records,
SIDs, template IDs, session keys, or captured biometric data. The reference
file intentionally contains exact record metadata for preservation checks.
"""

from __future__ import annotations

import argparse
import binascii
import ctypes
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from collections import Counter, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from goodix_probe import EP_IN, EP_OUT, ProbeError, ReadOnlyUsb, crc8, version_summary


class TrialError(ProbeError):
    pass


def records_from_reply(payload: bytes) -> tuple[bytes, ...]:
    if len(payload) < 2:
        raise TrialError("Template list has no count")
    count = int.from_bytes(payload[:2], "big")
    if count > 20 or len(payload) != 2 + 100 * count:
        raise TrialError("Template list is outside the known record layout")
    records = tuple(payload[2 + 100*i:102 + 100*i] for i in range(count))
    for record in records:
        if record[:4] != b"\x62\x00\x43\x04" or record[70] != 28 or record[99] != 0:
            raise TrialError("Template record is outside the known SDCP type-04 layout")
    return records


def compare_records(before: tuple[bytes, ...], after: tuple[bytes, ...], added=0) -> None:
    old, new = Counter(before), Counter(after)
    if old - new:
        raise TrialError("An original template record changed or disappeared; stop testing")
    if len(after) != len(before) + added or sum((new-old).values()) != added:
        raise TrialError("Template count changed unexpectedly; stop testing")


def reserve_reference(path: Path, version: dict, records: tuple[bytes, ...]) -> None:
    """Never overwrite a prior reference; make exact metadata durable first."""
    reserve_private_json(path, {"schema": "goodix-sdcp-reference-v1", "version": version,
                                "records_hex": [record.hex() for record in records]})


def reserve_private_json(path: Path, content: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as output:
            json.dump(content, output)
            output.write("\n")
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class CommandPolicy:
    """Hard boundary applied to plaintext immediately before every USB send."""

    FIXED = {
        (0xD0, 0): (b"\0",), (0xA6, 0): (b"\0",),
        (0xE1, 4): (b"\0",), (0xB0, 2): (b"\0",),
        (0xE0, 0): (b"\0",), (0xE0, 1): (b"\0",),
        (0xA2, 0): (bytes.fromhex("01002300"), bytes.fromhex("01002301"),
                    bytes.fromhex("000f4101")),
    }
    ENROLL = frozenset({0xA1, 0xA0, 0xA3, 0xA4})

    def __init__(self, mode: str):
        if mode not in ("inspect", "session-check", "enroll"):
            raise TrialError("Unknown trial mode")
        self.mode = mode
        self.reference_reserved = False
        self.begun = False
        self.accepted = self.attempts = self.commits = 0
        self.duplicate_checked = False
        self.expected_commit = None

    @property
    def sample_payload(self):
        return bytes.fromhex("016464" if self.accepted < 5 else "016450")

    def check(self, command: int, subcommand: int, payload: bytes):
        pair = command, subcommand
        if not isinstance(payload, bytes):
            raise TrialError("Command payload must be bytes")
        if pair in ((0xD0, 0), (0xA6, 0)) and payload == b"\0":
            return
        if self.mode == "inspect":
            raise TrialError("Inspect mode permits only version and template-list queries")
        if pair in self.FIXED and payload in self.FIXED[pair]:
            if command == 0xA2 and self.mode != "enroll":
                raise TrialError("Finger acquisition is disabled in session-check mode")
            return
        if command == 0xE3:
            valid = ((subcommand in (0, 2) and len(payload) == 162 and
                      payload[32] == 4 and payload[97] == 4) or
                     (subcommand in (1, 2) and len(payload) == 32))
            if not valid:
                raise TrialError("Unsupported SDCP plaintext request")
            return
        if command not in self.ENROLL or subcommand != 0 or self.mode != "enroll":
            raise TrialError("Command is outside the trial whitelist")
        if not self.reference_reserved:
            raise TrialError("Enrollment requires a durable private reference first")
        if command == 0xA1 and payload == b"\0" and not self.begun:
            self.begun = True
            return
        if command == 0xA0 and self.begun and self.accepted < 13 and not self.duplicate_checked:
            if payload != self.sample_payload or self.attempts >= 39:
                raise TrialError("Sample parameters or attempt budget are outside policy")
            self.attempts += 1
            return
        if command == 0xA3 and payload == b"\0" and self.begun and self.accepted == 13:
            if self.duplicate_checked:
                raise TrialError("Duplicate check is not repeated")
            return
        if command == 0xA4 and self.duplicate_checked and self.commits == 0:
            if self.expected_commit is None or payload != self.expected_commit or len(payload) != 100:
                raise TrialError("Commit differs from the prepared record")
            self.commits += 1  # Count before the transfer: an uncertain write is never retried.
            return
        raise TrialError("Enrollment command is out of sequence")

    def accept_sample(self, reply: bytes) -> bool:
        if len(reply) != 3 or not self.begun or self.accepted >= 13:
            raise TrialError("Invalid sample reply or sample state")
        if reply[0] == 0:
            self.accepted += 1
            return True
        if reply[0] in (0x72, 0x73):
            return False
        raise TrialError(f"Unexpected A0 status {reply[0]:02x}; capture aborted")

    def accept_duplicate_check(self, reply: bytes):
        if self.accepted != 13 or reply != b"\0":
            raise TrialError("Duplicate check did not confirm a clear result")
        self.duplicate_checked = True


def validate_transport_keys(aes_key: bytes, mac_key: bytes):
    if len(aes_key) != 16 or len(mac_key) != 32 or not any(aes_key) or not any(mac_key):
        raise TrialError("Configure private GOODIX_AES_KEY (16 bytes) and GOODIX_MAC_KEY (32 bytes); public defaults are placeholders")


class TrialUsb(ReadOnlyUsb):
    """Reuse safe libusb lifecycle and decoder; add guarded volatile commands."""

    def __init__(self, policy: CommandPolicy, library=None):
        super().__init__(library)
        self.policy = policy
        self.pending = deque()

    def __enter__(self):
        if self.policy.mode != "inspect":
            sys.path.insert(0, str(ROOT / "protocol"))
            import goodix_crypto
            validate_transport_keys(goodix_crypto.AES_KEY, goodix_crypto.MAC_KEY)
        return super().__enter__()

    def query(self, command: int, subcommand: int = 0) -> bytes:
        return self.exchange(command, subcommand, b"\0")

    def exchange(self, command: int, subcommand: int, payload: bytes, timeout=3.0) -> bytes:
        self.policy.check(command, subcommand, payload)
        if not self.claimed:
            raise TrialError("Sensor interface is not open")
        if command == 0xE3:
            sys.path.insert(0, str(ROOT / "protocol"))
            import goodix_crypto
            inner = goodix_crypto.encrypt(payload)
            payload = struct.pack("<I", len(inner)) + inner
        prefix = bytes((command, subcommand, 0, self.sequence)) + struct.pack("<H", len(payload)+4)
        check = crc8(prefix)
        packet = prefix + bytes((check, check ^ 0xff)) + payload
        packet += struct.pack("<I", binascii.crc32(packet) & 0xffffffff)
        packet += b"\0" * ((-len(packet)) % 64)
        self.sequence = (self.sequence + 1) & 0xff
        for offset in range(0, len(packet), 64):
            part = packet[offset:offset+64]
            data = (ctypes.c_ubyte * len(part)).from_buffer_copy(part)
            transferred = ctypes.c_int()
            status = self.lib.libusb_bulk_transfer(self.handle, EP_OUT, data, len(data),
                                                  ctypes.byref(transferred), 1000)
            if status != 0 or transferred.value != len(part):
                raise TrialError(f"USB write failed ({status}); no retry performed")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.pending:
                data = (ctypes.c_ubyte * 4096)()
                transferred = ctypes.c_int()
                status = self.lib.libusb_bulk_transfer(self.handle, EP_IN, data, len(data),
                                                      ctypes.byref(transferred), 250)
                if status not in (0, -7):
                    raise TrialError(f"USB read failed ({status}); no recovery performed")
                if transferred.value:
                    self.pending.extend(self.decoder.feed(bytes(data[:transferred.value])))
                continue
            frame = self.pending.popleft()
            if frame.command == 0xAA:
                if len(frame.payload) < 2 or frame.payload[1] != command or frame.payload[0] != 0:
                    raise TrialError("Malformed or rejected acknowledgement")
                continue
            if (frame.command, frame.subcommand) != (command, subcommand):
                raise TrialError("Unexpected response; refusing to continue with uncertain state")
            return frame.payload
        raise TrialError("Sensor response timeout; no retry performed")


def kdf(key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    return b"".join(hmac.new(key, struct.pack(">I", index) + label + context +
                             struct.pack(">I", length*8), hashlib.sha256).digest()
                    for index in range(1, (length+31)//32 + 1))[:length]


class Session:
    def __init__(self, transport, key: bytes):
        self.transport, self.key = transport, key

    @classmethod
    def connect(cls, transport):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        sys.path.insert(0, str(ROOT / "protocol"))
        import goodix_crypto
        status_ok(transport.exchange(0xE1, 4, b"\0"), "E1")
        private = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
        nonce = os.urandom(32)
        hello = nonce + b"".join(key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                                  for key in private)
        prepared = transport.exchange(0xE3, 2, hello)
        if len(prepared) != 5 or prepared[0] != 0:
            raise TrialError("SDCP connect preparation failed")
        response = transport.exchange(0xE3, 0, hello)
        if not response or response[0] != 0:
            raise TrialError("SDCP connection failed")
        try:
            server = goodix_crypto.decrypt(response[1:])
            if len(server) != 1366 or server[4:8] != bytes.fromhex("3082034b"):
                raise TrialError("Unsupported ServerHello layout")
            certificate, tail = server[4:851], server[851:]
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), tail[65:130])
            transcript = hashlib.sha256(certificate + tail[:290]).digest()
            for key in private:
                master = kdf(key.exchange(ec.ECDH(), peer), b"master secret\0", nonce+tail[451:483], 32)
                session_key = kdf(master, b"application keys\0", b"", 64)[:32]
                expected = hmac.new(session_key, b"connect\0"+transcript, hashlib.sha256).digest()
                if hmac.compare_digest(expected, tail[419:451]):
                    return cls(transport, session_key)
        except (ValueError, IndexError, struct.error):
            raise TrialError("Malformed or unauthenticated ServerHello") from None
        raise TrialError("SDCP server key-confirmation MAC failed")

    def reconnect(self):
        nonce = os.urandom(32)
        prepared = self.transport.exchange(0xE3, 2, nonce)
        if len(prepared) != 5 or prepared[0] != 0:
            raise TrialError("SDCP reconnect preparation failed")
        response = self.transport.exchange(0xE3, 1, nonce)
        expected = hmac.new(self.key, b"reconnect\0"+nonce, hashlib.sha256).digest()
        if len(response) != 33 or response[0] != 0 or not hmac.compare_digest(response[1:], expected):
            raise TrialError("SDCP reconnect MAC failed; session context is uncertain")


def status_ok(reply: bytes, operation: str):
    if not reply or reply[0] != 0:
        status = f"{reply[0]:02x}" if reply else "missing"
        raise TrialError(f"{operation} returned status {status}")


def prepare_commit(source: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(source) != 100 or len(key) != 32 or len(nonce) != 32:
        raise TrialError("Cannot prepare commit from invalid metadata")
    records_from_reply(b"\0\1" + source)
    mac = hmac.new(key, b"enroll\0"+nonce, hashlib.sha256).digest()
    # Byte 5 is the stored-record flag in A6; the successful A4 trace sends 00.
    return source[:5] + b"\0" + os.urandom(16) + b"\0"*16 + mac + source[70:]


def run(mode: str, reference: Path | None = None, transport_class=TrialUsb) -> dict:
    policy = CommandPolicy(mode)
    result = {"mode": mode, "commit_attempted": False, "new_finger_verification": "not_run"}
    with transport_class(policy) as device:
        version = version_summary(device.query(0xD0))
        if version["firmware_version"] != "01010032" or version["sensor"] != "GF3268":
            raise TrialError("Trial only supports the captured GF3268 firmware 01010032")
        before = records_from_reply(device.query(0xA6))
        result.update(version=version, templates_before=len(before))
        if mode == "enroll":
            if reference is None or not before:
                raise TrialError("Enrollment requires a new private reference file and an existing type-04 record")
            reserve_reference(reference, version, before)
            policy.reference_reserved = True
        primary_error = None
        try:
            if mode != "inspect":
                first = Session.connect(device)
                first.reconnect()
                second = Session.connect(device)
                if hmac.compare_digest(first.key, second.key):
                    raise TrialError("Fresh SDCP session did not change its key")
                second.reconnect()
                result["fresh_sessions_and_reconnects_verified"] = True
            if mode == "enroll":
                status_ok(device.exchange(0xB0, 2, b"\0"), "Calibration")
                status_ok(device.exchange(0xE0, 1, b"\0"), "Power button shield")
                nonce_reply = device.exchange(0xA1, 0, b"\0")
                if len(nonce_reply) != 33 or nonce_reply[0] != 0:
                    raise TrialError("A1 did not return the expected enrollment nonce")
                nonce = nonce_reply[1:]
                capture_deadline = time.monotonic() + 180
                capture_polls = 0
                while policy.accepted < 13:
                    if capture_polls >= 90 or time.monotonic() >= capture_deadline:
                        raise TrialError("Capture time or polling budget exhausted")
                    capture_polls += 1
                    print(f"Lift and reposition the finger: sample {policy.accepted+1}/13", file=sys.stderr, flush=True)
                    time.sleep(1.2)
                    second.reconnect()
                    status_ok(device.exchange(0xB0, 2, b"\0"), "Calibration")
                    capture = device.exchange(0xA2, 0, bytes.fromhex("000f4101"), timeout=15)
                    if capture and capture[0] in (0xC0, 0x71, 0x72, 0x73):
                        continue
                    status_ok(capture, "Finger capture")
                    reply = device.exchange(0xA0, 0, policy.sample_payload)
                    if policy.accept_sample(reply):
                        print(f"Sample {policy.accepted}/13 accepted", file=sys.stderr, flush=True)
                    else:
                        print("Excessive overlap: reposition the finger", file=sys.stderr, flush=True)
                policy.accept_duplicate_check(device.exchange(0xA3, 0, b"\0"))
                policy.expected_commit = prepare_commit(before[0], second.key, nonce)
                reserve_private_json(reference.with_name(reference.name + ".commit.json"),
                                     {"schema": "goodix-sdcp-commit-v1",
                                      "prepared_record_hex": policy.expected_commit.hex()})
                status_ok(device.exchange(0xA4, 0, policy.expected_commit), "Single A4 commit")
                result["commit_confirmed"] = True
        except (ProbeError, OSError) as error:
            primary_error = error
        except KeyboardInterrupt:
            primary_error = TrialError("Trial interrupted; no enrollment command will be retried")
        finally:
            result["commit_attempted"] = bool(policy.commits)
            result["accepted_samples"] = policy.accepted
            # Metadata postcheck is attempted even after an uncertain failed write.
            try:
                after_version = version_summary(device.query(0xD0))
                if after_version != version:
                    raise TrialError("Firmware metadata changed during trial")
                after = records_from_reply(device.query(0xA6))
                result["templates_after"] = len(after)
                if mode == "enroll":
                    reserve_reference(reference.with_name(reference.name + ".after.json"), version, after)
                if not (Counter(before) - Counter(after)):
                    result["original_records_preserved"] = True
                if policy.commits and not result.get("commit_confirmed") and len(after) == len(before) + 1:
                    result["possible_commit_despite_missing_confirmation"] = True
                expected_added = int(bool(result.get("commit_confirmed")))
                compare_records(before, after, added=expected_added)
                result["original_records_preserved"] = True
                if expected_added:
                    added = tuple((Counter(after)-Counter(before)).elements())
                    if added[0][38:70] != policy.expected_commit[38:70]:
                        raise TrialError("New record does not contain the prepared enrollment identifier")
                    result["new_record_confirmed"] = True
            except (ProbeError, OSError) as post_error:
                result["postcheck_failed"] = True
                if primary_error is None:
                    primary_error = post_error
            if mode == "enroll":
                try:
                    status_ok(device.exchange(0xE0, 0, b"\0"), "Power button shield cleanup")
                except (ProbeError, OSError) as cleanup_error:
                    result["shield_cleanup_failed"] = True
                    if primary_error is None:
                        primary_error = cleanup_error
            if primary_error is not None:
                # The caller receives the bounded summary without any record data.
                result["error"] = str(primary_error)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--inspect", action="store_true", help="Read only D0/A6 metadata")
    modes.add_argument("--session-check", action="store_true", help="Check fresh SDCP sessions without enrollment")
    modes.add_argument("--enroll", action="store_true", help="Experimental single new-template commit")
    parser.add_argument("--reference", type=Path, help="New private reference file, mandatory for --enroll")
    args = parser.parse_args(argv)
    mode = "enroll" if args.enroll else "session-check" if args.session_check else "inspect" if args.inspect else None
    if mode is None:
        parser.print_help()
        return 0
    if args.enroll and args.reference is None:
        parser.error("--enroll requires --reference pointing to a new file")
    if args.reference is not None and not args.enroll:
        parser.error("--reference is only used with --enroll")
    try:
        result = run(mode, args.reference)
    except (ProbeError, OSError, ImportError) as error:
        result = {"mode": mode, "error": str(error)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int("error" in result)


if __name__ == "__main__":
    raise SystemExit(main())
