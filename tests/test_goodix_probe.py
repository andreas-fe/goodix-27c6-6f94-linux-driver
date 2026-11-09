"""Protocol integrity and write-boundary tests; no hardware required."""

import binascii
import ctypes
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("goodix_probe", Path(__file__).parents[1] / "scripts/goodix_probe.py")
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def frame(command, payload, subcommand=0):
    header = bytes((command, subcommand, 0, 12)) + struct.pack("<H", len(payload) + 4)
    check = probe.crc8(header)
    body = header + bytes((check, check ^ 0xFF)) + payload
    return body + struct.pack("<I", binascii.crc32(body) & 0xFFFFFFFF)


class ProtocolTests(unittest.TestCase):
    def test_whitelist_rejects_all_other_commands(self):
        for command in range(256):
            for subcommand in range(256):
                if (command, subcommand) in probe.READ_COMMANDS:
                    continue
                with self.assertRaises(probe.ProbeError):
                    probe.query_packet(command, subcommand)

    def test_version_query_matches_independent_capture_vector(self):
        self.assertEqual(probe.query_packet(0xD0).hex(), "d00000000500ba4500611a297f")

    def test_fragmented_padded_ack_and_response(self):
        ack = frame(0xAA, b"\x00\xd0\x00\x01")
        response = frame(0xD0, b"\x00" + b"\x00" * 128)
        wire = ack + b"\x00" * ((-len(ack)) % 64) + response + b"\x00" * ((-len(response)) % 64)
        for chunk_size in (1, 7, 64, 4096):
            decoder, result = probe.FrameDecoder(), []
            for offset in range(0, len(wire), chunk_size):
                result.extend(decoder.feed(wire[offset:offset + chunk_size]))
            decoder.finish()
            self.assertEqual([item.command for item in result], [0xAA, 0xD0])

    def test_device_padding_may_contain_nonzero_buffer_contents(self):
        ack = frame(0xAA, b"\x00\xd0\x00\x01")
        response = frame(0xD0, b"\x00" + b"\x00" * 128)
        wire = ack + b"!" * ((-len(ack)) % 64) + response + b"?" * ((-len(response)) % 64)
        for chunk_size in (1, 7, 64, 4096):
            decoder, result = probe.FrameDecoder(padded=True), []
            for offset in range(0, len(wire), chunk_size):
                result.extend(decoder.feed(wire[offset:offset + chunk_size]))
            decoder.finish()
            self.assertEqual([item.command for item in result], [0xAA, 0xD0])

    def test_unpadded_adjacent_packets(self):
        result = probe.FrameDecoder().feed(frame(0xAA, b"\x00\xd0") + frame(0xD0, b"\x00"))
        self.assertEqual([item.command for item in result], [0xAA, 0xD0])

    def test_corruption_is_rejected(self):
        wire = frame(0xD0, b"metadata")
        for index in (4, 6, 7, 8, len(wire) - 1):
            changed = bytearray(wire)
            changed[index] ^= 1
            decoder = probe.FrameDecoder()
            with self.assertRaises(probe.ProbeError):
                decoder.feed(changed)
                decoder.finish()

    def test_truncated_packet_is_not_accepted(self):
        decoder = probe.FrameDecoder()
        self.assertEqual(decoder.feed(frame(0xD0, b"metadata")[:-1]), [])
        with self.assertRaises(probe.ProbeError):
            decoder.finish()

    def test_template_summary_never_contains_record_data(self):
        secret = b"private-record".ljust(100, b"!")
        self.assertEqual(probe.template_summary(b"\x00\x01" + secret), {"template_count": 1, "record_size": 100})
        with self.assertRaises(probe.ProbeError):
            probe.template_summary(b"\x00\x02" + secret)

    def test_version_summary_ignores_reserved_identifiers(self):
        fields = [b"APP", b"01010032", b"RONGYAO", b"GM188B0", b"GF3268", b"1.04.05."]
        payload = b"\x00\x02\xfe" + b"".join(value.ljust(8, b"\x00") for value in fields)
        payload = payload.ljust(129, b"X")
        result = probe.version_summary(payload)
        self.assertEqual(result["firmware_version"], "01010032")
        self.assertNotIn("XXXXXXXX", str(result))


class FakeUsb:
    def __init__(self, claim_status=0, init_status=0, incoming=None):
        self.claim_status, self.init_status = claim_status, init_status
        self.calls = []
        self.incoming = list(incoming or [])
        self.sent = []

    def libusb_init(self, context):
        self.calls.append("init")
        return self.init_status

    def libusb_open_device_with_vid_pid(self, *args):
        self.calls.append("open")
        return 1

    def libusb_kernel_driver_active(self, *args):
        return 0

    def libusb_claim_interface(self, *args):
        self.calls.append("claim")
        return self.claim_status

    def libusb_release_interface(self, *args):
        self.calls.append("release")

    def libusb_close(self, *args):
        self.calls.append("close")

    def libusb_exit(self, *args):
        self.calls.append("exit")

    def libusb_bulk_transfer(self, handle, endpoint, buffer, length, transferred, timeout):
        if endpoint == probe.EP_OUT:
            self.sent.append(bytes(buffer[:length]))
            size = length
        else:
            if not self.incoming:
                raise AssertionError("Unexpected extra USB read")
            data = bytes(self.incoming.pop(0))
            size = len(data)
            ctypes.memmove(buffer, data, size)
        ctypes.cast(transferred, ctypes.POINTER(ctypes.c_int))[0] = size
        return 0


class LifecycleTests(unittest.TestCase):
    def test_version_exchange_sends_only_fixed_query_and_skips_ack(self):
        ack = frame(0xAA, b"\x00\xd0\x00\x01")
        response = frame(0xD0, b"\x00" + b"\x00" * 128)
        fake = FakeUsb(incoming=[ack.ljust(64, b"!"), response.ljust(192, b"?")])
        with probe.ReadOnlyUsb(fake) as device:
            self.assertEqual(len(device.query(0xD0)), 129)
        self.assertEqual(fake.sent, [probe.query_packet(0xD0)])
        self.assertEqual(fake.calls, ["init", "open", "claim", "release", "close", "exit"])

    def test_bad_response_crc_closes_resources_without_retry(self):
        response = bytearray(frame(0xD0, b"\x00" + b"\x00" * 128))
        response[20] ^= 1
        fake = FakeUsb(incoming=[response.ljust(192, b"\x00")])
        with self.assertRaises(probe.ProbeError):
            with probe.ReadOnlyUsb(fake) as device:
                device.query(0xD0)
        self.assertEqual(len(fake.sent), 1)
        self.assertEqual(fake.calls[-3:], ["release", "close", "exit"])

    def test_claim_failure_closes_initialized_resources(self):
        fake = FakeUsb(claim_status=-6)
        with self.assertRaises(probe.ProbeError):
            with probe.ReadOnlyUsb(fake):
                self.fail("Claim failure must prevent context entry")
        self.assertEqual(fake.calls, ["init", "open", "claim", "close", "exit"])

    def test_initialization_failure_does_not_open_device(self):
        fake = FakeUsb(init_status=-99)
        with self.assertRaises(probe.ProbeError):
            with probe.ReadOnlyUsb(fake):
                self.fail("Initialization failure must prevent context entry")
        self.assertEqual(fake.calls, ["init"])

    def test_whitelist_applies_before_usb_transfer(self):
        fake = FakeUsb()
        with probe.ReadOnlyUsb(fake) as device:
            with self.assertRaises(probe.ProbeError):
                device.query(0xA7, 2)
        self.assertEqual(fake.calls, ["init", "open", "claim", "release", "close", "exit"])


if __name__ == "__main__":
    unittest.main()
