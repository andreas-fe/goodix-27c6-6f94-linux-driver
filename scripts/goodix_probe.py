#!/usr/bin/env python3
"""Read-only Goodix metadata probe; no enrollment, configuration, or reset.

Offline: python3 scripts/goodix_probe.py --capture CAPTURE.pcapng
Live:    python3 scripts/goodix_probe.py --live [--list]

Live mode only sends D0/00/00 (version), and optionally A6/00/00 (list).
It never detaches a kernel driver, clears a halt, resets a device, starts a
service, or writes configuration. JSON output excludes templates and IDs.
Offline input supports pcapng with Linux usbmon mmap (linktype 220).
"""

from __future__ import annotations

import argparse
import binascii
import ctypes
import json
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

VID, PID, EP_OUT, EP_IN = 0x27C6, 0x6F94, 0x01, 0x83
READ_COMMANDS = frozenset({(0xD0, 0x00), (0xA6, 0x00)})


class ProbeError(Exception):
    """A bounded, non-sensitive diagnostic failure."""


def crc8(data: bytes) -> int:
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            if crc & 0x8000:
                crc ^= 0x8380
            crc = (crc << 1) & 0xFFFF
    return (~(crc >> 8)) & 0xFF


@dataclass(frozen=True)
class Frame:
    command: int
    subcommand: int
    sequence: int
    payload: bytes


def query_packet(command: int, subcommand: int = 0, sequence: int = 0) -> bytes:
    """Only two fixed metadata requests can be encoded for live output."""
    if (command, subcommand) not in READ_COMMANDS:
        raise ProbeError("Command is outside the read-only whitelist")
    header = bytes((command, subcommand, 0, sequence & 0xFF)) + b"\x05\x00"
    checksum = crc8(header)
    packet = header + bytes((checksum, checksum ^ 0xFF)) + b"\x00"
    return packet + struct.pack("<I", binascii.crc32(packet) & 0xFFFFFFFF)


class FrameDecoder:
    """Incremental framing with strict CRCs and optional 64-byte USB padding.

    Device-side transfer padding can contain stale nonzero buffer contents.
    Those bytes are never interpreted or exposed. Host packets may be either
    unpadded or zero-padded, as both occur in the project's transports.
    """

    def __init__(self, padded=False):
        self.buffer = bytearray()
        self.padding = 0
        self.padded = padded

    def feed(self, chunk: bytes) -> list[Frame]:
        self.buffer.extend(chunk)
        frames = []
        while self.buffer:
            if self.padded and self.padding:
                discarded = min(self.padding, len(self.buffer))
                del self.buffer[:discarded]
                self.padding -= discarded
            while self.padding and self.buffer and self.buffer[0] == 0:
                del self.buffer[0]
                self.padding -= 1
            if not self.buffer:
                break
            self.padding = 0  # Next packet may be unpadded.
            if len(self.buffer) < 8:
                break
            check = crc8(self.buffer[:6])
            if self.buffer[6] != check or self.buffer[7] != (check ^ 0xFF):
                raise ProbeError("Goodix header CRC8 mismatch")
            length = int.from_bytes(self.buffer[4:6], "little")
            if length < 4:
                raise ProbeError("Goodix frame length is shorter than its CRC32")
            total = length + 8
            if len(self.buffer) < total:
                break
            packet = bytes(self.buffer[:total])
            if binascii.crc32(packet[:-4]) & 0xFFFFFFFF != int.from_bytes(packet[-4:], "little"):
                raise ProbeError("Goodix payload CRC32 mismatch")
            frames.append(Frame(packet[0], packet[1], packet[3], packet[8:-4]))
            del self.buffer[:total]
            self.padding = (-total) % 64
        return frames

    def finish(self):
        if self.buffer:
            raise ProbeError("Truncated Goodix frame at end of input")


def version_summary(payload: bytes) -> dict:
    if len(payload) != 129 or payload[0] != 0:
        raise ProbeError("Version reply has an unsupported length or status")
    names = ("firmware_type", "firmware_version", "customer", "mcu", "sensor", "algorithm")
    result = {}
    for index, name in enumerate(names):
        field = payload[3 + index * 8:11 + index * 8].rstrip(b"\x00")
        if any(value < 32 or value > 126 for value in field):
            raise ProbeError("Version metadata contains non-printable bytes")
        result[name] = field.decode("ascii")
    return result


def template_summary(payload: bytes) -> dict:
    if len(payload) < 2:
        raise ProbeError("Template list has no record count")
    count = int.from_bytes(payload[:2], "big")
    if len(payload) != 2 + count * 100:
        raise ProbeError("Template list does not match the known 100-byte record layout")
    return {"template_count": count, "record_size": 100}


def capture_packets(path: Path):
    """Yield selected bulk data only; reject unsupported/truncated pcapng."""
    data = path.read_bytes()
    offset, endian, links = 0, None, []
    while offset < len(data):
        if len(data) - offset < 12:
            raise ProbeError("Truncated pcapng block")
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            magic = data[offset + 8:offset + 12]
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(magic)
            if endian is None:
                raise ProbeError("Unsupported pcapng byte order")
            links = []
        if endian is None:
            raise ProbeError("Input is not pcapng")
        kind, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or length % 4 or offset + length > len(data):
            raise ProbeError("Invalid pcapng block length")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ProbeError("pcapng block length trailer mismatch")
        body = data[offset + 8:offset + length - 4]
        if kind == 1:
            if len(body) < 8:
                raise ProbeError("Truncated pcapng interface")
            links.append(struct.unpack_from(endian + "H", body)[0])
        elif kind == 6:
            if len(body) < 20:
                raise ProbeError("Truncated pcapng packet header")
            interface, _, _, captured, _ = struct.unpack_from(endian + "IIIII", body)
            if interface >= len(links) or links[interface] != 220:
                raise ProbeError("Only Linux usbmon mmap captures (linktype 220) are supported")
            if captured > len(body) - 20:
                raise ProbeError("Truncated captured USB packet")
            packet = body[20:20 + captured]
            if len(packet) >= 64 and packet[9] == 3:
                event, endpoint = packet[8], packet[10]
                host = endpoint == EP_OUT and event == ord("S")
                device = endpoint == EP_IN and event == ord("C")
                if host or device:
                    size = int.from_bytes(packet[36:40], "little")
                    if size > len(packet) - 64:
                        raise ProbeError("Truncated USB bulk payload")
                    if size:
                        key = (int.from_bytes(packet[12:14], "little"), packet[11], endpoint)
                        yield key, host, packet[64:64 + size]
        offset += length


def analyze_capture(path: Path) -> dict:
    decoders, counts, versions, template_counts = {}, Counter(), [], []
    ack_count = 0
    for key, host, chunk in capture_packets(path):
        decoder = decoders.setdefault(key, FrameDecoder(padded=not host))
        for frame in decoder.feed(chunk):
            if frame.command == 0xAA:
                ack_count += 1
                continue
            counts[f"{'host' if host else 'device'}:{frame.command:02x}/{frame.subcommand:02x}"] += 1
            if not host and (frame.command, frame.subcommand) == (0xD0, 0):
                summary = version_summary(frame.payload)
                if summary not in versions:
                    versions.append(summary)
            if not host and (frame.command, frame.subcommand) == (0xA6, 0):
                template_counts.append(template_summary(frame.payload)["template_count"])
    for decoder in decoders.values():
        decoder.finish()
    return {"mode": "offline", "crc_validation": "passed", "acks": ack_count,
            "commands": dict(sorted(counts.items())), "versions": versions,
            "template_counts": template_counts}


class ReadOnlyUsb:
    """Only metadata exchange; no mutating libusb operations are bound."""

    def __init__(self, library=None):
        self.lib = library
        self.context = ctypes.c_void_p()
        self.handle = None
        self.initialized = self.claimed = False
        self.decoder = FrameDecoder(padded=True)
        self.sequence = 0

    def __enter__(self):
        try:
            if self.lib is None:
                if not Path("/dev/bus/usb").is_dir():
                    raise ProbeError("USB device access is unavailable: /dev/bus/usb is missing")
                self.lib = ctypes.CDLL("libusb-1.0.so.0")
                pointer, integer = ctypes.c_void_p, ctypes.c_int
                signatures = {
                    "libusb_init": ([ctypes.POINTER(pointer)], integer),
                    "libusb_exit": ([pointer], None),
                    "libusb_open_device_with_vid_pid": ([pointer, ctypes.c_uint16, ctypes.c_uint16], pointer),
                    "libusb_close": ([pointer], None),
                    "libusb_kernel_driver_active": ([pointer, integer], integer),
                    "libusb_claim_interface": ([pointer, integer], integer),
                    "libusb_release_interface": ([pointer, integer], integer),
                    "libusb_bulk_transfer": ([pointer, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ubyte), integer,
                                               ctypes.POINTER(integer), ctypes.c_uint], integer),
                }
                for name, (args, result) in signatures.items():
                    function = getattr(self.lib, name)
                    function.argtypes, function.restype = args, result
            status = self.lib.libusb_init(ctypes.byref(self.context))
            if status != 0:
                raise ProbeError(f"libusb initialization failed ({status})")
            self.initialized = True
            self.handle = self.lib.libusb_open_device_with_vid_pid(self.context, VID, PID)
            if not self.handle:
                raise ProbeError("Sensor cannot be opened; check presence and user USB permissions")
            if self.lib.libusb_kernel_driver_active(self.handle, 0) == 1:
                raise ProbeError("Interface is owned by a kernel driver; probe will not detach it")
            status = self.lib.libusb_claim_interface(self.handle, 0)
            if status != 0:
                raise ProbeError(f"Cannot claim sensor interface ({status}); another application may own it")
            self.claimed = True
            return self
        except Exception:
            self.close()
            raise

    def close(self):
        if self.claimed:
            self.lib.libusb_release_interface(self.handle, 0)
            self.claimed = False
        if self.handle:
            self.lib.libusb_close(self.handle)
            self.handle = None
        if self.initialized:
            self.lib.libusb_exit(self.context)
            self.initialized = False

    def __exit__(self, *_):
        self.close()

    def query(self, command: int, subcommand: int = 0) -> bytes:
        packet = query_packet(command, subcommand, self.sequence)
        if not self.claimed:
            raise ProbeError("Sensor interface is not open")
        self.sequence = (self.sequence + 1) & 0xFF
        outgoing = (ctypes.c_ubyte * len(packet)).from_buffer_copy(packet)
        transferred = ctypes.c_int()
        status = self.lib.libusb_bulk_transfer(self.handle, EP_OUT, outgoing, len(packet),
                                              ctypes.byref(transferred), 1000)
        if status != 0 or transferred.value != len(packet):
            raise ProbeError(f"Metadata request transfer failed ({status}); no retry or reset performed")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            incoming = (ctypes.c_ubyte * 4096)()
            transferred = ctypes.c_int()
            status = self.lib.libusb_bulk_transfer(self.handle, EP_IN, incoming, len(incoming),
                                                  ctypes.byref(transferred), 500)
            if status not in (0, -7):
                raise ProbeError(f"Metadata response transfer failed ({status}); no recovery writes performed")
            if transferred.value:
                for frame in self.decoder.feed(bytes(incoming[:transferred.value])):
                    if frame.command == 0xAA:
                        if len(frame.payload) < 2:
                            raise ProbeError("Malformed acknowledgement")
                        if frame.payload[1] == command and frame.payload[0] != 0:
                            raise ProbeError("Sensor rejected metadata request")
                    elif (frame.command, frame.subcommand) == (command, subcommand):
                        return frame.payload
        raise ProbeError("Timed out waiting for metadata response; no retry or reset performed")


def live_probe(include_list: bool = False) -> dict:
    with ReadOnlyUsb() as device:
        result = {"mode": "live", "version": version_summary(device.query(0xD0)),
                  "sent_commands": ["d0/00"]}
        if include_list:
            result.update(template_summary(device.query(0xA6)))
            result["sent_commands"].append("a6/00")
        return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--capture", type=Path, help="Analyze a saved pcapng without accessing hardware")
    source.add_argument("--live", action="store_true", help="Send only the fixed version query to the sensor")
    parser.add_argument("--list", action="store_true", help="Also query the template count (live mode only)")
    args = parser.parse_args(argv)
    if args.list and not args.live:
        parser.error("--list requires --live")
    if not args.capture and not args.live:
        parser.print_help()
        return 0
    try:
        result = analyze_capture(args.capture) if args.capture else live_probe(args.list)
    except (ProbeError, OSError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
