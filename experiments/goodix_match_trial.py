#!/usr/bin/env python3
"""One bounded on-chip match check; no enrollment/configuration/deletion.

Optional --target-reference is the private .commit.json from an enrollment.
This checks the returned sensor record, not full Windows credential attestation.
"""
import argparse
import hmac
import json
import os
from pathlib import Path

from goodix_sdcp_trial import (CommandPolicy, Session, TrialError, TrialUsb,
                                compare_records, records_from_reply, status_ok,
                                version_summary)


class MatchPolicy(CommandPolicy):
    def __init__(self):
        super().__init__("session-check")

    def check(self, command, subcommand, payload):
        if (command, subcommand) == (0xA5, 0) and isinstance(payload, bytes) and len(payload) == 32:
            return
        if (command, subcommand) == (0xA2, 0) and payload == bytes.fromhex("01002301"):
            return
        return super().check(command, subcommand, payload)


def match_result(reply, target=None):
    if reply == b"\x01":
        return {"matched_any": False, "matched_target": False if target else None}
    if len(reply) < 108 or reply[0] != 0:
        raise TrialError("Unexpected match result")
    record = records_from_reply(b"\0\1" + reply[8:108])[0]
    same = (hmac.compare_digest(record[6:22], target[6:22]) and
            hmac.compare_digest(record[38:70], target[38:70])) if target else None
    return {"matched_any": True, "matched_target": same}


def resolve_target(records, prepared):
    matches = [record for record in records if hmac.compare_digest(record[38:70], prepared[38:70])]
    if len(matches) != 1:
        raise TrialError("Enrollment identifier does not identify exactly one stored record")
    return matches[0]


def run(target=None):
    result = {}
    with TrialUsb(MatchPolicy()) as device:
        version = version_summary(device.query(0xD0))
        if version["firmware_version"] != "01010032":
            raise TrialError("Unsupported firmware")
        before = records_from_reply(device.query(0xA6))
        if target is not None:
            # The sensor assigns the account field on commit; use its stored
            # record, located by the authenticated persistent enrollment ID.
            target = resolve_target(before, target)
        try:
            session = Session.connect(device)
            session.reconnect()
            status_ok(device.exchange(0xB0, 2, b"\0"), "Preparation")
            status_ok(device.exchange(0xE0, 1, b"\0"), "Power button shield")
            print("Ready: place the finger for one match check.", flush=True)
            for _ in range(6):
                capture = device.exchange(0xA2, 0, bytes.fromhex("01002301"), timeout=30)
                if capture[:1] == b"\xc0":
                    continue
                status_ok(capture, "Finger detection")
                if len(capture) >= 3:
                    result["capture_quality"] = capture[1]
                    result["capture_coverage"] = capture[2]
                result.update(match_result(device.exchange(0xA5, 0, os.urandom(32)), target))
                break
            else:
                raise TrialError("No finger detected within the polling budget")
        except TrialError as error:
            result["error"] = str(error)
        except KeyboardInterrupt:
            result["error"] = "Match check interrupted"
        finally:
            try:
                status_ok(device.exchange(0xE0, 0, b"\0"), "Shield cleanup")
            except TrialError as error:
                result["cleanup_error"] = str(error)
            try:
                after = records_from_reply(device.query(0xA6))
                compare_records(before, after)
                result["templates_unchanged"] = True
            except TrialError as error:
                result["postcheck_error"] = str(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-reference", type=Path)
    args = parser.parse_args()
    try:
        target = None
        if args.target_reference:
            target = bytes.fromhex(json.loads(args.target_reference.read_text())["prepared_record_hex"])
            records_from_reply(b"\0\1" + target)
        result = run(target)
    except (TrialError, OSError, ValueError, KeyError) as error:
        print(json.dumps({"error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return int(any(name in result for name in ("error", "cleanup_error", "postcheck_error")))


if __name__ == "__main__":
    raise SystemExit(main())
