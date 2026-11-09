import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "experiments"))
import goodix_match_trial as match


def record(seed):
    return bytes.fromhex("62004304f500") + bytes([seed])*32 + bytes([seed+1])*32 + b"\x1c" + b"\x01"*28 + b"\0"


class MatchTests(unittest.TestCase):
    def test_sensor_assigned_account_is_resolved_by_persistent_enrollment_id(self):
        prepared = record(1)
        stored = prepared[:6] + b"x"*16 + prepared[22:]
        target = match.resolve_target((record(2), stored), prepared)
        self.assertTrue(match.match_result(b"\0"*8 + stored, target)["matched_target"])
        with self.assertRaises(match.TrialError):
            match.resolve_target((record(2),), prepared)

    def test_match_is_bound_to_target_not_just_any_existing_finger(self):
        target = record(1)
        self.assertTrue(match.match_result(b"\0"*8 + target, target)["matched_target"])
        self.assertFalse(match.match_result(b"\0"*8 + record(2), target)["matched_target"])
        self.assertFalse(match.match_result(b"\x01", target)["matched_any"])

    def test_matching_never_permits_enroll_delete_or_config(self):
        policy = match.MatchPolicy()
        for command in (0xa0, 0xa1, 0xa3, 0xa4, 0xa7, 0xc0):
            with self.assertRaises(match.TrialError):
                policy.check(command, 0, b"\0")
        policy.check(0xa5, 0, b"n"*32)
        with self.assertRaises(match.TrialError):
            policy.check(0xa5, 0, b"n"*31)


if __name__ == "__main__":
    unittest.main()
