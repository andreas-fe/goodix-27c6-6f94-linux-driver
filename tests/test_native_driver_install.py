import importlib.util
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("native_install", Path(__file__).parents[1] / "scripts/install_native_driver.py")
install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(install)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.target = root / "libfprint-2.so.2.0.0"
        self.candidate = root / "candidate"
        self.references = root / "references"
        self.references.mkdir()
        (self.references / "existing-finger").write_bytes(b"keep-reference")
        self.target.write_bytes(b"old-library")
        self.value = b"\x7fELFnew-library"
        self.candidate.write_bytes(self.value)
        self.patches = [patch.object(install, name, value) for name, value in (
            ("TARGET", self.target), ("CANDIDATE", self.candidate),
            ("BACKUPS", root / "backups"), ("REFERENCES", self.references))]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_success_preserves_binary_and_fingerprint_references(self):
        with patch.object(install, "command", return_value=SimpleNamespace(returncode=0)):
            result = install.install(install.digest(self.value))
        backup = Path(result["backup"])
        self.assertEqual(self.target.read_bytes(), self.value)
        self.assertEqual((backup / self.target.name).read_bytes(), b"old-library")
        self.assertEqual((backup / "fingerprint-references/existing-finger").read_bytes(), b"keep-reference")
        self.assertEqual((self.references / "existing-finger").read_bytes(), b"keep-reference")

    def test_wrong_checksum_does_not_stop_service_or_modify_files(self):
        with patch.object(install, "command") as command:
            with self.assertRaises(ValueError):
                install.install("incorrect")
        command.assert_not_called()
        self.assertEqual(self.target.read_bytes(), b"old-library")

    def test_service_start_failure_rolls_back_library(self):
        failed = False
        def command(*args, **kwargs):
            nonlocal failed
            if args == ("/usr/bin/systemctl", "start", "fprintd") and not failed:
                failed = True
                raise RuntimeError("simulated service failure")
            return SimpleNamespace(returncode=0)
        with patch.object(install, "command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "simulated service failure"):
                install.install(install.digest(self.value))
        self.assertEqual(self.target.read_bytes(), b"old-library")
        self.assertEqual((self.references / "existing-finger").read_bytes(), b"keep-reference")


if __name__ == "__main__":
    unittest.main()
