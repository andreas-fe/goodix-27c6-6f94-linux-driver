import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('key_config', ROOT / 'scripts/configure_transport_keys.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class KeyConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'goodixsdcp_crypto.c'
        shutil.copy2(ROOT / 'driver/goodixsdcp_crypto.c', self.path)
        self.original = self.path.read_bytes()
        self.env = {'GOODIX_AES_KEY': '12' * 16, 'GOODIX_MAC_KEY': '34' * 32}

    def tearDown(self):
        self.temp.cleanup()

    def test_configures_only_private_copy_and_is_idempotent(self):
        module.configure(self.directory, self.env)
        configured = self.path.read_bytes()
        self.assertNotEqual(configured, self.original)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        module.configure(self.directory, self.env)
        self.assertEqual(self.path.read_bytes(), configured)

    def test_invalid_second_key_does_not_partially_write_first(self):
        for value in ('', '00' * 32, 'not-hex', '01' * 31):
            with self.assertRaises(ValueError):
                module.configure(self.directory, {**self.env, 'GOODIX_MAC_KEY': value})
            self.assertEqual(self.path.read_bytes(), self.original)

    def test_different_existing_key_is_not_overwritten(self):
        module.configure(self.directory, self.env)
        configured = self.path.read_bytes()
        with self.assertRaises(ValueError):
            module.configure(self.directory, {**self.env, 'GOODIX_AES_KEY': '56' * 16})
        self.assertEqual(self.path.read_bytes(), configured)

    def test_public_repository_source_is_protected(self):
        original = (ROOT / 'driver/goodixsdcp_crypto.c').read_bytes()
        with self.assertRaises(ValueError):
            module.configure(ROOT / 'driver', self.env)
        self.assertEqual((ROOT / 'driver/goodixsdcp_crypto.c').read_bytes(), original)
