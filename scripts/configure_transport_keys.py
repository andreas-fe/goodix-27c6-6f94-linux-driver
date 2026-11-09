#!/usr/bin/env python3
"""Configure redacted C transport constants in a separate private source tree.

Reads GOODIX_AES_KEY (32 hex characters) and GOODIX_MAC_KEY (64). Prints no
key values. Does not derive keys, access USB, build, or install anything.
"""
import argparse
import os
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def configure(directory, environment=None):
    environment = os.environ if environment is None else environment
    path = directory.resolve(strict=True) / 'goodixsdcp_crypto.c'
    if path.resolve() == (ROOT / 'driver/goodixsdcp_crypto.c').resolve():
        raise ValueError('Configure a separate build-source copy, not the public repository driver')
    text = path.read_text()
    for name, size in (('AES_KEY', 16), ('MAC_KEY', 32)):
        value = environment.get('GOODIX_' + name, '')
        if not re.fullmatch('[0-9a-fA-F]{' + str(size * 2) + '}', value) or not any(bytes.fromhex(value)):
            raise ValueError('Missing, zero or invalid ' + name + '; no files changed')
        key = bytes.fromhex(value)
        pattern = rf'static const guint8 {name}\[{size}\] = \{{(.*?)\n\}};'
        match = re.search(pattern, text, re.S)
        if not match:
            raise ValueError('Unexpected transport constant layout; no files changed')
        old = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', match.group(1)))
        if len(old) != size or (any(old) and old != key):
            raise ValueError('Refusing to replace different existing keys; no files changed')
        replacement = f'static const guint8 {name}[{size}] = {{\n  ' + ', '.join(f'0x{x:02x}' for x in key) + ',\n};'
        text = text[:match.start()] + replacement + text[match.end():]
    fd, temporary = tempfile.mkstemp(prefix='.goodix-private-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        configure(args.driver_dir)
    except (ValueError, OSError) as e:
        parser.exit(1, str(e) + '\n')
    print('Private transport constants configured in the separate C source (values not displayed).')
