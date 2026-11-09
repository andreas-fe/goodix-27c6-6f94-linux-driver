#!/usr/bin/env python3
"""Integrate this driver into a separate upstream libfprint v1.94.10 tree.

No downloads, installs, sensor access or private-key configuration.
"""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def integrate(source):
    source = source.resolve(strict=True)
    top = source / 'meson.build'
    child = source / 'libfprint/meson.build'
    text, sub = top.read_text(), child.read_text()
    if "version: '1.94.10'" not in text:
        raise ValueError('This integration helper is pinned to upstream libfprint 1.94.10')
    if "'goodixsdcp'" in text or "'goodixsdcp'" in sub:
        raise ValueError('Tree already contains goodixsdcp; use a fresh tree to avoid overwriting local configured keys')
    edits = [('default_drivers = [', "default_drivers = [\n    'goodixsdcp',"),
             ('driver_helper_mapping = {', "driver_helper_mapping = {\n    'goodixsdcp' : [ 'goodixsdcp_crypto', 'openssl' ],")]
    for before, after in edits:
        if text.count(before) != 1:
            raise ValueError('Unexpected top-level Meson layout')
        text = text.replace(before, after)
    for before, after in [
        ('driver_sources = {', "driver_sources = {\n    'goodixsdcp' : [ 'drivers/goodixsdcp/goodixsdcp.c' ],"),
        ('helper_sources = {', "helper_sources = {\n    'goodixsdcp_crypto' : [ 'drivers/goodixsdcp/goodixsdcp_crypto.c' ],")]:
        if sub.count(before) != 1:
            raise ValueError('Unexpected libfprint Meson layout')
        sub = sub.replace(before, after)
    target = source / 'libfprint/drivers/goodixsdcp'
    target.mkdir(parents=True, exist_ok=False)
    for name in ('goodixsdcp.c', 'goodixsdcp.h', 'goodixsdcp_crypto.c', 'goodixsdcp_crypto.h'):
        shutil.copy2(ROOT / 'driver' / name, target / name)
    top.write_text(text)
    child.write_text(sub)
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    print('Driver integrated:', integrate(args.source))
    print('Transport keys remain redacted; configure the separate copy before live use.')
