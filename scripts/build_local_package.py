#!/usr/bin/env python3
"""Build a local pacman provider from a trusted distro package + reviewed library.

No downloads or installation. Output packages contain privately configured
transport keys when the candidate does: do not publish those packages.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def prepare(base, candidate, expected, output):
    base, candidate = base.resolve(strict=True), candidate.resolve(strict=True)
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != expected:
        raise ValueError('Candidate checksum mismatch')
    info = subprocess.check_output(['bsdtar', '-xOf', str(base), '.PKGINFO'], text=True)
    fields = {}
    for line in info.splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    if fields.get('pkgname') != ['libfprint']:
        raise ValueError('Expected a trusted distribution libfprint package')
    with tempfile.TemporaryDirectory(prefix='goodix-package-abi-') as temporary:
        original = Path(temporary) / 'base.so'
        original.write_bytes(subprocess.check_output(
            ['bsdtar', '-xOf', str(base), 'usr/lib/libfprint-2.so.2.0.0']))
        def symbols(path):
            result = subprocess.check_output(['nm', '-D', '--defined-only', str(path)], text=True)
            return {line.split()[-1] for line in result.splitlines() if line.split()}
        if symbols(original) - symbols(candidate):
            raise ValueError('Candidate lacks public symbols from the base package; rebuild against a compatible source')
    version = fields['pkgver'][0].rsplit('-', 1)[0]
    if not re.fullmatch(r'[0-9A-Za-z._+]+', version):
        raise ValueError('Unsupported base version syntax')
    if output.exists():
        raise ValueError('Use a new output directory; existing packages are never overwritten')
    output.mkdir(mode=0o700, parents=True)
    shutil.copy2(base, output / 'base-package.pkg.tar.zst')
    shutil.copy2(candidate, output / 'libfprint-2.so.2.0.0')
    dependencies = ' '.join(quote(v) for v in fields.get('depend', []))
    checksums = [hashlib.sha256((output / p).read_bytes()).hexdigest()
                 for p in ('base-package.pkg.tar.zst', 'libfprint-2.so.2.0.0')]
    recipe = f'''# Local repack: preserve distro companion files and replace only the library.
# Base metadata version is not the custom library's upstream source version.
pkgname=libfprint-goodixsdcp
pkgver={version}.goodix20261109
pkgrel=1
pkgdesc='Local GF3268 SDCP driver with native enrollment and empty-store support'
arch=('x86_64')
url='https://github.com/andreas-fe/goodix-27c6-6f94-linux-driver'
license=('LGPL-2.1-or-later')
depends=({dependencies})
provides=('libfprint={version}' 'libfprint-2.so=2-64')
conflicts=('libfprint')
options=('!strip' '!debug')
source=('base-package.pkg.tar.zst' 'libfprint-2.so.2.0.0')
noextract=('base-package.pkg.tar.zst')
sha256sums=('{checksums[0]}' '{checksums[1]}')

package() {{
    bsdtar --no-same-owner -xf "$srcdir/base-package.pkg.tar.zst" -C "$pkgdir" \\
        --exclude='.PKGINFO' --exclude='.BUILDINFO' --exclude='.MTREE' \\
        --exclude='.INSTALL' --exclude='.CHANGELOG'
    install -m755 "$srcdir/libfprint-2.so.2.0.0" "$pkgdir/usr/lib/libfprint-2.so.2.0.0"
}}
'''
    (output / 'PKGBUILD').write_text(recipe)
    return version


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-package', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    version = prepare(args.base_package, args.candidate, args.expected_sha256, args.output)
    subprocess.run(['makepkg', '--noconfirm', '--nodeps'], cwd=args.output, check=True)
    print('Local provider package built; base version:', version)
    print('Not installed. Keep the package private and use only on a compatible host.')
