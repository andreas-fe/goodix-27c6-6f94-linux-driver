# Goodix GF3268 — Packages, Updates and Recovery

## 1. What Survives Reboot and What an Update Can Replace

A library installed under `/usr/lib` remains installed across reboot. Changing only a version string inside that file does **not** protect it from a package upgrade: pacman tracks the package database and owns the file path.

An artificial high package version/epoch can hold back distribution updates, but obscures the real source/version and still requires maintenance. This project instead used a local provider package named **`libfprint-goodixsdcp`**. Its `provides` satisfies `libfprint` and the shared-library dependency; its `conflicts` prevents simultaneous installation with the distribution package. This uses the ordinary [PKGBUILD provides/conflicts mechanism](https://man.archlinux.org/man/core/pacman/PKGBUILD.5).

A normal update of the differently named distribution `libfprint` does not silently overwrite this local provider merely because the repo package has a newer version. An explicit install of `libfprint`, repository replacement policy or replacing/removing the custom package can still change the installation. Read transaction prompts. This is not a promise that an unmaintained library stays compatible forever.

No fake enormous version, epoch, blanket package exclusion or automatic post-update root hook was required. The local provider must be deliberately rebuilt for relevant upstream fixes or dependency/API changes. Do not freeze the whole system or permanently ignore security maintenance to retain fingerprint support.

## 2. Local Provider Used in the Hardware Session

The machine initially had CachyOS `libfprint 1.94.100-1.1` recorded in pacman's database while the tested custom library had been installed over its library file. The local provider:

- Preserved the companion files from that exact cached distribution package: headers, typelib/GIR, udev data and documentation.
- Replaced only `usr/lib/libfprint-2.so.2.0.0` with the reviewed hardware-tested custom library.
- Retained all public exported symbols from the distribution library (checked before publication).
- Declared the original dependencies and `provides=('libfprint=1.94.100' 'libfprint-2.so=2-64')`, with `conflicts=('libfprint')`.
- Disabled stripping/debug splitting so the reviewed library bytes and checksum were preserved.

The installed package name/version was `libfprint-goodixsdcp 1.94.100.goodix20261109-1`. That package version describes the **local repack based on the distribution package**, not a claim that the custom source tree's upstream version is 1.94.100. The actual hardware library came from the local 1.94.5 fork; the independent clean-source build/test recipe uses upstream 1.94.10. Public-symbol checks alone are not a proof that arbitrary source/header/typelib combinations are safe.

After installation, pacman reported the custom package as owner, `pacman -T libfprint` reported no missing dependency, the installed library matched the reviewed checksum, and fprintd retained the new thumb. The package contained the same reviewed library already used in the successful unlock test; the package transaction did not enroll or delete anything.

## 3. Reproduce a Local Provider Package

Use a **trusted, distribution-signed cached package compatible with your machine** and a privately configured, reviewed local library. Do not download someone else's key-bearing binary. A CachyOS `x86_64_v3` base is suitable only for a compatible CPU; the output is a local package, not a portable public release.

```bash
sha256sum /absolute/path/to/reviewed/libfprint-2.so.2.0.0
python3 scripts/build_local_package.py \
  --base-package /var/cache/pacman/pkg/libfprint-YOUR_VERSION-ARCH.pkg.tar.zst \
  --candidate /absolute/path/to/reviewed/libfprint-2.so.2.0.0 \
  --expected-sha256 THE_REVIEWED_CHECKSUM \
  --output /absolute/path/to/new-private-package-directory
```

The helper builds with makepkg but never installs or downloads. It checks the candidate checksum, package identity and public-symbol coverage against the original library, records both source checksums, copies the base companion files and replaces the one library. A new output directory is required. The generated PKGBUILD is reviewable before installation. The helper uses `--nodeps` for the repack build only; pacman's installation transaction still checks runtime dependencies.

The output contains private transport constants if the library does. Keep the entire directory and package private. Do not commit it or publish a release asset. The public repository supplies source and synthetic tests, not a ready-to-use key-bearing package.

Inspect before installation:

```bash
pacman -Qip /absolute/path/to/libfprint-goodixsdcp-PACKAGE.pkg.tar.zst
bsdtar -xOf /absolute/path/to/libfprint-goodixsdcp-PACKAGE.pkg.tar.zst .PKGINFO
sudo pacman -U /absolute/path/to/libfprint-goodixsdcp-PACKAGE.pkg.tar.zst
```

The expected transaction removes the old `libfprint` package and installs the provider in the **same dependency-checked transaction**. Do not use `pacman -Rdd` to bypass dependency checks. Confirm only the expected replacement. Close fingerprint dialogs and restart fprintd afterward if needed.

Verify:

```bash
pacman -Q libfprint-goodixsdcp
pacman -Qo /usr/lib/libfprint-2.so.2.0.0
pacman -T libfprint
fprintd-list "$USER"
fprintd-verify -f right-thumb
```

Do not claim hardware success for a new machine solely from package installation. Test that machine's firmware, enrollment, matching, wake and reboot.

## 4. If Fingerprint Support Stops After an Update

1. Use your normal password and close competing fingerprint dialogs.
2. Check package ownership with `pacman -Qo` and whether `libfprint-goodixsdcp` is still installed.
3. Inspect `journalctl -u fprintd -b`. A busy/open error, missing device, missing library dependency and missing custom driver are different problems. Reinstalling is not a universal repair.
4. If the provider was replaced, reinstall the known compatible private package with `pacman -U`; verify its checksum first. Keep the saved package outside temporary directories.
5. If library dependencies or public API changed, rebuild against a compatible distribution source. Do not force an old library over new requirements. The [clean build guide](BUILD_AND_INSTALL.md) documents an independently tested starting point, not automatic compatibility with every later distribution update.

The original user's workspace also includes a local German operating guide and `release/reinstall-goodixsdcp.sh`. That wrapper checks the reviewed backup's checksum, public-symbol coverage and loader dependencies and prefers the saved provider package. It stops for missing compatibility rather than blindly overwriting a newer library. Those workstation-specific manifests/key-bearing packages are intentionally not exported.

Reinstalling a library/package should not require deleting or reenrolling existing fingers. Do not clear templates as an update repair.

## 5. Rollback

For a provider-package installation, restore the appropriate known compatible package using pacman. For example, a cached original distribution package can replace the local provider through the expected conflict-resolution transaction. This may remove custom sensor support, but restores consistent package ownership. Use the private known-working provider again to recover that support when still compatible.

For a prior manual library installation, the protected installer supports library rollback as documented in [Build and Installation](BUILD_AND_INSTALL.md). Do not mix manual file rollback and package ownership without understanding which package currently owns the path.

Neither operation restores deleted sensor templates. Fingerprint metadata/reference backups are not biometric restoration images. Avoid restoring stale host references automatically, because that can discard newer registrations or refer to deleted on-chip entries.
