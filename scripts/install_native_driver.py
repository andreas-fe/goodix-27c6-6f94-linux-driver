#!/usr/bin/env python3
"""Install the reviewed native libfprint build with backup and rollback.

Run through the operating system's administrator authentication. Fingerprint
reference backups remain root-private and are never restored automatically.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "build-install/libfprint/libfprint-2.so.2.0.0"
TARGET = Path("/usr/lib/libfprint-2.so.2.0.0")
BACKUPS = Path("/var/lib/goodixsdcp-backups")
REFERENCES = Path("/var/lib/fprint")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def replace_library(value):
    fd, temporary = tempfile.mkstemp(prefix=".libfprint-native-", dir=TARGET.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o755)
        os.replace(temporary, TARGET)
        directory = os.open(TARGET.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(expected_sha256):
    proposed = CANDIDATE.read_bytes()
    if digest(proposed) != expected_sha256 or not proposed.startswith(b"\x7fELF"):
        raise ValueError("Candidate checksum or ELF format does not match the reviewed build")
    previous = TARGET.read_bytes()
    was_active = command("/usr/bin/systemctl", "is-active", "fprintd", check=False).returncode == 0
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BACKUPS, 0o700)
    backup = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=BACKUPS))
    (backup / TARGET.name).write_bytes(previous)
    os.chmod(backup / TARGET.name, 0o600)
    (backup / "manifest.json").write_text(json.dumps({
        "previous_sha256": digest(previous), "installed_sha256": digest(proposed),
        "fprintd_was_active": was_active}, indent=2) + "\n")
    command("/usr/bin/systemctl", "stop", "fprintd")
    try:
        if REFERENCES.is_dir():
            shutil.copytree(REFERENCES, backup / "fingerprint-references", symlinks=True)
        replace_library(proposed)
        command("/usr/bin/ldconfig")
        command("/usr/bin/systemctl", "start", "fprintd")
    except Exception:
        replace_library(previous)
        command("/usr/bin/ldconfig", check=False)
        command("/usr/bin/systemctl", "start", "fprintd", check=False)
        raise
    return {"installed": str(TARGET), "sha256": digest(proposed), "backup": str(backup)}


def restore(backup):
    backup = backup.resolve(strict=True)
    if backup.parent != BACKUPS.resolve(strict=True):
        raise ValueError("Rollback must select a direct child of the protected backup directory")
    manifest = json.loads((backup / "manifest.json").read_text())
    value = (backup / TARGET.name).read_bytes()
    if digest(value) != manifest["previous_sha256"]:
        raise ValueError("Backup checksum mismatch")
    command("/usr/bin/systemctl", "stop", "fprintd")
    replace_library(value)
    command("/usr/bin/ldconfig")
    command("/usr/bin/systemctl", "start", "fprintd")
    return {"restored": str(TARGET), "backup": str(backup)}


def main():
    global CANDIDATE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=CANDIDATE,
                        help="Locally built library to install; never downloaded automatically")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--expected-sha256")
    action.add_argument("--restore-backup", type=Path)
    args = parser.parse_args()
    CANDIDATE = args.candidate
    if os.geteuid() != 0:
        parser.error("Administrator authentication is required")
    try:
        result = restore(args.restore_backup) if args.restore_backup else install(args.expected_sha256)
    except Exception as error:
        print(json.dumps({"error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
