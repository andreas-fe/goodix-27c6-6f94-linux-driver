#!/usr/bin/env python3
"""Build and run native driver lifecycle simulations against an isolated build."""
import argparse
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, default=Path("/tmp/goodixsdcp-native-src"))
parser.add_argument("--build", type=Path, default=Path("/tmp/goodixsdcp-native-build"))
args = parser.parse_args()
flags = shlex.split(subprocess.check_output(
    ["pkg-config", "--cflags", "--libs", "gusb", "gio-unix-2.0", "openssl"], text=True))
output = args.build / "tests/test-goodixsdcp-native"
command = ["cc", "-g", "-Wno-deprecated-declarations",
           "-I"+str(args.source), "-I"+str(args.source/"libfprint"),
           "-I"+str(args.build), "-I"+str(args.build/"libfprint"),
           str(ROOT/"tests/native_goodixsdcp.c"),
           str(ROOT/"driver/goodixsdcp_crypto.c"), "-o", str(output),
           "-Wl,-rpath,"+str(args.build/"libfprint"), "-Wl,--start-group",
           str(args.build/"libfprint/libfprint-private.a"),
           str(args.build/"libfprint/libnbis.a"),
           str(args.build/"libfprint/libfprint-2.so.2.0.0"),
           *flags, "-lm", "-Wl,--end-group"]
optional_archive = args.build / "libfprint/sigfm/libsigfm.a"
if optional_archive.exists():
    command.insert(command.index("-lm"), str(optional_archive))
subprocess.run(command, check=True)
result = subprocess.run([str(output)], text=True, capture_output=True)
if result.returncode:
    print(result.stdout)
    print(result.stderr)
else:
    print("\n".join(line for line in result.stdout.splitlines()
                    if line.startswith(("ok ", "not ok ", "1.."))))
result.check_returncode()
