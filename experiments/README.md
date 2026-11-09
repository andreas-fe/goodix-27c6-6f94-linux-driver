# Goodix GF3268 — Experimental Enrollment Tools

See the [complete native enrollment guide](../docs/NATIVE_ENROLLMENT.md) and [hardware test report](../docs/HARDWARE_TEST_REPORT_2026-11.md).

- `goodix_sdcp_trial.py`: inspected / session-check / single experimental Type-4 enrollment on firmware01010032.
- `goodix_match_trial.py`: one bounded on-chip match check, optionally against a specific new enrollment.
- `goodixmoc-6f94-safe.patch`: isolated regular-driver diagnostic patch against the local libfprint1.94.5 baseline. C0/A7 and automatic USB resets are disabled. This path reached thirteen captures but its ordinary Type-1 commit was rejected; it is not the successful enrollment implementation.
- `goodixmoc_trial.c`: standalone harness for that separate build. Never use it with an unreviewed system library: the safety restrictions reside in the matching patched library.

The diagnostic source tree and compiled library are not distributed here. The patch is not promised to apply to a current upstream libfprint checkout. The successful Python tools depend only on repository modules, Python cryptography and libusb; they do not need the diagnostic C build.

Use `python3 -m unittest discover -s tests -q` from the repository root. Public tools print status/count summaries; actual record references must remain under a private, untracked directory such as `experiments/private/`.

The public static transport keys remain redacted. SDCP requires private `GOODIX_AES_KEY`/`GOODIX_MAC_KEY`; see the guide. The two public configuration guards bring the complete offline suite to40 tests.
