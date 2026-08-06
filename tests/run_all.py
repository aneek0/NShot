#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runs all NShot unit tests."""

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

TESTS = [
    'test_generator.py',   # PIN generator, checksum, MAC
    'test_scanner.py',     # iw scan output parser + target selection
    'test_engine.py',      # attack engine: pixiewps, wpa_supplicant, brute-force
    'test_utils.py',       # utils: /proc, ip link, vulnerable list
    'test_android.py',     # android: cmd wifi / settings commands
    'test_fullflow.py',    # end-to-end: scan -> target pick -> WPS -> report
    'test_integration.py', # full attack pipeline (PIN, retry, Pixie Dust, report)
    'test_cli.py',         # CLI orchestration: kill/restore, iface up/down, loop
]


def main():
    failed = []
    for test in TESTS:
        print(f'==> {test}')
        proc = subprocess.run(
            [sys.executable, os.path.join(TESTS_DIR, test)],
            cwd=BASE,
        )
        if proc.returncode != 0:
            failed.append(test)

    if failed:
        print(f'\nFailed: {", ".join(failed)}')
        return 1

    print('\nAll tests passed ✅')
    return 0


if __name__ == '__main__':
    sys.exit(main())
