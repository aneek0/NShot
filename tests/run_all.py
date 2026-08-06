#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Запускает все юнит-тесты NShot."""

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

TESTS = [
    'test_generator.py',   # генератор PIN, контрольная сумма, MAC
    'test_scanner.py',     # парсер вывода iw scan
    'test_engine.py',      # движок атак: pixiewps, wpa_supplicant, брутфорс
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
        print(f'\nПровалены: {", ".join(failed)}')
        return 1

    print('\nВсе тесты пройдены ✅')
    return 0


if __name__ == '__main__':
    sys.exit(main())
