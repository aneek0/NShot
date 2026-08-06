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
    'test_scanner.py',     # парсер вывода iw scan + выбор цели
    'test_engine.py',      # движок атак: pixiewps, wpa_supplicant, брутфорс
    'test_utils.py',       # utils: /proc, ip link, список уязвимых
    'test_android.py',     # android: команды cmd wifi / settings
    'test_fullflow.py',    # сквозной: скан -> выбор цели -> WPS -> отчёт
    'test_integration.py', # полный конвейер атаки (PIN, retry, Pixie Dust, отчёт)
    'test_cli.py',         # оркестрация CLI: kill/restore, iface up/down, loop
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
