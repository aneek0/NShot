#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты парсера вывода `iw scan` (src/wifi/scanner.py)."""

import sys
import os
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wifi import scanner as scanner_mod  # noqa: E402

TEST_ARGS = SimpleNamespace(clear=False, verbose=False, reverse_scan=False)

# Пример вывода iw scan: сеть с WPS 1.0 и сеть без WPS (должна быть отфильтрована)
SAMPLE = """BSS 00:11:22:33:44:55(on wlan0)
\tSSID: TestNet
\tsignal: -45.00 dBm
\tcapability: ESS Privacy
\tRSN:\t * Version: 1
WPS:\t * Version: 1.0
\t * AP setup locked: 0x0
\t * Authentication suites: WPA-Personal
\t * Model: TestRouter
\t * Model Number: T1000
\t * Device name: TestWSC
BSS AA:BB:CC:DD:EE:FF(on wlan0)
\tSSID: NoWpsNet
\tsignal: -60.00 dBm
\tRSN:\t * Version: 1
\t * Authentication suites: WPA2-Personal
"""


class FakeResult:
    """Поддельный результат subprocess.run."""
    def __init__(self, stdout):
        self.stdout = stdout


def test_iw_scanner_parses_wps_network():
    scanner_mod.subprocess.run = lambda *a, **k: FakeResult(SAMPLE)
    s = scanner_mod.WiFiScanner('wlan0', vuln_list=None, args=TEST_ARGS)
    # Перехватываем вывод таблицы
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        nets = s._iwScanner()

    assert nets, 'не найдено WPS-сетей'
    assert len(nets) == 1, f'ожидалась 1 WPS-сеть, получено {len(nets)}'
    n = nets[1]
    assert n['BSSID'] == '00:11:22:33:44:55', n['BSSID']
    assert n['ESSID'] == 'TestNet', n['ESSID']
    assert n['WPS'] is True
    assert n['WPS version'] == '1.0', n['WPS version']
    assert n['Level'] == -45, n['Level']
    assert n['Model'] == 'TestRouter', n['Model']
    assert n['Model number'] == 'T1000', n['Model number']
    assert n['Device name'] == 'TestWSC', n['Device name']


if __name__ == '__main__':
    test_iw_scanner_parses_wps_network()
    print('Тесты сканера прошли ✅')