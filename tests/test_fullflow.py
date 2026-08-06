#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Полный сквозной тест: настоящий handleConnection от скана до отчёта.

Единственное, что мокается — железо: `iw scan` (subprocess.run), запуск
wpa_supplicant (Popen) и его stdout (M1 -> Network Key -> GOT_PSK), а также
интерактивный ввод выбора цели. Весь остальной конвейер — настоящий:
сканирование, парсинг, выбор сети, WPS-обмен, извлечение PSK, запись отчёта.
"""

import sys
import os
import io
import json
import tempfile
import builtins
from contextlib import redirect_stdout
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nshot                                # noqa: E402
from src.wps import connection as conn_mod  # noqa: E402
from src.wifi import scanner as scanner_mod # noqa: E402
import src.utils as utils_mod               # noqa: E402
from tests._fakes import (                  # noqa: E402
    BSSID, PIN, PSK, IW_SAMPLE, FakeSocket, FakeStream, FakeProcess, FakeIwResult,
    network_key_line,
)


class SuccessProcess(FakeProcess):
    """wpa_supplicant, который сразу выдаёт успешную WPS-последовательность."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stdout = FakeStream([
            "WPS: Building Message M1",
            "WPS: Received M1",
            f"wlan0: Trying to associate with 'TestNet' SSID: {BSSID}",
            network_key_line(),
        ])


def _full_args(tmpdir):
    return SimpleNamespace(
        interface='wlan0', bssid=None, pin=PIN,
        bruteforce=False, pbc=False, pixie_dust=False, null_pin=False,
        write=True, verbose=False, show_pixie=False, pixie_force=False,
        timeout=0, delay=0, loop=False, clear=False, reverse_scan=False,
        vuln_list=os.path.join(tmpdir, 'vuln.txt'),
    )


def test_full_flow_scan_to_report():
    """Скан -> выбор цели -> WPS-атака -> GOT_PSK -> отчёт (без моков конвейера)."""
    tmpdir = tempfile.mkdtemp()
    utils_mod.REPORTS_DIR = tmpdir + os.sep

    # Список уязвимых моделей (прочитается handleConnection)
    with open(os.path.join(tmpdir, 'vuln.txt'), 'w', encoding='utf-8') as f:
        f.write('TestRouter T1000\n')

    # Мокаем только железо и ввод
    conn_mod.subprocess.Popen = SuccessProcess
    conn_mod.os.path.exists = lambda p: True
    conn_mod.socket.socket = lambda *a, **k: FakeSocket()
    utils_mod.isInterfaceUp = lambda interface: True
    scanner_mod.subprocess.run = lambda *a, **k: FakeIwResult(IW_SAMPLE)

    real_input = builtins.input
    builtins.input = lambda prompt='': '1'  # выбор первой (единственной WPS) сети
    try:
        args = _full_args(tmpdir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            nshot.handleConnection(args)
    finally:
        builtins.input = real_input

    # BSSID выбран сканером и подставлен в args
    assert args.bssid == BSSID, args.bssid

    # Отчёт записан конвейером целиком
    recs = json.load(open(os.path.join(tmpdir, 'stored.json'), encoding='utf-8'))
    assert recs[0]['bssid'] == BSSID, recs
    assert recs[0]['essid'] == 'TestNet', recs
    assert recs[0]['wpa_psk'] == PSK, recs
    assert recs[0]['wps_pin'] == PIN, recs

    txt = open(os.path.join(tmpdir, 'stored.txt'), encoding='utf-8').read()
    assert PSK in txt and BSSID in txt and 'TestNet' in txt, txt


if __name__ == '__main__':
    test_full_flow_scan_to_report()
    print('Сквозной тест полного конвейера прошёл ✅')
