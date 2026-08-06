#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты движка атак (src/wps/connection.py, bruteforce.py, pixiewps.py).

Не требует root и Wi-Fi-адаптера: запуск wpa_supplicant и pixiewps мокается.
"""

import sys
import os
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wps import connection as conn_mod  # noqa: E402
from src.wps import bruteforce as bf_mod    # noqa: E402
from src.wps import pixiewps                # noqa: E402

TEST_ARGS = SimpleNamespace(
    verbose=False, show_pixie=False, pixie_force=False, timeout=60,
    delay=0, write=False, pixie_dust=False, null_pin=False, loop=False,
)


class FakeProcess:
    """Поддельный процесс wpa_supplicant."""
    def __init__(self, *args, **kwargs):
        self._args = args
        self.stdout = type('FakeStream', (), {'readline': lambda self: '', 'close': lambda self: None})()

    def poll(self):
        return None  # процесс «жив»

    def communicate(self, *a, **k):
        return ('fake output', None)

    def terminate(self):
        pass

    def wait(self):
        pass


def _mock_wpas_launch():
    """Подменяет запуск wpa_supplicant и существование control-сокета."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True


def test_pixiewps_command_build():
    """Сборка команды pixiewps."""
    data = pixiewps.Data()
    data.PKE = 'PKE'
    data.PKR = 'PKR'
    data.E_HASH1 = 'H1'
    data.E_HASH2 = 'H2'
    data.AUTHKEY = 'AK'
    data.E_NONCE = 'EN'
    data.R_NONCE = 'RN'
    data.BSSID = 'AA:BB:CC:DD:EE:FF'

    cmd = data._getPixieCmd(full_range=True)
    assert cmd[0] == 'pixiewps'
    assert '--pke' in cmd and cmd[cmd.index('--pke') + 1] == 'PKE'
    assert '--e-bssid' in cmd
    assert '--mode' in cmd and cmd[cmd.index('--mode') + 1] == '1,2,3,4,5'
    assert '--force' in cmd  # full_range


def test_pixiewps_run_parsing():
    """Разбор вывода pixiewps."""
    captured = []

    class FakeRun:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        return FakeRun('[+] WPS pin: 12345670\n')

    pixiewps.subprocess.run = fake_run
    data = pixiewps.Data()
    data.PKE = 'PKE'
    data.PKR = 'PKR'
    data.E_HASH1 = 'H1'
    data.E_HASH2 = 'H2'
    data.AUTHKEY = 'AK'
    data.E_NONCE = 'EN'
    data.R_NONCE = 'RN'
    data.BSSID = 'AA:BB:CC:DD:EE:FF'

    pin = data.runPixieWps(show_command=False)
    assert pin == '12345670', f'Ожидался PIN 12345670, получен {pin!r}'
    assert captured, 'команда pixiewps не выполнялась'


def test_pixiewps_empty_pin():
    """PIN '<empty>' превращается в пустой PIN."""
    def fake_run(cmd, **kwargs):
        return type('FakeRun', (), {'stdout': '[+] WPS pin: <empty>\n', 'returncode': 0})()

    pixiewps.subprocess.run = fake_run
    data = pixiewps.Data()
    data.PKE = data.PKR = data.E_HASH1 = data.E_HASH2 = 'x'
    data.AUTHKEY = data.E_NONCE = data.R_NONCE = 'x'
    data.BSSID = 'AA:BB:CC:DD:EE:FF'
    assert data.runPixieWps() == "''"


def test_connection_initializes_with_injected_args():
    """connection.Initialize принимает args и строит корректную команду wpa_supplicant."""
    _mock_wpas_launch()
    conn = conn_mod.Initialize('wlan0', TEST_ARGS)
    try:
        assert conn.INTERFACE == 'wlan0'
        assert conn.ARGS is TEST_ARGS, 'args не были переданы в движок'
        cmd = conn.WPAS._args[0]
        assert cmd[0] == 'wpa_supplicant'
        assert '-iwlan0' in cmd, cmd
        assert any(c.startswith('-c') for c in cmd), cmd
    finally:
        conn._cleanup()


def test_bruteforce_initializes_with_injected_args():
    """bruteforce.Initialize создаёт connection с теми же args."""
    _mock_wpas_launch()
    bf = bf_mod.Initialize('wlan0', TEST_ARGS)
    try:
        assert bf.ARGS is TEST_ARGS
        assert bf.CONNECTION.ARGS is TEST_ARGS, 'args не проброшены в connection внутри bruteforce'
        assert bf.CONNECTION.INTERFACE == 'wlan0'
    finally:
        bf.CONNECTION._cleanup()


if __name__ == '__main__':
    test_pixiewps_command_build()
    test_pixiewps_run_parsing()
    test_pixiewps_empty_pin()
    test_connection_initializes_with_injected_args()
    test_bruteforce_initializes_with_injected_args()
    print('Все тесты движка атак прошли ✅')
