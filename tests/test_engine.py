#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the attack engine (src/wps/connection.py, bruteforce.py, pixiewps.py).

Does not require root or a Wi-Fi adapter: the wpa_supplicant and pixiewps
launches are mocked.
"""

import sys
import os
import time
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
    """Fake wpa_supplicant process."""
    def __init__(self, *args, **kwargs):
        self._args = args
        self.stdout = type('FakeStream', (), {'readline': lambda self: '', 'close': lambda self: None})()

    def poll(self):
        return None  # process is "alive"

    def communicate(self, *a, **k):
        return ('fake output', None)

    def terminate(self):
        pass

    def wait(self):
        pass


def _mock_wpas_launch():
    """Replace the wpa_supplicant launch and the control-socket existence."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True


def test_pixiewps_command_build():
    """Build the pixiewps command."""
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
    """Parse pixiewps output."""
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
    assert pin == '12345670', f'Expected PIN 12345670, got {pin!r}'
    assert captured, 'pixiewps command was not run'


def test_pixiewps_empty_pin():
    """PIN '<empty>' becomes an empty PIN."""
    def fake_run(cmd, **kwargs):
        return type('FakeRun', (), {'stdout': '[+] WPS pin: <empty>\n', 'returncode': 0})()

    pixiewps.subprocess.run = fake_run
    data = pixiewps.Data()
    data.PKE = data.PKR = data.E_HASH1 = data.E_HASH2 = 'x'
    data.AUTHKEY = data.E_NONCE = data.R_NONCE = 'x'
    data.BSSID = 'AA:BB:CC:DD:EE:FF'
    assert data.runPixieWps() == "''"


def test_connection_initializes_with_injected_args():
    """connection.Initialize accepts args and builds the correct wpa_supplicant command."""
    _mock_wpas_launch()
    conn = conn_mod.Initialize('wlan0', TEST_ARGS)
    try:
        assert conn.INTERFACE == 'wlan0'
        assert conn.ARGS is TEST_ARGS, 'args were not passed into the engine'
        cmd = conn.WPAS._args[0]
        assert cmd[0] == 'wpa_supplicant'
        assert '-iwlan0' in cmd, cmd
        assert any(c.startswith('-c') for c in cmd), cmd
    finally:
        conn._cleanup()


def test_bruteforce_initializes_with_injected_args():
    """bruteforce.Initialize creates its connection with the same args."""
    _mock_wpas_launch()
    bf = bf_mod.Initialize('wlan0', TEST_ARGS)
    try:
        assert bf.ARGS is TEST_ARGS
        assert bf.CONNECTION.ARGS is TEST_ARGS, 'args were not passed into the connection inside bruteforce'
        assert bf.CONNECTION.INTERFACE == 'wlan0'
    finally:
        bf.CONNECTION._cleanup()


def test_reusable_objects_created_once():
    """WPSpin/WiFiCollector are created once and reused between attempts."""
    _mock_wpas_launch()
    conn = conn_mod.Initialize('wlan0', TEST_ARGS)
    try:
        assert conn.GENERATOR is not None and conn.COLLECTOR is not None
        import src.wps.connection as c
        calls = []
        orig_gen = c.src.wps.generator.WPSpin
        orig_col = c.src.wifi.collector.WiFiCollector
        c.src.wps.generator.WPSpin = lambda: calls.append(1) or orig_gen()
        c.src.wifi.collector.WiFiCollector = lambda: calls.append(2) or orig_col()
        try:
            conn.singleConnection('AA:BB:CC:DD:EE:FF', '12345670')
        except Exception:
            pass  # the fake stream does not produce full success - only check object creation
        finally:
            c.src.wps.generator.WPSpin = orig_gen
            c.src.wifi.collector.WiFiCollector = orig_col
        assert calls == [], f'should not create new generators/collectors, got {calls}'
    finally:
        conn._cleanup()


def test_drain_wpas_non_blocking_with_pipe():
    """_drainWpas flushes backlog via select without blocking."""
    _mock_wpas_launch()
    conn = conn_mod.Initialize('wlan0', TEST_ARGS)
    try:
        r, w = os.pipe()
        with os.fdopen(w, 'w', encoding='utf-8') as fw:
            fw.write('WPS: Building Message M1\n' * 5)
            fw.flush()
            with os.fdopen(r, 'r', encoding='utf-8') as fr:
                conn.WPAS.stdout = fr
                start = time.monotonic()
                conn._drainWpas()
                elapsed = time.monotonic() - start
                assert elapsed < 0.5, f'_drainWpas blocked for {elapsed:.2f}s'
    finally:
        conn._cleanup()


if __name__ == '__main__':
    test_pixiewps_command_build()
    test_pixiewps_run_parsing()
    test_pixiewps_empty_pin()
    test_connection_initializes_with_injected_args()
    test_bruteforce_initializes_with_injected_args()
    test_reusable_objects_created_once()
    test_drain_wpas_non_blocking_with_pipe()
    print('Attack engine tests passed ✅')