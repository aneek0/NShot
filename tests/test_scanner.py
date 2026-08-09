#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the `iw scan` output parser (src/wifi/scanner.py)."""

import sys
import os
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wifi import scanner as scanner_mod  # noqa: E402

TEST_ARGS = SimpleNamespace(clear=False, verbose=False, reverse_scan=False)

# Example iw scan output: a network with WPS 1.0 and a network without WPS (must be filtered)
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
    """Fake subprocess.run result."""
    def __init__(self, stdout):
        self.stdout = stdout


def test_prompt_network_selects_target():
    """Interactive target selection: input '1' -> (BSSID, network_info)."""
    import builtins
    scanner_mod.subprocess.run = lambda *a, **k: FakeResult(SAMPLE)

    real_input = builtins.input
    builtins.input = lambda prompt='': '1'
    try:
        s = scanner_mod.WiFiScanner('wlan0', vuln_list=None, args=TEST_ARGS)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = s.promptNetwork()
    finally:
        builtins.input = real_input

    assert result is not None
    bssid, info = result
    assert bssid == '00:11:22:33:44:55', bssid
    assert info['ESSID'] == 'TestNet', info['ESSID']


def test_iw_scanner_parses_wps_network():
    scanner_mod.subprocess.run = lambda *a, **k: FakeResult(SAMPLE)
    s = scanner_mod.WiFiScanner('wlan0', vuln_list=None, args=TEST_ARGS)
    # Capture the table output
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        nets = s._iwScanner()

    assert nets, 'No WPS networks found'
    assert len(nets) == 1, f'expected 1 WPS network, got {len(nets)}'
    n = nets[1]
    assert n['BSSID'] == '00:11:22:33:44:55', n['BSSID']
    assert n['ESSID'] == 'TestNet', n['ESSID']
    assert n['WPS'] is True
    assert n['WPS version'] == '1.0', n['WPS version']
    assert n['Level'] == -45, n['Level']
    assert n['Model'] == 'TestRouter', n['Model']
    assert n['Model number'] == 'T1000', n['Model number']
    assert n['Device name'] == 'TestWSC', n['Device name']


def test_iw_scanner_parses_wifi_standard():
    """WiFi standard detection from iw scan lines (HE/VHT/802.11ax/ac)."""
    sample = SAMPLE.replace(
        "\tRSN:\t * Version: 1",
        "\tRSN:\t * Version: 1\n\t * HE IEs:\n\t * 802.11ax\n", 1
    )
    scanner_mod.subprocess.run = lambda *a, **k: FakeResult(sample)
    s = scanner_mod.WiFiScanner('wlan0', vuln_list=None, args=TEST_ARGS)
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        nets = s._iwScanner()
    n = nets[1]
    assert n['WiFi Standard'] == 'WiFi 6 (802.11ax)', n['WiFi Standard']


def test_scanner_clears_screen_before_each_scan():
    """The screen is cleared before every scanner run (initial and Enter refresh)."""
    import builtins
    import io
    from contextlib import redirect_stdout

    scanner_mod.subprocess.run = lambda *a, **k: FakeResult(SAMPLE)
    clears = []
    scanner_mod.src.utils.clearScreen = lambda: clears.append(1)

    real_input = builtins.input
    inputs = iter(['', '1'])  # Enter -> refresh, then pick a target
    builtins.input = lambda prompt='': next(inputs)
    try:
        s = scanner_mod.WiFiScanner('wlan0', vuln_list=None, args=TEST_ARGS)
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = s.promptNetwork()
    finally:
        builtins.input = real_input

    assert result is not None
    # Initial scan + Enter refresh = at least 2 screen clears
    assert len(clears) >= 2, f'expected at least 2 clears, got: {clears}'


def _run_iw_scanner(calls):
    """Run _iwScanner with all hardware/state helpers mocked (fast, isolated)."""
    import io
    from contextlib import redirect_stdout
    scanner_mod.time.sleep = lambda s: None
    scanner_mod.src.utils.ensureInterfaceUp = lambda *a, **k: True
    scanner_mod.src.utils.isAndroid = lambda: False
    scanner_mod.src.utils.clearScreen = lambda: None
    # The real waitForInterfaceUp polls for up to 20s of wall time; with a
    # mocked sleep it would spin through millions of instant iterations, so
    # it must be mocked here too.
    scanner_mod.src.utils.waitForInterfaceUp = lambda *a, **k: True
    s = scanner_mod.WiFiScanner('wlan0', vuln_list=None, args=TEST_ARGS)
    buf = io.StringIO()
    with redirect_stdout(buf):
        return s._iwScanner(), calls


def test_iw_scanner_retries_transient_busy_error():
    """A transient 'Device or resource busy (-16)' is retried with backoff."""
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        if len(calls) < 3:
            return FakeResult('command failed: Device or resource busy (-16)')
        return FakeResult(SAMPLE)

    scanner_mod.subprocess.run = fake_run
    nets, _ = _run_iw_scanner(calls)

    assert nets, 'should retry and recover from a transient busy error'
    assert len(calls) == 3, f'expected 3 scan attempts, got {len(calls)}'
    assert nets[1]['ESSID'] == 'TestNet', nets[1]['ESSID']


def test_iw_scanner_times_out_instead_of_hanging():
    """A wedged driver (subprocess raising TimeoutExpired) is reported, not hung on."""
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        raise scanner_mod.subprocess.TimeoutExpired(cmd, timeout=k.get('timeout', 15))

    scanner_mod.subprocess.run = fake_run
    result, _ = _run_iw_scanner(calls)

    assert result is False, 'all attempts timed out -> scan must fail cleanly'
    assert len(calls) == 4, f'expected 4 timed-out attempts, got {len(calls)}'


def test_iw_scanner_yields_reason_on_persistent_busy():
    """Persistent 'Device or resource busy' after all retries: fail with the reason."""
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        return FakeResult('command failed: Device or resource busy (-16)')

    scanner_mod.subprocess.run = fake_run
    result, _ = _run_iw_scanner(calls)

    assert result is False, 'a scan that never succeeds must return False'
    assert len(calls) == 4, f'expected 4 scan attempts, got {len(calls)}'


def test_iw_scanner_falls_back_when_iw_missing():
    """If the iw binary is missing, the Android universal scan is used instead."""
    def fake_run(cmd, *a, **k):
        raise FileNotFoundError('iw not found')

    scanner_mod.subprocess.run = fake_run
    original_android_network = scanner_mod.AndroidNetwork
    scanner_mod.AndroidNetwork = lambda: SimpleNamespace(universalWifiScan=lambda: SAMPLE)
    try:
        nets, _ = _run_iw_scanner([])
    finally:
        scanner_mod.AndroidNetwork = original_android_network

    assert nets, 'should fall back to the universal scan when iw is missing'
    assert nets[1]['ESSID'] == 'TestNet', nets[1]['ESSID']


if __name__ == '__main__':
    test_prompt_network_selects_target()
    test_iw_scanner_parses_wps_network()
    test_iw_scanner_parses_wifi_standard()
    test_scanner_clears_screen_before_each_scan()
    test_iw_scanner_retries_transient_busy_error()
    test_iw_scanner_times_out_instead_of_hanging()
    test_iw_scanner_yields_reason_on_persistent_busy()
    test_iw_scanner_falls_back_when_iw_missing()
    print('Scanner tests passed ✅')