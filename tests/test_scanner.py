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


if __name__ == '__main__':
    test_prompt_network_selects_target()
    test_iw_scanner_parses_wps_network()
    test_iw_scanner_parses_wifi_standard()
    test_scanner_clears_screen_before_each_scan()
    print('Scanner tests passed ✅')