#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Android module (src/wifi/android.py): cmd/settings calls.

Does not require Android: subprocess.run and sleep calls are mocked and the
built enable/disable Wi-Fi commands are verified.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wifi import android  # noqa: E402


class FakeOut:
    def __init__(self, stdout=''):
        self.stdout = stdout


def _patch(captured, stdout='1'):
    def fake_run(cmd, *a, **k):
        captured.append(cmd)
        # `cmd wifi status` in the adaptive wait should immediately report
        # "disabled" so unit tests pass fast without a real wait.
        if cmd == ['cmd', 'wifi', 'status']:
            return FakeOut('Wi-Fi is disabled')
        return FakeOut(stdout)

    android.subprocess.run = fake_run
    android.time.sleep = lambda s: None


def test_store_always_scan_state():
    """storeAlwaysScanState saves the wifi_scan_always_enabled state."""
    captured = []
    _patch(captured, stdout='1')
    net = android.AndroidNetwork()
    net.storeAlwaysScanState()
    assert captured[0] == ['settings', 'get', 'global', 'wifi_scan_always_enabled']
    assert net.ENABLED_SCANNING == 1

    # If scanning was disabled (0), the flag is not set
    captured.clear()
    _patch(captured, stdout='0')
    net2 = android.AndroidNetwork()
    net2.storeAlwaysScanState()
    assert net2.ENABLED_SCANNING == 0


def test_disable_and_enable_wifi():
    """disableWifi/enableWifi send the correct cmd wifi commands."""
    captured = []
    _patch(captured)

    net = android.AndroidNetwork()
    net.ENABLED_SCANNING = 1
    net.disableWifi()

    assert ['cmd', 'wifi', 'set-wifi-enabled', 'disabled'] in captured, captured
    assert ['cmd', '-w', 'wifi', 'set-scan-always-available', 'disabled'] in captured, captured

    captured.clear()
    net.enableWifi()
    assert ['cmd', 'wifi', 'set-wifi-enabled', 'enabled'] in captured, captured
    assert ['cmd', '-w', 'wifi', 'set-scan-always-available', 'enabled'] in captured, captured


def test_disable_wifi_keeps_always_scan_off_when_unset():
    """If always-scan was not enabled, its disable command is not sent."""
    captured = []
    _patch(captured)

    net = android.AndroidNetwork()
    net.ENABLED_SCANNING = 0
    net.disableWifi()

    always_scan_cmds = [c for c in captured if 'set-scan-always-available' in c]
    assert always_scan_cmds == [], always_scan_cmds


def test_universal_wifi_scan():
    """universalWifiScan: only on Android, returns cmd wifi output / None."""
    # Not Android -> None, subprocess is not called
    android.src_utils.isAndroid = lambda: False
    captured = []
    android.subprocess.run = lambda *a, **k: captured.append(a) or FakeOut()
    assert android.AndroidNetwork().universalWifiScan() is None
    assert captured == [], captured

    # Android + non-empty output -> text is returned
    android.src_utils.isAndroid = lambda: True
    android.subprocess.run = lambda *a, **k: FakeOut('BSS 00:11:22:33:44:55(on wlan0)')
    result = android.AndroidNetwork().universalWifiScan()
    assert result == 'BSS 00:11:22:33:44:55(on wlan0)', result

    # Android + empty output -> None
    android.subprocess.run = lambda *a, **k: FakeOut('   ')
    assert android.AndroidNetwork().universalWifiScan() is None


def test_wait_for_radio_release_returns_early_when_disabled():
    """The adaptive wait exits immediately if Wi-Fi is already off."""
    android.time.sleep = lambda s: None
    status_calls = []

    def fake_run(cmd, *a, **k):
        if cmd == ['cmd', 'wifi', 'status']:
            status_calls.append(cmd)
            return FakeOut('Wi-Fi is disabled')
        return FakeOut('')

    android.subprocess.run = fake_run
    net = android.AndroidNetwork()
    net._waitForRadioRelease(timeout=1.0, poll=0.01)
    # Immediately 'disabled' -> no sleep, one status poll
    assert status_calls == [['cmd', 'wifi', 'status']], status_calls


def test_wait_for_radio_release_falls_back_after_timeout():
    """With a hanging framework (not disabled) - fallback after timeout, no error."""
    android.time.sleep = lambda s: None
    android.subprocess.run = lambda *a, **k: FakeOut('Wi-Fi is enabled')

    net = android.AndroidNetwork()
    start = time.time()
    net._waitForRadioRelease(timeout=0.05, poll=0.01)
    elapsed = time.time() - start
    assert elapsed < 1.0, f'waited too long: {elapsed:.2f}s'

    # Wi-Fi becomes disabled -> exits quickly
    android.subprocess.run = lambda *a, **k: FakeOut('Wi-Fi is disabled')
    start = time.time()
    net._waitForRadioRelease(timeout=1.0, poll=0.01)
    assert time.time() - start < 0.2, 'should exit immediately when disabled'


if __name__ == '__main__':
    test_store_always_scan_state()
    test_disable_and_enable_wifi()
    test_disable_wifi_keeps_always_scan_off_when_unset()
    test_universal_wifi_scan()
    test_wait_for_radio_release_returns_early_when_disabled()
    test_wait_for_radio_release_falls_back_after_timeout()
    print('Android tests passed ✅')