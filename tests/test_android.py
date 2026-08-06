#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты Android-модуля (src/wifi/android.py): команды cmd/settings.

Не требует Android: вызовы subprocess.run и sleep мокаются, проверяются
собранные команды включения/выключения Wi-Fi.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wifi import android  # noqa: E402


class FakeOut:
    def __init__(self, stdout=''):
        self.stdout = stdout


def _patch(captured, stdout='1'):
    def fake_run(cmd, *a, **k):
        captured.append(cmd)
        return FakeOut(stdout)

    android.subprocess.run = fake_run
    android.time.sleep = lambda s: None


def test_store_always_scan_state():
    """storeAlwaysScanState сохраняет состояние wifi_scan_always_enabled."""
    captured = []
    _patch(captured, stdout='1')
    net = android.AndroidNetwork()
    net.storeAlwaysScanState()
    assert captured[0] == ['settings', 'get', 'global', 'wifi_scan_always_enabled']
    assert net.ENABLED_SCANNING == 1

    # Если сканирование было выключено (0) — флаг не ставится
    captured.clear()
    _patch(captured, stdout='0')
    net2 = android.AndroidNetwork()
    net2.storeAlwaysScanState()
    assert net2.ENABLED_SCANNING == 0


def test_disable_and_enable_wifi():
    """disableWifi/enableWifi шлют корректные команды cmd wifi."""
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
    """Если always-scan не был включён, команда его отключения не шлётся."""
    captured = []
    _patch(captured)

    net = android.AndroidNetwork()
    net.ENABLED_SCANNING = 0
    net.disableWifi()

    always_scan_cmds = [c for c in captured if 'set-scan-always-available' in c]
    assert always_scan_cmds == [], always_scan_cmds


if __name__ == '__main__':
    test_store_always_scan_state()
    test_disable_and_enable_wifi()
    test_disable_wifi_keeps_always_scan_off_when_unset()
    print('Тесты android прошли ✅')
