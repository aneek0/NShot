#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты Android-модуля (src/wifi/android.py): команды cmd/settings.

Не требует Android: вызовы subprocess.run и sleep мокаются, проверяются
собранные команды включения/выключения Wi-Fi.
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
        # `cmd wifi status` в адаптивном ожидании пусть сразу говорит "disabled",
        # чтобы юнит-тесты проходили без реального ожидания и быстро.
        if cmd == ['cmd', 'wifi', 'status']:
            return FakeOut('Wi-Fi is disabled')
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


def test_universal_wifi_scan():
    """universalWifiScan: только на Android, возвращает вывод cmd wifi / None."""
    # Не Android -> None, subprocess не вызывается
    android.src_utils.isAndroid = lambda: False
    captured = []
    android.subprocess.run = lambda *a, **k: captured.append(a) or FakeOut()
    assert android.AndroidNetwork().universalWifiScan() is None
    assert captured == [], captured

    # Android + непустой вывод -> возвращается текст
    android.src_utils.isAndroid = lambda: True
    android.subprocess.run = lambda *a, **k: FakeOut('BSS 00:11:22:33:44:55(on wlan0)')
    result = android.AndroidNetwork().universalWifiScan()
    assert result == 'BSS 00:11:22:33:44:55(on wlan0)', result

    # Android + пустой вывод -> None
    android.subprocess.run = lambda *a, **k: FakeOut('   ')
    assert android.AndroidNetwork().universalWifiScan() is None


def test_wait_for_radio_release_returns_early_when_disabled():
    """Адаптивное ожидание мгновенно выходит, если Wi-Fi уже выключен."""
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
    # Сразу 'disabled' -> ни одного sleep, один опрос состояния
    assert status_calls == [['cmd', 'wifi', 'status']], status_calls


def test_wait_for_radio_release_falls_back_after_timeout():
    """При зависшем фреймворке (не disabled) — фолбэк после таймаута, без ошибки."""
    android.time.sleep = lambda s: None
    android.subprocess.run = lambda *a, **k: FakeOut('Wi-Fi is enabled')

    net = android.AndroidNetwork()
    start = time.time()
    net._waitForRadioRelease(timeout=0.05, poll=0.01)
    elapsed = time.time() - start
    assert elapsed < 1.0, f'ждал слишком долго: {elapsed:.2f}s'

    # Wi-Fi стал disabled -> выходит быстро
    android.subprocess.run = lambda *a, **k: FakeOut('Wi-Fi is disabled')
    start = time.time()
    net._waitForRadioRelease(timeout=1.0, poll=0.01)
    assert time.time() - start < 0.2, 'должен выйти сразу при disabled'


if __name__ == '__main__':
    test_store_always_scan_state()
    test_disable_and_enable_wifi()
    test_disable_wifi_keeps_always_scan_off_when_unset()
    test_universal_wifi_scan()
    test_wait_for_radio_release_returns_early_when_disabled()
    test_wait_for_radio_release_falls_back_after_timeout()
    print('Тесты android прошли ✅')
