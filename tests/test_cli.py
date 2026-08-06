#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест оркестрации CLI: запускает настоящий main() с моками тяжёлых звеньев.

Проверяет порядок работы entry point: проверка прав/интерфейса, kill/restore
процессов, поднятие интерфейса, вызов атаки, опускание интерфейса при -I.
"""

import sys
import os
import io
from contextlib import redirect_stdout
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nshot                      # noqa: E402
from src import utils as utils_mod  # noqa: E402


def _patch_main_deps():
    """Отключает всё, что требует root/железа, оставляя логику main()."""
    nshot.checkRoot = lambda: True
    nshot.checkCoreRequirements = lambda: []
    nshot.interfaceExists = lambda interface: True

    calls = {'handle_connection': 0, 'kill': 0, 'restore': 0, 'iface_ups': [], 'iface_downs': []}

    def fake_handle_connection(args):
        calls['handle_connection'] += 1
        assert args.interface == 'wlan0'

    def fake_kill():
        calls['kill'] += 1

    def fake_restore():
        calls['restore'] += 1

    def fake_iface_ctl(interface, action):
        calls[f'iface_{action}s'].append(interface)
        return False  # успех

    nshot.handleConnection = fake_handle_connection
    nshot.src.utils.killInterfering = fake_kill
    nshot.src.utils.restoreProcesses = fake_restore
    nshot.src.utils.ifaceCtl = fake_iface_ctl
    nshot.src.utils.checkRunningProcesses = lambda interface: None
    nshot.src.utils.isAndroid = lambda: False
    nshot.setupAndroidWifi = lambda android_network, enable=False: None
    return calls


def test_main_single_run_with_kill_restore_iface_down():
    """Одиночный прогон: -k -r -I -> kill, одна атака, restore, iface down."""
    calls = _patch_main_deps()
    sys.argv = ['nshot.py', '-i', 'wlan0', '-k', '-r', '-I']

    nshot.main()

    assert calls['kill'] == 1, '--kill должен убить мешающие процессы'
    assert calls['handle_connection'] == 1, 'атака должна выполниться один раз'
    assert calls['restore'] == 1, '--restore должен восстановить процессы'
    assert calls['iface_ups'] == ['wlan0'], calls['iface_ups']
    assert calls['iface_downs'] == ['wlan0'], calls['iface_downs']


def test_main_loop_continues_until_keyboard_interrupt():
    """--loop: перезапускает атаку до Ctrl+C, затем чисто завершается."""
    import builtins
    calls = _patch_main_deps()
    calls['loop_runs'] = 0
    # При Ctrl+C main() спрашивает «Выйти?» — отвечаем 'y'
    real_input = builtins.input
    builtins.input = lambda prompt='': 'y'
    try:

        def fake_handle_connection_loop(args):
            calls['handle_connection'] += 1
            calls['loop_runs'] += 1
            if calls['loop_runs'] == 3:
                raise KeyboardInterrupt

        nshot.handleConnection = fake_handle_connection_loop
        sys.argv = ['nshot.py', '-i', 'wlan0', '-l']

        nshot.main()
    finally:
        builtins.input = real_input

    assert calls['handle_connection'] == 3, f'ожидалось 3 итерации, было {calls["handle_connection"]}'
    assert calls['restore'] == 0  # -r не передавали


def test_run_check_warns_on_wired_interface():
    """--check предупреждает, если выбранный интерфейс не Wi-Fi."""
    nshot.interfaceExists = lambda iface: True
    nshot.isWirelessInterface = lambda iface: False

    buf = io.StringIO()
    with redirect_stdout(buf):
        nshot.runCheck(SimpleNamespace(interface='eno1'))
    assert 'Внимание' in buf.getvalue()
    assert 'wireless' in buf.getvalue()

    # Wi-Fi-интерфейс — без предупреждения
    nshot.isWirelessInterface = lambda iface: True
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        nshot.runCheck(SimpleNamespace(interface='wlan0'))
    assert 'Внимание' not in buf2.getvalue()


if __name__ == '__main__':
    test_run_check_warns_on_wired_interface()
    test_main_single_run_with_kill_restore_iface_down()
    test_main_loop_continues_until_keyboard_interrupt()
    print('Тесты оркестрации CLI прошли ✅')
