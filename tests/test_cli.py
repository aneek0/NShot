#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI orchestration test: runs the real main() with mocked heavy parts.

Verifies the entry-point order: root/interface checks, kill/restore
of processes, bringing the interface up, calling the attack, and bringing
the interface down with -I.
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
    """Disables everything that needs root/hardware, keeping main() logic."""
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

    def fake_ensure_up(interface):
        # New interface bring-up path: record it as the "up" action.
        calls[f'iface_ups'].append(interface)
        return True  # success

    def fake_iface_ctl(interface, action):
        calls[f'iface_{action}s'].append(interface)
        return False  # success

    nshot.handleConnection = fake_handle_connection
    nshot.src.utils.killInterfering = fake_kill
    nshot.src.utils.restoreProcesses = fake_restore
    nshot.src.utils.ensureInterfaceUp = fake_ensure_up
    nshot.src.utils.ifaceCtl = fake_iface_ctl
    nshot.src.utils.checkRunningProcesses = lambda interface: None
    nshot.src.utils.isAndroid = lambda: False
    nshot.setupAndroidWifi = lambda android_network, enable=False: None
    return calls


def test_main_single_run_with_kill_restore_iface_down():
    """Single run: -k -r -I -> kill, one attack, restore, iface down."""
    calls = _patch_main_deps()
    sys.argv = ['nshot.py', '-i', 'wlan0', '-k', '-r', '-I']

    nshot.main()

    assert calls['kill'] == 1, '--kill must kill interfering processes'
    assert calls['handle_connection'] == 1, 'attack must run once'
    assert calls['restore'] == 1, '--restore must restore processes'
    assert calls['iface_ups'] == ['wlan0'], calls['iface_ups']
    assert calls['iface_downs'] == ['wlan0'], calls['iface_downs']


def test_main_loop_continues_until_keyboard_interrupt():
    """--loop: restarts the attack until Ctrl+C, then exits cleanly."""
    import builtins
    calls = _patch_main_deps()
    calls['loop_runs'] = 0
    # On Ctrl+C main() asks 'Exit?' - answer 'y'
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

    assert calls['handle_connection'] == 3, f'expected 3 iterations, got {calls["handle_connection"]}'
    assert calls['restore'] == 0  # -r was not passed


def test_run_check_warns_on_wired_interface():
    """--check warns if the selected interface is not Wi-Fi."""
    nshot.interfaceExists = lambda iface: True
    nshot.isWirelessInterface = lambda iface: False

    buf = io.StringIO()
    with redirect_stdout(buf):
        nshot.runCheck(SimpleNamespace(interface='eno1'))
    assert 'Note' in buf.getvalue()
    assert 'wireless' in buf.getvalue()

    # Wi-Fi interface - no warning
    nshot.isWirelessInterface = lambda iface: True
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        nshot.runCheck(SimpleNamespace(interface='wlan0'))
    assert 'Note' not in buf2.getvalue()


def test_args_combine_bruteforce_with_pin():
    """-B -p 1234 (brute-force with a start mask) parse together; conflicts are rejected."""
    import src.args as args_mod

    def parse(argv):
        args_mod.parseArgs = args_mod.parseArgs  # real function
        sys.argv = argv
        try:
            return args_mod.parseArgs(), None
        except SystemExit:
            return None, 'exit'

    # Combination from README: brute-force + start mask
    a, err = parse(['nshot.py', '-i', 'wlan0', '-b', 'AA:BB:CC:DD:EE:FF', '-B', '-p', '1234'])
    assert err is None, f'-B -p 1234 should parse: {err}'
    assert a.bruteforce is True and a.pin == '1234', (a.bruteforce, a.pin)

    # Mutually exclusive modes are still rejected
    _, err = parse(['nshot.py', '-i', 'wlan0', '-P', '-B'])
    assert err == 'exit', 'Pixie Dust + brute-force must conflict'


if __name__ == '__main__':
    test_run_check_warns_on_wired_interface()
    test_main_single_run_with_kill_restore_iface_down()
    test_main_loop_continues_until_keyboard_interrupt()
    test_args_combine_bruteforce_with_pin()
    print('CLI orchestration tests passed ✅')