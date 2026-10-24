#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI orchestration: argument parsing and the main() lifecycle.

Root, hardware and the attack itself are replaced; the order of the steps and
the cleanup in `finally` are the real code under test.
"""

import io
import os
import sys

from contextlib import redirect_stdout

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nshot                                  # noqa: E402
import src.args                               # noqa: E402
from src.store import Store                   # noqa: E402
from tests._fakes import FakeRadio, make_options  # noqa: E402


def _patch_main(monkeypatch, tmp_path, argv):
    """Disable root/hardware/attack, keep main()'s own logic."""
    monkeypatch.setattr(nshot, 'checkRoot', lambda: True)
    monkeypatch.setattr(nshot, 'checkCoreRequirements', lambda: [])
    monkeypatch.setattr(nshot, 'interfaceExists', lambda interface: True)
    monkeypatch.setattr(nshot, 'isWirelessInterface', lambda interface: True)
    monkeypatch.setattr(nshot.src.utils, 'killInterfering', lambda: None)
    monkeypatch.setattr(nshot.src.utils, 'restoreProcesses', lambda: None)
    monkeypatch.setattr(nshot.src.utils, 'checkRunningProcesses', lambda interface: None)
    monkeypatch.setattr(nshot.src.utils, 'isAndroid', lambda: False)
    monkeypatch.setattr(nshot.src.utils, 'ifaceCtl',
                        lambda interface, action: _record(calls, f'iface_{action}s',
                                                         interface))
    monkeypatch.setattr(nshot.src.store, 'DEFAULT_STORE', Store(tmp_path))

    calls = {'runs': 0}
    radio = FakeRadio()
    monkeypatch.setattr(radio, 'ensure_up',
                        lambda: _record(calls, 'iface_ups', 'wlan0') or True)
    monkeypatch.setattr(nshot.src.radio, 'Radio', lambda interface: radio)

    def fake_handle_connection(options, store, passed_radio):
        calls['runs'] += 1
        calls['options'] = options
        calls['store'] = store
        calls['radio'] = passed_radio

    monkeypatch.setattr(nshot, 'handleConnection', fake_handle_connection)

    sys.argv = argv
    return calls

def _record(calls, key, value):
    calls.setdefault(key, []).append(value)
    return 0



def test_main_single_run_with_kill_restore_iface_down(monkeypatch, tmp_path):
    """Single run: -k -r -I -> kill, one attack, restore, interface down."""
    calls = _patch_main(monkeypatch, tmp_path,
                        ['nshot.py', '-i', 'wlan0', '-k', '-r', '-I'])
    kills = []
    monkeypatch.setattr(nshot.src.utils, 'killInterfering', lambda: kills.append(1))

    nshot.main()

    assert kills == [1], '--kill must kill interfering processes'
    assert calls['runs'] == 1, 'attack must run once'
    assert calls['iface_ups'] == ['wlan0'], calls.get('iface_ups')
    assert calls['iface_downs'] == ['wlan0'], calls.get('iface_downs')
    assert isinstance(calls['store'], Store)
    assert calls['radio'] is not None


def test_main_loop_continues_until_keyboard_interrupt(monkeypatch, tmp_path):
    """--loop restarts the attack until Ctrl+C, then exits cleanly."""
    calls = _patch_main(monkeypatch, tmp_path, ['nshot.py', '-i', 'wlan0', '-l'])
    runs = []

    def fake_handle_connection(options, store, radio):
        runs.append(1)
        if len(runs) == 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(nshot, 'handleConnection', fake_handle_connection)
    monkeypatch.setattr('builtins.input', lambda prompt='': 'y')

    nshot.main()

    assert len(runs) == 3, f'expected 3 iterations, got {len(runs)}'


def test_main_survives_failure_before_android_setup(monkeypatch, tmp_path):
    """A failure before `android_network` exists must not break cleanup."""
    calls = _patch_main(monkeypatch, tmp_path, ['nshot.py', '-i', 'wlan0', '-I'])
    monkeypatch.setattr(nshot.src.utils, 'isAndroid', lambda: True)

    def explode():
        raise RuntimeError('framework is gone')

    monkeypatch.setattr(nshot.src.wifi.android, 'AndroidNetwork', explode)

    with pytest.raises(RuntimeError, match='framework is gone'):
        nshot.main()

    # ifaceCtl still ran: cleanup did not die on an unbound variable
    assert calls['iface_downs'] == ['wlan0'], calls


def test_run_check_warns_on_wired_interface(monkeypatch):
    """--check warns if the selected interface is not Wi-Fi."""
    monkeypatch.setattr(nshot, 'checkRoot', lambda: True)
    monkeypatch.setattr(nshot, 'checkCoreRequirements', lambda: [])
    monkeypatch.setattr(nshot, 'interfaceExists', lambda iface: True)
    monkeypatch.setattr(nshot, 'isWirelessInterface', lambda iface: False)

    buf = io.StringIO()
    with redirect_stdout(buf):
        nshot.runCheck(make_options(interface='eno1'))
    assert 'Note' in buf.getvalue()
    assert 'wireless' in buf.getvalue()

    monkeypatch.setattr(nshot, 'isWirelessInterface', lambda iface: True)
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        nshot.runCheck(make_options(interface='wlan0'))
    assert 'Note' not in buf2.getvalue()


def _parse(argv):
    old = sys.argv
    sys.argv = argv
    try:
        return src.args.parseArgs(), None
    except SystemExit:
        return None, 'exit'
    finally:
        sys.argv = old


def test_args_combine_bruteforce_with_pin():
    """-B -p 1234 (brute-force with a start mask) parse together."""
    options, error = _parse(
        ['nshot.py', '-i', 'wlan0', '-b', 'AA:BB:CC:DD:EE:FF', '-B', '-p', '1234']
    )

    assert error is None
    assert options.bruteforce is True and options.pin == '1234'


def test_args_reject_conflicting_modes():
    """Pixie Dust + brute-force is rejected by argparse."""
    _, error = _parse(['nshot.py', '-i', 'wlan0', '-P', '-B'])

    assert error == 'exit'