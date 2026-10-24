#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end: real handleConnection from scan to stored credentials.

Only hardware is faked: `iw scan` output, the supplicant session, the radio.
Scanning, parsing, table selection, the WPS exchange, PSK extraction, PIN
resolution and credential storage are the production code paths.
"""

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nshot                                  # noqa: E402
import src.wps.attempt as attempt_mod         # noqa: E402
from src.store import Store                   # noqa: E402

from tests._fakes import (                    # noqa: E402
    BSSID, PIN, PSK, IW_SAMPLE, FakePixieRunner, FakeRadio, FakeSession,
    make_options, success_script,
)


class FakeResult:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


def _install_hardware(monkeypatch, script):
    """`iw scan` returns IW_SAMPLE; the supplicant answers from `script`."""
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: FakeResult(IW_SAMPLE))
    monkeypatch.setattr(attempt_mod, 'WpaSupplicantSession',
                        lambda interface: FakeSession(script=script))
    monkeypatch.setattr(attempt_mod.pixiewps, 'run',
                        lambda data, *a, **k: FakePixieRunner()(data))


def test_full_flow_scan_select_and_store(monkeypatch, tmp_path, capsys):
    """No --bssid: scan, pick network 1, crack it, store the PSK."""
    _install_hardware(monkeypatch, [success_script()])
    monkeypatch.setattr('builtins.input', lambda prompt='': '1')

    store = Store(tmp_path)
    options = make_options(interface='wlan0', pin=PIN, write=True)
    nshot.handleConnection(options, store, FakeRadio())

    output = capsys.readouterr().out
    assert 'TestNet' in output, 'the scan table must be rendered'

    text = (store.reports / 'stored.txt').read_text(encoding='utf-8')
    assert BSSID in text and PSK in text
    records = json.loads((store.reports / 'stored.json').read_text(encoding='utf-8'))
    assert records[0]['essid'] == 'TestNet'
    assert records[0]['wps_pin'] == PIN


def test_full_flow_with_explicit_bssid_skips_scan(monkeypatch, tmp_path):
    """--bssid avoids scanning entirely."""
    _install_hardware(monkeypatch, [success_script()])
    scan_calls = []
    monkeypatch.setattr(subprocess, 'run',
                        lambda *a, **k: scan_calls.append(a) or FakeResult(IW_SAMPLE))

    store = Store(tmp_path)
    options = make_options(interface='wlan0', bssid=BSSID, pin=PIN, write=False)
    nshot.handleConnection(options, store, FakeRadio())

    assert scan_calls == [], 'a given BSSID must not trigger a scan'


def test_full_flow_bruteforce_saves_mask(monkeypatch, tmp_path):
    """--bruteforce walks from the given mask and records its position."""
    _install_hardware(monkeypatch, [success_script()])

    store = Store(tmp_path)
    options = make_options(interface='wlan0', bssid=BSSID,
                           bruteforce=True, pin='1234567', write=False)
    nshot.handleConnection(options, store, FakeRadio())

    mask = store.load_mask(BSSID)
    assert mask == '1234567', mask


def test_full_flow_bruteforce_rejected_pin_advances(monkeypatch, tmp_path):
    """A rejected first half advances the walk instead of retrying forever."""
    _install_hardware(monkeypatch, [
        ['WPS: Building Message M1', 'WPS: Received M1',
         'WPS: Building Message M4', 'WPS: Received WSC_NACK'],
        success_script(),
    ])

    store = Store(tmp_path)
    options = make_options(interface='wlan0', bssid=BSSID,
                           bruteforce=True, pin='1234', write=False)
    nshot.handleConnection(options, store, FakeRadio())

    # First half 1234 rejected, then 1235's PIN is accepted by the script.
    assert store.load_mask(BSSID) == '1235'
    assert (store.reports / 'stored.txt').exists() is False


def test_handle_connection_pixie_requires_binary(monkeypatch, tmp_path):
    """--pixie-dust without pixiewps dies before touching the radio."""
    monkeypatch.setattr(nshot, 'which', lambda binary: None)

    with pytest.raises(SystemExit):
        nshot.handleConnection(
            make_options(interface='wlan0', pixie_dust=True),
            Store(tmp_path), FakeRadio(),
        )


# -- PIN resolution --------------------------------------------------------

def test_resolve_pin_null_pin_wins():
    """-N sends the null PIN even when -p was also given."""
    options = make_options(null_pin=True, pin='11111111')
    assert nshot.resolvePin(options, BSSID, Store('/nonexistent'), None) == '00000000'


def test_resolve_pin_uses_explicit_pin():
    options = make_options(pin=PIN)
    assert nshot.resolvePin(options, BSSID, Store('/nonexistent'), None) == PIN


def test_resolve_pin_pixie_reuses_saved_pin(monkeypatch, tmp_path):
    """A PIN from an earlier Pixie Dust run is offered for reuse."""
    store = Store(tmp_path)
    store.save_pin(BSSID, PIN)
    monkeypatch.setattr('builtins.input', lambda prompt='': '')

    options = make_options(pixie_dust=True)
    assert nshot.resolvePin(options, BSSID, store, None) == PIN


def test_resolve_pin_pixie_declined_falls_back_to_likely(monkeypatch, tmp_path):
    """Refusing the saved PIN asks the generator for a likely PIN."""
    store = Store(tmp_path)
    store.save_pin(BSSID, PIN)
    monkeypatch.setattr('builtins.input', lambda prompt='': 'n')

    class Generator:
        def getLikely(self, bssid):  # noqa: N802 - mirrors production API
            return '55555555'

    options = make_options(pixie_dust=True)
    assert nshot.resolvePin(options, BSSID, store, Generator()) == '55555555'


def test_resolve_pin_prompts_without_pixie(monkeypatch):
    """Without Pixie Dust the user picks a PIN; empty answer means null PIN."""
    class Generator:
        def promptPin(self, bssid):  # noqa: N802 - mirrors production API
            return None

    assert nshot.resolvePin(make_options(), BSSID, Store('/nonexistent'),
                            Generator()) == '00000000'