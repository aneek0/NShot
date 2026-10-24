#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan parsing, scan retry policy, and the network table."""

import os
import subprocess
import sys

from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wifi import table as table_mod
from src.wifi.iwparse import parse_scan_lines
from src.wifi.scanner import MAX_EMPTY_SCAN_RETRIES, SCAN_ATTEMPTS, Scanner

from tests._fakes import BSSID, IW_SAMPLE, FakeAndroid, FakeRadio, make_options


class FakeResult:
    """Fake subprocess.run result."""

    def __init__(self, stdout='', returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _scanner(radio=None, results=None):
    """Scanner whose `iw` is a list of results (or one callable)."""
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        result = results() if callable(results) else results
        if isinstance(result, Exception):
            raise result
        if isinstance(result, list):
            result = result.pop(0) if result else FakeResult('')
        return result

    scanner = Scanner('wlan0', make_options(), radio=radio or FakeRadio(),
                      runner=runner)
    return scanner, calls


# -- parsing ---------------------------------------------------------------

def test_parses_wps_network_fields():
    """A WPS AP keeps its ESSID, WPS version, model and WSC name."""
    networks = parse_scan_lines(IW_SAMPLE.splitlines())

    assert len(networks) == 1, 'networks without WPS must be filtered out'
    network = networks[0]
    assert network['BSSID'] == BSSID
    assert network['ESSID'] == 'TestNet'
    assert network['WPS version'] == '1.0'
    assert network['WPS locked'] is False
    assert network['Level'] == -45
    assert network['Model'] == 'TestRouter'
    assert network['Model number'] == 'T1000'
    assert network['Device name'] == 'TestWSC'
    assert network['Security type'] == 'WPA2'


def test_hidden_essid_is_marked():
    """An empty or whitespace ESSID is shown as <hidden>, not as ''."""
    lines = [
        f'BSS {BSSID}(on wlan0)',
        r'\tSSID: ',
        r'\tsignal: -40.00 dBm',
        r'WPS:\t * Version: 1.0',
    ]
    networks = parse_scan_lines([line.replace('\\t', '\t') for line in lines])

    assert networks[0]['ESSID'] == '<hidden>'


def test_wps_2_locked_and_wifi_standard():
    """Version 2.0, the lock flag and the 802.11 standard are parsed."""
    lines = [
        f'BSS {BSSID}(on wlan0)',
        '\tSSID: ModernAP',
        '\tsignal: -50.00 dBm',
        '\tcapability: ESS Privacy',
        '\tRSN:\t * Version: 1',
        '\t * Authentication suites: PSK SAE',
        '\tHE   IEs:',
        'WPS:\t * Version: 1.0',
        '\t * Version2: 2.0',
        '\t * AP setup locked: 0x01',
    ]
    network = parse_scan_lines(lines)[0]

    assert network['WPS version'] == '2.0'
    assert network['WPS locked'] is True
    assert network['WiFi Standard'] == 'WiFi 6 (802.11ax)'


def test_networks_sorted_by_signal():
    """Strongest signal first, whatever the scan order was."""
    lines = [
        'BSS AA:AA:AA:AA:AA:AA(on wlan0)',
        '\tSSID: Weak',
        '\tsignal: -80.00 dBm',
        'WPS:\t * Version: 1.0',
        f'BSS {BSSID}(on wlan0)',
        '\tSSID: Strong',
        '\tsignal: -30.00 dBm',
        'WPS:\t * Version: 1.0',
    ]
    networks = parse_scan_lines(lines)

    assert [network['ESSID'] for network in networks] == ['Strong', 'Weak']


def test_truncated_scan_raises():
    """`command failed:` inside output is an error, not an empty scan."""
    with pytest.raises(ValueError):
        parse_scan_lines(['BSS 00:11:22:33:44:55(on wlan0)',
                          'command failed: Device or resource busy (-16)'])


# -- scan policy -----------------------------------------------------------

def test_scan_returns_parseable_networks():
    """A single successful scan yields the WPS networks."""
    scanner, calls = _scanner(results=FakeResult(IW_SAMPLE))

    networks = scanner.scan()

    assert len(calls) == 1
    assert [network['ESSID'] for network in networks] == ['TestNet']


def test_transient_busy_is_retried():
    """'Device or resource busy' clears after a retry instead of failing."""
    busy = FakeResult('command failed: Device or resource busy (-16)')
    scanner, calls = _scanner(results=[busy, busy, FakeResult(IW_SAMPLE)])

    networks = scanner.scan()

    assert networks
    assert len(calls) == 3, f'expected 3 scan attempts, got {len(calls)}'


def test_persistent_busy_fails_after_all_attempts():
    """A scan that never succeeds reports failure instead of an empty table."""
    busy = FakeResult('command failed: Device or resource busy (-16)')
    scanner, calls = _scanner(results=lambda: busy)

    assert scanner.scan() is None
    assert len(calls) == SCAN_ATTEMPTS


def test_scan_timeout_does_not_hang():
    """A wedged driver (TimeoutExpired) ends after the bounded attempts."""
    timeout = subprocess.TimeoutExpired('iw', timeout=15)
    scanner, calls = _scanner(results=timeout)

    assert scanner.scan() is None
    assert len(calls) == SCAN_ATTEMPTS


def test_empty_scan_is_retried():
    """A successful but empty scan is retried while the driver settles."""
    empty = FakeResult('BSS aa:bb:cc:dd:ee:ff(on wlan0)\n\tSSID: NoWps\n')
    results = [empty] * MAX_EMPTY_SCAN_RETRIES + [FakeResult(IW_SAMPLE)]
    scanner, calls = _scanner(results=results)

    networks = scanner.scan()

    assert networks
    assert len(calls) == MAX_EMPTY_SCAN_RETRIES + 1, calls


def test_iw_missing_uses_framework_fallback():
    """Without `iw`, the Android framework scan replaces the binary."""
    android = FakeAndroid(IW_SAMPLE)
    scanner, calls = _scanner(radio=FakeRadio(android=android),
                              results=FileNotFoundError('iw'))

    networks = scanner.scan()

    assert networks and networks[0]['ESSID'] == 'TestNet'
    assert android.scans == 1
    assert len(calls) == 1


def test_fallback_without_output_fails():
    """A silent framework fallback is a scan failure, not an empty list."""
    scanner, _ = _scanner(radio=FakeRadio(android=FakeAndroid('')),
                          results=FileNotFoundError('iw'))

    assert scanner.scan() is None


# -- table -----------------------------------------------------------------

def _network(essid, level=-45, version='1.0', locked=False, model='M', name='N'):
    return {
        'BSSID': BSSID, 'ESSID': essid, 'Security type': 'WPA2', 'Level': level,
        'WPS version': version, 'WPS locked': locked, 'Model': model,
        'Model number': '1', 'Device name': name, 'WiFi Standard': '',
    }


def test_render_numbers_networks_and_marks_stored():
    """Rows are numbered from 1 and a cracked network is highlighted."""
    lines = []
    table = table_mod.render(
        [_network('Known'), _network('Other', level=-70)],
        stored={(BSSID, 'Known')},
        print_function=lines.append,
    )

    assert sorted(table) == [1, 2]
    assert table[1]['ESSID'] == 'Known'
    assert any('\033[1m\033[93m' in line and 'Known' in line for line in lines), lines
    assert not any('\033[1m\033[93m' in line and 'Other' in line for line in lines)


def test_render_reverses_when_asked():
    """--reverse-scan flips the display order but keeps the numbering."""
    lines = []
    table = table_mod.render(
        [_network('First', level=-30), _network('Second', level=-70)],
        reverse=True, print_function=lines.append,
    )

    assert table[1]['ESSID'] == 'First'
    body = [line for line in lines if 'First' in line or 'Second' in line]
    assert 'Second' in body[0], body


def test_prompt_returns_selection(monkeypatch):
    """Typing a number that exists selects that network."""
    monkeypatch.setattr('builtins.input', lambda prompt='': '2')
    networks = {1: _network('One'), 2: _network('Two')}

    bssid, network = table_mod.prompt(networks)

    assert bssid == BSSID
    assert network['ESSID'] == 'Two'


def test_prompt_refreshes_on_empty_input(monkeypatch):
    """Enter (or r/0) asks the caller for a fresh scan."""
    monkeypatch.setattr('builtins.input', lambda prompt='': '')

    assert table_mod.prompt({1: _network('One')}) is None


def test_prompt_rejects_unknown_number(monkeypatch):
    """An out-of-range number warns and asks again."""
    answers = iter(['9', '1'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(answers))
    warnings = []
    monkeypatch.setattr(table_mod.logger, 'warning',
                        lambda message, *a, **k: warnings.append(message))

    bssid, network = table_mod.prompt({1: _network('One')})

    assert network['ESSID'] == 'One'
    assert warnings == ['Invalid number']