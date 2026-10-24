#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the WPS engine seams: pixiewps adapter, attempt reuse.

The supplicant session and the radio are fakes here; what is exercised is the
command pixiewps receives and the objects `Attempt` builds.
"""

import os
import sys

from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.store import Store
from src.wps import pixiewps
from src.wps.attempt import Attempt
from src.wps.protocol import PixieData

from tests._fakes import BSSID, PIN, FakePixieRunner, FakeRadio, FakeSession, make_options


def _data():
    data = PixieData()
    data.PKE = 'PKE'
    data.PKR = 'PKR'
    data.E_HASH1 = 'H1'
    data.E_HASH2 = 'H2'
    data.AUTHKEY = 'AK'
    data.E_NONCE = 'EN'
    data.R_NONCE = 'RN'
    data.BSSID = 'AA:BB:CC:DD:EE:FF'
    return data


def test_pixiewps_command_build():
    """Every captured field reaches pixiewps, with --force for the full range."""
    command = pixiewps.build_command(_data(), full_range=True)

    assert command[0] == 'pixiewps'
    assert command[command.index('--pke') + 1] == 'PKE'
    assert command[command.index('--pkr') + 1] == 'PKR'
    assert command[command.index('--e-bssid') + 1] == 'AA:BB:CC:DD:EE:FF'
    assert command[command.index('--mode') + 1] == '1,2,3,4,5'
    assert '--force' in command


def test_pixiewps_command_without_force():
    """A normal-range run does not pass --force."""
    assert '--force' not in pixiewps.build_command(_data(), full_range=False)


def test_pixiewps_run_parses_pin():
    """The PIN line is extracted and the command is actually executed."""
    captured = []
    result = SimpleNamespace(stdout='[+] WPS pin: 12345670\n', returncode=0)

    def fake_run(command, **kwargs):
        captured.append(command)
        return result

    with mock.patch.object(pixiewps.subprocess, 'run', side_effect=fake_run), \
         mock.patch('builtins.print'):
        pin = pixiewps.run(_data())

    assert pin == PIN
    assert captured and captured[0][0] == 'pixiewps'


def test_pixiewps_run_shows_command_when_asked():
    """show_command prints the command line before running it."""
    printed = []

    with mock.patch.object(pixiewps.subprocess, 'run',
                           return_value=SimpleNamespace(stdout='', returncode=0)), \
         mock.patch.object(pixiewps.logger, 'info',
                           side_effect=lambda message, *a, **k: printed.append(message)), \
         mock.patch('builtins.print'):
        pixiewps.run(_data(), show_command=True)

    assert any('--pke PKE' in message for message in printed), printed


def test_pixiewps_empty_pin_is_marked():
    """pixiewps reports an empty PIN as '<empty>'; it is handed back as '' quoted."""
    with mock.patch.object(pixiewps.subprocess, 'run',
                           return_value=SimpleNamespace(stdout='[+] WPS pin: <empty>\n',
                                                        returncode=0)), \
         mock.patch('builtins.print'):
        assert pixiewps.run(_data()) == "''"


def test_pixiewps_failure_returns_none():
    """Non-zero exit, no PIN line, or a missing binary all mean "no PIN"."""
    with mock.patch.object(pixiewps.subprocess, 'run',
                           return_value=SimpleNamespace(stdout='[+] WPS pin: 1\n',
                                                        returncode=1)), \
         mock.patch('builtins.print'):
        assert pixiewps.run(_data()) is None

    with mock.patch.object(pixiewps.subprocess, 'run',
                           return_value=SimpleNamespace(stdout='nothing useful\n',
                                                        returncode=0)), \
         mock.patch('builtins.print'):
        assert pixiewps.run(_data()) is None

    with mock.patch.object(pixiewps.subprocess, 'run',
                           side_effect=FileNotFoundError('pixiewps')):
        assert pixiewps.run(_data()) is None


def test_attempt_creates_one_session_and_reuses_it(tmp_path):
    """Two attempts on one Attempt reuse the supplicant session."""
    store = Store(tmp_path)
    created = []

    def factory():
        created.append(FakeSession(script=[[]]))
        return created[-1]

    attempt = Attempt('wlan0', make_options(write=False), store=store,
                      radio=FakeRadio(), session_factory=factory,
                      pixie_runner=FakePixieRunner())

    attempt.attempt(BSSID, PIN)
    attempt.attempt(BSSID, PIN)

    assert len(created) == 1, 'the session must be started once and reused'
    assert created[0].started
    attempt.close()
    assert created[0].closed


def test_attempt_context_manager_closes(tmp_path):
    """The context manager owns the session lifecycle."""
    session = FakeSession(script=[[]])
    attempt = Attempt('wlan0', make_options(write=False), store=Store(tmp_path),
                      radio=FakeRadio(), session_factory=lambda: session,
                      pixie_runner=FakePixieRunner())

    with attempt as opened:
        assert opened is attempt
        assert session.started and not session.closed

    assert session.closed


def test_attempt_uses_injected_store_for_pins(tmp_path):
    """A recovered PIN is kept in the injected store, not a global one."""
    store = Store(tmp_path)
    attempt = Attempt('wlan0', make_options(write=False), store=store,
                      radio=FakeRadio(), session_factory=lambda: FakeSession(),
                      pixie_runner=FakePixieRunner())
    attempt.store.save_pin(BSSID, PIN)

    assert store.load_pin(BSSID) == PIN
    assert (store.pixie_pins / '001122334455.pin').exists()