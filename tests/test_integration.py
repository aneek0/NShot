#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attempt policy: WPS exchange -> outcome, PIN retry, Pixie Dust, radio loss.

The supplicant is a scripted fake (one line list per WPS_REG), the radio is a
fake with scriptable link state, pixiewps is a stub. No root, no adapter, no
subprocess.
"""

import json
import os
import sys

from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.store import Store
from src.wps.attempt import (
    GOT_PSK, NO_PIN, RADIO_LOST, WSC_NACK, Attempt,
)

from tests._fakes import (
    BSSID, PIN, PSK, FakePixieRunner, FakeRadio, FakeSession, make_options,
    nack_script, pixie_script, success_script,
)


def _setup(tmp_path, script, radio=None, pixie=None, **overrides):
    """Attempt wired to fakes and a throw-away store."""
    store = Store(tmp_path)
    session = FakeSession(script=script)
    options = make_options(**overrides)
    radio = radio or FakeRadio()
    pixie = pixie or FakePixieRunner()

    attempt = Attempt(
        'wlan0', options,
        store=store,
        radio=radio,
        session_factory=lambda: session,
        pixie_runner=pixie,
    )
    return attempt, session, store, pixie


def test_pin_attack_success_writes_credentials(tmp_path):
    """PIN -> GOT_PSK -> PSK/ESSID reported and written to stored.*."""
    attempt, session, store, _ = _setup(
        tmp_path, [success_script()], write=True
    )

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert result.ok
    assert result.outcome == GOT_PSK
    assert result.psk == PSK
    assert result.essid == 'TestNet'

    wps_regs = [command for command in session.sent if command.startswith('WPS_REG')]
    assert wps_regs == [f'WPS_REG {BSSID} {PIN}'], wps_regs
    assert 'WPS_CANCEL' in session.sent

    text = (store.reports / 'stored.txt').read_text(encoding='utf-8')
    assert PSK in text and BSSID in text
    records = json.loads((store.reports / 'stored.json').read_text(encoding='utf-8'))
    assert records[0]['wpa_psk'] == PSK
    assert records[0]['wps_pin'] == PIN


def test_no_write_keeps_disk_clean(tmp_path):
    """Without --write nothing is stored, but the credential is reported."""
    attempt, _, store, _ = _setup(tmp_path, [success_script()], write=False)

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert result.ok and result.psk == PSK
    assert not (store.reports / 'stored.txt').exists()


def test_wrong_pin_is_rejected_without_retry(tmp_path):
    """Wrong PIN (WSC_NACK on M4) -> NACK outcome, no retry, WPS_CANCEL sent."""
    attempt, session, _, _ = _setup(
        tmp_path, [nack_script(('M4',))], write=False
    )

    with attempt:
        result = attempt.attempt(BSSID, '99999999')

    assert not result.ok
    assert result.outcome == WSC_NACK
    assert not result.locked
    assert len([c for c in session.sent if c.startswith('WPS_REG')]) == 1
    assert 'WPS_CANCEL' in session.sent


def test_locked_ap_retries_then_succeeds(tmp_path):
    """A NACK before M3 means WPS lock: retry after timeout, then succeed."""
    attempt, session, _, _ = _setup(
        tmp_path, [nack_script(('M1',)), success_script()], timeout=0
    )

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert result.ok
    wps_regs = [command for command in session.sent if command.startswith('WPS_REG')]
    assert len(wps_regs) == 2, wps_regs


def test_pixie_dust_recovers_pin_and_connects(tmp_path):
    """A NACK after a full capture runs pixiewps, then retries with its PIN."""
    attempt, session, _, pixie = _setup(
        tmp_path, [pixie_script(), success_script()], pixie_dust=True
    )

    with attempt:
        result = attempt.attempt(BSSID, '11111111')

    assert result.ok
    assert result.pin == PIN
    assert len(pixie.calls) == 1, 'pixiewps must run after a data-carrying NACK'
    wps_regs = [command for command in session.sent if command.startswith('WPS_REG')]
    assert wps_regs == [f'WPS_REG {BSSID} 11111111', f'WPS_REG {BSSID} {PIN}'], wps_regs


def test_pixie_dust_insufficient_data_does_not_run(tmp_path):
    """A NACK without captured fields stops as NO_PIN; pixiewps is not spawned."""
    attempt, _, _, pixie = _setup(
        tmp_path, [nack_script(('M4',))], pixie_dust=True
    )

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert result.outcome == NO_PIN
    assert not result.ok
    assert pixie.calls == []


@mock.patch('src.wps.attempt.time.sleep', lambda seconds: None)
def test_interface_drop_recovers_and_resends(tmp_path):
    """A mid-attempt link drop is recovered: restart, resend, finish."""
    radio = FakeRadio(up=[True, False] + [True] * 8)
    attempt, session, _, _ = _setup(
        tmp_path,
        [['WPS: Building Message M1'], success_script()],
        radio=radio,
        write=False,
    )

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert result.ok
    wps_regs = [command for command in session.sent if command.startswith('WPS_REG')]
    assert len(wps_regs) == 2, wps_regs
    assert session.restarts == 1


@mock.patch('src.wps.attempt.time.sleep', lambda seconds: None)
def test_interface_drop_recovery_is_bounded(tmp_path):
    """A link that never returns ends the attempt as RADIO_LOST."""
    radio = FakeRadio(up=False, recover=[True, True, True, False])
    attempt, session, _, _ = _setup(tmp_path, [[], [], [], []], radio=radio)

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert not result.ok
    assert result.outcome == RADIO_LOST
    wps_regs = [command for command in session.sent if command.startswith('WPS_REG')]
    assert len(wps_regs) == 4, f'expected 1 attempt + 3 recoveries, got {wps_regs}'


def test_supplicant_rejection_is_a_failed_attempt(tmp_path):
    """A non-OK WPS_REG reply is reported as WPS_FAIL, not as an exception."""
    attempt, session, _, _ = _setup(tmp_path, [[]], write=False)
    session.replies = ['FAIL']

    with attempt:
        result = attempt.attempt(BSSID, PIN)

    assert not result.ok
    assert result.outcome == 'WPS_FAIL'


def test_pin_saved_on_abort_but_not_on_nack(tmp_path):
    """A non-NACK failure keeps the PIN for a resume; a NACK never does."""
    attempt, _, store, _ = _setup(tmp_path, [nack_script(('M4',))], write=False)
    with attempt:
        attempt.attempt(BSSID, PIN, save_pin_on_abort=True)
    assert store.load_pin(BSSID) is None

    attempt2, _, store2, _ = _setup(tmp_path / 'second', [nack_script(('M4',))],
                                    write=False)
    with mock.patch.object(attempt2, '_register', side_effect=KeyboardInterrupt):
        result = attempt2.attempt(BSSID, PIN, save_pin_on_abort=True)
    assert not result.ok
    assert store2.load_pin(BSSID) == PIN