#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Integration test of the full attack pipeline.

Mocks wpa_supplicant (stdout + control socket) and pixiewps to exercise the
whole path: WPS_REG -> M1/M4 message parsing -> NACK -> Pixie Dust -> retry
with the found PIN -> GOT_PSK -> report write.
Does not require root or a Wi-Fi adapter.
"""

import sys
import os
import json
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wps import connection as conn_mod  # noqa: E402
from src.wps import bruteforce as bf_mod    # noqa: E402
from src.wps import pixiewps                # noqa: E402
import src.utils as utils_mod               # noqa: E402

BSSID = '00:11:22:33:44:55'
PIN = '12345670'
PSK = 'secret1234'
PSK_HEX = PSK.encode().hex()  # 73656372657431323334

BASE_ARGS = dict(
    verbose=False, show_pixie=False, pixie_force=False, timeout=0,
    delay=0, write=True, pixie_dust=False, null_pin=False, loop=False,
)


def make_args(**overrides):
    return SimpleNamespace(**{**BASE_ARGS, **overrides})


class FakeSocket:
    """Fake wpa_supplicant control socket."""
    def __init__(self):
        self.sent = []
        self.reply = b'OK'

    def sendto(self, data, _addr):
        self.sent.append(data.decode())

    def recvfrom(self, _n):
        return (self.reply, None)

    def close(self):
        pass


class FakeStream:
    """Fake wpa_supplicant stdout: yields lines in sequence."""
    def __init__(self, lines):
        self._lines = list(lines)

    def read(self, _n=0):
        return ''

    def readline(self):
        return self._lines.pop(0) if self._lines else ''

    def close(self):
        pass


class FakeProcess:
    """Fake wpa_supplicant process."""
    def __init__(self, *args, **kwargs):
        self._args = args
        self.stdout = FakeStream([])

    def poll(self):
        return None

    def communicate(self, *a, **k):
        return ('', None)

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, *a, **k):
        return 0


def _setup(stream_lines, reports_dir=None, **args_overrides):
    """Creates a connection.Initialize with a replaced wpa_supplicant."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    utils_mod.isInterfaceUp = lambda interface: True
    # Self-contained reports dir so successful connections can write reports
    # without depending on state left by other tests.
    utils_mod.REPORTS_DIR = (reports_dir or tempfile.mkdtemp()) + os.sep

    args = make_args(**args_overrides)
    conn = conn_mod.Initialize('wlan0', args)
    conn.WPAS.stdout = FakeStream(stream_lines)
    conn.RETSOCK = FakeSocket()
    return conn, args


def test_pin_attack_success_writes_report():
    """Full success: PIN -> GOT_PSK -> report in reports/."""
    tmpdir = tempfile.mkdtemp()
    lines = [
        "WPS: Building Message M1",
        "WPS: Received M1",
        "wlan0: Trying to associate with 'TestNet' SSID: " + BSSID,
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",
    ]
    conn, _ = _setup(lines, reports_dir=tmpdir)

    try:
        result = conn.singleConnection(BSSID, PIN)
        assert result is True, 'singleConnection must return True on GOT_PSK'
        assert conn.CONNECTION_STATUS.WPA_PSK == PSK, conn.CONNECTION_STATUS.WPA_PSK
        assert conn.CONNECTION_STATUS.ESSID == 'TestNet', conn.CONNECTION_STATUS.ESSID

        wps_cmds = [c for c in conn.RETSOCK.sent if c.startswith('WPS_REG')]
        assert wps_cmds == [f'WPS_REG {BSSID} {PIN}'], wps_cmds

        # Report saved
        txt = open(os.path.join(tmpdir, 'stored.txt'), encoding='utf-8').read()
        assert PSK in txt and BSSID in txt, txt
        recs = json.load(open(os.path.join(tmpdir, 'stored.json'), encoding='utf-8'))
        assert recs[0]['wpa_psk'] == PSK and recs[0]['wps_pin'] == PIN, recs
    finally:
        conn._cleanup()


def test_wrong_pin_returns_false():
    """Wrong PIN (WSC_NACK on M4) -> False, no retry, no report."""
    lines = [
        "WPS: Building Message M4",
        "WPS: Received WSC_NACK",
    ]
    conn, _ = _setup(lines)

    try:
        result = conn.singleConnection(BSSID, '99999999')
        assert result is False
        assert conn.CONNECTION_STATUS.STATUS == 'WSC_NACK'
        # After a failure WPS_CANCEL is sent
        assert 'WPS_CANCEL' in conn.RETSOCK.sent, conn.RETSOCK.sent
    finally:
        conn._cleanup()


def test_locked_retries_then_succeeds():
    """WPS lock on M1 -> retry through timeout=0 -> success."""
    lines = [
        "WPS: Building Message M1",
        "WPS: Received WSC_NACK",      # LAST_M_MESSAGE=1 -> locked
        "WPS: Building Message M1",
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",
    ]
    conn, _ = _setup(lines)

    try:
        result = conn.singleConnection(BSSID, PIN)
        assert result is True
        wps_regs = [c for c in conn.RETSOCK.sent if c.startswith('WPS_REG')]
        assert len(wps_regs) == 2, f'expected 2 attempts, got {len(wps_regs)}'
    finally:
        conn._cleanup()


def test_pixie_dust_collects_data_and_uses_pin():
    """Pixie Dust: collect data -> WSC_NACK -> pixiewps -> PIN -> success."""
    # Pixie Dust data in wpa_supplicant hexdump format
    def hx(nbytes):
        return 'AB' * nbytes

    pixie_lines = [
        f"WPS: E-Hash1 (hexdump)(32): {hx(32)}",
        f"WPS: E-Hash2 (hexdump)(32): {hx(32)}",
        f"WPS: AuthKey (hexdump)(32): {hx(32)}",
        f"WPS: Enrollee Nonce (hexdump)(16): {hx(16)}",
        f"WPS: Registrar Nonce (hexdump)(16): {hx(16)}",
        f"WPS: DH own Public Key (hexdump)(192): {hx(192)}",
        f"WPS: DH peer Public Key (hexdump)(192): {hx(192)}",
        "WPS: Building Message M4",
        "WPS: Received WSC_NACK",   # PIN from getLikely did not work -> go to pixiewps
        "WPS: Building Message M1",
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",  # retry with the pixiewps PIN
    ]

    # Mock the pixiewps launch
    pixie_cmds = []

    def fake_pixie_run(cmd, **kwargs):
        pixie_cmds.append(cmd)
        return type('FakeRun', (), {'stdout': '[+] WPS pin: 12345670\n', 'returncode': 0})()

    pixiewps.subprocess.run = fake_pixie_run

    conn, _ = _setup(pixie_lines, pixie_dust=True)

    try:
        result = conn.singleConnection(BSSID)
        assert result is True, 'Pixie Dust path must end in success'
        assert conn.CONNECTION_STATUS.WPA_PSK == PSK
        assert pixie_cmds, 'pixiewps was not called'
        cmd = pixie_cmds[0]
        assert cmd[0] == 'pixiewps'
        # The pixiewps PIN was used in the retry
        wps_regs = [c for c in conn.RETSOCK.sent if c.startswith('WPS_REG')]
        assert any(c.endswith(' 12345670') for c in wps_regs), wps_regs
    finally:
        conn._cleanup()


def test_bruteforce_quick_success():
    """smartBruteforce with a 7-digit mask: one attempt -> M7 -> PIN found."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    utils_mod.isInterfaceUp = lambda interface: True

    tmpdir = tempfile.mkdtemp()
    utils_mod.SESSIONS_DIR = tmpdir + os.sep

    args = make_args()
    bf = bf_mod.Initialize('wlan0', args)

    tried_pins = []

    def fake_single_connection(bssid, pin):
        tried_pins.append(pin)
        # M7 received -> the second half of the PIN is correct -> success
        bf.CONNECTION.CONNECTION_STATUS.LAST_M_MESSAGE = 7

    bf.CONNECTION.singleConnection = fake_single_connection

    try:
        bf.smartBruteforce(BSSID, '1234567')
        # Expected PIN: '1234' + '567' + checksum(1234567)=0
        assert tried_pins == ['12345670'], tried_pins
        # Session saved with the current mask
        sess = open(os.path.join(tmpdir, BSSID.replace(':', '') + '.run'), encoding='utf-8').read()
        assert sess == '1234567', sess
    finally:
        bf.CONNECTION._cleanup()


def test_bruteforce_abort_saves_session():
    """Aborting brute-force saves progress (the mask) into the session."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    utils_mod.isInterfaceUp = lambda interface: True

    tmpdir = tempfile.mkdtemp()
    utils_mod.SESSIONS_DIR = tmpdir + os.sep

    args = make_args()
    bf = bf_mod.Initialize('wlan0', args)

    def fake_single_connection(bssid, pin):
        raise KeyboardInterrupt  # the user aborted the loop

    bf.CONNECTION.singleConnection = fake_single_connection

    try:
        bf.smartBruteforce(BSSID, '1234567')
        sess = open(os.path.join(tmpdir, BSSID.replace(':', '') + '.run'), encoding='utf-8').read()
        assert sess == '1234567', sess
    finally:
        bf.CONNECTION._cleanup()


def test_null_pin_mode_uses_zero_pin():
    """NULL PIN (-N): singleConnection with null_pin=True sends WPS_REG with PIN 00000000."""
    lines = [
        "WPS: Building Message M1",
        "WPS: Received M1",
        "wlan0: Trying to associate with 'TestNet' SSID: " + BSSID,
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",
    ]
    conn, _ = _setup(lines, null_pin=True)
    try:
        result = conn.singleConnection(BSSID)  # without an explicit pin
        assert result is True, 'NULL PIN path must end in success'
        wps_regs = [c for c in conn.RETSOCK.sent if c.startswith('WPS_REG')]
        assert wps_regs == [f'WPS_REG {BSSID} 00000000'], wps_regs
    finally:
        conn._cleanup()


def test_pbc_mode_uses_wps_pbc():
    """PBC: singleConnection(pbc_mode=True) sends WPS_PBC and waits for a Network Key."""
    lines = [
        "WPS: Starting PBC",
        "WPS: Building Message M1",
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",
    ]
    conn, _ = _setup(lines)
    try:
        result = conn.singleConnection(BSSID, pbc_mode=True)
        assert result is True, 'PBC path must end in success'
        assert any(c.startswith('WPS_PBC') for c in conn.RETSOCK.sent), conn.RETSOCK.sent
        assert conn.CONNECTION_STATUS.WPA_PSK == PSK, conn.CONNECTION_STATUS.WPA_PSK
    finally:
        conn._cleanup()


if __name__ == '__main__':
    test_pin_attack_success_writes_report()
    test_wrong_pin_returns_false()
    test_locked_retries_then_succeeds()
    test_pixie_dust_collects_data_and_uses_pin()
    test_bruteforce_quick_success()
    test_bruteforce_abort_saves_session()
    test_null_pin_mode_uses_zero_pin()
    test_pbc_mode_uses_wps_pbc()
    print('Attack integration tests passed ✅')