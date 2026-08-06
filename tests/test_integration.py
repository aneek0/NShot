#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Интеграционный тест полного конвейера атаки.

Мокает wpa_supplicant (stdout + control socket) и pixiewps, чтобы прогнать
весь путь: WPS_REG -> разбор сообщений M1/M4 -> NACK -> Pixie Dust ->
повторная попытка с найденным PIN -> GOT_PSK -> запись отчёта.
Не требует root и Wi-Fi-адаптера.
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
    """Поддельный control-сокет wpa_supplicant."""
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
    """Поддельный stdout wpa_supplicant: выдаёт строки по очереди."""
    def __init__(self, lines):
        self._lines = list(lines)

    def read(self, _n=0):
        return ''

    def readline(self):
        return self._lines.pop(0) if self._lines else ''

    def close(self):
        pass


class FakeProcess:
    """Поддельный процесс wpa_supplicant."""
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


def _setup(stream_lines, **args_overrides):
    """Создаёт connection.Initialize с подменённым wpa_supplicant."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    utils_mod.isInterfaceUp = lambda interface: True

    args = make_args(**args_overrides)
    conn = conn_mod.Initialize('wlan0', args)
    conn.WPAS.stdout = FakeStream(stream_lines)
    conn.RETSOCK = FakeSocket()
    return conn, args


def test_pin_attack_success_writes_report():
    """Полный успех: PIN -> GOT_PSK -> отчёт в reports/."""
    tmpdir = tempfile.mkdtemp()
    utils_mod.REPORTS_DIR = tmpdir + os.sep

    lines = [
        "WPS: Building Message M1",
        "WPS: Received M1",
        "wlan0: Trying to associate with 'TestNet' SSID: " + BSSID,
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",
    ]
    conn, _ = _setup(lines)

    try:
        result = conn.singleConnection(BSSID, PIN)
        assert result is True, 'singleConnection должен вернуть True при GOT_PSK'
        assert conn.CONNECTION_STATUS.WPA_PSK == PSK, conn.CONNECTION_STATUS.WPA_PSK
        assert conn.CONNECTION_STATUS.ESSID == 'TestNet', conn.CONNECTION_STATUS.ESSID

        wps_cmds = [c for c in conn.RETSOCK.sent if c.startswith('WPS_REG')]
        assert wps_cmds == [f'WPS_REG {BSSID} {PIN}'], wps_cmds

        # Отчёт сохранён
        txt = open(os.path.join(tmpdir, 'stored.txt'), encoding='utf-8').read()
        assert PSK in txt and BSSID in txt, txt
        recs = json.load(open(os.path.join(tmpdir, 'stored.json'), encoding='utf-8'))
        assert recs[0]['wpa_psk'] == PSK and recs[0]['wps_pin'] == PIN, recs
    finally:
        conn._cleanup()


def test_wrong_pin_returns_false():
    """Неправильный PIN (WSC_NACK на M4) -> False, без retry и без отчёта."""
    lines = [
        "WPS: Building Message M4",
        "WPS: Received WSC_NACK",
    ]
    conn, _ = _setup(lines)

    try:
        result = conn.singleConnection(BSSID, '99999999')
        assert result is False
        assert conn.CONNECTION_STATUS.STATUS == 'WSC_NACK'
        # После неудачи шлётся WPS_CANCEL
        assert 'WPS_CANCEL' in conn.RETSOCK.sent, conn.RETSOCK.sent
    finally:
        conn._cleanup()


def test_locked_retries_then_succeeds():
    """WPS-lock на M1 -> повтор через timeout=0 -> успех."""
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
        assert len(wps_regs) == 2, f'ожидалось 2 попытки, получено {len(wps_regs)}'
    finally:
        conn._cleanup()


def test_pixie_dust_collects_data_and_uses_pin():
    """Pixie Dust: собирает данные -> WSC_NACK -> pixiewps -> PIN -> успех."""
    # Данные Pixie Dust в формате wpa_supplicant hexdump
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
        "WPS: Received WSC_NACK",   # PIN из getLikely не подошёл -> идём в pixiewps
        "WPS: Building Message M1",
        f"WPS: Network Key (hexdump)(32): {PSK_HEX}",  # повтор с PIN от pixiewps
    ]

    # Мокаем запуск pixiewps
    pixie_cmds = []

    def fake_pixie_run(cmd, **kwargs):
        pixie_cmds.append(cmd)
        return type('FakeRun', (), {'stdout': '[+] WPS pin: 12345670\n', 'returncode': 0})()

    pixiewps.subprocess.run = fake_pixie_run

    conn, _ = _setup(pixie_lines, pixie_dust=True)

    try:
        result = conn.singleConnection(BSSID)
        assert result is True, 'Pixie Dust путь должен закончиться успехом'
        assert conn.CONNECTION_STATUS.WPA_PSK == PSK
        assert pixie_cmds, 'pixiewps не вызывался'
        cmd = pixie_cmds[0]
        assert cmd[0] == 'pixiewps'
        # PIN от pixiewps использован во второй попытке
        wps_regs = [c for c in conn.RETSOCK.sent if c.startswith('WPS_REG')]
        assert any(c.endswith(' 12345670') for c in wps_regs), wps_regs
    finally:
        conn._cleanup()


def test_bruteforce_quick_success():
    """smartBruteforce с 7-значной маской: одна попытка -> M7 -> PIN найден."""
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
        # M7 получено -> вторая половина PIN верна -> успех
        bf.CONNECTION.CONNECTION_STATUS.LAST_M_MESSAGE = 7

    bf.CONNECTION.singleConnection = fake_single_connection

    try:
        bf.smartBruteforce(BSSID, '1234567')
        # Ожидаемый PIN: '1234' + '567' + контрольная сумма(1234567)=0
        assert tried_pins == ['12345670'], tried_pins
        # Сессия сохранена с текущей маской
        sess = open(os.path.join(tmpdir, BSSID.replace(':', '') + '.run'), encoding='utf-8').read()
        assert sess == '1234567', sess
    finally:
        bf.CONNECTION._cleanup()


def test_bruteforce_abort_saves_session():
    """Прерывание брутфорса сохраняет прогресс (маску) в сессию."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    utils_mod.isInterfaceUp = lambda interface: True

    tmpdir = tempfile.mkdtemp()
    utils_mod.SESSIONS_DIR = tmpdir + os.sep

    args = make_args()
    bf = bf_mod.Initialize('wlan0', args)

    def fake_single_connection(bssid, pin):
        raise KeyboardInterrupt  # пользователь прервал перебор

    bf.CONNECTION.singleConnection = fake_single_connection

    try:
        bf.smartBruteforce(BSSID, '1234567')
        sess = open(os.path.join(tmpdir, BSSID.replace(':', '') + '.run'), encoding='utf-8').read()
        assert sess == '1234567', sess
    finally:
        bf.CONNECTION._cleanup()


if __name__ == '__main__':
    test_pin_attack_success_writes_report()
    test_wrong_pin_returns_false()
    test_locked_retries_then_succeeds()
    test_pixie_dust_collects_data_and_uses_pin()
    test_bruteforce_quick_success()
    test_bruteforce_abort_saves_session()
    print('Интеграционные тесты атаки прошли ✅')
