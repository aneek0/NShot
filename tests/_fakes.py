#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Общие подделки (fakes) для тестов NShot: wpa_supplicant, iw, pixiewps.

Переиспользуются интеграционными тестами, чтобы не дублировать код.
"""

from types import SimpleNamespace

BSSID = '00:11:22:33:44:55'
PIN = '12345670'
PSK = 'secret1234'
PSK_HEX = PSK.encode().hex()

# Пример вывода `iw scan`: сеть с WPS 1.0 и сеть без WPS (отфильтровывается)
IW_SAMPLE = f"""BSS {BSSID}(on wlan0)
\tSSID: TestNet
\tsignal: -45.00 dBm
\tcapability: ESS Privacy
\tRSN:\t * Version: 1
WPS:\t * Version: 1.0
\t * AP setup locked: 0x0
\t * Authentication suites: WPA-Personal
\t * Model: TestRouter
\t * Model Number: T1000
\t * Device name: TestWSC
BSS AA:BB:CC:DD:EE:FF(on wlan0)
\tSSID: NoWpsNet
\tsignal: -60.00 dBm
\tRSN:\t * Version: 1
\t * Authentication suites: WPA2-Personal
"""


class FakeSocket:
    """Поддельный control-сокет wpa_supplicant."""
    def __init__(self):
        self.sent = []
        self.reply = b'OK'

    def bind(self, _addr):
        pass

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


class FakeIwResult:
    """Поддельный результат subprocess.run для `iw scan`."""
    def __init__(self, stdout):
        self.stdout = stdout


BASE_ARGS = dict(
    verbose=False, show_pixie=False, pixie_force=False, timeout=0,
    delay=0, write=True, pixie_dust=False, null_pin=False, loop=False,
)


def make_args(**overrides):
    return SimpleNamespace(**{**BASE_ARGS, **overrides})


def mock_wpa_supplicant_launch(conn_mod, utils_mod):
    """Подменяет запуск wpa_supplicant и проверку интерфейса на машине без железа."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    if hasattr(utils_mod, 'isInterfaceUp'):
        utils_mod.isInterfaceUp = lambda interface: True


def network_key_line():
    """Строка wpa_supplicant, приводящая к GOT_PSK (Network Key hexdump)."""
    return f"WPS: Network Key (hexdump)(32): {PSK_HEX}"