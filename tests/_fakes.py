#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared fakes for NShot tests: wpa_supplicant, iw, pixiewps.

Reused by integration tests so the code is not duplicated.
"""

from types import SimpleNamespace

BSSID = '00:11:22:33:44:55'
PIN = '12345670'
PSK = 'secret1234'
PSK_HEX = PSK.encode().hex()

# Example `iw scan` output: a WPS 1.0 network and one without WPS (filtered out)
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
    """Fake wpa_supplicant control socket."""
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


class FakeIwResult:
    """Fake subprocess.run result for `iw scan`."""
    def __init__(self, stdout):
        self.stdout = stdout


BASE_ARGS = dict(
    verbose=False, show_pixie=False, pixie_force=False, timeout=0,
    delay=0, write=True, pixie_dust=False, null_pin=False, loop=False,
)


def make_args(**overrides):
    return SimpleNamespace(**{**BASE_ARGS, **overrides})


def mock_wpa_supplicant_launch(conn_mod, utils_mod):
    """Replace wpa_supplicant launch and interface check on machines without hardware."""
    conn_mod.subprocess.Popen = FakeProcess
    conn_mod.os.path.exists = lambda p: True
    if hasattr(utils_mod, 'isInterfaceUp'):
        utils_mod.isInterfaceUp = lambda interface: True


def network_key_line():
    """wpa_supplicant line that leads to GOT_PSK (Network Key hexdump)."""
    return f"WPS: Network Key (hexdump)(32): {PSK_HEX}"