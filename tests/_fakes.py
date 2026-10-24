#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared fakes for NShot tests.

Hardware and interaction enter production code through small interfaces:
`Attempt` takes a supplicant session, a radio and a pixie runner; `Scanner`
takes a radio and a subprocess runner. Tests inject fakes for those seams
instead of patching stdlib or module globals.
"""

import src.options as options_mod

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


def make_options(**overrides):
    """Real Options with test-friendly defaults."""
    return options_mod.Options(**overrides)


class FakeSession:
    """wpa_supplicant session driven by a script.

    `script` holds one list of output lines per `send()`: the first element
    answers WPS_REG, the second answers a retry (lock, restart, pixie), and so
    on. This mirrors the real socket, where each command starts a new burst.
    """

    def __init__(self, script=None, replies=None):
        self.script = [list(lines) for lines in (script or [])]
        self.replies = list(replies or [])
        self.sent = []
        self.pending = []
        self.started = self.closed = False
        self.restarts = 0
        self.drains = 0

    def start(self):
        self.started = True

    def close(self):
        self.closed = True

    def restart(self):
        self.restarts += 1
        self.started = True

    def drain(self):
        # The script is authoritative: draining stale output must not eat it.
        self.drains += 1

    def send(self, command):
        self.sent.append(command)
        self.pending = self.script.pop(0) if self.script else []
        return self.replies.pop(0) if self.replies else 'OK'

    def send_only(self, command):
        self.sent.append(command)

    def next_line(self):
        return self.pending.pop(0) if self.pending else ''


class FakeRadio:
    """Radio with scriptable link state and recovery outcomes."""

    def __init__(self, up=True, recover=True, android=None):
        self.up = up
        self.recover_ok = recover
        self.android = android or FakeAndroid()
        self.recoveries = 0
        self.retries = 0

    def _next(self, value):
        if isinstance(value, (list, tuple)):
            return value.pop(0) if value else True
        return value

    def is_up(self):
        return self._next(self.up)

    def recover(self):
        self.recoveries += 1
        return self._next(self.recover_ok)

    def reset_recoveries(self):
        self.recoveries = 0

    def wait_until_up(self, timeout=0):
        return True

    def ensure_up(self):
        return True

    def retry(self, operation, attempts=4, on_retry=None):
        self.retries += 1
        result = None
        for attempt in range(1, attempts + 1):
            result = operation()
            if result:
                return result
            if on_retry:
                on_retry(attempt)
        return result


class FakeAndroid:
    """Android framework stand-in for the fallback scan path."""

    def __init__(self, scan_output=''):
        self.scan_output = scan_output
        self.scans = 0

    def universalWifiScan(self):  # noqa: N802 - mirrors the production API
        self.scans += 1
        return self.scan_output


class FakePixieRunner:
    """pixiewps stand-in: records the captured data, returns a fixed PIN."""

    def __init__(self, pin=PIN):
        self.pin = pin
        self.calls = []

    def __call__(self, data, show_command=False, full_range=False):
        self.calls.append((data, show_command, full_range))
        return self.pin


# supplicant label -> (pixiewps field, valid hex value of the enforced length)
PIXIE_FIELDS = {
    'DH peer Public Key': ('PKE', 'AA' * 192),
    'DH own Public Key': ('PKR', 'BB' * 192),
    'E-Hash1': ('E_HASH1', 'CC' * 32),
    'E-Hash2': ('E_HASH2', 'DD' * 32),
    'AuthKey': ('AUTHKEY', 'EE' * 32),
    'Enrollee Nonce': ('E_NONCE', '11' * 16),
    'Registrar Nonce': ('R_NONCE', '22' * 16),
}


def pixie_script():
    """A rejected registration that captured every field pixiewps needs."""
    lines = ['WPS: Building Message M1', 'WPS: Received M1']
    lines += [f'WPS: {label} (hexdump): {value}'
              for label, (_field, value) in PIXIE_FIELDS.items()]
    lines += ['WPS: Building Message M4', 'WPS: Received WSC_NACK']
    return lines


def network_key_line():
    """wpa_supplicant line that leads to GOT_PSK (Network Key hexdump)."""
    return f'WPS: Network Key (hexdump)(32): {PSK_HEX}'


def success_script(essid='TestNet'):
    """One registration that ends with the PSK."""
    return [
        'WPS: Building Message M1',
        'WPS: Received M1',
        f"wlan0: Trying to associate with '{essid}' SSID: {BSSID}",
        network_key_line(),
    ]


def nack_script(messages=('M1', 'M4')):
    """One registration rejected with WSC_NACK after the given messages."""
    lines = [f'WPS: Building Message {message}' for message in messages]
    lines.append('WPS: Received WSC_NACK')
    return lines