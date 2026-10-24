#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""wpa_supplicant output -> typed facts.

Nothing here talks to a process or prints: each function turns one line of
wpa_supplicant output into a value the attempt policy can act on, so the
protocol can be tested against captured lines instead of a live socket.
"""

import codecs

from dataclasses import dataclass

# attribute name in the pixiewps data record -> expected hex length (None: any)
HEXDUMP_ATTRIBUTES = {
    'Enrollee Nonce': ('E_NONCE', 32),
    'Registrar Nonce': ('R_NONCE', 32),
    'DH own Public Key': ('PKR', 192 * 2),
    'DH peer Public Key': ('PKE', 192 * 2),
    'AuthKey': ('AUTHKEY', 32 * 2),
    'E-Hash1': ('E_HASH1', 32 * 2),
    'E-Hash2': ('E_HASH2', 32 * 2),
}

MESSAGES = {
    'M2D': 'm2d',
    'Building Message M': 'sending',
    'Received M': 'received',
    'Received WSC_NACK': 'nack',
    'Network Key': 'network_key',
}


@dataclass(frozen=True)
class WpsEvent:
    """One fact from a `WPS: …` line."""

    kind: str                 # m2d | sending | received | nack | hexdump | network_key | other
    index: int | None = None  # message number for sending/received
    attribute: str | None = None  # pixiewps field for hexdump
    value: str | None = None  # hex payload / PSK


@dataclass(frozen=True)
class StateEvent:
    """One fact from a non-WPS wpa_supplicant line."""

    kind: str                 # scanning | wps_fail | authenticating | ...
    essid: str | None = None
    bssid: str | None = None


def hex_value(line: str) -> str:
    """Hex payload of a `label: hexdump(...): XX XX …` line."""
    parts = line.split(':', 3)
    return parts[2].replace(' ', '').upper()


def decode_essid(line: str) -> str:
    """Decode the ESSID that wpa_supplicant prints between single quotes."""
    return codecs.decode(
        '\''.join(line.split('\'')[1:-1]),
        'unicode-escape'
    ).encode('latin1').decode('utf-8', errors='replace')


def parse_wps_line(line: str) -> WpsEvent:
    """Classify one `WPS: …` line."""
    if 'M2D' in line:
        return WpsEvent('m2d')

    if 'Building Message M' in line:
        return WpsEvent('sending', index=int(line.split('Building Message M')[1]))

    if 'Received M' in line:
        return WpsEvent('received', index=int(line.split('Received M')[1]))

    if 'Received WSC_NACK' in line:
        return WpsEvent('nack')

    if 'hexdump' in line:
        for marker, (attribute, expected) in HEXDUMP_ATTRIBUTES.items():
            if marker in line:
                value = hex_value(line)
                if expected is not None and len(value) != expected:
                    raise ValueError(
                        f'Invalid {attribute} length: expected {expected}, got {len(value)}'
                    )
                return WpsEvent('hexdump', attribute=attribute, value=value)
        if 'Network Key' in line:
            value = hex_value(line)
            return WpsEvent(
                'network_key',
                value=bytes.fromhex(value).decode('utf-8', errors='replace'),
            )

    return WpsEvent('other')


def parse_state_line(line: str, interface: str, has_status: bool) -> StateEvent:
    """Classify one non-WPS line of wpa_supplicant output.

    `has_status` mirrors the original guard: a `WPS-FAIL` line is only a
    failure once an attempt is actually in flight.
    """
    if ': State: ' in line and '-> SCANNING' in line:
        return StateEvent('scanning')

    if 'WPS-FAIL' in line and has_status:
        return StateEvent('wps_fail')

    if 'Trying to authenticate with' in line:
        essid = decode_essid(line) if 'SSID' in line else None
        return StateEvent('authenticating', essid=essid)

    if 'Authentication response' in line:
        return StateEvent('authenticated')

    if 'Trying to associate with' in line:
        essid = decode_essid(line) if 'SSID' in line else None
        return StateEvent('associating', essid=essid)

    if 'Associated with' in line and interface in line:
        return StateEvent('associated', bssid=line.split()[-1].upper())

    if 'EAPOL: txStart' in line:
        return StateEvent('eapol_start')

    if 'EAP entering state IDENTITY' in line:
        return StateEvent('identity_request')

    if 'using real identity' in line:
        return StateEvent('identity_response')

    if 'WPS-TIMEOUT' in line:
        return StateEvent('wps_timeout')

    if 'NL80211_CMD_DEL_STATION' in line:
        return StateEvent('del_station')

    if 'selected BSS ' in line:
        bssid = line.split('selected BSS ')[-1].split()[0].upper()
        return StateEvent('selected_bss', bssid=bssid)

    return StateEvent('other')


@dataclass
class PixieData:
    """PKE/PKR/nonces/hashes that feed pixiewps."""

    PKE: str = ''
    PKR: str = ''
    E_HASH1: str = ''
    E_HASH2: str = ''
    AUTHKEY: str = ''
    E_NONCE: str = ''
    R_NONCE: str = ''
    BSSID: str = ''

    def clear(self):
        self.PKE = self.PKR = self.E_HASH1 = self.E_HASH2 = ''
        self.AUTHKEY = self.E_NONCE = self.R_NONCE = ''
        self.BSSID = ''

    def getAll(self) -> bool:
        """True when every field pixiewps needs was captured."""
        return all([
            self.PKE, self.PKR, self.E_NONCE, self.R_NONCE,
            self.AUTHKEY, self.E_HASH1, self.E_HASH2, self.BSSID,
        ])