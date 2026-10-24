#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""Scan output -> networks.

Pure: no subprocess, no printing, no retries. Both `iw dev … scan` and the
Android framework fallback (which prints the same shape) are parsed here, so
the formats can be tested against captured text instead of a live adapter.
"""

import codecs
import re

# A hidden ESSID is not the same as an empty field: the table shows it.
HIDDEN = '<hidden>'


def _new_network(bssid: str) -> dict:
    return {
        'ESSID': '',
        'Security type': 'Unknown',
        'WPS': False,
        'WPS version': '1.0',
        'WPS locked': False,
        'Model': '',
        'Model number': '',
        'Device name': '',
        'WiFi Standard': '',
        'BSSID': bssid.upper(),
    }


def _decode(text: str) -> str:
    return codecs.decode(text, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')


def _handle_network(_line, result, networks):
    networks.append(_new_network(result.group(1)))


def _handle_essid(_line, result, networks):
    try:
        essid = _decode(result.group(1))
        networks[-1]['ESSID'] = essid if essid.strip('\x00 ') else HIDDEN
    except (AttributeError, IndexError):
        networks[-1]['ESSID'] = HIDDEN


def _handle_level(_line, result, networks):
    networks[-1]['Level'] = int(float(result.group(1)))


def _handle_security_type(_line, result, networks):
    sec = networks[-1]['Security type']
    if result.group(1) == 'capability':
        sec = 'WEP' if 'Privacy' in result.group(2) else 'Open'
    elif sec == 'WEP':
        if result.group(1) == 'RSN':
            sec = 'WPA2'
        elif result.group(1) == 'WPA':
            sec = 'WPA'
    elif sec == 'WPA':
        if result.group(1) == 'RSN':
            sec = 'WPA/WPA2'
    elif sec == 'WPA2':
        if result.group(1) == 'PSK SAE':
            sec = 'WPA2/WPA3'
        elif result.group(1) == 'WPA':
            sec = 'WPA/WPA2'
    networks[-1]['Security type'] = sec


def _handle_wifi_standard(line, result, networks):
    lowered = line.upper()
    if 'HE' in lowered or '802.11AX' in lowered:
        networks[-1]['WiFi Standard'] = 'WiFi 6 (802.11ax)'
    elif 'VHT' in lowered or '802.11AC' in lowered:
        networks[-1]['WiFi Standard'] = 'WiFi 5 (802.11ac)'


def _handle_wps(_line, result, networks):
    networks[-1]['WPS'] = True


def _handle_wps_version(_line, result, networks):
    version = networks[-1]['WPS version']
    # Only WPS 2.0 APs broadcast this line, which distinguishes 1.0 from 2.0.
    if result.group(1).replace('* Version2:', '') == '2.0':
        version = '2.0'
    networks[-1]['WPS version'] = version


def _handle_wps_locked(_line, result, networks):
    if int(result.group(1), 16):
        networks[-1]['WPS locked'] = True


def _handle_model(_line, result, networks):
    networks[-1]['Model'] = _decode(result.group(1))


def _handle_model_number(_line, result, networks):
    networks[-1]['Model number'] = _decode(result.group(1))


def _handle_device_name(_line, result, networks):
    networks[-1]['Device name'] = _decode(result.group(1))


MATCHERS = {
    re.compile(r'BSS (\S+)( )?\(on \w+\)'): _handle_network,
    re.compile(r'SSID: (.*)'): _handle_essid,
    re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): _handle_level,
    re.compile(r'(capability): (.+)'): _handle_security_type,
    re.compile(r'(RSN):\t [*] Version: (\d+)'): _handle_security_type,
    re.compile(r'(WPA):\t [*] Version: (\d+)'): _handle_security_type,
    re.compile(r'.*(HE |VHT |802\.11ax|802\.11ac).*'): _handle_wifi_standard,
    re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): _handle_wps,
    re.compile(r' [*] Version2: (.+)'): _handle_wps_version,
    re.compile(r' [*] Authentication suites: (.+)'): _handle_security_type,
    re.compile(r' [*] AP setup locked: (0x[0-9]+)'): _handle_wps_locked,
    re.compile(r' [*] Model: (.*)'): _handle_model,
    re.compile(r' [*] Model Number: (.*)'): _handle_model_number,
    re.compile(r' [*] Device name: (.*)'): _handle_device_name,
}


def parse_scan_lines(raw_lines) -> list[dict]:
    """Parse raw scan output into WPS-capable networks, strongest first.

    Raises ValueError when the adapter reported `command failed:` in the
    middle of its output: a truncated scan is not an empty scan.
    """
    networks = []
    for line in raw_lines:
        if line.startswith('command failed:'):
            raise ValueError(line)

        line = line.strip('\t')

        for regexp, handler in MATCHERS.items():
            result = re.match(regexp, line)
            if result:
                handler(line, result, networks)

    networks = [network for network in networks if network['WPS']]
    networks.sort(key=lambda network: network['Level'], reverse=True)
    return networks