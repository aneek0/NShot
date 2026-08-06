#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the PIN generator (src/wps/generator.py)."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wps.generator import WPSpin, NetworkAddress  # noqa: E402


def test_checksum():
    """WPS checksum (standard algorithm)."""
    # Reference values, computed by hand following the OneShot algorithm
    assert WPSpin.checksum(1234567) == 0, 'checksum(1234567) should be 0'
    assert WPSpin.checksum(8765432) == 5, 'checksum(8765432) should be 5'
    assert WPSpin.checksum(0) == 0, 'checksum(0) should be 0'


def test_network_address():
    """Parse MAC addresses in different formats."""
    for mac in ['00:90:4C:C1:AC:21', '00-90-4C-C1-AC-21', '0090.4cc1.ac21', '00904CC1AC21']:
        na = NetworkAddress(mac)
        assert na._STR_REPR == '00:90:4C:C1:AC:21', f'Bad parse of {mac}: {na._STR_REPR}'


def test_get_likely():
    """Generate a likely PIN from a BSSID (OUI 04BF6D is in the pin24 list)."""
    pin = WPSpin().getLikely('04:BF:6D:12:34:56')
    assert pin is not None, 'getLikely did not return a PIN for a BSSID with a known OUI'
    assert len(str(pin)) == 8, f'PIN {pin} should be 8 digits'


def test_suggested_pins_valid():
    """All generated PINs must be valid (8 digits + checksum)."""
    gen = WPSpin()
    bssid = '04:BF:6D:12:34:56'
    for ident, algo in gen.ALGOS.items():
        try:
            pin = gen._generate(ident, bssid)
        except (ValueError, TypeError):
            continue  # algorithm not applicable to this BSSID - skip
        if pin is None:
            continue
        pin = str(pin)
        # Empty/static PINs do not have to carry a correct checksum
        if algo['mode'] in (gen.ALGO_STATIC, gen.ALGO_EMPTY):
            continue
        assert len(pin) == 8, f'Algorithm {ident}: PIN {pin} is not 8 digits'
        first7 = int(pin[:7])
        assert WPSpin.checksum(first7) == int(pin[7]), \
            f'Algorithm {ident}: checksum of PIN {pin} is wrong'


def test_farhan_static_pins():
    """Static PINs from FARHAN-Shot-v2: available and valid."""
    gen = WPSpin()
    # A MAC-specific PIN must be suggested for its own BSSID
    pins = gen._getSuggested('90:F6:52:DE:23:1B')
    ids = [p['id'] for p in pins]
    assert 'pinTDW8960N_90F652DE231B' in ids, 'MAC-specific PIN not suggested for its own BSSID'
    pin = gen._generate('pinTDW8960N_90F652DE231B', '90:F6:52:DE:23:1B')
    assert len(str(pin)) == 8 and str(pin).isdigit(), f'PIN {pin} is invalid'
    # A foreign MAC must not get TD-specific suggestions
    ids_other = [p['id'] for p in gen._getSuggested('04:BF:6D:12:34:56')]
    assert 'pinTDW8960N_90F652DE231B' not in ids_other, 'Foreign BSSID got foreign PINs'
    # Model static PINs are available in the common list
    for ident in ['pinTLWR741N', 'pinNetgearDGN1000', 'pinSapidoRB1602', 'pinTalkTalk4E26D4']:
        assert ident in gen.ALGOS, f'Missing algorithm {ident}'
        p = gen._generate(ident, '90:F6:52:DE:23:1B')
        assert len(str(p)) == 8 and str(p).isdigit(), f'PIN {p} for {ident} is invalid'


if __name__ == '__main__':
    test_checksum()
    test_network_address()
    test_get_likely()
    test_suggested_pins_valid()
    test_farhan_static_pins()
    print('PIN generator tests passed ✅')