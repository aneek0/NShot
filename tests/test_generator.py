#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты для генератора PIN (src/wps/generator.py)."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wps.generator import WPSpin, NetworkAddress  # noqa: E402


def test_checksum():
    """Контрольная сумма WPS (стандартный алгоритм)."""
    # Эталонные значения, вычисленные вручную по алгоритму из OneShot
    assert WPSpin.checksum(1234567) == 0, 'checksum(1234567) должен быть 0'
    assert WPSpin.checksum(8765432) == 5, 'checksum(8765432) должен быть 5'
    assert WPSpin.checksum(0) == 0, 'checksum(0) должен быть 0'


def test_network_address():
    """Разбор MAC-адресов в разных форматах."""
    for mac in ['00:90:4C:C1:AC:21', '00-90-4C-C1-AC-21', '0090.4cc1.ac21', '00904CC1AC21']:
        na = NetworkAddress(mac)
        assert na._STR_REPR == '00:90:4C:C1:AC:21', f'Неверный разбор {mac}: {na._STR_REPR}'


def test_get_likely():
    """Генерация вероятного PIN по BSSID (OUI 04BF6D есть в списке pin24)."""
    pin = WPSpin().getLikely('04:BF:6D:12:34:56')
    assert pin is not None, 'getLikely не вернул PIN для BSSID с известным OUI'
    assert len(str(pin)) == 8, f'PIN {pin} должен быть 8-значным'


def test_suggested_pins_valid():
    """Все сгенерированные PIN должны быть валидными (8 цифр + контрольная сумма)."""
    gen = WPSpin()
    bssid = '04:BF:6D:12:34:56'
    for ident, algo in gen.ALGOS.items():
        try:
            pin = gen._generate(ident, bssid)
        except (ValueError, TypeError):
            continue  # алгоритм неприменим к этому BSSID — пропускаем
        if pin is None:
            continue
        pin = str(pin)
        # Пустые/статичные PIN не обязаны иметь корректную контрольную сумму
        if algo['mode'] in (gen.ALGO_STATIC, gen.ALGO_EMPTY):
            continue
        assert len(pin) == 8, f'Алгоритм {ident}: PIN {pin} не 8-значный'
        first7 = int(pin[:7])
        assert WPSpin.checksum(first7) == int(pin[7]), \
            f'Алгоритм {ident}: контрольная сумма PIN {pin} неверна'


if __name__ == '__main__':
    test_checksum()
    test_network_address()
    test_get_likely()
    test_suggested_pins_valid()
    print('Все тесты генератора PIN прошли ✅')
