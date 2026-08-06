#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  NShot - WPS-пентестер (Pixie Dust, онлайн-брутфорс, предсказание PIN, PBC)
#  Собран на основе:
#    - OneShot (https://github.com/kimocoder/OneShot)  -> автор rofl0r, форк kimocoder
#    - OneShot-Extended (https://github.com/chkndrp/OneShot-Extended)
#
#  This program is free software, distributed under the GNU General Public
#  License, version 3 or later. See the LICENSE file for details.
#
#  ВНИМАНИЕ: использовать ТОЛЬКО на собственных или явно авторизованных сетях.
#  Несанкционированный доступ к чужим сетям незаконен.

import os
import sys

# pylint: disable=wrong-import-position
if sys.version_info < (3, 10):
    sys.exit('Требуется Python 3.10 или новее.')

from shutil import which
from pathlib import Path

from src import logger

import src.wifi.android
import src.wifi.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args

VERSION = '1.0'

# Бинарники, обязательные для любых режимов
CORE_BINARIES = ['wpa_supplicant', 'iw', 'ip']
# Бинарник, нужный только для Pixie Dust
PIXIEWPS_BINARY = 'pixiewps'


def checkCoreRequirements() -> list:
    """Проверить наличие обязательных бинарников. Возвращает список отсутствующих."""
    return [b for b in CORE_BINARIES if not which(b)]


def checkRoot() -> bool:
    """Проверить запуск от root (нужен для работы с интерфейсом)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # На некоторых платформах (Android/Termux) geteuid может отсутствовать
        return os.getenv('PREFIX', '').startswith('/data/data/com.termux')


def interfaceExists(interface: str) -> bool:
    """Проверить существование интерфейса."""
    return Path(f'/sys/class/net/{interface}').exists()


def isWirelessInterface(interface: str) -> bool:
    """Проверить, что интерфейс — Wi-Fi (есть /sys/class/net/<if>/wireless)."""
    return Path(f'/sys/class/net/{interface}/wireless').exists()


def runCheck(args) -> int:
    """Самотест: печатает состояние окружения и не выполняет атак."""
    src.utils.clearScreen()
    print(f'NShot v{VERSION} — проверка окружения\n' + '=' * 50)

    ok = True

    # Python
    print(f'[PY] Python: {sys.version.split()[0]} (нужно >= 3.10)', end='')
    if sys.version_info >= (3, 10):
        print(' - OK')
    else:
        print(' - НЕТ')
        ok = False

    # Права
    root = checkRoot()
    print(f'[PR] Запуск от root: {"да" if root else "нет"}', end='')
    if not root:
        print(' (совет: запусти через sudo)')
        ok = False
    else:
        print(' ✅')

    # Обязательные бинарники
    missing_core = checkCoreRequirements()
    for b in CORE_BINARIES:
        presence = 'OK' if b not in missing_core else 'НЕТ'
        print(f'[БН] {b}: {presence}')
    if missing_core:
        ok = False

    # Pixiewps (только для Pixie Dust)
    has_pixiewps = bool(which(PIXIEWPS_BINARY))
    print(f'[БН] {PIXIEWPS_BINARY}: {"OK" if has_pixiewps else "НЕТ (нужен только для -P/--pixie-dust)"}')

    # Интерфейс
    if args.interface:
        if interfaceExists(args.interface):
            print(f'[IF] Интерфейс {args.interface}: найден ✅')
            if not isWirelessInterface(args.interface):
                print(f'[IF] Внимание: {args.interface} выглядит как проводной (нет /sys/class/net/{args.interface}/wireless). '
                      'WPS-атаки требуют Wi-Fi-адаптера (обычно wlan0).')
        else:
            print(f'[IF] Интерфейс {args.interface}: НЕ найден ❌')
            ok = False
    else:
        print('[IF] Интерфейс не указан (передай -i wlan0)')

    # Сводка доступности атак
    print('\n' + '─' * 50)
    print('Доступные режимы:')
    print(f'  - сканирование / PBC / PIN    : {"да" if not missing_core else "нет"}')
    print(f'  - онлайн-брутфорс (-B)        : {"да" if not missing_core else "нет"}')
    print(f'  - Pixie Dust (-P)              : {"да" if has_pixiewps and not missing_core else "нет"}' +
          (' (установи pixiewps)' if not has_pixiewps else ''))
    print('─' * 50)

    print('\nИтог: ' + ('Окружение готово к работе.' if ok else 'Есть проблемы — исправь их и запусти снова.'))
    return 0 if ok else 1


def setupDirectories():
    """Создать рабочие каталоги под данными NShot."""
    for directory in [src.utils.SESSIONS_DIR, src.utils.PIXIEWPS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)


def setupAndroidWifi(android_network: src.wifi.android.AndroidNetwork, enable: bool = False):
    """Настроить Wi-Fi на Android в зависимости от режима."""
    if enable:
        android_network.enableWifi()
    else:
        android_network.storeAlwaysScanState()
        android_network.disableWifi()


def setupMediatekWifi(wmt_wifi_device: Path):
    """Инициализировать драйвер MediaTek Wi-Fi."""
    if not wmt_wifi_device.is_char_device():
        src.utils.die('Невозможно активировать /dev/wmtWifi: устройство MediaTek '
                      'не существует или это не символьное устройство (--mtk-wifi)')
    wmt_wifi_device.chmod(0o644)
    wmt_wifi_device.write_text('1', encoding='utf-8')


def scanForNetworks(interface: str, vuln_list: list, args) -> tuple | None:
    """Просканировать эфир и дать пользователю выбрать сеть."""
    scanner = src.wifi.scanner.WiFiScanner(interface, vuln_list, args)
    return scanner.promptNetwork()


def handleConnection(args):
    """Основная логика подключения/атаки."""
    network_info = {}
    success = False

    # Pixie Dust требует pixiewps
    if args.pixie_dust and not which(PIXIEWPS_BINARY):
        src.utils.die('Для атаки Pixie Dust нужен pixiewps (apt install pixiewps)')

    if args.bruteforce:
        connection = src.wps.bruteforce.Initialize(args.interface, args)
    else:
        connection = src.wps.connection.Initialize(args.interface, args)

    if args.pbc:
        connection.singleConnection(pbc_mode=True)
    else:
        if not args.bssid:
            try:
                with open(args.vuln_list, 'r', encoding='utf-8') as file:
                    vuln_list = file.read().splitlines()
            except FileNotFoundError:
                vuln_list = []

            if not args.loop:
                logger.info('Не указан BSSID (--bssid) — сканирую доступные сети')

            result = scanForNetworks(args.interface, vuln_list, args)
            if result is None:
                return

            args.bssid, network_info = result

        if args.bssid:
            if args.bruteforce:
                connection.smartBruteforce(args.bssid, args.pin)
            else:
                success = connection.singleConnection(args.bssid, args.pin)

            # При успешной Pixie Dust-атаке добавить устройство в список уязвимых
            if success and args.pixie_dust and network_info:
                src.utils.addVulnerableAP(network_info, args.vuln_list)


def main():
    args = src.args.parseArgs()

    if args.check:
        sys.exit(runCheck(args))

    if not checkRoot():
        src.utils.die('Запусти от имени root (sudo python3 nshot.py ...)')

    missing = checkCoreRequirements()
    if missing:
        src.utils.die(f'Отсутствуют обязательные утилиты: {", ".join(missing)}. '
                      'Установи их (см. install.sh)')

    if args.interface and not interfaceExists(args.interface):
        src.utils.die(f'Интерфейс \'{args.interface}\' не найден. Проверь имя (iw dev)')

    if args.interface and not isWirelessInterface(args.interface):
        logger.warning(f'{args.interface} не похож на Wi-Fi (нет /sys/class/net/{args.interface}/wireless). '
                       'WPS-атаки требуют Wi-Fi-адаптера (обычно wlan0)')

    setupDirectories()
    logger.initializeLogging()

    src.utils.checkRunningProcesses(args.interface)

    if args.kill:
        src.utils.killInterfering()

    while True:
        try:
            android_network = src.wifi.android.AndroidNetwork()

            if args.clear:
                src.utils.clearScreen()

            if src.utils.isAndroid() and not args.dont_touch_settings and not args.mtk_wifi:
                setupAndroidWifi(android_network)

            if args.mtk_wifi:
                wmt_wifi_device = Path('/dev/wmtWifi')
                setupMediatekWifi(wmt_wifi_device)

            if src.utils.ifaceCtl(args.interface, action='up'):
                src.utils.die(f'Не удалось поднять интерфейс \'{args.interface}\'')

            handleConnection(args)

            if not args.loop:
                break

            args.bssid = None

        except KeyboardInterrupt:
            if args.loop:
                if input('\n[?] Выйти (иначе продолжить сканирование)? [N/y] ').lower() == 'y':
                    logger.info('Прерывание…')
                    break
                args.bssid = None
            else:
                logger.info('Прерывание…')
                break

        finally:
            if src.utils.isAndroid() and not args.dont_touch_settings and not args.mtk_wifi:
                setupAndroidWifi(android_network, enable=True)

            if args.iface_down:
                src.utils.ifaceCtl(args.interface, action='down')

            if args.mtk_wifi:
                Path('/dev/wmtWifi').write_text('0', encoding='utf-8')

            if args.restore:
                src.utils.restoreProcesses()


if __name__ == '__main__':
    main()