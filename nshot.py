#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  NShot - WPS security tester (Pixie Dust, online brute-force, PIN prediction, PBC)
#  Built on:
#    - OneShot (https://github.com/kimocoder/OneShot)  -> author rofl0r, fork kimocoder
#    - OneShot-Extended (https://github.com/chkndrp/OneShot-Extended)
#
#  This program is free software, distributed under the GNU General Public
#  License, version 3 or later. See the LICENSE file for details.
#
#  WARNING: use ONLY on your own or explicitly authorized networks.
#  Unauthorized access to other people's networks is illegal.

import os
import sys

# pylint: disable=wrong-import-position
if sys.version_info < (3, 10):
    sys.exit('Python 3.10 or newer is required.')

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

# Binaries required in every mode
CORE_BINARIES = ['wpa_supplicant', 'iw', 'ip']
# Binary needed only for Pixie Dust
PIXIEWPS_BINARY = 'pixiewps'


def checkCoreRequirements() -> list:
    """Check that core binaries are present. Returns the list of missing ones."""
    return [b for b in CORE_BINARIES if not which(b)]


def checkRoot() -> bool:
    """Check whether the tool runs as root (needed to manage the interface)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # On some platforms (Android/Termux) geteuid may be missing
        return os.getenv('PREFIX', '').startswith('/data/data/com.termux')


def interfaceExists(interface: str) -> bool:
    """Check whether the interface exists."""
    return Path(f'/sys/class/net/{interface}').exists()


def isWirelessInterface(interface: str) -> bool:
    """Check that the interface is Wi-Fi (there is /sys/class/net/<if>/wireless)."""
    return Path(f'/sys/class/net/{interface}/wireless').exists()


def runCheck(args) -> int:
    """Self-test: prints the environment state and does not run any attacks."""
    src.utils.clearScreen()
    print(f'NShot v{VERSION} — environment check\n' + '=' * 50)
    ok = True

    # Python
    print(f'[PY] Python: {sys.version.split()[0]} (requires >= 3.10)', end='')
    if sys.version_info >= (3, 10):
        print(' - OK')
    else:
        print(' - NO')
        ok = False

    # Privileges
    root = checkRoot()
    print(f'[PR] Running as root: {"yes" if root else "no"}', end='')
    if not root:
        print(' (tip: run via sudo)')
        ok = False
    else:
        print(' ')

    # Core binaries
    missing_core = checkCoreRequirements()
    for b in CORE_BINARIES:
        presence = 'OK' if b not in missing_core else 'NO'
        print(f'[BN] {b}: {presence}')
    if missing_core:
        ok = False

    # Pixiewps (only needed for Pixie Dust)
    has_pixiewps = bool(which(PIXIEWPS_BINARY))
    print(f'[BN] {PIXIEWPS_BINARY}: {"OK" if has_pixiewps else "NO (only needed for -P/--pixie-dust)"}')

    # Interface
    if args.interface:
        if interfaceExists(args.interface):
            print(f'[IF] Interface {args.interface}: found ')
            if not isWirelessInterface(args.interface):
                print(f'[IF] Note: {args.interface} looks wired (no /sys/class/net/{args.interface}/wireless). '
                      'WPS attacks need a Wi-Fi adapter (usually wlan0).')
        else:
            print(f'[IF] Interface {args.interface}: NOT found ')
            ok = False
    else:
        print('[IF] No interface given (pass -i wlan0)')

    # Attack availability summary
    print('\n' + '-' * 50)
    print('Available modes:')
    print(f'  - scan / PBC / PIN        : {"yes" if not missing_core else "no"}')
    print(f'  - online brute-force (-B)  : {"yes" if not missing_core else "no"}')
    print(f'  - Pixie Dust (-P)          : {"yes" if has_pixiewps and not missing_core else "no"}' +
          (' (install pixiewps)' if not has_pixiewps else ''))
    print('-' * 50)
    print('\nResult: ' + ('Environment is ready to use.' if ok else 'There are problems - fix them and run again.'))
    return 0 if ok else 1


def setupDirectories():
    """Create the working directories for NShot data."""
    for directory in [src.utils.SESSIONS_DIR, src.utils.PIXIEWPS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)


def setupAndroidWifi(android_network: src.wifi.android.AndroidNetwork, enable: bool = False):
    """Set up Wi-Fi on Android depending on the mode."""
    if enable:
        android_network.enableWifi()
    else:
        android_network.storeAlwaysScanState()
        android_network.disableWifi()


def setupMediatekWifi(wmt_wifi_device: Path):
    """Initialize the MediaTek Wi-Fi driver."""
    if not wmt_wifi_device.is_char_device():
        src.utils.die('Cannot activate /dev/wmtWifi: MediaTek device '
                      'does not exist or is not a char device (--mtk-wifi)')
    wmt_wifi_device.chmod(0o644)
    wmt_wifi_device.write_text('1', encoding='utf-8')


def scanForNetworks(interface: str, vuln_list: list, args) -> tuple | None:
    """Scan the air and let the user pick a network."""
    scanner = src.wifi.scanner.WiFiScanner(interface, vuln_list, args)
    return scanner.promptNetwork()


def handleConnection(args):
    """Core connection/attack logic."""
    network_info = {}
    success = False

    # Pixie Dust requires pixiewps
    if args.pixie_dust and not which(PIXIEWPS_BINARY):
        src.utils.die('Pixie Dust requires pixiewps (apt install pixiewps)')

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
                logger.info('No BSSID (--bssid) given - scanning for available networks')

            result = scanForNetworks(args.interface, vuln_list, args)
            if result is None:
                return

            args.bssid, network_info = result

        if args.bssid:
            if args.bruteforce:
                connection.smartBruteforce(args.bssid, args.pin)
            else:
                success = connection.singleConnection(args.bssid, args.pin)

            # On a successful Pixie Dust attack, add the device to the vulnerable list
            if success and args.pixie_dust and network_info:
                src.utils.addVulnerableAP(network_info, args.vuln_list)


def main():
    args = src.args.parseArgs()

    if args.check:
        sys.exit(runCheck(args))

    if not checkRoot():
        src.utils.die('Run as root (sudo python3 nshot.py ...)')

    missing = checkCoreRequirements()
    if missing:
        src.utils.die(f'Missing required utilities: {", ".join(missing)}. '
                      'Install them (see install.sh)')

    if args.interface and not interfaceExists(args.interface):
        src.utils.die(f'Interface \'{args.interface}\' not found. Check the name (iw dev)')

    if args.interface and not isWirelessInterface(args.interface):
        logger.warning(f'{args.interface} does not look like Wi-Fi (no /sys/class/net/{args.interface}/wireless). '
                       'WPS attacks need a Wi-Fi adapter (usually wlan0)')

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
                src.utils.die(f'Failed to bring interface \'{args.interface}\' up')

            handleConnection(args)

            if not args.loop:
                break

            args.bssid = None

        except KeyboardInterrupt:
            if args.loop:
                if input('\n[?] Exit (otherwise continue scanning)? [N/y] ').lower() == 'y':
                    logger.info('Interrupt...')
                    break
                args.bssid = None
            else:
                logger.info('Interrupt...')
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