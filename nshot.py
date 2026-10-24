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
import src.wifi.table
import src.wps.attempt
import src.wps.bruteforce
import src.wps.generator
import src.utils
import src.args
import src.store

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


def loadVulnList(path: str | None) -> list:
    """Read the vulnerable-AP list used to highlight known targets."""
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return file.read().splitlines()
    except (FileNotFoundError, TypeError):
        return []


def scanForNetworks(interface: str, vuln_list: list, options,
                    store, radio) -> tuple | None:
    """Scan the air, show the table, and let the user pick a network."""
    scanner = src.wifi.scanner.Scanner(interface, options, store=store, radio=radio)

    while True:
        networks = scanner.scan()
        if not networks:
            logger.error('No WPS networks found.')
            return None

        src.utils.clearScreen()
        table = src.wifi.table.render(
            networks,
            stored=store.known_networks(),
            vuln_list=vuln_list,
            reverse=options.reverse_scan,
        )

        selection = src.wifi.table.prompt(table)
        if selection:
            return selection


def resolvePin(options, bssid: str, store, generator) -> str | None:
    """Pick the PIN to try: null PIN, explicit PIN, saved PIN, likely PIN."""
    if options.null_pin:
        return '00000000'
    if options.pin:
        return options.pin
    if options.pbc:
        return None

    if options.pixie_dust:
        saved = store.load_pin(bssid)
        if saved:
            try:
                if input(f'[?] Use previously calculated PIN {saved}? [n/Y] ').lower() != 'n':
                    return saved
            except EOFError:
                return saved
        return generator.getLikely(bssid) or '12345670'

    return generator.promptPin(bssid) or '00000000'


def handleConnection(options, store, radio):
    """Core connection/attack logic."""
    network_info = {}
    success = False

    # Pixie Dust requires pixiewps
    if options.pixie_dust and not which(PIXIEWPS_BINARY):
        src.utils.die('Pixie Dust requires pixiewps (apt install pixiewps)')

    attempt = src.wps.attempt.Attempt(options.interface, options,
                                      store=store, radio=radio)

    if options.bruteforce:
        brute = src.wps.bruteforce.Bruteforce(options, attempt, store=store)
        bssid = options.bssid
        if not bssid:
            vuln_list = loadVulnList(options.vuln_list)
            if not options.loop:
                logger.info('No BSSID (--bssid) given - scanning for available networks')
            result = scanForNetworks(options.interface, vuln_list, options, store, radio)
            if result is None:
                return
            bssid = result[0]
        brute.run(bssid, options.pin)
        return

    with attempt:
        if options.pbc:
            attempt.attempt_pbc(options.bssid)
            return

        bssid = options.bssid
        if not bssid:
            vuln_list = loadVulnList(options.vuln_list)
            if not options.loop:
                logger.info('No BSSID (--bssid) given - scanning for available networks')

            result = scanForNetworks(options.interface, vuln_list, options, store, radio)
            if result is None:
                return

            bssid, network_info = result

        pin = resolvePin(options, bssid, store, src.wps.generator.WPSpin())
        success = attempt.attempt(bssid, pin).ok

        # On a successful Pixie Dust attack, add the device to the vulnerable list
        if success and options.pixie_dust and network_info:
            src.utils.addVulnerableAP(network_info, options.vuln_list)


def main():
    options = src.args.parseArgs()

    if options.check:
        sys.exit(runCheck(options))

    if not checkRoot():
        src.utils.die('Run as root (sudo python3 nshot.py ...)')

    missing = checkCoreRequirements()
    if missing:
        src.utils.die(f'Missing required utilities: {", ".join(missing)}. '
                      'Install them (see install.sh)')

    if options.interface and not interfaceExists(options.interface):
        src.utils.die(f'Interface \'{options.interface}\' not found. Check the name (iw dev)')

    if options.interface and not isWirelessInterface(options.interface):
        logger.warning(f'{options.interface} does not look like Wi-Fi (no /sys/class/net/{options.interface}/wireless). '
                       'WPS attacks need a Wi-Fi adapter (usually wlan0)')

    store = src.store.DEFAULT_STORE
    store.ensure()
    logger.initializeLogging()

    src.utils.checkRunningProcesses(options.interface)

    if options.kill:
        src.utils.killInterfering()

    radio = src.radio.Radio(options.interface)

    while True:
        # Assigned in the try, but the finally block lives outside it: an
        # exception before this line must not turn cleanup into UnboundLocalError.
        android_network = None
        try:
            android_network = src.wifi.android.AndroidNetwork()

            if options.clear:
                src.utils.clearScreen()

            if src.utils.isAndroid() and not options.dont_touch_settings and not options.mtk_wifi:
                setupAndroidWifi(android_network)

            if options.mtk_wifi:
                setupMediatekWifi(Path('/dev/wmtWifi'))

            # Bring the interface up and keep it up: a single `ip link set up`
            # is not enough on Android right after Wi-Fi was disabled - the
            # framework tears the interface down asynchronously and it can
            # drop again right after we raised it. ensureInterfaceUp re-raises
            # until the interface stays UP.
            if not radio.ensure_up():
                src.utils.die(f'Failed to bring interface \'{options.interface}\' up')

            handleConnection(options, store, radio)

            if not options.loop:
                break

        except KeyboardInterrupt:
            if options.loop:
                if input('\n[?] Exit (otherwise continue scanning)? [N/y] ').lower() == 'y':
                    logger.info('Interrupt...')
                    break
            else:
                logger.info('Interrupt...')
                break

        finally:
            if (android_network is not None and src.utils.isAndroid()
                    and not options.dont_touch_settings and not options.mtk_wifi):
                setupAndroidWifi(android_network, enable=True)

            if options.iface_down:
                src.utils.ifaceCtl(options.interface, action='down')

            if options.mtk_wifi:
                Path('/dev/wmtWifi').write_text('0', encoding='utf-8')

            if options.restore:
                src.utils.restoreProcesses()


if __name__ == '__main__':
    main()
