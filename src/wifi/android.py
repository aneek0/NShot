#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.

import subprocess
import time

from src import logger
from src import utils as src_utils

class AndroidNetwork:
    """Manages android Wi-Fi-related settings"""

    def __init__(self):
        self.ENABLED_SCANNING = 0

    def storeAlwaysScanState(self):
        """Stores Initial Wi-Fi 'always-scanning' state, so it can be restored on exit"""

        settings_cmd = ['settings', 'get', 'global', 'wifi_scan_always_enabled']

        try:
            is_scanning_on = subprocess.run(
                settings_cmd,
                encoding='utf-8',
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            )
            is_scanning_on = is_scanning_on.stdout.strip()

            if is_scanning_on == '1':
                self.ENABLED_SCANNING = 1
        except subprocess.CalledProcessError:
            logger.info('[-] Failed to get initial Wi-Fi scanning state, assuming it\'s enabled')
            self.ENABLED_SCANNING = 1

    def disableWifi(self, force_disable: bool = False, whisper: bool = False):
        """Disable Wi-Fi connectivity on Android."""

        if whisper is False:
            logger.info('[*] Android: disabling Wi-Fi')

        wifi_disable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'disabled']
        wifi_disable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'disabled']

        # Disable Android Wi-Fi scanner
        try:
            subprocess.run(wifi_disable_scanner_cmd)
        except subprocess.CalledProcessError:
            logger.info('[-] Failed to disable Wi-Fi scanner, skipping')

        # Always scanning for networks causes the interface to be occupied by android
        if self.ENABLED_SCANNING == 1 or force_disable is True:
            try:
                subprocess.run(wifi_disable_always_scanning_cmd)
            except subprocess.CalledProcessError:
                logger.info('[-] Failed to disable always-on Wi-Fi scanning, skipping')

        # Adaptive wait for the radio to be released instead of a fixed
        # time.sleep(3): return as soon as the framework confirms Wi-Fi is off.
        self._waitForRadioRelease()

    def _isWifiDisabled(self) -> bool:
        """True when the Android framework reports that Wi-Fi is disabled."""
        try:
            out = subprocess.run(
                ['cmd', 'wifi', 'status'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8', errors='replace', timeout=2
            )
        except (OSError, FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
        return 'disabled' in (out.stdout or '').lower()

    def _waitForRadioRelease(self, timeout: float = 3.0, poll: float = 0.2):
        """Wait for the radio to be released for up to `timeout` seconds.

        Replaces the old fixed time.sleep(3): poll the framework state and
        proceed as soon as Wi-Fi is off. The hard ceiling is the same (3s),
        so it is never worse than the old behavior - it usually finishes
        noticeably earlier.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._isWifiDisabled():
                return
            time.sleep(poll)
        logger.info(f'[-] Wi-Fi did not report disabled within {timeout:.0f}s, continuing anyway')

    def enableWifi(self, force_enable: bool = False, whisper: bool = False):
        """Enable Wi-Fi connectivity on Android."""

        if whisper is False:
            logger.info('[*] Android: enabling Wi-Fi')

        wifi_enable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'enabled']
        wifi_enable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'enabled']

        # Enable Android Wi-Fi scanner
        try:
            subprocess.run(wifi_enable_scanner_cmd)
        except subprocess.CalledProcessError:
            logger.info('[!] Failed to enable Wi-Fi scanner, skipping')

        if self.ENABLED_SCANNING == 1 or force_enable is True:
            try:
                subprocess.run(wifi_enable_always_scanning_cmd)
            except subprocess.CalledProcessError:
                logger.info('[-] Failed to enable always-on Wi-Fi scanning, skipping')

    def universalWifiScan(self) -> str | None:
        """Android fallback scan when `iw` is unavailable.

        Uses the Android WiFi manager (`cmd wifi list-scan-results`) or falls back
        to `dumpsys wifi` output. Returns raw text (iw-like), or None if not
        on Android / the command fails.
        """
        if not src_utils.isAndroid():
            return None

        logger.info('Android: using universal WiFi scan (cmd wifi)…')
        cmd = ('cmd wifi list-scan-results 2>/dev/null || '
               'dumpsys wifi | grep -A 20 "Latest scan results"')
        try:
            proc = subprocess.run(cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                encoding='utf-8', errors='replace')
            return proc.stdout if proc.stdout.strip() else None
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            logger.info(f'Android WiFi fetch failed: {error}')
            return None
