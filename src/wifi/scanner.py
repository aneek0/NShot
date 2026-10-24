#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""Radio scanning: run `iw`, retry transient failures, return networks.

No table, no prompts, no logo — those belong to the CLI layer. What is left
here is the part that has to talk to a driver that may be busy, gone, or slow.
"""

import subprocess

from src import logger
from src.radio import Radio
from src.store import DEFAULT_STORE
from src.wifi.iwparse import parse_scan_lines

# A fresh radio can answer with zero networks while the driver is settling.
MAX_EMPTY_SCAN_RETRIES = 3
# A busy interface ("device or resource busy") clears up after a short wait.
SCAN_ATTEMPTS = 4
SCAN_TIMEOUT = 15


class ScanFailed(RuntimeError):
    """The adapter can not scan at all: missing binary, broken subsystem."""


class Scanner:
    """Finds WPS-capable networks on one interface."""

    def __init__(self, interface: str, options, *, store=None, radio=None,
                 runner=None):
        self.interface = interface
        self.options = options
        self.store = store if store is not None else DEFAULT_STORE
        self.radio = radio if radio is not None else Radio(interface)
        # Resolved at call time so a replaced subprocess.run (tests, wrappers)
        # is honoured instead of a default bound at import.
        self._runner = runner or subprocess.run
        self._last_error = None

    def scan(self) -> list[dict] | None:
        """Networks seen by the radio, strongest first; None if scanning failed."""
        self.radio.wait_until_up()

        command = ['iw', 'dev', self.interface, 'scan']

        try:
            lines = self.radio.retry(
                lambda: self._scan_lines(command),
                attempts=SCAN_ATTEMPTS,
                on_retry=self._note_retry,
            )
        except ScanFailed as error:
            logger.error(str(error))
            return None

        if lines is None:
            logger.error(f'iw scan failed: {self._last_error}')
            return None

        if self.options.verbose:
            print('\n'.join(lines))

        networks = self._parse(lines)

        if not networks:
            networks = self.radio.retry(
                lambda: self._rescan(command),
                attempts=MAX_EMPTY_SCAN_RETRIES,
            ) or []

        return networks

    # -- internals ---------------------------------------------------------

    def _scan_lines(self, command) -> list[str] | None:
        """One `iw scan`. None means "retry"; ScanFailed means "give up"."""
        try:
            process = self._runner(
                command,
                encoding='utf-8', errors='replace',
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=SCAN_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            self._last_error = f'timed out after {SCAN_TIMEOUT}s'
            return None
        except FileNotFoundError:
            return self._framework_fallback()
        except (subprocess.CalledProcessError, OSError) as error:
            raise ScanFailed(f'Failed to perform an iw scan: \n {error}') from error

        stdout = process.stdout or ''
        if 'command failed' in stdout or getattr(process, 'returncode', 0) != 0:
            self._last_error = stdout.strip() or 'iw reported a failure'
            return None

        self._last_error = None
        return stdout.splitlines()

    def _framework_fallback(self) -> list[str]:
        """`iw` is not installed: ask the Android framework for a scan."""
        output = self.radio.android.universalWifiScan()
        if not output:
            raise ScanFailed('iw is not installed and the framework scan returned nothing')
        return output.splitlines()

    def _rescan(self, command) -> list[dict] | None:
        """Retry an empty scan; None means "try again"."""
        try:
            lines = self._scan_lines(command)
        except ScanFailed:
            return None
        if not lines:
            return None
        networks = self._parse(lines)
        return networks or None

    def _parse(self, lines) -> list[dict]:
        """Parse, treating a truncated scan as an empty retry point."""
        try:
            return parse_scan_lines(lines)
        except ValueError as error:
            logger.error(f'Error: {error}')
            return []

    def _note_retry(self, attempt: int) -> None:
        if self._last_error:
            logger.warning(f'Scan attempt {attempt} failed: {self._last_error}')