#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""The radio as a resource: one owner for "the interface went away".

Four modules used to carry their own retry loop with different attempt counts,
backoffs and timeouts. They now ask this module to bring the interface back,
which keeps the schedule in one place.
"""

import subprocess
import time

from src import logger
import src.utils
from src.wifi.android import AndroidNetwork

# How many times a caller may recover the interface inside one operation.
MAX_RECOVERIES = 3
# Give the Android framework time to report that it released the radio.
FRAMEWORK_RELEASE_TIMEOUT = 4.0
# How long the interface may take to come back (and stay) up.
ENSURE_TIMEOUT = 10.0

class RadioError(RuntimeError):
    """The interface could not be brought back."""


def backoff(attempt: int) -> float:
    """Delay before retry number `attempt` (1-based)."""
    return min(0.5 * attempt, 2.0)


class Radio:
    """Interface state and recovery for one wireless interface."""

    def __init__(self, interface: str, *, android=None):
        self.interface = interface
        self._android = android
        self.recoveries = 0

    @property
    def android(self) -> AndroidNetwork:
        """Framework adapter, created on first use."""
        if self._android is None:
            self._android = AndroidNetwork()
        return self._android

    # -- state -------------------------------------------------------------

    def is_up(self) -> bool:
        return src.utils.isInterfaceUp(self.interface)

    def wait_until_up(self, timeout: float = 20.0) -> bool:
        return src.utils.waitForInterfaceUp(self.interface, timeout=timeout)

    def ensure_up(self, timeout: float = ENSURE_TIMEOUT) -> bool:
        return src.utils.ensureInterfaceUp(self.interface, timeout=timeout)

    def await_framework_release(self, timeout: float = FRAMEWORK_RELEASE_TIMEOUT) -> None:
        """On Android, wait until the framework stops holding the radio."""
        if src.utils.isAndroid():
            self.android.waitForWifiOff(timeout=timeout)

    def release_framework(self) -> None:
        """On Android, ask the framework to let go of the radio."""
        if src.utils.isAndroid():
            self.android.disableWifi(force_disable=True, whisper=True)

    # -- recovery ----------------------------------------------------------

    def recover(self) -> bool:
        """Ask the framework to release the radio, then re-raise the interface.

        Returns False when the budget of recoveries for this operation is
        exhausted or the interface refuses to come back up.
        """
        self.recoveries += 1
        if self.recoveries > MAX_RECOVERIES:
            return False

        logger.warning(
            f'Interface {self.interface} dropped; bringing it back up '
            f'({self.recoveries}/{MAX_RECOVERIES})…'
        )
        self.release_framework()
        if not self.ensure_up():
            return False
        return True

    def reset_recoveries(self) -> None:
        self.recoveries = 0

    def retry(self, operation, *, attempts: int = 4, on_retry=None, timeout: float = 15.0):
        """Run `operation` until it succeeds, recovering the radio in between.

        `operation` returns a truthy value on success; exceptions of the
        transient kind (timeout, OSError, "command failed" results) are the
        operation's business — it returns None/False for those. Returns the
        last result.
        """
        result = None
        for attempt in range(1, attempts + 1):
            self.recoveries = 0
            result = operation()
            if result:
                return result
            if attempt == attempts:
                break
            if on_retry is not None:
                on_retry(attempt)
            time.sleep(backoff(attempt))
            self.await_framework_release()
            self.ensure_up(timeout=5.0)
        return result