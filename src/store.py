#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""On-disk state: brute-force masks, Pixie PINs, cracked networks.

Everything that knows where NShot keeps its files and what a file means lives
here. Callers ask for a meaning ("the mask for this BSSID"), never for a path.
"""

import csv
import json
import os
import pathlib

from datetime import datetime

from src import logger


def default_root() -> pathlib.Path:
    """Root of the NShot state directory.

    `$NSHOT_HOME` wins, otherwise `~/.NShot`. Deliberately not derived from the
    current working directory: the tool used to write reports next to wherever
    it was launched from, so the same target produced different files.
    """
    override = os.environ.get('NSHOT_HOME')
    if override:
        return pathlib.Path(override).expanduser()
    return pathlib.Path.home() / '.NShot'


class Store:
    """Paths and formats for everything NShot persists."""

    MASK_SUFFIX = '.run'
    PIN_SUFFIX = '.pin'
    LEGACY_PIN_SUFFIX = '.run'

    def __init__(self, root=None, reports=None):
        self.root = pathlib.Path(root) if root is not None else default_root()
        self.sessions = self.root / 'sessions'
        self.pixie_pins = self.root / 'pixiewps'
        self.reports = pathlib.Path(reports) if reports is not None else self.root / 'reports'

    def ensure(self):
        """Create the directories this store writes to."""
        for directory in (self.sessions, self.pixie_pins, self.reports):
            directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(bssid: str) -> str:
        """File-name form of a BSSID: `00:11:22:33:44:55` -> `001122334455`."""
        return bssid.replace(':', '').upper()

    # -- brute-force masks -------------------------------------------------

    def mask_path(self, bssid: str) -> pathlib.Path:
        return self.sessions / f'{self.key(bssid)}{self.MASK_SUFFIX}'

    def save_mask(self, bssid: str, mask: str) -> pathlib.Path:
        """Persist the brute-force position so the next run can resume."""
        path = self.mask_path(bssid)
        self.sessions.mkdir(parents=True, exist_ok=True)
        path.write_text(mask, encoding='utf-8')
        return path

    def load_mask(self, bssid: str) -> str | None:
        """Return the saved brute-force mask, or None when there is none."""
        try:
            return self.mask_path(bssid).read_text(encoding='utf-8').strip()
        except (OSError, UnicodeDecodeError):
            return None

    # -- Pixie Dust pins ---------------------------------------------------

    def pin_path(self, bssid: str) -> pathlib.Path:
        return self.pixie_pins / f'{self.key(bssid)}{self.PIN_SUFFIX}'

    def _legacy_pin_path(self, bssid: str) -> pathlib.Path:
        return self.pixie_pins / f'{self.key(bssid)}{self.LEGACY_PIN_SUFFIX}'

    def save_pin(self, bssid: str, pin: str) -> pathlib.Path:
        """Store a PIN recovered offline by pixiewps."""
        path = self.pin_path(bssid)
        self.pixie_pins.mkdir(parents=True, exist_ok=True)
        path.write_text(pin, encoding='utf-8')
        return path

    def load_pin(self, bssid: str) -> str | None:
        """Return a previously computed PIN, including pre-1.1 `.run` files."""
        for path in (self.pin_path(bssid), self._legacy_pin_path(bssid)):
            try:
                pin = path.read_text(encoding='utf-8').strip()
            except (OSError, UnicodeDecodeError):
                continue
            if pin:
                return pin
        return None

    def take_pin(self, bssid: str) -> str | None:
        """Read a computed PIN and delete it: it is consumed by the attempt."""
        pin = self.load_pin(bssid)
        for path in (self.pin_path(bssid), self._legacy_pin_path(bssid)):
            try:
                path.unlink()
            except OSError:
                pass
        return pin

    # -- cracked networks --------------------------------------------------

    @property
    def credentials_csv(self) -> pathlib.Path:
        return self.reports / 'stored.csv'

    def known_networks(self) -> list[tuple[str, str]]:
        """(BSSID, ESSID) pairs already cracked, for marking the scan table."""
        try:
            with open(self.credentials_csv, 'r', newline='', encoding='utf-8') as file:
                rows = list(csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL))
        except (OSError, UnicodeDecodeError, csv.Error):
            return []
        return [(row[1], row[2]) for row in rows[1:] if len(row) >= 3]

    def has_credentials(self, bssid: str, psk: str) -> bool:
        """Whether this BSSID + PSK pair is already on disk."""
        try:
            text = self.credentials_csv.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            return False
        return f'"{bssid}"' in text and f'"{psk}"' in text

    def save_credentials(self, bssid: str, essid: str, pin: str, psk: str) -> bool:
        """Append a cracked network to stored.{txt,csv,json}.

        Returns False when the pair is already saved, so the caller can skip
        the "saved" message instead of printing it twice.
        """
        if self.has_credentials(bssid, psk):
            return False

        self.reports.mkdir(parents=True, exist_ok=True)
        base = self.reports / 'stored'
        date_str = datetime.now().strftime('%d.%m.%Y %H:%M')

        with open(f'{base}.txt', 'a', encoding='utf-8') as file:
            file.write('{}\nBSSID: {}\nESSID: {}\nWPS PIN: {}\nWPA PSK: {}\n\n'.format(
                date_str, bssid, essid, pin, psk
            ))

        write_header = not os.path.isfile(f'{base}.csv')
        with open(f'{base}.csv', 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
            if write_header:
                writer.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            writer.writerow([date_str, bssid, essid, pin, psk])

        records = []
        if os.path.isfile(f'{base}.json'):
            try:
                with open(f'{base}.json', 'r', encoding='utf-8') as file:
                    records = json.load(file)
            except (json.JSONDecodeError, OSError):
                records = []
        records.append({
            'date': date_str,
            'bssid': bssid,
            'essid': essid,
            'wps_pin': pin,
            'wpa_psk': psk,
        })
        with open(f'{base}.json', 'w', encoding='utf-8') as file:
            json.dump(records, file, ensure_ascii=False, indent=2)

        logger.info(f'[*] Credentials saved to {base}.txt, {base}.csv, {base}.json')
        return True

    # -- misc state --------------------------------------------------------

    def killed_processes_path(self) -> pathlib.Path:
        return self.sessions / 'killed_processes.json'


DEFAULT_STORE = Store()