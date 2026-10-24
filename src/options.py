#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""The configuration record every module receives.

Modules used to fall back to `parseArgs()` when the caller passed nothing,
which made `sys.argv` the configuration channel and let a constructor exit the
process. `Options` is built once by the CLI and handed down explicitly.
"""

import os

from dataclasses import dataclass, fields

DEFAULT_VULN_LIST = os.path.join(os.path.dirname(__file__), '../vulnwsc.txt')


@dataclass(frozen=True)
class Options:
    """Parsed command line, immutable for the lifetime of the process."""

    interface: str | None = None
    bssid: str | None = None
    check: bool = False

    # Attack mode
    pin: str | None = None
    null_pin: bool = False
    pixie_dust: bool = False
    bruteforce: bool = False
    pbc: bool = False

    # Additional
    kill: bool = False
    restore: bool = False
    write: bool = False
    loop: bool = False
    clear: bool = False
    delay: float = 0
    timeout: float = 60

    # Advanced
    pixie_force: bool = False
    show_pixie: bool = False
    iface_down: bool = False
    mtk_wifi: bool = False
    dont_touch_settings: bool = False
    reverse_scan: bool = False
    vuln_list: str = DEFAULT_VULN_LIST
    verbose: bool = False

    @classmethod
    def from_namespace(cls, namespace) -> 'Options':
        """Build from an argparse namespace (or anything with the same fields)."""
        known = {field.name for field in fields(cls)}
        return cls(**{name: value for name, value in vars(namespace).items() if name in known})

    @classmethod
    def defaults(cls) -> 'Options':
        return cls()