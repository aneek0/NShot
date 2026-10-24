#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""One wpa_supplicant process and its control socket.

The attempt policy does not know how the supplicant is launched, how the
control socket is addressed, or how output is read; it asks this adapter for
the next line and sends commands. Tests replace the adapter, not the policy.
"""

import os
import select
import shutil
import socket
import subprocess
import tempfile
import time

from src import logger

STARTUP_TIMEOUT = 30.0  # seconds to wait for the control socket


class SupplicantError(RuntimeError):
    """wpa_supplicant could not be started or lost its control socket."""


def _reply_socket_path() -> str:
    """A short path for the datagram socket that receives command replies.

    `AF_UNIX` paths are limited to ~108 bytes, so the reply socket lives in
    the system temp dir rather than in the per-run directory.
    """
    # mktemp already guarantees the name is free; binding fails loudly if not.
    return tempfile.mktemp(dir=tempfile.gettempdir())


class WpaSupplicantSession:
    """A running `wpa_supplicant -K -d` and the socket used to command it."""

    def __init__(self, interface: str, *, startup_timeout: float = STARTUP_TIMEOUT):
        self.interface = interface
        self.startup_timeout = startup_timeout

        self.tempdir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            temp.write(f'ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n')
            self.config_path = temp.name

        self.ctrl_path = f'{self.tempdir}/{self.interface}'
        self.process = None

        self.reply_path = _reply_socket_path()
        self.reply_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.reply_socket.bind(self.reply_path)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Launch wpa_supplicant and wait for its control interface."""
        logger.info('Running wpa_supplicant…')
        command = [
            'wpa_supplicant', '-K', '-d',
            '-Dnl80211,wext,hostapd,wired',
            f'-i{self.interface}',
            f'-c{self.config_path}',
        ]

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8',
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            raise SupplicantError(f'Failed to open wpa_supplicant: {error}') from error

        deadline = time.time() + self.startup_timeout
        while not os.path.exists(self.ctrl_path):
            if self.process.poll() is not None:
                output = self.process.communicate()[0]
                raise SupplicantError(f'wpa_supplicant exited before its control interface appeared: {output}')
            if time.time() >= deadline:
                raise SupplicantError(
                    f'wpa_supplicant did not create {self.ctrl_path} in {self.startup_timeout:.0f}s'
                )
            time.sleep(0.1)

    def restart(self) -> None:
        """Replace the process: the current one is no longer usable."""
        if self.process is not None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except (OSError, AttributeError):
                pass
        self.start()

    def close(self) -> None:
        """Terminate the process and remove the temporary files (idempotent)."""
        if getattr(self, '_closed', False):
            return

        try:
            self.reply_socket.close()
            if self.process is not None:
                try:
                    self.process.terminate()
                except (OSError, AttributeError):
                    pass
                if getattr(self.process, 'stdout', None):
                    try:
                        self.process.stdout.close()
                    except OSError:
                        pass
                try:
                    self.process.wait()
                except (OSError, AttributeError):
                    pass
        except OSError:
            pass

        for path in (self.reply_path, self.config_path):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

        shutil.rmtree(self.tempdir, ignore_errors=True)
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False

    # -- commands and output -----------------------------------------------

    def send(self, command: str) -> str:
        """Send a command and return the supplicant's reply."""
        self.reply_socket.sendto(command.encode(), self.ctrl_path)
        payload, _address = self.reply_socket.recvfrom(4096)
        return payload.decode('utf-8', errors='replace')

    def send_only(self, command: str) -> None:
        """Send a command without waiting for a reply."""
        self.reply_socket.sendto(command.encode(), self.ctrl_path)

    def next_line(self) -> str:
        """Next line of supplicant output, or '' at end of stream."""
        line = self.process.stdout.readline()
        return line.rstrip('\n') if line else ''

    def drain(self) -> None:
        """Consume output already buffered, without blocking the hot loop."""
        stream = getattr(self.process, 'stdout', None)
        if stream is None:
            return
        if getattr(stream, 'fileno', None) is None:
            try:
                stream.read(300)
            except (OSError, ValueError, TypeError):
                pass
            return
        try:
            while select.select([stream], [], [], 0)[0]:
                if not stream.readline():
                    break
        except (OSError, ValueError, TypeError):
            pass