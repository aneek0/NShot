#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the helper layer (src/utils.py): /proc, ip link, lists.

Does not require root: reading /proc, ip and file writes are mocked.
"""

import sys
import os
import io
import tempfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.utils as u  # noqa: E402


class FakeDirEntry:
    def __init__(self, path):
        self.path = path


def test_get_interfering_processes():
    """Finds a process holding a netlink socket (protocol 16) and its name."""
    def fake_open(file, *a, **k):
        name = file if isinstance(file, str) else file.name
        if name == '/proc/net/netlink':
            # header + a line where p[1]='16' (NETLINK_GENERIC), p[2]=pid
            return io.StringIO(
                'sk   Eth  Pid   Groups Lock Drops  Rmem Wmem Dump Locks Inode\n'
                'f1   16   1234  0      0    0      0    0    0    0     12345\n'
                'f2   5    999   0      0    0      0    0    0    0     54321\n'
            )
        if name == '/proc/1234/comm':
            return io.StringIO('NetworkManager')
        raise FileNotFoundError(name)

    with mock.patch('builtins.open', side_effect=fake_open), \
         mock.patch.object(u.os, 'scandir', return_value=[FakeDirEntry('/proc/1234/fd/5')]), \
         mock.patch.object(u.os, 'readlink', return_value='socket:[9876]'):

        result = u._getInterferingProcesses()

    assert result == [(1234, 'NetworkManager')], result


def test_ignores_netlink_processes_that_do_not_hold_socket():
    """A PID with a netlink socket but no real socket in fd is not interfering."""
    def fake_open(file, *a, **k):
        if isinstance(file, str) and file == '/proc/net/netlink':
            return io.StringIO('sk Eth Pid Groups Lock Drops Rmem Dode Dump Locks Inode\n'
                               'f1 16 9999 0 0 0 0 0 0 0 555\n')
        raise FileNotFoundError(file)

    with mock.patch('builtins.open', side_effect=fake_open), \
         mock.patch.object(u.os, 'scandir', return_value=[FakeDirEntry('/proc/9999/fd/3')]), \
         mock.patch.object(u.os, 'readlink', return_value='anon_inode:[eventpoll]'):

        result = u._getInterferingProcesses()

    assert result == [], result


def test_iface_flags_up_fast_path():
    """_ifaceFlagsUp reads IFF_UP from sysfs without subprocess."""
    def fake_open(file, *a, **k):
        if isinstance(file, str) and file == '/sys/class/net/wlan0/flags':
            return io.StringIO('0x1003')  # contains IFF_UP (0x1)
        raise FileNotFoundError(file)

    with mock.patch('builtins.open', side_effect=fake_open):
        assert u._ifaceFlagsUp('wlan0') is True

    def fake_open_down(file, *a, **k):
        if isinstance(file, str) and file == '/sys/class/net/wlan0/flags':
            return io.StringIO('0x1002')  # IFF_UP is off
        raise FileNotFoundError(file)

    with mock.patch('builtins.open', side_effect=fake_open_down):
        assert u._ifaceFlagsUp('wlan0') is False

    # No / unreadable file -> None (fallback to ip link show)
    with mock.patch('builtins.open', side_effect=FileNotFoundError):
        assert u._ifaceFlagsUp('wlan0') is None


def test_is_interface_up():
    """isInterfaceUp depends on 'UP' being present in ip link show (fallback)."""
    class FakeOut:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    # Force the fallback: no sysfs file
    u._ifaceFlagsUp = lambda interface: None

    u.subprocess.run = lambda *a, **k: FakeOut('wlan0: <BROADCAST,MULTICAST,UP>')
    assert u.isInterfaceUp('wlan0') is True

    u.subprocess.run = lambda *a, **k: FakeOut('wlan0: <NO-CARRIER>')
    assert u.isInterfaceUp('wlan0') is False

    u.subprocess.run = lambda *a, **k: FakeOut('', returncode=1)
    assert u.isInterfaceUp('wlan0') is False


def test_is_interface_up_fast_path_skips_subprocess():
    """If sysfs responds, subprocess (ip link) is never launched."""
    u._ifaceFlagsUp = lambda interface: True
    subprocess_was_called = []
    u.subprocess.run = lambda *a, **k: subprocess_was_called.append(a)
    assert u.isInterfaceUp('wlan0') is True
    assert subprocess_was_called == [], 'ip must not be called on the fast path'


def test_iface_ctl_builds_command():
    """ifaceCtl calls ip link set <iface> <action> and returns returncode."""
    captured = []

    class FakeOut:
        def __init__(self, returncode=0, stdout='OK'):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        return FakeOut()

    u.subprocess.run = fake_run
    # Disable the rfkill branch: stdout without 'RF-kill', not Android
    u.isAndroid = lambda: False

    assert u.ifaceCtl('wlan0', 'up') == 0
    assert captured[0] == ['ip', 'link', 'set', 'wlan0', 'up'], captured


def test_add_vulnerable_ap_appends_and_dedups():
    """addVulnerableAP appends vulnerable models and does not duplicate."""
    tmp = tempfile.mktemp()
    try:
        u.addVulnerableAP({'Model': 'TestRouter', 'Model number': 'T1000'}, tmp)
        u.addVulnerableAP({'Model': 'TestRouter', 'Model number': 'T1000'}, tmp)
        with open(tmp, encoding='utf-8') as f:
            entries = [l for l in f.read().splitlines() if l.strip()]
        assert entries == ['TestRouter T1000'], entries
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def test_kill_interfering_kills_and_saves():
    """killInterfering kills interfering processes and saves them for restore."""
    tmp = tempfile.mkdtemp()
    u.SESSIONS_DIR = tmp + os.sep

    killed = []
    real_open = open

    def fake_open(file, *a, **k):
        name = file if isinstance(file, str) else file.name
        if name == '/proc/net/netlink':
            return io.StringIO('sk Eth Pid Groups Lock Drops Rmem Dode Dump Locks Inode\n'
                               'f1 16 1234 0 0 0 0 0 0 0 555\n')
        if name == '/proc/1234/comm':
            return io.StringIO('NetworkManager')
        if name == '/proc/1234/cmdline':
            return io.StringIO('NetworkManager\x00--foo')
        if name.endswith('killed_processes.json'):
            # Writing/reading the save file - delegate to the real open
            return real_open(file, *a, **k)
        raise FileNotFoundError(name)

    def fake_kill(pid, sig):
        killed.append((pid, sig))

    with mock.patch('builtins.open', side_effect=fake_open), \
         mock.patch.object(u.os, 'scandir', return_value=[FakeDirEntry('/proc/1234/fd/3')]), \
         mock.patch.object(u.os, 'readlink', return_value='socket:[555]'), \
         mock.patch.object(u.os, 'kill', side_effect=fake_kill), \
         mock.patch.object(u, 'time'):

        u.killInterfering()

    assert killed == [(1234, 15)], killed
    saved = real_open(os.path.join(tmp, 'killed_processes.json'), encoding='utf-8').read()
    assert 'NetworkManager' in saved and '1234' in saved, saved


def test_restore_processes_relaunches():
    """restoreProcesses relaunches saved processes by cmdline."""
    tmp = tempfile.mkdtemp()
    u.SESSIONS_DIR = tmp + os.sep
    with open(os.path.join(tmp, 'killed_processes.json'), 'w', encoding='utf-8') as f:
        f.write('[["1234", "NetworkManager", "NetworkManager --foo"]]')

    launched = []
    class FakePopen:
        def __init__(self, cmdline, *a, **k):
            launched.append(cmdline)

    u.subprocess.Popen = FakePopen
    u.restoreProcesses()
    assert launched == ['NetworkManager --foo'], launched


def test_restore_processes_no_file_is_noop():
    """restoreProcesses without a save file does nothing."""
    tmp = tempfile.mkdtemp()
    u.SESSIONS_DIR = tmp + os.sep
    launched = []
    class FakePopen:
        def __init__(self, cmdline, *a, **k):
            launched.append(cmdline)
    u.subprocess.Popen = FakePopen
    u.restoreProcesses()
    assert launched == [], launched


if __name__ == '__main__':
    test_get_interfering_processes()
    test_ignores_netlink_processes_that_do_not_hold_socket()
    test_iface_flags_up_fast_path()
    test_is_interface_up()
    test_is_interface_up_fast_path_skips_subprocess()
    test_iface_ctl_builds_command()
    test_add_vulnerable_ap_appends_and_dedups()
    test_kill_interfering_kills_and_saves()
    test_restore_processes_relaunches()
    test_restore_processes_no_file_is_noop()
    print('Utils tests passed ✅')