#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты вспомогательного слоя (src/utils.py): /proc, ip link, списки.

Не требует root: чтение /proc, ip и записи в файлы мокаются.
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
    """Находит процесс, держащий netlink-сокет (протокол 16), и его имя."""
    def fake_open(file, *a, **k):
        name = file if isinstance(file, str) else file.name
        if name == '/proc/net/netlink':
            # заголовок + строка, где p[1]='16' (NETLINK_GENERIC), p[2]=pid
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
    """PID с netlink-сокетом, но без реального сокета в fd, не считается мешающим."""
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


def test_is_interface_up():
    """isInterfaceUp зависит от наличия 'UP' в выводе ip link show."""
    class FakeOut:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    u.subprocess.run = lambda *a, **k: FakeOut('wlan0: <BROADCAST,MULTICAST,UP>')
    assert u.isInterfaceUp('wlan0') is True

    u.subprocess.run = lambda *a, **k: FakeOut('wlan0: <NO-CARRIER>')
    assert u.isInterfaceUp('wlan0') is False

    u.subprocess.run = lambda *a, **k: FakeOut('', returncode=1)
    assert u.isInterfaceUp('wlan0') is False


def test_iface_ctl_builds_command():
    """ifaceCtl вызывает ip link set <iface> <action> и возвращает returncode."""
    captured = []

    class FakeOut:
        def __init__(self, returncode=0, stdout='OK'):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        return FakeOut()

    u.subprocess.run = fake_run
    # Отключаем rfkill-ветку: stdout без 'RF-kill', не Android
    u.isAndroid = lambda: False

    assert u.ifaceCtl('wlan0', 'up') == 0
    assert captured[0] == ['ip', 'link', 'set', 'wlan0', 'up'], captured


def test_add_vulnerable_ap_appends_and_dedups():
    """addVulnerableAP дополняет список уязвимых моделей и не дублирует."""
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


if __name__ == '__main__':
    test_get_interfering_processes()
    test_is_interface_up()
    test_iface_ctl_builds_command()
    test_add_vulnerable_ap_appends_and_dedups()
    print('Тесты utils прошли ✅')