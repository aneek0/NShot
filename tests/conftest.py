#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared pytest fixture: keep the suite order-independent.

Several tests mock hardware by directly assigning to shared modules
(src.utils, subprocess, os.path, socket, time, builtins, nshot) and never
restore them. That leaks state across test files, so the suite failed when
run as a whole (e.g. test_cli replaced handleConnection/ifaceCtl and broke
test_fullflow/test_utils; test_fullflow/test_integration replaced
isInterfaceUp and broke test_utils).

This autouse fixture snapshots the affected attributes before each test and
restores them afterwards, so every test starts from a clean state no matter
in which order the files are run.
"""

import builtins
import os
import socket
import subprocess
import sys
import time

import pytest

import src.utils
import nshot

_MISSING = object()

# module -> attributes that tests replace without restoring
_SNAPSHOT = {
    src.utils: [
        'isInterfaceUp', '_ifaceFlagsUp', 'ifaceCtl', 'isAndroid',
        'killInterfering', 'restoreProcesses', 'ensureInterfaceUp',
        'checkRunningProcesses', 'SESSIONS_DIR', 'REPORTS_DIR', 'clearScreen',
    ],
    subprocess: ['run', 'Popen'],
    time: ['sleep'],
    builtins: ['input'],
    sys: ['argv'],
    os.path: ['exists'],
    socket: ['socket'],
    nshot: [
        'checkRoot', 'checkCoreRequirements', 'interfaceExists',
        'isWirelessInterface', 'handleConnection', 'setupAndroidWifi',
    ],
}


@pytest.fixture(autouse=True)
def _restore_module_state():
    saved = {
        mod: {name: getattr(mod, name, _MISSING) for name in attrs}
        for mod, attrs in _SNAPSHOT.items()
    }
    yield
    for mod, attrs in saved.items():
        for name, value in attrs.items():
            if value is _MISSING:
                if hasattr(mod, name):
                    delattr(mod, name)
            else:
                setattr(mod, name, value)
