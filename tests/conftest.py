#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Autouse fixture: isolate tests that replace shared module attributes.

Most tests inject fakes through constructor seams and need nothing here. A
few hardware tests still assign to module attributes directly (subprocess.run,
time.sleep, src.utils helpers, src.store.DEFAULT_STORE, sys.argv); those
assignments leak into later test files, so they are snapshotted and restored.
"""

import builtins
import os
import socket
import subprocess
import sys
import time

import pytest

import nshot
import src.utils

_MISSING = object()

_SNAPSHOT = {
    src.utils: [
        'isInterfaceUp', '_ifaceFlagsUp', 'ifaceCtl', 'isAndroid',
        'killInterfering', 'restoreProcesses', 'ensureInterfaceUp',
        'checkRunningProcesses', 'clearScreen', 'DEFAULT_STORE',
    ],
    subprocess: ['run', 'Popen'],
    time: ['sleep'],
    builtins: ['input'],
    sys: ['argv'],
    os.path: ['exists'],
    socket: ['socket'],
    nshot: [
        'checkRoot', 'checkCoreRequirements', 'interfaceExists',
        'isWirelessInterface', 'handleConnection', 'setupAndroidWifi', 'which',
        'runCheck',
    ],
}


@pytest.fixture(autouse=True)
def _restore_module_state():
    saved = {
        module: {name: getattr(module, name, _MISSING) for name in names}
        for module, names in _SNAPSHOT.items()
    }

    yield

    for module, attributes in saved.items():
        for name, value in attributes.items():
            if value is _MISSING:
                if hasattr(module, name):
                    delattr(module, name)
            else:
                setattr(module, name, value)