#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runs all NShot tests via pytest (same suite as `python3 -m pytest -q`)."""

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    proc = subprocess.run([sys.executable, '-m', 'pytest', '-q', *sys.argv[1:]], cwd=BASE)
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main())
