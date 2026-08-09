#!/usr/bin/env bash
# NShot auto-installer (Debian/Ubuntu, Arch, Fedora, Termux).
# - First install (no NShot folder yet): updates packages and installs the
#   dependencies, then clones NShot.
# - Re-run (NShot folder or repo already exists): only updates the NShot
#   folder (git pull), installed packages are left untouched.
# Run as root: sudo ./install.sh

set -e

REPO_URL="https://github.com/aneek0/NShot.git"
REPO_DIR="NShot"

LOGO='  ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
  ████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
  ██╔██╗ ██║███████╗███████║██║   ██║   ██║
  ██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║
  ██║ ╚████║███████║██║  ██║╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝'

# Are we already inside the NShot repo?
IN_REPO=false
if [ -f "nshot.py" ] && [ -f "LICENSE" ]; then
    IN_REPO=true
fi

# Fresh install (no checkout yet: needs the repo cloned and system packages
# set up) vs an update of an existing checkout (only git pull, packages are
# left alone). Detected up-front so the package step can be skipped on re-runs.
FIRST_INSTALL=false
if [ "$IN_REPO" = true ] || [ -d "$REPO_DIR/.git" ]; then
    FIRST_INSTALL=false
else
    FIRST_INSTALL=true
fi

# Fetch or update the repo. When we are outside the repo but an NShot folder
# already exists, update it (git pull) instead of cloning, since `git clone`
# would fail into a non-empty directory.
do_clone_or_update() {
    if [ "$IN_REPO" = true ]; then
        echo "==> Updating NShot..."
        git pull
    elif [ -d "$REPO_DIR/.git" ]; then
        echo "==> Updating existing NShot folder..."
        (cd "$REPO_DIR" && git pull)
    else
        echo "==> Cloning NShot..."
        git clone "$REPO_URL" "$REPO_DIR"
    fi
}

# Command path depends only on whether we are inside the repo, not on whether
# we cloned or updated an existing folder.
nshot_command() {
    if [ "$IN_REPO" = true ]; then
        echo "sudo python3 nshot.py"
    else
        echo "sudo python3 NShot/nshot.py"
    fi
}

# Logo - only on the first run (outside the repo)
if [ "$IN_REPO" = false ]; then
    echo "$LOGO"
fi

# --- Termux ---
if [ -n "$PREFIX" ] && [ "${PREFIX#/data/data/com.termux}" != "$PREFIX" ]; then
    echo "==> Termux detected"
    if [ "$FIRST_INSTALL" = true ]; then
        echo "==> First install: updating packages and installing dependencies..."
        pkg update -y
        pkg upgrade -y
        pkg i root-repo
        pkg i -y sudo python wpa-supplicant pixiewps iw openssl git
    else
        echo "==> Existing installation: updating NShot only (packages are not touched)"
    fi
    do_clone_or_update
    echo
    echo "==> Done! Test commands (replace wlan0 with your interface):"
    if [ "$IN_REPO" = true ]; then
        echo "    sudo python3 nshot.py -i wlan0 -P   # Pixie Dust"
        echo "    sudo python3 nshot.py -i wlan0 -N   # NULL PIN"
        echo "    sudo python3 nshot.py -i wlan0 -B   # online brute-force"
    else
        echo "    sudo python3 NShot/nshot.py -i wlan0 -P   # Pixie Dust"
        echo "    sudo python3 NShot/nshot.py -i wlan0 -N   # NULL PIN"
        echo "    sudo python3 NShot/nshot.py -i wlan0 -B   # online brute-force"
    fi
    exit 0
fi

# --- package setup: only on the first install ---
if [ "$FIRST_INSTALL" = true ]; then
    echo "==> NShot: installing dependencies"

    # --- git: needed for cloning, always installed ---
    if command -v apt-get >/dev/null 2>&1; then
        echo "==> apt detected (Debian/Ubuntu)"
        apt update
        apt upgrade
        apt install -y python3 wpasupplicant iw iproute2 pixiewps git
    elif command -v pacman >/dev/null 2>&1; then
        echo "==> pacman detected (Arch)"
        pacman -Sy --noconfirm python wpa_supplicant iw iproute2 pixiewps git
    elif command -v dnf >/dev/null 2>&1; then
        echo "==> dnf detected (Fedora)"
        dnf install -y python3 wpa_supplicant iw iproute pixiewps git
    else
        echo "==> Could not determine the package manager."
        echo "    Install manually: python3, wpa_supplicant, iw, iproute2, pixiewps, git"
    fi
else
    echo "==> Existing installation: updating NShot only (packages are not touched)"
fi

# --- clone, or update when inside the repo or an NShot folder already exists ---
do_clone_or_update
NSHOT_CMD="$(nshot_command)"

echo
echo "==> Environment check:"
if [ "$IN_REPO" = true ]; then
    python3 nshot.py --check || true
else
    (cd "$REPO_DIR" && python3 nshot.py --check) || true
fi

echo
echo "==> Done! Test commands (replace wlan0 with your interface):"
echo "    $NSHOT_CMD -i wlan0 -P   # Pixie Dust"
echo "    $NSHOT_CMD -i wlan0 -N   # NULL PIN"
echo "    $NSHOT_CMD -i wlan0 -B   # online brute-force"
