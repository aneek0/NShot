#!/usr/bin/env bash
# NShot auto-installer (Debian/Ubuntu, Arch, Fedora, Termux).
# - Run inside the repo (sudo ./install.sh): installs dependencies and
#   updates the repo (git pull).
# - Run from outside (curl ... | bash): installs dependencies and clones NShot
#   into ./NShot. If an NShot folder already exists, it is updated instead of
#   cloned, then the run commands are shown.
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

echo "==> NShot: installing dependencies"

# --- Termux ---
if [ -n "$PREFIX" ] && [ "${PREFIX#/data/data/com.termux}" != "$PREFIX" ]; then
    echo "==> Termux detected"
    pkg update -y
    pkg upgrade -y
    pkg i root-repo
    pkg i -y sudo python wpa-supplicant pixiewps iw openssl git
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

# --- git: needed for cloning/updating, always installed ---
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
