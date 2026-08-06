#!/usr/bin/env bash
# Установка зависимостей NShot (Debian/Ubuntu, Arch, Fedora, Termux).
# Запускать от root: sudo ./install.sh

set -e

echo "==> NShot: установка зависимостей"

if [ -n "$PREFIX" ] && [ "${PREFIX#/data/data/com.termux}" != "$PREFIX" ]; then
    echo "==> Обнаружен Termux"
    pkg update -y
    pkg install -y root-repo tsu python wpa-supplicant pixiewps iw openssl
    echo "==> Готово. Запуск: sudo python nshot.py -i wlan0"
    exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
    echo "==> Детектирован apt (Debian/Ubuntu)"
    apt-get update
    apt-get install -y python3 wpasupplicant iw iproute2 pixiewps
elif command -v pacman >/dev/null 2>&1; then
    echo "==> Детектирован pacman (Arch)"
    pacman -Sy --noconfirm python wpa_supplicant iw iproute2 pixiewps
elif command -v dnf >/dev/null 2>&1; then
    echo "==> Детектирован dnf (Fedora)"
    dnf install -y python3 wpa_supplicant iw iproute pixiewps
else
    echo "==> Не удалось определить менеджер пакетов."
    echo "    Установи вручную: python3, wpa_supplicant, iw, iproute2, pixiewps"
fi

echo
echo "==> Проверка окружения:"
python3 nshot.py --check || true
