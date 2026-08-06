#!/usr/bin/env bash
# Установка зависимостей NShot (Debian/Ubuntu, Arch, Fedora, Termux).
# Если запущен изнутри репозитория (sudo ./install.sh) — только ставит
# зависимости. Если запущен снаружи (например, curl ... | bash) — сам
# скачивает git (если нет) и клонирует NShot.
# Запускать от root: sudo ./install.sh

set -e

REPO_URL="https://github.com/aneek0/NShot.git"
REPO_DIR="NShot"

# Находимся ли уже внутри репозитория NShot
IN_REPO=false
if [ -f "nshot.py" ] && [ -f "LICENSE" ]; then
    IN_REPO=true
fi

echo "==> NShot: установка зависимостей"

# --- Termux ---
if [ -n "$PREFIX" ] && [ "${PREFIX#/data/data/com.termux}" != "$PREFIX" ]; then
    echo "==> Обнаружен Termux"
    pkg update -y
    pkg install -y root-repo sudo python wpa-supplicant pixiewps iw openssl git
    if [ "$IN_REPO" = false ]; then
        echo "==> Клонирование NShot..."
        git clone "$REPO_URL" "$REPO_DIR"
        cd "$REPO_DIR"
    fi
    echo
    echo "==> Готово! Тестовые команды (замените wlan0 на ваш интерфейс):"
    echo "    sudo python3 nshot.py -i wlan0 -P   # Pixie Dust"
    echo "    sudo python3 nshot.py -i wlan0 -N   # NULL PIN"
    echo "    sudo python3 nshot.py -i wlan0 -B   # онлайн-брутфорс"
    exit 0
fi

# --- git: нужен для клонирования, ставим всегда ---
if command -v apt-get >/dev/null 2>&1; then
    echo "==> Детектирован apt (Debian/Ubuntu)"
    apt-get update
    apt-get install -y python3 wpasupplicant iw iproute2 pixiewps git
elif command -v pacman >/dev/null 2>&1; then
    echo "==> Детектирован pacman (Arch)"
    pacman -Sy --noconfirm python wpa_supplicant iw iproute2 pixiewps git
elif command -v dnf >/dev/null 2>&1; then
    echo "==> Детектирован dnf (Fedora)"
    dnf install -y python3 wpa_supplicant iw iproute pixiewps git
else
    echo "==> Не удалось определить менеджер пакетов."
    echo "    Установи вручную: python3, wpa_supplicant, iw, iproute2, pixiewps, git"
fi

# --- клонирование при запуске вне репозитория ---
if [ "$IN_REPO" = false ]; then
    if command -v git >/dev/null 2>&1; then
        echo "==> Клонирование NShot..."
        git clone "$REPO_URL" "$REPO_DIR"
        cd "$REPO_DIR"
    else
        echo "==> git не установлен — клонирование невозможно."
        echo "    Скачайте репозиторий вручную: git clone $REPO_URL"
        exit 1
    fi
fi

echo
echo "==> Проверка окружения:"
python3 nshot.py --check || true

echo
echo "==> Готово! Тестовые команды (замените wlan0 на ваш интерфейс):"
echo "    sudo python3 nshot.py -i wlan0 -P   # Pixie Dust"
echo "    sudo python3 nshot.py -i wlan0 -N   # NULL PIN"
echo "    sudo python3 nshot.py -i wlan0 -B   # онлайн-брутфорс"
