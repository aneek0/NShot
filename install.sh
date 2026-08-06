#!/usr/bin/env bash
# Автоустановка NShot (Debian/Ubuntu, Arch, Fedora, Termux).
# - Запущен внутри репозитория (sudo ./install.sh): ставит зависимости и
#   обновляет репозиторий (git pull).
# - Запущен снаружи (curl ... | bash): ставит зависимости, клонирует NShot
#   в ./NShot и показывает команды запуска.
# Запускать от root: sudo ./install.sh

set -e

REPO_URL="https://github.com/aneek0/NShot.git"
REPO_DIR="NShot"

LOGO='  ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
  ████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
  ██╔██╗ ██║███████╗███████║██║   ██║   ██║
  ██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║
  ██║ ╚████║███████║██║  ██║╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝'

# Находимся ли уже внутри репозитория NShot
IN_REPO=false
if [ -f "nshot.py" ] && [ -f "LICENSE" ]; then
    IN_REPO=true
fi

# Лого — только при первом запуске (снаружи репозитория)
if [ "$IN_REPO" = false ]; then
    echo "$LOGO"
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
    else
        echo "==> Обновление NShot..."
        git pull
    fi
    echo
    echo "==> Готово! Тестовые команды (замените wlan0 на ваш интерфейс):"
    if [ "$IN_REPO" = true ]; then
        echo "    sudo python3 nshot.py -i wlan0 -P   # Pixie Dust"
        echo "    sudo python3 nshot.py -i wlan0 -N   # NULL PIN"
        echo "    sudo python3 nshot.py -i wlan0 -B   # онлайн-брутфорс"
    else
        echo "    sudo python3 NShot/nshot.py -i wlan0 -P   # Pixie Dust"
        echo "    sudo python3 NShot/nshot.py -i wlan0 -N   # NULL PIN"
        echo "    sudo python3 NShot/nshot.py -i wlan0 -B   # онлайн-брутфорс"
    fi
    exit 0
fi

# --- git: нужен для клонирования/обновления, ставим всегда ---
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

# --- клонирование при запуске снаружи, обновление при запуске внутри ---
if [ "$IN_REPO" = true ]; then
    echo "==> Обновление NShot..."
    git pull
    NSHOT_CMD="sudo python3 nshot.py"
else
    echo "==> Клонирование NShot..."
    git clone "$REPO_URL" "$REPO_DIR"
    NSHOT_CMD="sudo python3 NShot/nshot.py"
fi

echo
echo "==> Проверка окружения:"
if [ "$IN_REPO" = true ]; then
    python3 nshot.py --check || true
else
    (cd "$REPO_DIR" && python3 nshot.py --check) || true
fi

echo
echo "==> Готово! Тестовые команды (замените wlan0 на ваш интерфейс):"
echo "    $NSHOT_CMD -i wlan0 -P   # Pixie Dust"
echo "    $NSHOT_CMD -i wlan0 -N   # NULL PIN"
echo "    $NSHOT_CMD -i wlan0 -B   # онлайн-брутфорс"
