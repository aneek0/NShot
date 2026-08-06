# NShot

Тестирование защиты WPS своих сетей: **Pixie Dust**, **онлайн-брутфорс PIN**,
**предсказание PIN по BSSID** и **подключение по кнопке (PBC)** — без режима монитора,
через `wpa_supplicant`.

Собран из открытых проектов [OneShot](https://github.com/kimocoder/OneShot)
и [OneShot-Extended](https://github.com/chkndrp/OneShot-Extended).
Полная атрибуция — в [CREDITS.md](CREDITS.md).

> ⚠️ **Только для собственных или явно авторизованных сетей.**
> Использование против чужих сетей незаконно и преследуется по закону.

---

## Возможности

- 🔍 Сканер сетей через `iw` с подсветкой:
  - уязвимые модели из списка (`vulnwsc.txt`) — зелёным
  - уязвимая версия WPS `1.0` — тёмно-зелёным
  - заблокированный WPS — красным
  - уже сохранённые сети — жёлтым
- ⚡ Pixie Dust (офлайн-атака через `pixiewps`)
- 🔢 Онлайн-брутфорс PIN (маска 4/7/8 цифр, с сохранением сессии)
- 🎯 Предсказание PIN по BSSID (алгоритмы 3WiFi, D-Link, ASUS, Broadcom и др.)
- 🔘 WPS PBC и NULL PIN (`-N`)
- 🧹 Авто-убийство мешающих процессов (`--kill`) и восстановление (`--restore`)
- 📊 Сохранение результатов в `reports/stored.{txt,csv,json}`
- 🔎 Самопроверка окружения (`--check`)
- 🤖 Работает на Linux и Android/Termux (root), Python ≥ 3.10, без pip-зависимостей

---

## Установка

Требуются бинарники: `python3`, `wpa_supplicant`, `iw`, `ip` (iproute2), а для
Pixie Dust — `pixiewps`. Всё, кроме pixiewps, нужно в любом режиме.

```bash
# Debian / Ubuntu
sudo apt install -y python3 wpasupplicant iw iproute2 pixiewps

# Arch
sudo pacman -S python wpa_supplicant iw iproute2 pixiewps
```

Или одним скриптом:

```bash
chmod +x install.sh && sudo ./install.sh
```

Для Android/Termux (root): `pkg install -y root-repo tsu python wpa-supplicant pixiewps iw openssl`

### Проверка окружения

```bash
python3 nshot.py --check
```

Покажет статус прав, бинарников и интерфейса и скажет, какие режимы доступны.

---

## Использование

```bash
sudo python3 nshot.py -i wlan0                  # сканировать и выбрать цель
sudo python3 nshot.py -i wlan0 -P               # Pixie Dust после выбора цели
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -P
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B        # онлайн-брутфорс
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234  # с первой половиной PIN
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -p 12345670 # с конкретным PIN
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -N          # NULL PIN
sudo python3 nshot.py -i wlan0 --pbc                             # PBC
```

### Ключевые опции

| Опция | Что делает |
|---|---|
| `-i, --interface` | Wi-Fi интерфейс (например `wlan0`) |
| `-b, --bssid` | Целевая точка доступа |
| `-p, --pin` | Свой PIN (строка или 4/8 цифр) |
| `-N, --null-pin` | Пробовать нулевой PIN |
| `-P, --pixie-dust` | Атака Pixie Dust |
| `-B, --bruteforce` | Онлайн-брутфорс |
| `--pbc` | Подключение по кнопке |
| `-k / -r` | Убить мешающие процессы / восстановить их при выходе |
| `-w, --write` | Сохранять результаты в `reports/` |
| `-l, --loop` | Работать в цикле |
| `-c, --clear` | Очищать экран при сканировании |
| `-d, --delay` | Задержка между попытками PIN (сек) |
| `-t, --timeout` | Пауза при WPS-локе (сек) |
| `-F, --pixie-force` | Pixiewps с `--force` (полный диапазон) |
| `-S, --show-pixie` | Показывать команду pixiewps |
| `-I, --iface-down` | Опустить интерфейс по завершении |
| `-M, --mtk-wifi` | Драйвер MediaTek Wi-Fi (Android) |
| `-D, --dont-touch-settings` | Не трогать настройки Wi-Fi на Android |
| `--vuln-list` | Свой список уязвимых устройств |
| `--check` | Проверка окружения |

---

## Результаты

При успехе (`-w` или автоматически) пишутся три файла в `reports/`:

- `stored.txt` — читаемый отчёт
- `stored.csv` — таблица (используется для подсветки уже известных сетей)
- `stored.json` — машинно-читаемый отчёт для автоматизации

Сессии онлайн-брутфорса сохраняются в `~/.NShot/sessions/`, найденные PIN —
в `~/.NShot/pixiewps/`.

---

## Как это работает

NShot поднимает собственный экземпляр `wpa_supplicant` на временном конфиге и
общается с ним через управляющий сокет. Это позволяет:

- запрашивать у точки WPS-транзакции без переключения в monitor mode;
- собирать параметры (PKE, E-Hash1/2, nonce'ы и т.д.) для офлайн-атаки
  Pixie Dust через `pixiewps`;
- перебирать PIN онлайн, отслеживая WPS-lock и WPS-FAIL.

---

## Тесты

Все тесты не требуют root и Wi-Fi-адаптера (запуск `wpa_supplicant`/`pixiewps` мокается).

```bash
python3 tests/run_all.py                     # весь набор сразу
python3 tests/test_generator.py             # генератор PIN, контрольная сумма, MAC
python3 tests/test_scanner.py              # парсер вывода iw scan
python3 tests/test_engine.py               # движок атак: pixiewps, wpa_supplicant, брутфорс
python3 tests/test_utils.py                # utils: /proc, ip link, список уязвимых
python3 tests/test_android.py             # android: команды cmd wifi / settings
python3 tests/test_integration.py          # полный конвейер атаки (PIN, retry, Pixie Dust, отчёт)
python3 tests/test_cli.py                 # оркестрация CLI: kill/restore, iface up/down, loop
```

---

## Предупреждение о безопасности исходников

Перед сборкой были изучены три проекта (см. CREDITS). Код **FARHAN-Shot-v2**
использовать не стал: его `main.py` — это обфусцированный байт-код
(`exec(marshal.loads(...))`), который нельзя проверить. Не запускайте подобное
«из коробки» на своих машинах.

Лицензия NShot: [GPL-2.0](LICENSE).
