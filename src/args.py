#  OneShot-Extended (WPS penetration testing utility) is a fork of the tool with extra features
#  Copyright (C) 2026 chkndrp
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

import argparse
import os

def parseArgs():
    """Parse arguments passed to the main python script."""

    parser = argparse.ArgumentParser(
        description='''
  ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
  ████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
  ██╔██╗ ██║███████╗███████║██║   ██║   ██║
  ██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║
  ██║ ╚████║███████║██║  ██║╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝

NShot v1.0 - тестирование защиты WPS: Pixie Dust, онлайн-брутфорс,
предсказание PIN и PBC. Только для своих или авторизованных сетей.
Основан на OneShot (kimocoder/rofl0r) и OneShot-Extended (chkndrp).
''',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    target_group = parser.add_argument_group('Основные аргументы')
    target_group.add_argument(
        '-i', '--interface',
        type=str,
        help='Имя интерфейса (например wlan0)'
    )
    target_group.add_argument(
        '-b', '--bssid',
        type=str,
        help='BSSID целевой точки доступа'
    )
    target_group.add_argument(
        '--check',
        action='store_true',
        help='Проверить готовность окружения (зависимости, права, интерфейс) и выйти'
    )

    attack_group = parser.add_argument_group('Режимы атаки')
    attack_pin_group = attack_group.add_mutually_exclusive_group()
    attack_pin_group.add_argument(
        '-p', '--pin',
        type=str,
        help='Использовать указанный PIN (произвольная строка или 4/8-значный PIN)'
    )
    attack_pin_group.add_argument(
        '-N', '--null-pin',
        action='store_true',
        help='Использовать нулевой PIN'
    )
    attack_pin_group.add_argument(
        '-P', '--pixie-dust',
        action='store_true',
        help='Запустить атаку Pixie Dust (офлайн)'
    )
    attack_pin_group.add_argument(
        '-B', '--bruteforce',
        action='store_true',
        help='Запустить онлайн-брутфорс PIN'
    )
    attack_pin_group.add_argument(
        '--pbc', '--push-button-connect',
        action='store_true',
        help='Подключение по WPS PBC (кнопка)'
    )

    opt_group = parser.add_argument_group('Дополнительные аргументы')
    opt_group.add_argument(
        '-k', '--kill',
        action='store_true',
        help='Автоматически убить процессы, мешающие работе с интерфейсом'
    )
    opt_group.add_argument(
        '-r', '--restore',
        action='store_true',
        help='Восстановить убитые процессы при выходе (вместе с --kill)'
    )
    opt_group.add_argument(
        '-w', '--write',
        action='store_true',
        help='Сохранять найденные пароли/PIN в файл при успехе'
    )
    opt_group.add_argument(
        '-l', '--loop',
        action='store_true',
        help='Работать в цикле'
    )
    opt_group.add_argument(
        '-c', '--clear',
        action='store_true',
        help='Очищать экран при каждом сканировании'
    )
    opt_group.add_argument(
        '-d', '--delay',
        type=float,
        default=0,
        help='Задержка между попытками PIN в секундах (по умолчанию: %(default)s)'
    )
    opt_group.add_argument(
        '-t', '--timeout',
        type=float,
        default=60,
        help='Таймаут ожидания после WPS-лока (по умолчанию: %(default)s)'
    )

    adv_group = parser.add_argument_group('Продвинутые аргументы')
    adv_group.add_argument(
        '-F', '--pixie-force',
        action='store_true',
        help='Запустить Pixiewps с опцией --force (брутфорс полного диапазона)'
    )
    adv_group.add_argument(
        '-S', '--show-pixie',
        action='store_true',
        help='Показывать команду pixiewps и связанные данные'
    )
    adv_group.add_argument(
        '-I', '--iface-down',
        action='store_true',
        help='Опустить сетевой интерфейс после завершения работы'
    )
    adv_group.add_argument(
        '-M', '--mtk-wifi',
        action='store_true',
        help='Активировать драйвер MediaTek Wi-Fi при запуске и деактивировать при выходе'
    )
    adv_group.add_argument(
        '-D', '--dont-touch-settings',
        action='store_true',
        help='Не трогать настройки Wi-Fi Android при запуске и выходе'
    )
    adv_group.add_argument(
        '--reverse-scan',
        action='store_true',
        help='Обратный порядок сетей в списке. Полезно на маленьких экранах'
    )
    adv_group.add_argument(
        '--vuln-list',
        type=str,
        default=os.path.join(os.path.dirname(__file__), '../vulnwsc.txt'),
        help='Свой файл со списком уязвимых устройств'
    )
    adv_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Подробный вывод'
    )
    adv_group.add_argument(
        '-h', '--help',
        action='help',
        help='Показать эту справку и выйти'
    )

    args = parser.parse_args()

    if not args.check and not args.interface:
        parser.error('укажите интерфейс (-i wlan0) или используйте --check для проверки окружения')

    if (args.pixie_force or args.show_pixie) and not args.pixie_dust:
        parser.error('аргументы -F/--pixie-force и -S/--show-pixie можно использовать только с -P/--pixie-dust')

    if args.delay and not args.bruteforce:
        parser.error('аргумент -d/--delay можно использовать только с -B/--bruteforce')

    if args.restore and not args.kill:
        parser.error('аргумент -r/--restore можно использовать только с -k/--kill')

    return args
