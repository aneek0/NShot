#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.
"""Terminal presentation for scanned networks: logo, table, selection."""

from src import logger

LOGO = '''  ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
  ████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
  ██╔██╗ ██║███████╗███████║██║   ██║   ██║
  ██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║
  ██║ ╚████║███████║██║  ██║╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝'''


def truncate(text: str | None, length: int, postfix: str = '…') -> str:
    """Truncate with an ellipsis instead of cutting a value silently."""
    if len(text) > length:
        return text[:length - len(postfix)] + postfix
    return text


def colored(text: str, color: str) -> str:
    """ANSI colour for one table row."""
    if color == 'green':
        return f'\033[1m\033[92m{text}\033[00m'
    if color == 'dark_green':
        return f'\033[32m{text}\033[00m'
    if color == 'red':
        return f'\033[1m\033[91m{text}\033[00m'
    if color == 'yellow':
        return f'\033[1m\033[93m{text}\033[00m'
    return text


def render(networks, *, stored=(), vuln_list=None, reverse: bool = False,
           print_function=print) -> dict[int, dict]:
    """Print the network table and return it keyed by the number shown."""
    if not networks:
        return {}

    network_list = {i + 1: network for i, network in enumerate(networks)}
    items = list(network_list.items())

    print_function(LOGO)
    print_function('Network marks: {1} {0} {2} {0} {3} {0} {4}'.format(
        '|',
        colored('Vulnerable model', 'green'),
        colored('Vulnerable WPS ver.', 'dark_green'),
        colored('WPS locked', 'red'),
        colored('Already stored', 'yellow'),
    ))

    def width(item: str, max_length: int = 27) -> int:
        lengths = [len(entry[1].get(item, '')) for entry in items]
        return min(max(lengths), max_length) + 1

    lengths = {
        '#': 4,
        'sec': width('Security type'),
        'bssid': 18,
        'essid': width('ESSID'),
        'name': width('Device name'),
        'model': width('Model'),
        'wifi': width('WiFi Standard'),
    }

    row = '{:<{#}} {:<{bssid}} {:<{essid}} {:<{sec}} {:<{#}} {:<{#}} {:<{wifi}} {:<{name}} {:<{model}}'

    print_function(row.format(
        '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'Ver.', 'WiFi', 'WSC name', 'WSC model',
        **lengths
    ))

    if reverse:
        items = items[::-1]

    stored = set(stored)
    for number, network in items:
        model = f'{network["Model"]} {network["Model number"]}'
        essid = truncate(network['ESSID'], 25)
        device_name = truncate(network['Device name'], 27)
        line = row.format(
            f'{number})', network['BSSID'], essid,
            network['Security type'], network['Level'],
            network['WPS version'], network['WiFi Standard'], device_name, model,
            **lengths
        )

        if (network['BSSID'], network['ESSID']) in stored:
            print_function(colored(line, 'yellow'))
        elif network['WPS version'] == '1.0':
            print_function(colored(line, 'dark_green'))
        elif network['WPS locked']:
            print_function(colored(line, 'red'))
        elif vuln_list and (model in vuln_list or device_name in vuln_list):
            print_function(colored(line, 'green'))
        else:
            print_function(line)

    return network_list


def prompt(networks: dict[int, dict]) -> tuple[str, dict] | None:
    """Ask for a target. None means "refresh the list"."""
    while True:
        try:
            choice = input('Select target (press Enter to refresh): ')

            if choice.lower() in {'r', '0', ''}:
                return None

            if int(choice) in networks:
                selected = networks[int(choice)]
                return (selected['BSSID'], selected)

            raise IndexError
        except (IndexError, ValueError):
            logger.warning('Invalid number')