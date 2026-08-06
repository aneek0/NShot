#  NShot - WPS penetration testing utility
#  License: GPL-3.0-or-later, see LICENSE.
#  Origin and attribution: see CREDITS.md.

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

NShot v1.0 - WPS security testing: Pixie Dust, online brute-force,
PIN prediction and PBC. Only for your own or authorized networks.
Based on OneShot (kimocoder/rofl0r) and OneShot-Extended (chkndrp).
''',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    target_group = parser.add_argument_group('Main arguments')
    target_group.add_argument(
        '-i', '--interface',
        type=str,
        help='Name of the interface (e.g. wlan0)'
    )
    target_group.add_argument(
        '-b', '--bssid',
        type=str,
        help='BSSID of the target access point'
    )
    target_group.add_argument(
        '--check',
        action='store_true',
        help='Check the environment (dependencies, privileges, interface) and exit'
    )

    attack_group = parser.add_argument_group('Attack modes')
    # -p/--pin is outside the mutually exclusive group: it combines with -B
    # (the brute-force start mask) and with other modes as an explicit PIN.
    attack_group.add_argument(
        '-p', '--pin',
        type=str,
        help='Use the given PIN (arbitrary string or a 4/8-digit PIN);\n'
             'together with -B/--bruteforce it sets the brute-force start mask'
    )
    attack_pin_group = attack_group.add_mutually_exclusive_group()
    attack_pin_group.add_argument(
        '-N', '--null-pin',
        action='store_true',
        help='Use the null PIN'
    )
    attack_pin_group.add_argument(
        '-P', '--pixie-dust',
        action='store_true',
        help='Run the Pixie Dust attack (offline)'
    )
    attack_pin_group.add_argument(
        '-B', '--bruteforce',
        action='store_true',
        help='Run online PIN brute-force'
    )
    attack_pin_group.add_argument(
        '--pbc', '--push-button-connect',
        action='store_true',
        help='Connect via WPS PBC (push button)'
    )

    opt_group = parser.add_argument_group('Additional arguments')
    opt_group.add_argument(
        '-k', '--kill',
        action='store_true',
        help='Automatically kill processes that interfere with the interface'
    )
    opt_group.add_argument(
        '-r', '--restore',
        action='store_true',
        help='Restore killed processes on exit (together with --kill)'
    )
    opt_group.add_argument(
        '-w', '--write',
        action='store_true',
        help='Save found passwords/PINs to a file on success'
    )
    opt_group.add_argument(
        '-l', '--loop',
        action='store_true',
        help='Run in a loop'
    )
    opt_group.add_argument(
        '-c', '--clear',
        action='store_true',
        help='Clear the screen on every scan'
    )
    opt_group.add_argument(
        '-d', '--delay',
        type=float,
        default=0,
        help='Delay between PIN attempts in seconds (default: %(default)s)'
    )
    opt_group.add_argument(
        '-t', '--timeout',
        type=float,
        default=60,
        help='Timeout wait after a WPS lock (default: %(default)s)'
    )

    adv_group = parser.add_argument_group('Advanced arguments')
    adv_group.add_argument(
        '-F', '--pixie-force',
        action='store_true',
        help='Run Pixiewps with the --force option (full-range brute-force)'
    )
    adv_group.add_argument(
        '-S', '--show-pixie',
        action='store_true',
        help='Show the pixiewps command and related data'
    )
    adv_group.add_argument(
        '-I', '--iface-down',
        action='store_true',
        help='Bring the network interface down after finishing'
    )
    adv_group.add_argument(
        '-M', '--mtk-wifi',
        action='store_true',
        help='Activate the MediaTek Wi-Fi driver on start and deactivate on exit'
    )
    adv_group.add_argument(
        '-D', '--dont-touch-settings',
        action='store_true',
        help='Do not touch Android Wi-Fi settings on start and exit'
    )
    adv_group.add_argument(
        '--reverse-scan',
        action='store_true',
        help='Reverse the network list order. Useful on small screens'
    )
    adv_group.add_argument(
        '--vuln-list',
        type=str,
        default=os.path.join(os.path.dirname(__file__), '../vulnwsc.txt'),
        help='Your own file with the list of vulnerable devices'
    )
    adv_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    adv_group.add_argument(
        '-h', '--help',
        action='help',
        help='Show this help and exit'
    )

    args = parser.parse_args()

    if not args.check and not args.interface:
        parser.error('specify an interface (-i wlan0) or use --check to verify the environment')

    if (args.pixie_force or args.show_pixie) and not args.pixie_dust:
        parser.error('the -F/--pixie-force and -S/--show-pixie arguments can only be used with -P/--pixie-dust')

    if args.delay and not args.bruteforce:
        parser.error('the -d/--delay argument can only be used with -B/--bruteforce')

    if args.restore and not args.kill:
        parser.error('the -r/--restore argument can only be used with -k/--kill')

    return args