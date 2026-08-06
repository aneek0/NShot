# NShot

```
  ███╗   ██╗███████╗██╗  ██╗ ██████╗  ████████╗
  ████╗  ██║██╔════╝██║  ██║██╔═══██╗╚═███╔══╝
  ██╔██╗ ██║███████╗ ███████║██║    ██║  ██║
  ██║╚██╗██║╚════██║ ██╔══██║██║   ██║  ██║
  ██║ ╚████║███████║  ██║  ██║╚██████╔╝  ██║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝
```

Testing WPS security of your own networks: **Pixie Dust**, **online PIN
brute-force**, **PIN prediction from BSSID** and **push-button connection
(PBC)** — without monitor mode, through `wpa_supplicant`.

Built from the open-source projects [OneShot](https://github.com/kimocoder/OneShot)
and [OneShot-Extended](https://github.com/chkndrp/OneShot-Extended).
Full attribution in [CREDITS.md](CREDITS.md).

> ⚠️ **For your own or explicitly authorized networks only.**
> Using this against someone else's networks is illegal and prosecuted by law.

---

## Features

- 🔍 Network scanner via `iw` with highlighting:
  - vulnerable models from the list (`vulnwsc.txt`) — green
  - vulnerable WPS version `1.0` — dark green
  - locked WPS — red
  - already saved networks — yellow
- ⚡ Pixie Dust (offline attack via `pixiewps`)
- 🔢 Online PIN brute-force (4/7/8-digit mask, session resume)
- 🎯 PIN prediction from BSSID (3WiFi, D-Link, ASUS, Broadcom and other algorithms)
- 📇 Static PINs for 52 router models (TP-Link, Netgear, Belkin, D-Link, etc.),
  MAC-specific PINs are suggested automatically by OUI
- 📶 WiFi standard detection (WiFi 6/5) in the scanner table, Android fallback scan
  via `cmd wifi`/`dumpsys` when `iw` is unavailable
- 🔘 WPS PBC and NULL PIN (`-N`); automatic NULL PIN (`00000000`) fallback
  when no specific PIN is found or selected
- 🧹 Auto-kill of interfering processes (`--kill`) and restore (`--restore`)
- 📊 Results saved to `reports/stored.{txt,csv,json}`
- 🔎 Environment self-check (`--check`)
- 🤖 Runs on Linux and Android/Termux (root), Python ≥ 3.10, no pip dependencies

---

## Installation

No Python packages are required: NShot runs on the Python 3.10+ standard library
only, there are no pip dependencies to install.

System utilities needed: `python3`, `wpa_supplicant`, `iw`, `ip` (iproute2), and
`pixiewps` for Pixie Dust. Everything except pixiewps is required in any mode.

```bash
# Debian / Ubuntu
sudo apt install -y python3 wpasupplicant iw iproute2 pixiewps

# Arch
sudo pacman -S python wpa_supplicant iw iproute2 pixiewps
```

Or with a single script:

```bash
# Auto-install: installs dependencies, clones the repo into ./NShot
# (and pulls updates when run from inside the repo)
curl -fsSL https://raw.githubusercontent.com/aneek0/NShot/master/install.sh | bash
```

Or when the repo is already cloned:

```bash
chmod +x install.sh && sudo ./install.sh
```

For Android/Termux (root): `pkg install -y root-repo tsu python wpa-supplicant pixiewps iw openssl`

### Environment check

```bash
python3 nshot.py --check
```

Shows the status of privileges, binaries and the interface, and tells you which
modes are available.

---

## Usage

```bash
sudo python3 nshot.py -i wlan0                  # scan and pick a target
sudo python3 nshot.py -i wlan0 -P               # Pixie Dust after picking a target
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -P
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B        # online brute-force
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234  # with first half of PIN
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -p 12345670 # with a specific PIN
sudo python3 nshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -N          # NULL PIN
sudo python3 nshot.py -i wlan0 --pbc                             # PBC
```

### Key options

| Option | What it does |
|---|---|
| `-i, --interface` | Wi-Fi interface (e.g. `wlan0`) |
| `-b, --bssid` | Target access point |
| `-p, --pin` | Your PIN (string or 4/8 digits) |
| `-N, --null-pin` | Force the null PIN (`00000000`); without it the null PIN is still tried automatically when no PIN is found or selected |
| `-P, --pixie-dust` | Pixie Dust attack |
| `-B, --bruteforce` | Online brute-force |
| `--pbc` | Push-button connection |
| `-k / -r` | Kill interfering processes / restore them on exit |
| `-w, --write` | Save results to `reports/` |
| `-l, --loop` | Work in a loop |
| `-c, --clear` | Clear screen when scanning |
| `-d, --delay` | Delay between PIN attempts (sec) |
| `-t, --timeout` | Pause on WPS lock (sec) |
| `-F, --pixie-force` | Pixiewps with `--force` (full range) |
| `-S, --show-pixie` | Show the pixiewps command |
| `-I, --iface-down` | Bring the interface down on exit |
| `-M, --mtk-wifi` | MediaTek Wi-Fi driver (Android) |
| `-D, --dont-touch-settings` | Don't touch Wi-Fi settings on Android |
| `--vuln-list` | Your own list of vulnerable devices |
| `--check` | Environment check |

---

## Results

On a successful crack with the `-w/--write` flag, three files are written to `reports/`:

- `stored.txt` — human-readable report
- `stored.csv` — table (used to highlight already known networks)
- `stored.json` — machine-readable report for automation

> Tip: always add `-w` so you don't lose a found PIN/password.
> `--check` tells you that WPS attacks need a Wi-Fi interface (usually `wlan0`), not a wired one.

Online brute-force sessions are saved in `~/.NShot/sessions/`, found PINs in
`~/.NShot/pixiewps/`.

---

## How it works

NShot starts its own `wpa_supplicant` instance on a temporary config and talks to
it through the control socket. This allows:

- requesting WPS transactions from the AP without switching to monitor mode;
- collecting parameters (PKE, E-Hash1/2, nonces, etc.) for the offline Pixie Dust
  attack through `pixiewps`;
- brute-forcing the PIN online while tracking WPS-lock and WPS-FAIL.

---

## Tests

All tests need no root and no Wi-Fi adapter (`wpa_supplicant`/`pixiewps` runs are mocked).

```bash
python3 tests/run_all.py                     # the whole suite at once
python3 tests/test_generator.py             # PIN generator, checksum, MAC
python3 tests/test_scanner.py              # iw scan output parser
python3 tests/test_engine.py               # attack engine: pixiewps, wpa_supplicant, brute-force
python3 tests/test_utils.py                # utils: /proc, ip link, vulnerable list
python3 tests/test_android.py             # android: cmd wifi / settings commands
python3 tests/test_fullflow.py          # end-to-end: scan -> target pick -> WPS -> report
python3 tests/test_integration.py          # full attack pipeline (PIN, retry, Pixie Dust, report)
python3 tests/test_cli.py                 # CLI orchestration: kill/restore, iface up/down, loop
```

---

## Source security note

Three projects were reviewed before building (see CREDITS). **FARHAN-Shot-v2** ships
with an obfuscated `main.py` (`exec(marshal.loads(...))`) — not runnable "as is".
The code, however, is open under GPL-2.0, so we **decompiled** it
(`marshal → zlib → base64`) and verified it: no malicious logic, it is a OneShot fork.
From it NShot takes 52 static WPS PINs for specific router models and a merged list
of vulnerable devices (~1007 entries). Details in CREDITS.

NShot license: [GPL-3.0](LICENSE).
