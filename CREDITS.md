# NShot — attribution and credits

NShot is built on the following open-source projects (all GPL):

| Project | Author | Role |
|---|---|---|
| [OneShot](https://github.com/kimocoder/OneShot) | rofl0r (original), kimocoder (fork) | Core WPS attack implementation: Pixie Dust, online brute-force, PIN prediction, PBC |
| [OneShot-Extended](https://github.com/chkndrp/OneShot-Extended) | chkndrp | Modular structure, improved scanner, kill/restore of processes, Android support |
| [Pixiewps](https://github.com/wiire-a/pixiewps) | wiire | External tool for the offline Pixie Dust attack |
| [3WiFi](https://3wifi.stascorp.com/wpspin) | — | WPS PIN prediction database by OUI |

**Special note about FARHAN-Shot-v2** ([frnAlt/FARHAN-Shot-v2](https://github.com/frnAlt/FARHAN-Shot-v2)):
its `main.py` is obfuscated (`exec(marshal.loads(...))`), but the code is fully
available under GPL-2.0, so under the terms of that license it was **decompiled**
and checked (unpacking `marshal → zlib → base64` yields plain Python source,
~1500 lines). No malicious logic was found per the audit (no telemetry, no
webhooks, no hidden commands); the code is a OneShot fork.

From FARHAN-Shot-v2 NShot takes:

- **52 static WPS PINs** for specific router models (TP-Link WR741N/WR841N/TD-W8960N
  tied to MAC, Netgear DGN1000/WNR2000, Belkin F9J1102/F7D4401/F5D8635,
  D-Link DIR-655/DSL-2740B, TalkTalk, Billion, MediaPack, ASUS DSL-N10, Sapido and
  others). For 18 of them (names with a MAC prefix) the PIN is suggested
  automatically when the BSSID matches; the rest are available in the common
  algorithm list.
- **+395 entries** in the vulnerable router list (`vulnwsc.txt`, merged database
  ~1007 models).
- **Android fallback scan** (`universalWifiScan`): if `iw` is missing, networks
  are scanned via `cmd wifi list-scan-results` / `dumpsys wifi`.
- **WiFi standard detection** (WiFi 6/5) in the scanner table.

Note: in FARHAN itself those static PINs were dead code (only `__suggest__` mask
algorithms were called during attacks, while the static-PIN table was never used).
In NShot they are wired into the OUI/MAC-based PIN suggestion mechanism.

License: GNU General Public License v3 (see LICENSE).