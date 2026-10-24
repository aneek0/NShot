# GLOSSARY

One term per concept. Code identifiers use the English term; this file maps
them to the Russian words used in discussion and docs.

| Term | Code | Meaning |
|---|---|---|
| Попытка (attempt) | `Attempt`, `attempt()` | One WPS registration against one AP: send `WPS_REG`, read the supplicant exchange, produce one `AttemptResult`. The unit the CLI and the brute-force loop both consume. |
| Исход (outcome) | `AttemptResult.outcome` | Terminal classification of a попытка: `GOT_PSK`, `WSC_NACK`, `WPS_FAIL`, `WPS_TIMEOUT`, `RADIO_LOST`, `NO_PIN`. Callers branch on this string; no exceptions cross the API. |
| Сессия (session) | `WpaSupplicantSession` | The NShot-owned `wpa_supplicant -K -d` process plus its control socket. One per interface, reused across попытки, restartable without leaving the process. |
| Радио (radio) | `Radio` | The kernel view of the interface: up/down state, recovery after a drop, bounded retries. Owns every `ip link` and Android framework interaction for the link itself. |
| Хранилище (store) | `Store` | Everything persisted: brute-force masks (`sessions/*.run`), recovered PINs (`pixiewps/*.pin`), and cracked credentials (`reports/stored.{txt,csv,json}`). Root is `$NSHOT_HOME` or `~/.NShot`. |
| Маска (mask) | `BruteforceStatus.MASK` | Brute-force position: 4 digits (first half) or 7 digits (first half + second-half start). Saved to the store so `--bruteforce` can resume. |
| Pixie-данные (pixie data) | `PixieData` | The captured exchange fields (PKE, PKR, E-Hash1/2, AuthKey, nonces, BSSID) pixiewps needs. Collected during a NACK-ed попытка. |
| Таблица (table) | `src/wifi/table.py` | The numbered network list after a scan; selection returns `(BSSID, network)` or "refresh". Presentation only — no scanning logic. |
