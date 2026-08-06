# NShot — атрибуция и благодарности

NShot собран на основе следующих открытых проектов (все — GPL):

| Проект | Автор | Роль |
|---|---|---|
| [OneShot](https://github.com/kimocoder/OneShot) | rofl0r (оригинал), kimocoder (форк) | Базовая реализация атак WPS: Pixie Dust, онлайн-брутфорс, предсказание PIN, PBC |
| [OneShot-Extended](https://github.com/chkndrp/OneShot-Extended) | chkndrp | Модульная структура, улучшенный сканер, kill/restore процессов, поддержка Android |
| [Pixiewps](https://github.com/wiire-a/pixiewps) | wiire | Внешний инструмент для офлайн-атаки Pixie Dust |
| [3WiFi](https://3wifi.stascorp.com/wpspin) | — | База данных предсказания WPS PIN по OUI |

**Особое предупреждение про FARHAN-Shot-v2** ([frnAlt/FARHAN-Shot-v2](https://github.com/frnAlt/FARHAN-Shot-v2)):

`main.py` в этом репозитории обфусцирован (`exec(marshal.loads(...))`), но код полностью
открыт под GPL-2.0, поэтому в рамках лицензии он был **декомпилирован** и проверен
(распаковка `marshal → zlib → base64` даёт обычный Python-исходник, ~1500 строк).
Вредоносной логики (телеметрия, вебхуки, скрытые команды) не обнаружено; код является
форком OneShot.

Из FARHAN-Shot-v2 в NShot взято:
- **52 статических WPS-PIN** для конкретных моделей (TP-Link WR741N/WR841N/TD-W8960N
  с привязкой к MAC, Netgear DGN1000/WNR2000, Belkin F9J1102/F7D4401/F5D8635,
  D-Link DIR-655/DSL-2740B, TalkTalk, Billion, MediaPack, ASUS DSL-N10, Sapido и др.).
  Для 18 из них (имена с MAC-префиксом) PIN автоматически предлагаются при совпадении
  BSSID; остальные доступны в общем списке алгоритмов.
- **+395 записей** в списке уязвимых роутеров (`vulnwsc.txt`, объединённая база ≈1007 моделей).
- **Android fallback-скан** (`universalWifiScan`): если `iw` отсутствует, сеть
  сканируется через `cmd wifi list-scan-results` / `dumpsys wifi`.
- **Определение WiFi-стандарта** (WiFi 6/5) в таблице сканера.

Замечание: в самом FARHAN эти статик-PIN лежат мёртвым грузом (в атаке вызываются только
алгоритмы из `_suggest`-масок, а таблица статик-PIN нигде не используется). В NShot они
включены в механизм подсказок по OUI/MAC.

Лицензия: GNU General Public License v2 (см. LICENSE).
