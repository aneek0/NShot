# NShot — атрибуция и благодарности

NShot собран на основе следующих открытых проектов (все — GPL):

| Проект | Автор | Роль |
|---|---|---|
| [OneShot](https://github.com/kimocoder/OneShot) | rofl0r (оригинал), kimocoder (форк) | Базовая реализация атак WPS: Pixie Dust, онлайн-брутфорс, предсказание PIN, PBC |
| [OneShot-Extended](https://github.com/chkndrp/OneShot-Extended) | chkndrp | Модульная структура, улучшенный сканер, kill/restore процессов, поддержка Android |
| [Pixiewps](https://github.com/wiire-a/pixiewps) | wiire | Внешний инструмент для офлайн-атаки Pixie Dust |
| [3WiFi](https://3wifi.stascorp.com/wpspin) | — | База данных предсказания WPS PIN по OUI |

**Особое предупреждение про FARHAN-Shot-v2** ([frnAlt/FARHAN-Shot-v2](https://github.com/frnAlt/FARHAN-Shot-v2)):

Этот репозиторий был рассмотрен, но **его код не использовался**. Файл `main.py` там
представляет собой закомпилированный/обфусцированный байт-код Python
(`exec(marshal.loads(...))`), то есть **чёрный ящик, который невозможно проверить
на безопасность**. Запускать его не рекомендуется: такой код может делать что угодно
(собирать данные, выполнять скрытые команды и т.п.). В NShot вместо этого включён
обычный, читаемый код с той же функциональностью: NULL-PIN автофолбэк реализован
флагом `-N/--null-pin`, который пробует нулевой PIN автоматически.

Лицензия: GNU General Public License v2 (см. LICENSE).
