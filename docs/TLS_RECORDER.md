# Регистратор TLS

TLS Recorder записывает фактический первый ClientHello на двух границах:

```text
клиент → CLIENT_IN → JA3Proxy → PROXY_OUT → сервер
                                      ↑
                                  SERVER_IN
```

`CLIENT_IN` отражает байты клиента после установления HTTP CONNECT или SOCKS5
туннеля. `PROXY_OUT` отражает успешно переданные нижележащему сокету байты
исходящего соединения. Успешный `Write` не доказывает получение данных удалённым
сервером; это отдельно проверяется сквозными тестами.

## Включение

```bash
./ja3proxy --capture-tls --web-panel 127.0.0.1:9090
```

Recorder выключен по умолчанию. Параметры `--capture-raw`, `--capture-jsonl`
и `--capture-sqlite` без `--capture-tls` считаются ошибкой конфигурации.

Web-панель на loopback может работать по HTTP. Для non-loopback binding
обязательно одновременно указать Bearer-токен и TLS-сертификат:

```bash
./ja3proxy --web-panel 0.0.0.0:9090 \
  --web-panel-token-file credentials/panel.token \
  --web-panel-cert credentials/panel.crt \
  --web-panel-key credentials/panel.key
```

Удалённый HTTP без аутентификации или удалённый запуск без HTTPS отклоняется
до старта сервера. Параметры `--web-panel-cert` и `--web-panel-key` должны
задаваться парой.

Для согласованной ротации можно указать один PEM-файл, содержащий сертификат
и закрытый ключ, в обоих параметрах. Панель считывает такой файл один раз на
каждое новое TLS-подключение. Подготовьте новый файл отдельно и атомарно
замените им старый по тому же пути (например, переименованием в пределах одного
тома); уже установленные соединения сохраняют прежний сертификат. При двух
отдельных файлах замена между их чтениями может привести к ошибке handshake,
поэтому для бесшовной ротации используйте общий PEM-файл.

## Что вычисляется

- строка и MD5 JA3;
- составной JA4 для TLS поверх TCP;
- строка и MD5 JA3S для upstream ServerHello;
- versioned JA4S для upstream ServerHello;
- нормализованная структура TLS-NORM-1;
- SHA-256 исходного ClientHello;
- SHA-256 захваченных TLS records;
- SHA-256 канонической нормализованной структуры.
- тип handshake: `FULL`, `RESUMED` или `PSK`;
- признаки `session_resumption`, `psk_present`, число PSK identities и `early_data`.

GREASE нормализуется в распознанных списках. SNI, random, session ID bytes,
ключевые данные key share, PSK identities и binders не входят в
нормализованный hash. Длины и структурное положение сохраняются там, где это
нужно для сравнения.

`SERVER_IN` записывает первый upstream ServerHello внутри TLS-туннеля. Поля
`server_hello.fields.*` имеют единый контракт `value/source/available/reason`:
это позволяет отличить реально отсутствующее расширение от данных TLS 1.3,
которые находятся в зашифрованных `EncryptedExtensions`. Для ServerHello
доступны TLS version, selected cipher, extensions, selected group, session
reuse и HelloRetryRequest. JA4S вычисляется по доступным ServerHello-полям;
ALPN становится `00`, если он находится только в зашифрованных
EncryptedExtensions. Поле `server_hello.fields.encrypted_extensions` явно
помечается `available=false, reason=encrypted_without_keys` для TLS 1.3 и
`reason=not_applicable` для остальных версий. В режимах `PASSTHROUGH` и
`OBSERVE_ONLY` EncryptedExtensions можно расшифровать, передав NSS key-log:

```powershell
ja3proxy --capture-tls --tls-mode PASSTHROUGH --tls-keylog-file C:\temp\tls.keys
```

Key-log должен содержать `SERVER_HANDSHAKE_TRAFFIC_SECRET` для ClientHello,
который проходит через этот процесс. Поддерживаются TLS 1.3 cipher suites
AES-128-GCM, AES-256-GCM и ChaCha20-Poly1305. Расшифрованные расширения и
выбранный ALPN объединяются с соответствующей записью ServerHello и получают
источник `decrypted_encrypted_extensions`; при отсутствии или неподходящем
секрете сохраняется явная причина неполноты. Сам файл ключей, traffic secrets и
расшифрованные TLS records в recorder не сохраняются. Пользователь отвечает за
получение и использование разрешённого key-log. В MITM-режиме этот observer не
используется: там доступно отдельно согласованное состояние локального TLS
handshake.
`session_resumption` не выводится из длины `legacy_session_id_echo`: в TLS 1.3
это поле может заполняться для совместимости. Отсутствие выбранного PSK означает
`available=true, value=false`; при выбранном PSK тип секрета (внешний или
возобновление) из ServerHello не определяется и записывается
`available=false, reason=psk_selected_type_unknown`. Для TLS 1.2 без
соответствующего ClientHello причина — `requires_client_hello`.
После собственного upstream TLS handshake MITM дополнительно записывает
`negotiated_state` с согласованными version, cipher, ALPN, SNI и признаком
resumption. Это состояние не содержит ключей, сертификатов или raw ALPS и не
создаётся для PASSTHROUGH, где proxy не завершает TLS.
Для MITM также записываются HTTP/1.x fingerprints на raw application bytes:
метод или status, target, HTTP version, порядок и исходный регистр заголовков,
content length и transfer encoding. Значения заголовков не сохраняются — в
`http1.headers[].value_sha256` попадает только SHA-256. HTTP/2 и passthrough
этим анализатором не классифицируются как HTTP/1.x.
Тела HTTP не сохраняются и не входят в fingerprint. Для body-bearing
Content-Length/chunked сообщений observation помечается `completeness: partial`
и `body_captured: false`; chunk framing пропускается, а trailers явно
обозначаются `trailer_status: not_fingerprinted`. Close-delimited, upgrade и
неподдерживаемое framing также остаются partial и не интерпретируются как
следующие HTTP-сообщения.
Для MITM с ALPN `h2` дополнительно записывается `http2` по внутреннему
формату `H2-NORM-2`: preface, порядок и значения SETTINGS, типы фреймов,
WINDOW_UPDATE (stream/increment), параметры PRIORITY, порядок pseudo headers и
обновления размера HPACK dynamic table. Fingerprint всегда имеет статус
`partial`; поле `availability` различает наблюдавшиеся, не наблюдавшиеся и
намеренно не записываемые данные. Frame payload, имена обычных заголовков и
декодированные значения заголовков не сохраняются, кроме разобранных из
клиентского `User-Agent` ограниченных version claims. В HTTP/1 и HTTP/2
записываются только product/version пары со `source=http_user_agent`,
`confidence=low`, `status=unverified`; исходный заголовок не сохраняется.
Это могут быть версии библиотек, spoofed или устаревшие значения: claim не
привязывается автоматически к приложению/устройству и не применяется правилами.
Подтверждённую версию задавайте вручную через `POST /api/v1/device-assignments`
с явными `device_id`, `application_id` и периодом `valid_from`/`valid_to`.
Только подтверждённая временная привязка появляется в `application_version`.
Снимок ограничен первыми
64 фреймами, размером одного фрейма/header block/таблицы 1 МиБ и 4096
элементами metadata; wall-clock timing не измеряется.
В пакете также есть отдельный IPv4/IPv6 TCP SYN parser и вход recorder для
структурированных SYN metadata; парсер формирует JA4T/1, включая порядок
option kinds и значения window/MSS/window-scale. На Windows live capture
доступен через Npcap: список интерфейсов выводится флагом
`--list-capture-interfaces`, запуск выполняется с `--capture-tcp-interface
<имя>`. На Linux используются native AF_PACKET-сокеты (нужно системное право
`CAP_NET_RAW`, например запуск от root). Сервис также парсит DNS/UDP-пакеты на
этом интерфейсе и сохраняет сопоставленные запросы/ответы только как
метаданные. Это не меняет proxy forwarding. На ОС вне Windows/Linux live
capture adapter пока не реализован. IPv4/IPv6 IP fragments собираются до
TCP/DNS-разбора; некорректные перекрывающиеся fragments отбрасываются.
DNS-NORM-1 sensor принимает готовые UDP DNS payload или полные
length-prefixed TCP frames; live-сборщик восстанавливает DNS/TCP messages по
TCP sequence numbers. Если захват начинается без SYN внутри сообщения,
неполный первый frame пропускается, а разбор продолжается со следующего
полностью валидного DNS frame; с наблюдаемым SYN framing проверяется строго.
CNAME-ответы связываются до 16 переходов, в том числе
между DNS exchanges одного клиента; TTL каждой записи ограничивает её срок
действия, циклы безопасно завершаются, неоднозначные имена не угадываются.
Активная CNAME-цепочка считается именем исходного alias, а промежуточный target
не добавляет ложную неоднозначность; после истечения TTL target может быть
сопоставлен самостоятельно.
Для live DNS↔TLS связи включите оба флага:
`--capture-tls --capture-tcp-interface <имя>`. TLS observations сопоставляются
с недавними A/AAAA/CNAME-данными того же client IP и destination IP. Raw DNS
packets не сохраняются.

Тот же `--capture-tcp-interface` включает пассивный QUIC v1/v2 client Initial
sensor. Он принимает только datagrams с UDP payload не меньше 1200 байт и
расшифровывает Initial с публичными version-specific Initial keys,
собирает переупорядоченные CRYPTO frames и сохраняет разобранный ClientHello,
SNI и нормализованные transport parameters. Для opaque parameters записывается
только длина; raw пакеты, connection IDs, tokens и CRYPTO bytes не сохраняются.
Неверная аутентификация, неизвестная версия/frame и неполный ClientHello не
создают успешное QUIC observation. Поддерживается только client Initial:
Retry, server Initial, Handshake/0-RTT/1-RTT, server transport parameters и
JA4-QUIC сейчас не реализованы. Для QUIC не требуется включать `--capture-tls`.
При HelloRetryRequest wrapper создаёт отдельное событие `HELLO_RETRY_REQUEST`,
а последующий ServerHello получает следующий `handshake_sequence` в той же
`connection_id`. Одно-байтовый TLS 1.3 compatibility `ChangeCipherSpec` между
ними пропускается и не создаёт ложное наблюдение.

Для capture только ClientHello тип `PSK` определяется по extension
`pre_shared_key`; `RESUMED` требует подтверждения последующими handshake
сообщениями и может быть передан внешним state. Поля не раскрывают ticket,
identity или binder bytes.

## Идентичность клиента

Observation сохраняет identity evidence отдельно от fingerprint:

- `proxy_username` с confidence `exact`, если клиент прошёл HTTP/SOCKS5-аутентификацию;
- `source_ip` с confidence `inferred`, если username отсутствует и source —
  валидный IP-адрес.
- При активной временной привязке observation также получает `application`,
  `application_version` и `application_assignment_id`. Интервал действует как
  `[valid_from, valid_to)`, а пустой `valid_to` означает открытый конец.
  Для одного устройства пересекающиеся интервалы запрещены, поэтому активная
  assignment однозначна.

Пароль, `Proxy-Authorization` и другие секреты не попадают в observation.
Fingerprint сам по себе не назначает устройство; `resolved_device_id` остаётся
пустым до появления явного mapping/Device Manager.

## Лимиты по умолчанию

| Ресурс | Лимит |
| --- | ---: |
| ClientHello | 256 КиБ |
| TLS record | 18 432 байта |
| Records одного захвата | 64 |
| Очередь | 64 наблюдения |
| Окно памяти | 256 наблюдений |
| Объём окна памяти | 32 МиБ |
| JSONL | 256 МиБ |
| SQLite retention | 100 000 наблюдений |
| Encrypted recorder spool | 512 МиБ по умолчанию, максимум 4 ГиБ |
| Audit memory window | 10 000 событий |
| Durable audit JSONL | 16 МиБ |
| Durable audit SQLite | без JSONL-лимита, с проверкой SHA-256 цепочки |

Очередь неблокирующая: при переполнении прокси продолжает обслуживать трафик, а
счётчик `dropped` увеличивается. При ошибке или исчерпании квоты JSONL дальнейшая
запись в файл прекращается, но прокси и окно памяти продолжают работать.
Для `CRITICAL`-событий используется отдельная bounded spill-очередь; её
состояние доступно в `stats.critical_queue_depth` и
`stats.critical_spill_accepted`.

## Исходные данные

Без `--capture-raw` исходные байты используются только для вычисления
fingerprints и не включаются в сохранённое наблюдение. С этим параметром поля
`raw_client_hello` и `raw_records` сериализуются в JSON как base64.

```bash
./ja3proxy \
  --capture-tls \
  --capture-raw \
  --capture-jsonl recordings/lab-001.jsonl
```

JSONL создаётся с запретом перезаписи существующего файла. Выбирайте новое имя
для каждого запуска. Текущая реализация не шифрует файл.

### Durable SQLite

```bash
./ja3proxy \
  --capture-tls \
  --capture-sqlite recordings/recorder.db \
  --capture-sqlite-retention 50000
```

Основной файл состояния проекта — единая SQLite-база `state/ja3proxy.db`
(`--state-sqlite` меняет путь). При включённом `--capture-tls` наблюдения
автоматически сохраняются в этой базе; `--capture-sqlite` позволяет явно
выбрать путь общей БД. Если задан `--capture-sqlite` или
`--audit-sqlite`, его путь выбирает эту базу; несколько SQLite-параметров должны
указывать на один и тот же файл. Запись наблюдений работает параллельно с окном
памяти и, при необходимости, JSONL. При старте выполняются versioned migrations; после перезапуска последние
наблюдения восстанавливаются в bounded memory window. В таблице `observations`
хранится полный JSON payload и индексируемые поля времени, connection ID,
capture point, destination, device и application. Retention удаляет самые старые записи после каждой вставки; по
умолчанию — 100 000 наблюдений, лимит можно изменить через
`--capture-sqlite-retention`. Если `--capture-raw` не указан, SQLite также не
содержит `raw_client_hello` и `raw_records`. Ошибка SQLite не останавливает
прокси, увеличивает `write_errors` и отражается в `recording_degraded`.

### Зашифрованный spool при сбое SQLite

Для временного durable-буфера при недоступности SQLite включите bounded spool:

```bash
./ja3proxy \
  --capture-tls \
  --capture-sqlite recordings/recorder.db \
  --capture-spool recordings/spool \
  --capture-spool-key credentials/recorder-spool.key \
  --capture-spool-max-bytes 536870912
```

`recorder-spool.key` должен содержать ровно 32 случайных байта в бинарном виде
(AES-256-GCM), иметь права только владельца и не попадать в Git. Spool-файлы
содержат только зашифрованный payload наблюдения; незавершённые записи не
публикуются благодаря временному файлу и атомарному rename. При следующем
запуске записи повторно доставляются в SQLite, а одинаковый `observation_id`
обрабатывается идемпотентно. Повреждённые или неаутентичные записи перемещаются
в `quarantine/` и не блокируют запуск.

Для смены ключа с перезапуском остановите приложение и убедитесь, что в spool не осталось
файлов `.evt` (в норме они доставляются в SQLite при запуске с прежним ключом).
После этого замените ключевой файл и запустите приложение снова. В каталоге
spool хранится `key.id` — отпечаток поколения ключа, не сам ключ. Если при
смене ключа есть ожидающие записи, запуск отклоняется, а файлы остаются на
месте: верните прежний ключ и повторите доставку. При пустом spool `key.id`
обновляется автоматически. Для старого spool без `key.id` ключ проверяется по
ожидающей записи до создания маркера; если проверка невозможна, записи не
меняются и требуется ручная проверка.

Смена без перезапуска доступна в настройках панели кнопкой «Применить ключ
spool из файла» или через `POST /api/v1/admin/spool/reload-key` без тела запроса.
Подготовьте новый 32-байтный ключ по настроенному пути, сохранив предыдущий до
успешного применения. Проверка пустоты spool и публикация ключа выполняются
под одной блокировкой с записью. При успехе API возвращает `204`; новые записи
шифруются новым ключом и читаются после перезапуска. При ожидающих записях или
ошибке файла API возвращает `409`, активный ключ остаётся прежним. В таком
случае верните прежний файл ключа до перезапуска. Non-loopback требует роль
`admin`, локальный режим работает без токена; журнал аудита обязателен.

Spool ограничен `--capture-spool-max-bytes` (по умолчанию 512 МиБ, максимум
4 ГиБ). При заполнении новая запись не принимается в spool, но proxy остаётся
работоспособным. Состояние доступно в `stats.spool_bytes`,
`stats.spool_events` и `stats.spool_quarantined`; механизм не заменяет резервное
копирование SQLite и включается только явными флагами.

Для диагностики потерь `stats.dropped_by_class` содержит счётчики по классам
`CRITICAL`, `IMPORTANT` и `OPTIONAL`. Неуказанный класс для TLS metadata
считается `CRITICAL`; `stats.lost_by_class` отдельно показывает потери при
ошибке SQLite и невозможности записи в spool. Метрика `spool_quota_failures` и событие
`RECORDER_SPOOL_FULL` показывают исчерпание дисковой квоты; proxy при этом не
блокируется.

Существующая база открывается и мигрируется, поэтому накопление продолжается
после штатного перезапуска. Каталог для файла должен существовать.

### Явный реестр устройств

Для разрешения evidence в device ID укажите реестр:

```bash
./ja3proxy --capture-tls --device-map-file devices.json
```

Формат файла — `schema_version: "device-registry/1"` и массив `devices` с
полями `id`, `name`, `proxy_username`, `source_ips`, `tags`, сведениями о
платформе/приложении и `enabled`. Сначала проверяется уникальный username,
затем source IP. Если mapping неоднозначен, `resolved_device_id` не
назначается, а `confidence` становится `ambiguous`. Fingerprint никогда не
используется для автоматического назначения устройства.

Минимальный пример:

```json
{
  "schema_version": "device-registry/1",
  "config_version": 1,
  "devices": [
    {
      "id": "iphone-017",
      "name": "iPhone 017",
      "proxy_username": "iphone017",
      "source_ips": ["192.0.2.10"],
      "platform": "iOS",
      "enabled": true
    }
  ]
}
```

Каталог приложений хранится в том же реестре и связывается с assignment через
`application_id`. Старый формат assignment с полем `application` поддерживается
для совместимости.

Реестр можно изменять через локальный Device Manager API. Все операции требуют
`expected_version`, равный текущему `config_version`; при конфликте сервер
возвращает `409`, поэтому клиент должен перечитать список и повторить изменение.
`POST` принимает пустой `id` и генерирует его автоматически. Изменение файла
сохраняется на диск, если реестр был открыт через `--device-map-file`.

## Локальный API

| Метод и путь | Назначение |
| --- | --- |
| `GET /api/v1/status` | состояние recorder и счётчики |
| `GET /api/v1/observations` | поиск и постраничный список TLS/HTTP/TCP/DNS/QUIC наблюдений; `storage=sqlite` ищет по durable retention; доступны фильтры устройства, приложения, revision и времени |
| `GET /api/v1/observations/{id}` | полное наблюдение; `storage=sqlite` выбирает историческую запись |
| `POST /api/v1/observations/{id}/reparse?storage=sqlite` | повторный разбор сохранённого исходного ClientHello с созданием новой revision |
| `POST /api/v1/reparse/sqlite` | пакетный повторный разбор исходных SQLite-наблюдений по `next_cursor` |
| `GET /api/v1/fingerprints/diff?a=&b=&storage=sqlite` | сравнение совместимого fingerprint-семейства; для HTTP/1, HTTP/2, TCP SYN, DNS и QUIC совпадение помечается `PARTIAL_MATCH` |
| `GET /api/v1/export/observations` | экспорт текущего окна или `storage=sqlite` потоковый экспорт durable retention |
| `GET /api/v1/export/config?format=json|zip` | безопасная резервная копия control-plane конфигурации без telemetry и паролей upstream |
| `GET /api/v1/export/telemetry` | согласованный standalone SQLite snapshot telemetry; scopes `export` и `raw` |
| `POST /api/v1/import/telemetry` | идемпотентное восстановление telemetry из SQLite snapshot; scopes `write` и `raw` |
| `POST /api/v1/import/config/validate` | preflight-проверка JSON/ZIP backup без применения изменений |
| `POST /api/v1/import/config` | применение проверенного backup с optimistic version checks |
| `GET /api/v1/audit` | постраничный append-only аудит действий панели |
| `GET /api/v1/tls/presets` | доступные пресеты uTLS |
| `GET /api/v1/devices` | список устройств и `config_version` |
| `GET /api/v1/devices/{id}` | одно устройство |
| `POST /api/v1/devices` | создать устройство с проверкой версии |
| `PUT /api/v1/devices/{id}` | заменить mapping с проверкой версии |
| `DELETE /api/v1/devices/{id}` | удалить mapping с проверкой версии |
| `GET /api/v1/device-assignments` | временные привязки приложения к устройствам |
| `GET /api/v1/device-assignments/{id}` | одна временная привязка |
| `POST /api/v1/device-assignments` | создать привязку периода |
| `PUT /api/v1/device-assignments/{id}` | изменить привязку периода |
| `DELETE /api/v1/device-assignments/{id}` | удалить привязку периода |
| `GET /api/v1/applications` | каталог приложений |
| `GET /api/v1/applications/{id}` | одно приложение |
| `POST /api/v1/applications` | создать приложение |
| `PUT /api/v1/applications/{id}` | изменить приложение |
| `DELETE /api/v1/applications/{id}` | удалить приложение |
| `GET /api/v1/fingerprints/timeline` | timeline JA3/JA4 с отметкой изменений |
| `GET /api/v1/export/observations?format=jsonl|csv&storage=sqlite` | потоковый исторический экспорт |
| `GET /api/v1/tls/profiles` | библиотека и версия конфигурации TLS-профилей |
| `POST /api/v1/tls/profiles/from-preset` | черновик из uTLS-пресета |
| `POST /api/v1/tls/profiles/from-observation` | черновик/профиль из наблюдения |
| `POST /api/v1/tls/profiles/preview` | материализация и ожидаемые fingerprints |
| `POST /api/v1/tls/profiles` | сохранить новый профиль |
| `PUT /api/v1/tls/profiles/{id}` | сохранить новую версию профиля |
| `DELETE /api/v1/tls/profiles/{id}` | удалить неактивный профиль |
| `GET /api/v1/tls/profiles/{id}/versions` | неизменяемая история версий |
| `POST /api/v1/tls/profiles/{id}/rollback` | откат как новая версия |
| `PUT /api/v1/tls/profiles/active` | выбрать один или несколько профилей для новых соединений |
| `GET /metrics` | метрики в текстовом формате |
| `GET /health/live` | проверка активности процесса |
| `GET /health/ready` | готовность и признак деградации |

Параметры списка:

- `q` — поиск по хосту, адресу клиента, connection ID, JA3, JA4, JA3S или JA3S hash;
- `limit` — от 1 до 100;
- `cursor` — ID последнего элемента предыдущей страницы.

Для мультиактивации передайте `ids` в порядке приоритета. Точное совпадение
host pattern имеет приоритет над wildcard; при одинаковой специфичности раньше
стоящий ID выигрывает. Старый параметр `id` по-прежнему выбирает один профиль.

Route manager загружается через `--route-config-file`. Он разрешает правила в
фазах `PRE_TLS` и `POST_CLIENTHELLO`, учитывая host/wildcard, CIDR, порт,
device/device tag и username. В POST_CLIENTHELLO доступны также ALPN, offered
TLS versions, JA3, JA3 hash и JA4. Для проверки без реального соединения доступен
`POST /api/v1/routes/test`; ответ содержит версию snapshot, список кандидатов,
победившее правило, action и причину совпадения. PRE_TLS и POST_CLIENTHELLO
actions `BLOCK`, `MITM_REISSUE`, `PASSTHROUGH` и `OBSERVE_ONLY` применяются к
новым соединениям; POST_CLIENTHELLO выбирается по SNI после bounded buffering
первого ClientHello;
`action.upstream` выбирает HTTP/SOCKS5 upstream для нового туннеля; PRE_TLS
выбирает его до CONNECT/SOCKS5-ответа, а POST_CLIENTHELLO может заменить
destination после определения SNI. `action.tls_profile` закрепляет конкретный
ID профиля TLS для MITM. При
отсутствии этих полей используются глобальные upstream и TLS-настройки;
глобальная конфигурация при этом не изменяется.
При старте route-конфигурация проходит cross-reference validation: upstream URL
и `tls_profile` должны быть корректными, активными и воспроизводимыми. Ошибка
обнаруживается до открытия proxy listener.

В observation поле `routing` сохраняет immutable `evaluated_config_version`, полный
ordered список кандидатов, выбранное правило, priority и причину совпадения для
PRE_TLS и POST_CLIENTHELLO. В metadata отдельно сохраняются `connect_host`, `sni`
и `authority_mismatch`; значения `action` (в том числе credentials в URL upstream)
в route evidence не попадают.

Если курсор уже вытеснен из ограниченного окна, API возвращает `409`, и клиент
должен обновить список с начала.

Полный контракт: [spec/recorder-openapi.json](spec/recorder-openapi.json).

## Защита панели

Для loopback binding (`127.0.0.1`, `::1` или `localhost`) панель работает по
обычному HTTP без Bearer-аутентификации, в том числе если token registry
настроен. Для non-loopback binding одновременно обязательны Bearer-токен и
HTTPS-сертификат; без них сервер завершается ошибкой до запуска. Настройки
токена используются для non-loopback доступа:

```bash
./ja3proxy --web-panel 0.0.0.0:9090 \
  --web-panel-cert credentials/panel.crt \
  --web-panel-key credentials/panel.key \
  --web-panel-token-file credentials/panel.token
```

Файл читается только при запуске, не попадает в runtime/status, аудит и ответы
API. В простом формате файл содержит один токен длиной не менее 16 символов;
такой токен получает scopes `read` и `write`. Для выдачи минимальных прав можно
использовать JSON-формат:

```json
{"token":"замените-на-длинный-токен","scopes":["read","write","raw","export"],"expires_at":"2026-12-31T23:59:59Z"}
```

Для нескольких операторов поддерживается JSON-регистр токенов. Роль задаёт
scopes, если они не указаны явно: `viewer` — только `read`, `operator` —
`read/write`, `investigator` — `read/raw/export`, `admin` — все scopes.

```json
{"tokens":[
  {"id":"analyst-1","token":"длинный-токен-аналитика","role":"investigator"},
  {"id":"operator-1","token":"длинный-токен-оператора","role":"operator","expires_at":"2026-12-31T23:59:59Z"},
  {"id":"old-token","token":"отозванный-токен-длиной-16","role":"viewer","revoked":true}
]}
```

Идентификатор токена используется как actor в audit; сами секреты не записываются
в audit и не публикуются API. Это локальный file-backed registry, а не замена
внешнему secret provider.

При non-loopback-доступе все пути `/api/` требуют заголовок `Authorization: Bearer <токен>`;
неверный или отсутствующий токен получает `401` и `WWW-Authenticate`. Статика
панели остаётся доступной для загрузки, а loopback-ограничение сохраняется.
Получение полного наблюдения, reparse и экспорт наблюдений дополнительно требуют
scope `raw`; любой экспорт конфигурации требует `export`. Недостающий scope
получает `403`. Поле `expires_at` необязательно, задаётся в RFC3339; просроченный
токен отклоняется при запуске или получает `401` после истечения срока.
Токен с `revoked: true` остаётся в реестре для аудируемой истории, но сразу
отклоняется с `401`; это позволяет отзывать credential без удаления его записи.
Registry только с отозванными токенами отклоняется при запуске, чтобы оператор
не получил панель, к которой невозможно подключиться.
После восьми неудачных попыток с одного адреса новые запросы на минуту получают
`429`; лимит ограничен и не блокирует другие адреса. Эти проверки не применяются
к loopback-панели.

Bearer-токен не заменяет RBAC и не делает безопасным публичное раскрытие порта.

### Источник файловых секретов

Внутренний интерфейс `secrets.Provider` централизует чтение файловых секретов;
по умолчанию используется `FileProvider`, который принимает локальный путь к
обычному файлу размером не более 1 МиБ. Сейчас через него читаются bootstrap-
файл токенов панели, ключ зашифрованного recorder-spool, ключ/сертификат CA и
сертификат/ключ HTTPS панели. Существующие CLI-пути остались совместимы.
Секретные байты не попадают в runtime status или экспорт профилей. URL userinfo
(имя пользователя и пароль) удаляется целиком при экспорте конфигурации.

HTTPS-панель заново загружает согласованную пару сертификат/ключ при каждом
новом TLS handshake: заменённая пара применяется к следующим подключениям;
между заменой файлов пара должна оставаться согласованной. Срок действия MITM
CA и HTTPS-сертификата панели отображаются в `/api/state` и настройках панели со статусом `VALID`,
`EXPIRING` (порог 30 дней), `EXPIRED`, `NOT_YET_VALID` или `UNAVAILABLE`.
Для статуса HTTPS-сертификата считывается только публичный файл сертификата.
Для MITM CA также можно указать один путь в `--ca-cert` и `--ca-key`:
при первоначальной генерации создаётся единый PEM-файл с сертификатом и ключом,
а загрузка читает его как одну пару. Для смены подготовьте новый согласованный
PEM отдельно и атомарно замените файл по тому же пути. Затем можно перезапустить
приложение или применить его к работающему прокси через
`POST /api/v1/admin/ca/reload` (например,
`curl -X POST http://127.0.0.1:9090/api/v1/admin/ca/reload`). При ошибке чтения
или проверки прежний CA остаётся активным. На non-loopback панели нужен Bearer-
токен с ролью `admin`; локальная панель по-прежнему работает без обязательной
авторизации, но журнал аудита должен быть доступен. Новые соединения используют
новый CA, существующие не меняются. Клиенты должны заранее доверять публичному
сертификату нового CA. Никогда не импортируйте и не распространяйте общий
PEM-файл как доверенный сертификат: он содержит закрытый ключ; для клиентов
выделяйте только блок `CERTIFICATE` в отдельный файл.
То же действие доступно в разделе «Настройки» кнопкой «Применить CA из файла»;
панель показывает результат и актуальный срок действия CA.
Автоматического продления пока нет. CA для MITM, ключ spool и proxy/upstream
credentials пока не имеют автоматической ротации; ключ spool можно
безопасно сменить после опустошения очереди по процедуре выше. Внешние
Secret Manager/KMS-провайдеры не
подключены; интерфейс Provider позволяет добавить их без встраивания значений
секретов в профили и backup.

Для исходящего upstream-прокси логин или пароль можно указать ссылкой на файл
через `file:` в URL userinfo. Например, на Linux:

```text
socks5://file%3A%2Fetc%2Fja3proxy%2Fupstream-user:file%3A%2Fetc%2Fja3proxy%2Fupstream-pass@127.0.0.1:1080
```

В URL двоеточия и слеши в ссылках должны быть percent-encoded. Обычные значения
логина и пароля в URL по-прежнему поддерживаются. Ссылки разрешаются через
`SecretProvider` при создании/обновлении upstream dialer; изменение файлового
секрета (содержимое файлов используется как есть, без удаления завершающего
перевода строки) применяется после повторной конфигурации upstream; активные
соединения не прерываются.

Для проверки учётных данных входящих клиентов можно вместо литеральных
`--proxy-username`/`--proxy-password` задать парные параметры
`--proxy-username-file` и `--proxy-password-file`. Файлы читаются через
`SecretProvider` при запуске proxy, должны содержать непустые значения и
удовлетворять ограничениям HTTP Basic/SOCKS5. Содержимое используется как есть:
завершающий перевод строки станет частью логина или пароля.
При изменении файлов перезапустите процесс; активные соединения продолжают
работать до завершения.

Для изменяющих API-операций audit работает в fail-closed режиме: сначала
фиксируется событие запроса, и только после успешной записи запускается mutation.
Если журнал недоступен, операция получает `503` и обработчик конфигурации не
вызывается.

События append-only журнала связаны SHA-256 integrity chain (`prev_hash` и
`hash`) и хранятся в общей SQLite-базе. Путь задаётся через `--state-sqlite`;
`--audit-sqlite` может указать тот же файл. `--audit-log` служит только для
однократного атомарного импорта прежнего JSONL-журнала, если таблица аудита пуста.
После импорта SQLite становится источником истины. При открытии цепочка
проверяется, поддерживается cursor pagination после перезапуска.

Не публикуйте порт панели в общедоступную сеть. Для удалённого исследования
используйте контролируемый туннель с отдельной аутентификацией и ограничением
доступа на уровне операционной системы.

Runtime API `PUT /api/config` принимает обязательный `expected_version`. Его
текущее значение возвращается через `GET /api/state` в
`runtime.configVersion`; после успешного изменения версия увеличивается.
Устаревший запрос получает `409` и не применяется.

## Сравнение и проверка профиля

- `MATCH` — нормализованные структуры совпадают;
- `MISMATCH` — обнаружены add/remove/replace/move;
- `UNKNOWN` — захват неполный или версии нормализации несовместимы.

Обычный diff сравнивает два наблюдения. Для исходящего наблюдения, созданного
активным редактируемым профилем, дополнительно записывается `verification`:

- `MATCH` — все MUST и SHOULD поля совпали;
- `PARTIAL_MATCH` — MUST совпали, но различается хотя бы одно SHOULD поле;
- `MISMATCH` — различается MUST поле;
- `UNKNOWN` — сравнение невозможно из-за неполного захвата или несовместимых
  версий нормализации/материализатора.

Ожидаемая структура вычисляется из эффективного шаблона непосредственно перед
исходящим handshake. Фактическая структура строится независимым захватом байтов
`PROXY_OUT`; поэтому проверка не подменяется сравнением объекта конфигурации с
самим собой.

Для PASSTHROUGH и OBSERVE_ONLY поле `forwarding.status` имеет отдельные значения:
`FORWARDED_UNCHANGED`, `MISMATCH` или `UNVERIFIED`. Сравниваются SHA-256 полного
ClientHello и захваченных TLS records на `CLIENT_IN` и успешных записях
`PROXY_OUT`; неполный захват никогда не объявляется совпадением. Каждая запись
также содержит нормативный `byte_source`.

Destination evidence разделена на `destination_host` (заявленный host из
CONNECT/SOCKS), `sni` (имя из ClientHello) и `destination_ip` (resolved IP,
только когда proxy может доказать его напрямую). Адрес upstream proxy никогда
не записывается как IP назначения. При ошибке отдельно сохраняются
`error_stage` (`capture`, `parse`, `fingerprint` или `forwarding`) и
`error_code`, поэтому одинаковые коды можно фильтровать по месту возникновения.

## Редактор TLS-профилей и JA4

Откройте `http://127.0.0.1:9090/profiles.html`. Шаблон можно создать из
скомпилированного uTLS-пресета или кнопкой «В профиль» у полного наблюдения.
Редактируются cipher suites, порядок extensions, ALPN/ALPS, их policy,
padding length, supported versions, supported groups и signature algorithms. JA3/JA4 нельзя
править как готовую строку — они пересчитываются из materialized ClientHello.

Длина TLS padding сохраняется в `fields.padding_length`. При replay она
фиксируется в профиле, чтобы случайные session ID/key share не меняли
presence/length padding между preview и фактическими wire-байтами.

ALPS всегда согласуется с эффективным ALPN: если протокол удалён из ALPN,
соответствующая запись ALPS также удаляется до handshake. Несовместимый
`CUSTOM`-вариант отклоняется на этапе validation.

Профиль хранит версию, ожидаемый fingerprint, политику MUST/SHOULD,
`ignored_dynamic`, versioned constraints (`present`, `equals`, `one_of`) и явный
статус воспроизводимости. `UNSUPPORTED` нельзя активировать. Библиотека и
история версий хранятся в общей SQLite-базе с compare-and-swap по
`config_version`; `--tls-template-file` (по умолчанию
`profiles/tls-templates.jsonl`) служит только для разового импорта старых данных.

При создании из наблюдения сохраняется source fingerprint. Его MUST-поля
сравниваются с materialized ClientHello до публикации; скрытая подмена
неподдерживаемого extension payload содержимым базового пресета переводит
шаблон в `UNSUPPORTED`. История опубликованных версий доступна через API и
интерфейс. Откат не переписывает историю, а создаёт новую версию с
`based_on_version`.

Одновременно выбирается один активный шаблон. Пустой список host patterns
означает все хосты; поддерживаются точные имена и `*.example.com` без совпадения
с apex-доменом. Для безопасности протокола ALPN шаблона фильтруется по ALPN
входящего клиента с сохранением порядка шаблона; отсутствие пересечения явно
прерывает TLS handshake.

Профили имеют тип `PRESET`, `OBSERVED`, `CUSTOM` или `RANDOMIZED`. Для
`RANDOMIZED` доступны варианты ALPN `AUTO`, `REQUIRED` и `DISABLED`, которые
соответствуют генераторам uTLS `HelloRandomized*`. Такой профиль не заявляет
статический expected fingerprint: JA3/JA4/TLS-NORM вычисляются по фактическому
исходящему ClientHello в точке `PROXY_OUT`; тип профиля отдельно записывается
в metadata наблюдения (`profile_type`). В текущей версии uTLS случайный
гибридный ML-KEM key-share исключён, поскольку библиотека не может применить
его как первый локальный key exchange; остальные поддерживаемые случайные
поля сохраняются.

## Replay Lab

Страница `/replay-lab.html` запускает изолированный handshake к заданному
тестовому TLS endpoint с сохранённым профилем, uTLS-пресетом или RANDOMIZED.
Можно выбрать исходное наблюдение, чтобы получить `captured_vs_actual`; для
детерминированного профиля также рассчитывается `compiled_vs_actual`. В
результате показываются фактические outbound JA3/JA4/TLS-NORM, ServerHello,
JA3S/JA4S и согласованные параметры TLS. HTTP-запрос приложению не отправляется;
проверка сертификата endpoint отключена. API — `POST /api/v1/replay-lab/run`.
Для deterministic-профиля результат отдельно показывает несовпавшие JSON Pointer
пути MUST и SHOULD, нарушения constraints и полный список normalized changes;
общий diff не скрывает, какое правило профиля не выполнено.
Лабораторный запуск не меняет активные профили или production-маршрутизацию.
Вкладка Compatibility Matrix последовательно прогоняет выбранные сохранённые
профили на том же endpoint; для каждой строки показывает negotiated TLS/ALPN,
outbound JA4 и статусы diff. Это отдельные подключения, production routing и
производственные соединения не задействуются. В режиме лабораторного Roller
профили испытываются в порядке выбора и перебор останавливается после первого
полного успешного TLS handshake; все испытанные строки сохраняют фактический
ClientHello и diff. Режим не меняет выбранные/активные профили и не применяется
в proxy routing.

Каждый сохранённый профиль хранит `created_with_utls`,
`last_validated_with_utls`, `last_validated_at` и `compatibility_status`.
Список профилей сравнивает baseline профиля с текущим runtime uTLS. При смене
движка статус становится `PROFILE_REVALIDATION_REQUIRED`; такой профиль нельзя
активировать или применить в туннеле до успешного локального Replay Lab. Кнопка
«Проверить» открывает лабораторию с выбранным профилем. Успешный handshake и
совпадение MUST-полей фиксируются как `VALID`, отличие только SHOULD-полей — как
`VALID_WITH_DIFFERENCES`, а несовпадение MUST-полей/ошибка handshake — как
`INCOMPATIBLE`. При изменении профиля проверка сбрасывается. Проверка после смены
uTLS относится к выбранному endpoint; это не заменяет CI-регрессию на полном
наборе golden ClientHello.

## Текущие ограничения

- для passthrough/observe wrapper фиксирует дополнительные complete ClientHello
  в той же последовательности с `handshake_sequence`; зашифрованные application
  records не принимаются за ClientHello;
- в `MITM_REISSUE` второй ClientHello после HelloRetryRequest не доступен через
  стандартный callback TLS-сервера и остаётся ограничением текущего пути;
- encrypted spool включается вместе с `--capture-tls` (SQLite используется по умолчанию) и сохраняет
  записи лишь на время восстановления SQLite;
- Device Manager поддерживает постоянные mappings по username/IP и CAS-защиту
  изменений; временные application assignments теперь поддерживают период
  `valid_from/valid_to`, а application catalog поддерживает CRUD и ссылочную
  связь assignment через `application_id`; автоматические правила по
  приложениям относятся к следующим этапам ТЗ;
- без `storage=sqlite` HTTP export выгружает текущее окно, а не содержимое JSONL;
- SQLite persistence поддерживает bounded SQL-поиск и потоковый JSONL/CSV экспорт;
  полный reparse всей базы выполняется bounded-страницами через
  `POST /api/v1/reparse/sqlite` с повтором по `next_cursor`;
- file-backed registry поддерживает роли, expiry и отзыв через `revoked: true`;
  полноценные users CRUD, runtime-ротация и recovery последнего Admin ещё не
  реализованы;
  append-only audit-журнал действий панели уже реализован. Двухфазный route manager уже
  использует immutable runtime snapshot всех фаз. Upstream TLS store также
  выдаёт immutable `upstream_config_version` для каждого нового MITM-соединения.
  Observation сохраняет `evaluated_config_version`, список кандидатов,
  `matched_route_id`, `matched_route_priority` и `route_match_reason`. Маршруты
  поддерживают необязательное поле `priority`:
  сначала выбирается большая
  priority, затем точный host pattern выигрывает у wildcard, а при полном
равенстве сохраняется порядок в JSON. TLS profile library также поддерживает
несколько активных шаблонов с детерминированным host-priority.

Route evidence также содержит безопасные `action_mode` и `match_policy`. Для
`OBSERVE_ONLY` режим фиксируется как исследовательский и не может быть повышен
POST_CLIENTHELLO-правилом до `MITM_REISSUE`; профиль и активная проверка TLS не
применяются.

Для правил, которым нужен POST_CLIENTHELLO-анализ, можно задать
`capture_failure_policy`:

- `continue_passthrough` — продолжить поток в исходном режиме (значение по
  умолчанию);
- `continue_without_recording` — продолжить как `PASSTHROUGH`, сохранив только
  событие неудачного захвата без запуска следующей записи потока;
- `block` — закрыть туннель до upstream-handshake.

Неудача захвата (тайм-аут, неполный или malformed ClientHello) сохраняет
`completeness`, `error_stage` и `error_code`, если доступна очередь/spool.

Нормативные детали и матрица требований находятся в
[spec/RECORDER_IMPLEMENTATION.md](spec/RECORDER_IMPLEMENTATION.md).
