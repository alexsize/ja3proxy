# Регистратор TLS

TLS Recorder записывает фактический первый ClientHello на двух границах:

```text
клиент → CLIENT_IN → JA3Proxy → PROXY_OUT → сервер
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

## Что вычисляется

- строка и MD5 JA3;
- составной JA4 для TLS поверх TCP;
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

Очередь неблокирующая: при переполнении прокси продолжает обслуживать трафик, а
счётчик `dropped` увеличивается. При ошибке или исчерпании квоты JSONL дальнейшая
запись в файл прекращается, но прокси и окно памяти продолжают работать.

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

SQLite включается явно и работает параллельно с окном памяти и, при необходимости,
JSONL. При старте выполняется versioned migration; после перезапуска последние
наблюдения восстанавливаются в bounded memory window. В таблице `observations`
хранится полный JSON payload и индексируемые поля времени, connection ID и
capture point. Retention удаляет самые старые записи после каждой вставки; по
умолчанию — 100 000 наблюдений, лимит можно изменить через
`--capture-sqlite-retention`. Если `--capture-raw` не указан, SQLite также не
содержит `raw_client_hello` и `raw_records`. Ошибка SQLite не останавливает
прокси, увеличивает `write_errors` и отражается в `recording_degraded`.

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
| `GET /api/v1/observations` | поиск и постраничный список |
| `GET /api/v1/observations/{id}` | полное наблюдение |
| `GET /api/v1/fingerprints/diff?a=&b=` | структурное сравнение |
| `GET /api/v1/export/observations` | экспорт текущего окна в JSONL |
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
| `GET /api/v1/export/observations?format=jsonl|csv` | фильтруемый экспорт |
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

- `q` — поиск по хосту, адресу клиента, connection ID, JA3 или JA4;
- `limit` — от 1 до 100;
- `cursor` — ID последнего элемента предыдущей страницы.

Для мультиактивации передайте `ids` в порядке приоритета. Точное совпадение
host pattern имеет приоритет над wildcard; при одинаковой специфичности раньше
стоящий ID выигрывает. Старый параметр `id` по-прежнему выбирает один профиль.

Если курсор уже вытеснен из ограниченного окна, API возвращает `409`, и клиент
должен обновить список с начала.

Полный контракт: [spec/recorder-openapi.json](spec/recorder-openapi.json).

## Защита панели

При активном recorder веб-панель запускается только на loopback. Каждый запрос
проверяется по адресу TCP-клиента, `Host` и `Origin`. Это снижает риск DNS
rebinding, но не заменяет будущие аутентификацию и RBAC.

Не публикуйте порт панели в общедоступную сеть. Для удалённого исследования
используйте контролируемый туннель с отдельной аутентификацией и ограничением
доступа на уровне операционной системы.

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

## Редактор TLS-профилей и JA4

Откройте `http://127.0.0.1:9090/profiles.html`. Шаблон можно создать из
скомпилированного uTLS-пресета или кнопкой «В профиль» у полного наблюдения.
Редактируются cipher suites, порядок extensions, ALPN/ALPS, их policy,
supported versions, supported groups и signature algorithms. JA3/JA4 нельзя
править как готовую строку — они пересчитываются из materialized ClientHello.

ALPS всегда согласуется с эффективным ALPN: если протокол удалён из ALPN,
соответствующая запись ALPS также удаляется до handshake. Несовместимый
`CUSTOM`-вариант отклоняется на этапе validation.

Профиль хранит версию, ожидаемый fingerprint, политику MUST/SHOULD,
`ignored_dynamic`, versioned constraints (`present`, `equals`, `one_of`) и явный
статус воспроизводимости. `UNSUPPORTED` нельзя активировать. Библиотека —
append-only JSONL с compare-and-swap по `config_version`; путь задаёт
`--tls-template-file`, по умолчанию `profiles/tls-templates.jsonl`.

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

## Текущие ограничения

- анализируется первый ClientHello;
- второй ClientHello после HelloRetryRequest не сопоставляется;
- без `--capture-sqlite` хранилище в памяти не является durable spool;
- Device Manager поддерживает постоянные mappings по username/IP и CAS-защиту
- Device Manager поддерживает постоянные mappings по username/IP и CAS-защиту
  изменений; временные application assignments теперь поддерживают период
  `valid_from/valid_to`, а application catalog поддерживает CRUD и ссылочную
  связь assignment через `application_id`; автоматические правила по
  приложениям относятся к следующим этапам ТЗ;
- HTTP export выгружает текущее окно, а не содержимое JSONL;
- SQLite persistence уже есть, но полноценного SQL-поиска/экспорта по всей базе,
  пользователей, ролей и общего audit-журнала конфигурации ещё нет;
- общий двухфазный route manager и полный runtime snapshot всех route-фаз
  относятся к следующим этапам. Upstream TLS store уже выдаёт immutable
  `upstream_config_version` для каждого нового MITM-соединения. Маршруты также
  поддерживают необязательное поле `priority`: сначала выбирается большая
  priority, затем точный host pattern выигрывает у wildcard, а при полном
  равенстве сохраняется порядок в JSON. TLS profile library также поддерживает
  несколько активных шаблонов с детерминированным host-priority.

Нормативные детали и матрица требований находятся в
[spec/RECORDER_IMPLEMENTATION.md](spec/RECORDER_IMPLEMENTATION.md).
