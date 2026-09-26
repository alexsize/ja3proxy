# Техническое задание
## Регистратор TLS-отпечатков и центр управления JA3Proxy

> Версия: 2.0-draft
> Статус: нормативная спецификация реализации
> Базовый репозиторий: `alexsize/ja3proxy` (fork `LyleMi/ja3proxy`)
> Область применения: лабораторные и иные авторизованные среды анализа трафика

### Как читать документ

Ключевые слова **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** и **MAY** имеют нормативный смысл:

- **MUST / MUST NOT** — обязательное условие приёмки указанного релиза;
- **SHOULD / SHOULD NOT** — требование выполняется по умолчанию, отклонение документируется;
- **MAY** — необязательная возможность.

При конфликте требований действует следующий приоритет:

1. раздел 108 «Критические требования»;
2. критерии приёмки конкретного релиза;
3. протокольные контракты и требования безопасности;
4. прочие функциональные требования;
5. примеры UI и рекомендуемая структура кода.

Схемы экранов, имена Go-пакетов и перечисления библиотек являются рекомендуемыми, если явно не помечены как **MUST**. Все сетевые данные, имена хостов, заголовки и импортируемые файлы считаются недоверенными входными данными.

### 1. Назначение проекта

Создать fork `LyleMi/ja3proxy`, превращающий JA3Proxy из простого TLS/uTLS proxy в централизованную систему:

```text
сбор → разбор → хранение → агрегация → сравнение
       ↓
профилирование → применение профиля → проверка результата
```

Система должна позволять для каждого нашего устройства/приложения видеть:

```text
что отправил клиент
        ↓
INBOUND fingerprint

что сделал proxy
        ↓
применённый профиль

что реально отправлено proxy наружу
        ↓
OUTBOUND fingerprint

что ответил сервер
        ↓
SERVER fingerprint
```

Ключевое требование:

**Не вычислять исходящий fingerprint только по выбранному пресету. Нужно фиксировать реальный ClientHello, который фактически ушёл в сеть.**

### 1.1. Границы проекта

Система предназначена для трафика устройств и приложений, анализ которого явно разрешён владельцем среды. Она не должна позиционироваться как средство скрытого перехвата чужого трафика.

В базовый TLS Recorder не входят:

- расшифровка TLS/QUIC без контролируемой MITM-среды или предоставленных session secrets;
- гарантированное byte-for-byte воспроизведение произвольного captured ClientHello;
- определение приложения только по fingerprint без внешней разметки;
- обещание того, что fingerprint, наблюдаемый на proxy, совпадает с fingerprint на удалённом сервере при наличии NAT/VPN/upstream proxy.

### 1.2. Термины

```text
Connection
  один принятый proxy transport flow с единым connection_id

Observation
  измерение в определённой точке и направлении; не является профилем

Fingerprint Variant
  уникальная нормализованная структура согласно версии алгоритма

Fingerprint Family
  группа вариантов, созданная версионированным алгоритмом агрегации

Profile Template
  воспроизводимая статическая структура + policy динамических полей

Capture Point
  точное место наблюдения байтов: CLIENT_IN, PROXY_OUT или SERVER_IN
```

`session` в UI является представлением `Connection`; отдельную сущность session вводить нельзя без явной модели связи.

---

## 2. Основная архитектура

```text
                             ┌──────────────────────┐
                             │      WEB PANEL       │
                             │                      │
                             │ Devices              │
                             │ Sessions             │
                             │ Fingerprints         │
                             │ Profiles             │
                             │ Diff                 │
                             │ Routes               │
                             │ Upstreams            │
                             │ TCP / DNS / QUIC     │
                             └──────────┬───────────┘
                                        │
                                  REST / WS API
                                        │
                         ┌──────────────▼─────────────┐
                         │       CONTROL PLANE       │
                         │                           │
                         │ Config Manager            │
                         │ Profile Manager           │
                         │ Route Manager             │
                         │ Recorder Manager          │
                         │ Device Manager            │
                         │ Export / Import           │
                         └──────────────┬─────────────┘
                                        │
             ┌──────────────────────────▼────────────────────────┐
             │                  JA3PROXY CORE                    │
             │                                                   │
Client ─────►│ Listener                                          │
             │    │                                              │
             │    ├── HTTP                                       │
             │    ├── HTTPS CONNECT                              │
             │    └── SOCKS5                                     │
             │                                                   │
             │    ↓                                              │
             │ Inbound TLS Capture                               │
             │    ↓                                              │
             │ MITM / Passthrough / Observe                      │
             │    ↓                                              │
             │ HTTP/H2 Analyzer                                  │
             │    ↓                                              │
             │ Routing Engine                                    │
             │    ↓                                              │
             │ uTLS                                              │
             │    ↓                                              │
             │ Outbound TLS Capture                              │
             │    ↓                                              │
             │ Upstream proxy / Direct                           │
             └──────────────────┬────────────────────────────────┘
                                │
                             Internet

                ┌───────────────┴────────────────┐
                │                                │
        SQLite                            Packet Sensor
                                             │
                                      TCP / DNS / QUIC
```

---

## 3. Базовый принцип работы

Для каждого нового соединения должна создаваться единая сущность:

```text
connection_id
```

Все события далее привязываются к ней:

```text
connection
 ├── client/device
 ├── TCP fingerprint
 ├── inbound ClientHello
 ├── inbound JA3
 ├── inbound JA4
 ├── HTTP fingerprint
 ├── route
 ├── selected TLS profile
 ├── upstream proxy
 ├── outbound ClientHello
 ├── outbound JA3
 ├── outbound JA4
 ├── ServerHello
 ├── JA3S / JA4S
 ├── errors
 └── timing
```

Идентификаторы рекомендуется генерировать как ULID, чтобы они были сортируемыми по времени.

### 3.1. Жизненный цикл соединения

Connection MUST иметь монотонный переход состояний:

```text
ACCEPTED
  → AUTHENTICATED | AUTH_FAILED
  → ROUTED_PRE_TLS
  → CLIENTHELLO_PENDING
  → CLIENTHELLO_CAPTURED | NOT_TLS | CAPTURE_INCOMPLETE
  → ROUTED_POST_TLS
  → MITM_HANDSHAKE | PASSTHROUGH | OBSERVE_ONLY | BLOCKED
  → UPSTREAM_CONNECTING
  → ACTIVE
  → CLOSED | FAILED
```

Реализация MAY пропускать неприменимые состояния, но MUST сохранять:

```text
terminal_status
error_code
error_stage
error_detail_safe
config_version
route_version
profile_version
```

`error_detail_safe` не должен содержать secrets или payload. Перечни status/error code являются версионированной частью API, а не произвольными строками логов.

### 3.2. Временная модель

Все persisted timestamps MUST храниться в UTC с точностью не хуже миллисекунды. Длительности MUST измеряться монотонными часами процесса. Для каждого события сохраняются `occurred_at` и, если запись была отложена, `persisted_at`.

### 3.3. Точки перехвата

```text
CLIENT_IN
  bytes после proxy protocol/authentication, до tls.Server и HTTP parser

PROXY_OUT
  bytes, записанные uTLS в уже созданный direct/CONNECT/SOCKS tunnel

SERVER_IN
  bytes ответа сервера до TLS parser proxy
```

Recorder MUST находиться внутри upstream tunnel. HTTP CONNECT/SOCKS negotiation не должна попадать в `PROXY_OUT` ClientHello.

Для каждой observation MUST сохраняться `capture_point`, `direction`, `byte_source` и `completeness`. Значение `completeness` принимает `complete`, `truncated`, `malformed`, `timeout` или `not_applicable`.

---

## 4. Режимы обработки соединения

Каждому route/domain должен назначаться режим.

### 4.1 MITM_REISSUE

```text
Client
   ↓ TLS A
JA3Proxy
   ↓ TLS B / uTLS
Server
```

Позволяет:
- анализировать ClientHello клиента;
- расшифровывать HTTP;
- анализировать HTTP/1.1;
- анализировать HTTP/2;
- формировать новый ClientHello;
- изменять outbound fingerprint.

### 4.2 PASSTHROUGH

```text
Client
   ↓
JA3Proxy TCP tunnel
   ↓
Server
```

Proxy ничего не расшифровывает.

При этом обязательно собирать:

```text
ClientHello
JA3
JA4
SNI
ALPN
TLS metadata
```

Исходящий TLS fingerprint при этом является fingerprint самого клиента.

В PASSTHROUGH proxy не формирует второй ClientHello. `CLIENT_IN` и `PROXY_OUT` являются двумя точками наблюдения одного потока. Реализация MUST либо:

- хранить одну TLS observation с обеими capture points и результатом byte-equivalence check; либо
- хранить две связанные observation с одинаковым `stream_id`.

UI MUST показывать `forwarded unchanged`, а не `profile applied`. Если из-за truncation или capture error равенство байтов не доказано, статус должен быть `UNVERIFIED`, а не `MATCH`.

Этот режим особенно нужен для приложений с certificate pinning.

### 4.3 OBSERVE_ONLY

Практически passthrough, но маршрут явно маркируется как исследовательский:

```text
изменять соединение запрещено
собирать metadata разрешено
```

OBSERVE_ONLY отличается от PASSTHROUGH политикой: никакая автоматическая смена режима, profile application или активная проверка не допускается. Различие MUST сохраняться в route decision и audit log.

### 4.4 BLOCK

Немедленное завершение соединения.

Для BLOCK route MUST быть задано, когда именно выполняется блокировка: `PRE_TLS` или `POST_CLIENTHELLO`. Вторая форма допускает чтение только ограниченного ClientHello и не должна устанавливать upstream connection.

Использовать в основном для тестирования routing rules.

---

## 5. Идентификация устройства

Нельзя полагаться только на IP.

Ввести сущность:

```text
Device
```

Поля:

```text
id
name
description
proxy_username
source_ips[]
tags[]
platform
app_name
app_version
os_name
os_version
hardware
created_at
last_seen_at
enabled
```

Например:

```text
Name: iphone-017
Platform: iOS
OS: 16.7.11
Application: TestApp
Proxy user: iphone017
Tags:
  ios
  lab
  iphone
```

Основной идентификатор клиента:

```text
proxy authentication username
```

Если авторизации нет, fallback:

```text
source IP
```

Дополнительно MAC можно определять packet sensor'ом, если устройство находится в той же L2-сети.

Каждая идентификация MUST сохранять:

```text
identity_source       # proxy_username | api_mapping | source_ip | packet_sensor
identity_value
confidence            # exact | inferred | ambiguous
resolved_device_id nullable
```

При proxy authentication username имеет приоритет над IP mapping. Один source IP не должен автоматически объединять несколько usernames в Device. При неоднозначности observation остаётся без `device_id`, но сохраняет identity evidence. Device metadata и application version являются временными назначениями с `valid_from`/`valid_to`, а не вечными свойствами соединения.

---

## 6. Регистратор TLS ClientHello

Это основной модуль проекта.

Он должен анализировать **исходный ClientHello до TLS MITM**.

Поддержать:

```text
TLS 1.0
TLS 1.1
TLS 1.2
TLS 1.3
```

Основная работа — TLS 1.2/1.3.

Необходимо корректно поддерживать ClientHello, разбитый:
- на несколько TCP segments;
- на несколько TLS records.

Нельзя предполагать:

```text
1 read() = 1 ClientHello
```

Нужен нормальный TLS handshake reassembler.

### 6.1. Контракт сборщика фрагментов

Reassembler MUST:

- читать 5-byte TLS record header через `io.ReadFull`-эквивалент;
- поддерживать ClientHello, разбитый на произвольное число TCP segments и TLS records;
- отделять record framing от handshake framing;
- прекращать накопление после первого полного ClientHello;
- сохранять все прочитанные байты для последующего replay в TLS stack или passthrough;
- иметь конфигурируемые timeout и жёсткий upper bound памяти;
- не паниковать на unknown versions, extension IDs, duplicate extensions и malformed lengths;
- возвращать структурированный результат `complete`, `not_tls`, `timeout`, `truncated` или `malformed`.

Значения по умолчанию для MVP:

```text
capture_timeout          5s
max_tls_record_size      18432 bytes
max_clienthello_size     256 KiB
max_records_per_hello    64
```

При превышении лимита proxy MUST применить route-specific `capture_failure_policy`:

```text
continue_passthrough
continue_without_recording
block
```

Значение по умолчанию — `continue_passthrough`. Событие capture failure сохраняется всегда, если доступна memory queue или spool.

### 6.2. Обнаружение TLS

Распознавание TLS по одному байту, только по destination port или по одному `read()` запрещено. Для SOCKS5 и нестандартных портов используется bounded sniffing buffer с replay прочитанных байтов. `not_tls` не является ошибкой соединения.

---

## 7. Что записывать из ClientHello

Сохранять **как decoded representation, так и raw ClientHello**.

### Основные данные

```text
record_version
client_version
client_random
session_id_length
cipher_suites
compression_methods
extensions
extensions_order
client_hello_length
tls_record_length
```

### SNI

```text
extension_id
hostname
hostname_length
```

### ALPN

Сохранять в исходном порядке:

```text
["h2", "http/1.1"]
```

### supported_versions

Сохранять значения и порядок.

### supported_groups

Сохранять numeric ID, имя и порядок.

### signature_algorithms

Полный ordered array.

### signature_algorithms_cert

Отдельно.

### key_share

Сохранять:

```text
group
key_length
position
```

Сам ключ по умолчанию в normalized fingerprint не включать.

### Форматы точек EC

Сохранить полный список.

### Режимы обмена ключами PSK

Сохранить.

### PSK

Сохранять:

```text
identity_count
identity_lengths
obfuscated_ticket_age
binder_count
binder_lengths
```

Сами PSK/ticket secrets по умолчанию не хранить.

### GREASE

Определять все GREASE-значения.

Для каждого:

```text
value
position
context
```

Например:

```text
cipher[0]
extension[2]
supported_group[0]
```

### Дополнение padding

Сохранять:

```text
presence
length
position
```

### Сессионный билет

```text
presence
length
```

### Запрос статуса

Сохранять наличие и параметры.

### SCT

Наличие.

### certificate_compression

Алгоритмы и порядок.

### delegated_credentials

Если присутствует.

### record_size_limit

Если присутствует.

### ALPS / application_settings

Сохранять extension ID и параметры.

### ECH

При наличии:

```text
ECH detected
outer ClientHello
extension id
length
```

Нужно явно указывать:

```text
Inner ClientHello unavailable
```

если он скрыт ECH и ключ отсутствует.

---

## 8. Исходный ClientHello

Для каждого handshake должна быть возможность сохранить:
- raw TLS records;
- raw ClientHello handshake bytes.

Форматы экспорта:

```text
binary
hex
base64
pcap reference
```

В интерфейсе:

```text
RAW
Decoded
JSON
HEX
```

---

## 9. JA3

Для каждого ClientHello рассчитывать:

```text
JA3 string
JA3 MD5
```

При этом хранить:

```text
algorithm = ja3
algorithm_version
implementation_version
```

JA3 implementation MUST соответствовать опубликованному алгоритму JA3 и иметь golden vectors. GREASE cipher suites, extensions и supported groups исключаются согласно версии алгоритма; порядок остальных значений сохраняется. Поле TLS version берётся из legacy ClientHello version согласно JA3, а не из `supported_versions`. Для malformed ClientHello JA3 не вычисляется, сохраняется `calculation_status` и `error_code`.

---

## 10. JA4

Дополнительно обязательно рассчитывать:

```text
JA4
```

JA3 одного недостаточно.

Хранить:

```text
ja4
ja4_a
ja4_b
ja4_c
algorithm_version
```

Если библиотека или спецификация алгоритма обновляется, старые fingerprint'ы не пересчитывать молча.

Хранить версию расчёта.

До начала реализации MUST быть зафиксированы:

- нормативная версия JA4;
- конкретная библиотека/commit или собственная реализация;
- лицензионная совместимость;
- набор официальных и собственных test vectors;
- поведение для QUIC, ECH, unknown extensions и incomplete capture.

В persisted record хранятся `algorithm_version`, `implementation_name`, `implementation_version` и `calculated_at`. Массовый пересчёт выполняется только отдельной миграцией/job и создаёт новую calculation record, не перезаписывая старую.

---

## 11. Собственный полный TLS fingerprint

Нужен внутренний fingerprint, более подробный, чем JA3/JA4.

Назвать, например:

```text
TLS-NORM-1
```

Он представляет canonical JSON.

Пример:

```json
{
  "tls": "1.3",
  "ciphers": [4865, 4866, 4867],
  "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43],
  "supported_groups": ["x25519", "secp256r1"],
  "alpn": ["h2", "http/1.1"],
  "signature_algorithms": [1027, 2052],
  "grease_positions": ["cipher:0", "extension:1"]
}
```

Вычислять:

```text
SHA-256(canonical JSON)
```

Результат:

```text
normalized_sha256
```

### 11.1. Нормативная канонизация TLS-NORM-1

`TLS-NORM-1` MUST быть отдельным versioned contract, а не сериализацией внутренней Go-структуры. Для версии 1:

- JSON кодируется UTF-8 без BOM;
- ключи объектов сортируются лексикографически по Unicode code points;
- пробелы вне строк отсутствуют;
- numeric protocol IDs кодируются десятичными integers;
- отсутствующее поле не эквивалентно `null` или пустому массиву;
- поля с множественным значением сохраняются как arrays;
- порядок ciphers, extensions, ALPN, groups, signature algorithms и key shares сохраняется;
- known names MAY храниться рядом для UI, но hash строится только по numeric IDs и нормативным scalar values;
- unknown IDs сохраняются числом и не удаляются;
- duplicate extensions сохраняются с позицией;
- concrete GREASE values заменяются token `GREASE`, а позиция и context сохраняются;
- dynamic byte strings заменяются типизированными descriptors, например `{ "kind": "key_share", "length": 32 }`.

Рекомендуемая сериализация — JSON Canonicalization Scheme (RFC 8785) поверх нормативной схемы TLS-NORM-1. Если применяется другая сериализация, она MUST иметь отдельное имя и byte-level golden vectors.

Hash input MUST включать идентификатор формата, чтобы разные версии не пересекались:

```text
SHA256("TLS-NORM-1\n" || canonical_json_bytes)
```

Изменение набора полей, правил normalization или сериализации требует нового имени (`TLS-NORM-2`), а не тихого изменения версии 1.

---

## 12. Динамические поля

Нельзя считать следующие значения стабильной частью fingerprint:

```text
Client Random
Session ID
Key Share public key
PSK binder bytes
session tickets
GREASE concrete numeric value
timestamps
```

Поэтому хранить сразу два значения:

```text
raw_sha256
normalized_sha256
```

`raw_sha256`:

```text
SHA256(original ClientHello bytes)
```

`normalized_sha256`:

```text
SHA256(ClientHello after dynamic-field normalization)
```

`raw_sha256` вычисляется строго по handshake bytes ClientHello, включая 4-byte handshake header, но без TLS record headers. Дополнительно MAY храниться `records_sha256` по исходным TLS records. Это различие MUST быть отражено в schema и UI.

Normalization MUST сохранять длины динамических значений, если длина является наблюдаемой характеристикой, и MUST удалять сами secret/session bytes из normalized representation.

---

## 13. Семейство fingerprints

Один ClientHello не должен автоматически считаться целым профилем устройства.

Современные TLS-клиенты могут менять порядок некоторых элементов между соединениями.

Поэтому должна существовать сущность:

```text
Fingerprint Family
```

В ней:

```text
observations: 14 528

JA4 variants:
  variant A      96.1%
  variant B       3.8%
  variant C       0.1%

JA3 variants:
  17 different variants

ALPN:
  h2,http/1.1    99.7%
  http/1.1        0.3%
```

Интерфейс должен отличать:

```text
Observation
Fingerprint Variant
Fingerprint Family
Profile Template
```

### 13.1. Версионирование семей

Автоматическое объединение в Family не входит в Core Recorder MVP. До его включения MUST быть утверждён `family_algorithm_version`, определяющий:

- признаки и их веса;
- обязательные и допустимо изменяющиеся поля;
- минимальное число observations;
- временное окно;
- порог similarity;
- правила merge/split;
- ручное закрепление и исключения;
- возможность воспроизвести решение по сохранённым данным.

До появления такого алгоритма Family создаётся только вручную или импортом. Изменение алгоритма создаёт новую family membership version и не переписывает историю.

---

## 14. Автоматическая агрегация

Для каждой новой записи по сочетанию:

```text
device
application
destination
normalized fingerprint
```

`destination` в ключе MUST быть нормализованной структурой `{host, port}`. Host приводится к lowercase, завершающая точка DNS удаляется, Unicode domain хранится одновременно как исходное значение и ASCII A-label. Агрегация по IP или registrable domain выполняется отдельным представлением и не меняет базовый ключ.

обновлять:

```text
first_seen
last_seen
count
```

---

## 15. Регистратор исходящего ClientHello

Это второе критически важное требование.

Когда JA3Proxy устанавливает TLS-соединение:

```text
JA3Proxy → destination
```

нельзя просто записать:

```text
selected_profile = Chrome@120
```

Нужно записать **реальный ClientHello, который uTLS записал в socket**.

Архитектура:

```text
uTLS
   ↓
RecordingConn
   ↓
TCP / upstream CONNECT
```

`RecordingConn.Write()` должен отслеживать первые TLS handshake records и восстанавливать ClientHello.

RecordingConn MUST:

- передавать в underlying connection ровно те же bytes и возвращать совместимые `(n, err)`;
- корректно обрабатывать partial writes и повторные `Write`;
- не задерживать handshake после достижения полного ClientHello;
- не считать profile или `utls.ClientHelloSpec` доказательством отправленных bytes;
- завершать observation только после подтверждённой записи всех ClientHello bytes underlying connection;
- иметь bounded buffer и не блокировать data plane записью в БД;
- сохранять capture error отдельно от network error.

Для acceptance test фактические bytes MUST независимо фиксироваться тестовым сервером или packet capture. Сравнение двух результатов одного и того же parser недостаточно из-за common-mode error.

В результате для одного соединения:

```text
INBOUND ClientHello
OUTBOUND ClientHello
```

---

## 16. Работа через следующий прокси

Поддержать:

```text
DIRECT
SOCKS5
HTTP CONNECT
```

Recorder должен располагаться:

```text
uTLS
 ↓
Recorder
 ↓
CONNECT tunnel
 ↓
upstream proxy
```

а не перед upstream proxy protocol.

Иначе он будет захватывать HTTP CONNECT вместо TLS.

Порядок wrappers является нормативным:

```text
uTLS → RecordingConn(PROXY_OUT) → established tunnel conn → upstream transport
```

Для DIRECT `established tunnel conn` является обычным TCP connection. Для HTTP CONNECT и SOCKS5 это уже согласованный tunnel после успешного ответа upstream.

---

## 17. Проверка исходящего соединения

После создания соединения система должна автоматически сравнить:

```text
EXPECTED PROFILE
vs
ACTUAL OUTBOUND CLIENTHELLO
```

Статусы:

```text
MATCH
PARTIAL_MATCH
MISMATCH
UNKNOWN
```

Статусы вычисляются детерминированно:

```text
MATCH
  expected и actual представлены одной версией schema;
  все MUST-match поля равны;
  различаются только поля, объявленные dynamic policy

PARTIAL_MATCH
  все structural MUST-match поля равны;
  отличается хотя бы одно SHOULD-match поле

MISMATCH
  отличается MUST-match поле либо actual нарушает template constraints

UNKNOWN
  capture неполный, schema несовместима или expected profile не материализован
```

Profile Template MUST перечислять `must_match`, `should_match`, `ignored_dynamic` и допустимые constraints. Verification record хранит версии profile, normalization и diff algorithm.

Отображать:
- Expected profile;
- Actual JA3;
- Expected JA3;
- Actual JA4;
- конкретные отличия.

Например:

```text
cipher order differs
extension 17513 missing
ALPN differs
supported_groups differs
GREASE position differs
```

---

## 18. Механизм сравнения

Нужен универсальный просмотр:

```text
Fingerprint A ↔ Fingerprint B
```

Например:

```text
Inbound ↔ Outbound
iPhone A ↔ iPhone B
App version 470 ↔ 471
Native ↔ uTLS
Chrome 133 ↔ Chrome 131
```

Интерфейс должен показывать:
- added;
- removed;
- changed;
- moved.

Diff result MUST быть машинно-читаемым и адресовать поля JSON Pointer-подобным path. Для ordered arrays различаются операции `add`, `remove`, `replace` и `move`; UI-текст является представлением структурированного результата. Diff engine MUST принимать только явно указанную schema version либо выполнять документированное преобразование.

---

## 19. Регистратор ServerHello

Желательно фиксировать также ответ сервера.

Сохранять:

```text
TLS version
selected cipher
selected ALPN
selected group
extensions
session reuse
HelloRetryRequest
```

Рассчитывать:

```text
JA3S
```

и при наличии реализации:

```text
JA4S
```

Для TLS 1.3 выбранный ALPN находится в `EncryptedExtensions`, а не в ServerHello. Поэтому каждое server-side поле MUST иметь:

```text
value
source          # wire_server_hello | decrypted_encrypted_extensions | negotiated_state
available       # true | false
reason          # encrypted_without_keys, truncated, not_present, ...
```

В PASSTHROUGH без session secrets ALPN и часть параметров могут быть недоступны. UI не должен отображать отсутствие наблюдения как отсутствие extension. HelloRetryRequest сохраняется как отдельное handshake event, связанное с последующим ServerHello.

TLS 1.3 server-side observation также MUST содержать
`server_hello.fields.encrypted_extensions` в общем формате поля. Если для
соединения не предоставлены разрешённые session secrets, поле имеет
`available=false`, `reason=encrypted_without_keys`; это означает, что содержимое
зашифровано и неизвестно, а не что расширений нет. Для TLS-версий, где
EncryptedExtensions неприменим, причина — `not_applicable`. Источник текущей
недоступности — `wire_server_hello`; после разрешённого расшифрования должен
указываться `decrypted_encrypted_extensions`. В реализации proxy такое
расшифрование разрешается только при явном `--tls-keylog-file` в режимах
`PASSTHROUGH`/`OBSERVE_ONLY`; без файла пассивный capture не является основанием
утверждать, что handshake расшифрован. Key-log и plaintext не сохраняются.

---

## 20. Fingerprint HTTP/1.1

Если TLS успешно перехвачен, записывать HTTP-level fingerprint.

Критически важно сохранять:

```text
header order
header capitalization
```

Для сохранения порядка и capitalization HTTP/1 analyzer MUST работать по raw bytes до `net/http` normalization. После извлечения metadata те же bytes передаются штатному HTTP parser без изменений. Header values обрабатываются privacy policy до помещения в event queue.

Хранить:

```text
method
request_target
http_version
header_order
original_header_names
header values according to privacy policy
content_length
transfer_encoding
```

---

## 21. HTTP/2 fingerprint

Необходимо отдельно анализировать HTTP/2.

Сохранять:

### Префикс соединения

Наличие и корректность.

### SETTINGS

Все параметры и их порядок:

```text
HEADER_TABLE_SIZE
ENABLE_PUSH
MAX_CONCURRENT_STREAMS
INITIAL_WINDOW_SIZE
MAX_FRAME_SIZE
MAX_HEADER_LIST_SIZE
```

### WINDOW_UPDATE

```text
initial increment
timing
```

### HEADERS

Сохранять порядок pseudo headers.

### Сведения о приоритете

Если присутствует.

### Порядок заголовков

После pseudo headers.

### HPACK

Метаданные:

```text
dynamic table size
```

### Фреймы

При включённом advanced capture:

```text
frame types
initial frame sequence
```

---

## 22. Hash fingerprint HTTP/2

Сделать внутренний формат:

```text
H2-NORM-1
```

Например:

```text
settings_order
settings_values
window_update
pseudo_header_order
priority
```

и вычислять:

```text
SHA256(canonical representation)
```

Также возможно рассчитывать распространённый Akamai-style HTTP/2 fingerprint.

---

## 23. Важное техническое требование по HTTP/2

Нельзя строить H2 fingerprint только поверх уже разобранного `net/http.Request`.

К тому моменту важная часть транспортного fingerprint может быть потеряна.

H2 analyzer должен работать ближе к HTTP/2 frame layer до высокоуровневой нормализации.

---

## 24. Библиотека TLS-профилей

Web UI должен содержать библиотеку:

```text
Profiles
```

Типы профилей:

```text
uTLS preset
Observed fingerprint
Custom template
Imported profile
```

---

## 25. Профили uTLS

Нужно оставить поддержку uTLS presets:
- Chrome;
- Firefox;
- iOS;
- Android;
- Edge;
- Safari;
- другие, доступные в текущей версии uTLS.

Список должен получать backend:

```text
GET /api/v1/tls/presets
```

а не hardcode frontend.

---

## 26. Наблюдаемый профиль ≠ готовый профиль воспроизведения

Если записан ClientHello реального устройства, нельзя утверждать, что:

```text
capture → JSON → uTLS
```

автоматически даст полностью идентичный клиент.

Часть параметров динамическая:

```text
random
key shares
PSK
GREASE
session data
```

Поэтому профиль должен содержать:

```text
static structure
dynamic field policy
```

---

## 27. Механизм маршрутизации

Нужна таблица Routes.

Поддержать:
- exact host;
- `*.domain.com`;
- CIDR;
- destination port;
- device;
- device tag.

Можно позднее добавить regex.

Каждое правило MUST иметь:

```text
id
priority
enabled
phase                 # PRE_TLS | POST_CLIENTHELLO
match
action
created_version
```

Порядок разрешения: меньшее числовое `priority` имеет преимущество; при одинаковом priority выигрывает более специфичное правило; оставшаяся ничья является validation error и не может быть опубликована.

Regex не входит в Release 1 из-за сложности оценки стоимости и ReDoS-риска.

---

## 28. Вычисление маршрута

Для каждого соединения сохранять:

```text
matched_rule_id
matched_rule_priority
match_reason
```

Routing выполняется в две фазы:

```text
PRE_TLS
  device, tag, authenticated username, CONNECT/SOCKS host, IP, port

POST_CLIENTHELLO
  SNI, ALPN, offered TLS versions, fingerprint fields
```

PRE_TLS выбирает preliminary mode и определяет, разрешено ли читать ClientHello. POST_CLIENTHELLO MAY уточнить profile/upstream и MAY сменить `MITM_REISSUE` на `PASSTHROUGH`, пока upstream TLS ещё не начат. После первой записи в upstream TLS смена mode/profile запрещена.

При несовпадении CONNECT/SOCKS host и SNI сохраняются оба значения и `authority_mismatch=true`. Политика (`allow`, `passthrough`, `block`) задаётся route action. Default для лабораторного режима — `allow_and_record`; для hardened deployment — `block`.

Каждая фаза сохраняет `evaluated_config_version`, полный ordered список подходящих rule IDs и итоговое объяснение. Конфигурация connection является immutable snapshot: runtime update влияет только на новые Connection.

---

## 29. Проверка маршрута

В web UI:

```text
Test routing
```

Ввод:
- Device;
- Host;
- Port.
- при необходимости SNI, ALPN и TLS metadata для POST_CLIENTHELLO simulation.

Результат:
- matched rule;
- mode;
- TLS profile;
- upstream.

Без реального соединения.

---

## 30. Управление следующими прокси

Сущность:

```text
UpstreamProxy
```

Поля:

```text
id
name
type
host
port
username
password
enabled
tags
created_at
updated_at
last_check
latency
last_external_ip
```

Типы:

```text
DIRECT
SOCKS5
HTTP
```

---

## 31. Проверка следующего прокси

Кнопка:

```text
Test
```

Результат:

```text
TCP      OK
CONNECT  OK
TLS      OK

Latency: 47 ms
Exit IP: ...
```

Пароль frontend обратно никогда не получает.

API возвращает только:

```text
has_password: true
```

---

## 32. Сборщик TCP fingerprints

Сам JA3Proxy работает на уровне выше SYN handshake, поэтому полноценный TCP fingerprint необходимо собирать отдельным модулем.

Назвать:

```text
packet-sensor
```

Для Linux предпочтительно:
- AF_PACKET;
- eBPF.

Для переносимой реализации:
- libpcap.

На Windows:
- Npcap.

---

## 33. TCP параметры

Из SYN клиента собирать:

```text
IPv4 TTL / IPv6 hop limit
IP DF
IP ID behaviour metadata

TCP window size
MSS
window scale
SACK permitted
timestamps
TCP option order
ECN
SYN size
```

---

## 34. JA4T

Если используется JA4T-compatible implementation:

```text
JA4T
```

записывать вместе с TLS fingerprint.

Корреляция:

```text
TCP flow
        ↓
proxy connection_id
```

по:

```text
src IP
src port
dst IP
dst port
timestamp
```

Для explicit HTTP/SOCKS proxy клиентский SYN направлен на адрес JA3Proxy, а не на исходный destination. Поэтому основная корреляция packet sensor выполняется по accepted client socket tuple:

```text
client_src_ip
client_src_port
proxy_listen_ip
proxy_listen_port
time_window
```

Destination из CONNECT/SOCKS связывается на уровне `connection_id`. Исходный destination tuple может использоваться только для transparent proxy mode, если такой режим будет отдельно специфицирован. Корреляция MUST хранить confidence и algorithm version; неоднозначное совпадение не выбирается молча.

---

## 35. Ограничение TCP fingerprint

Нужно явно показывать точку наблюдения:

```text
Observed between:
Device → JA3Proxy
```

Это не обязательно тот же TCP fingerprint, который сервер увидел бы при прямом соединении через NAT/VPN/proxy.

---

## 36. Сборщик DNS

Опциональный модуль:

```text
DNS Sensor
```

Собирать:

```text
device
timestamp
query name
query type
response type
resolver
rcode
latency
```

Поддержать:
- UDP DNS;
- TCP DNS.

DoH/DoT без MITM отдельно не расшифровываются.

---

## 37. Корреляция DNS ↔ TLS

По времени и устройству связывать DNS-ответ и последующее TLS-соединение.

---

## 38. QUIC / HTTP3

JA3Proxy ориентирован на HTTP/HTTPS/SOCKS5 и TCP/TLS; QUIC требует отдельного collector.

Создать отдельный модуль:

```text
QUIC Sensor
```

Первый этап — passive observation.

---

## 39. QUIC Initial

Для QUIC v1/v2 parser должен:
- detect Initial;
- derive Initial keys;
- decrypt Initial payload;
- reassemble CRYPTO frames;
- extract TLS ClientHello.

Затем рассчитать доступные TLS/JA4-параметры.

---

## 40. Метаданные QUIC

Сохранять:

```text
QUIC version
DCID length
SCID length
token length
packet size
TLS ClientHello
ALPN
SNI/ECH
transport parameters
```

---

## 41. Не заявлять расшифровку прикладного трафика QUIC

После handshake обычный QUIC 1-RTT traffic не расшифровывать без session secrets.

То есть:

```text
QUIC Initial fingerprint       YES
HTTP/3 payload                 NO by default
```

---

## 42. Основная БД

Единственный backend хранения recorder и control-plane в этом проекте —
SQLite. Он используется и в single-node production, и в development mode.
Другие СУБД проектом не поддерживаются и в CLI не публикуются.

Основные параметры:

```text
--capture-sqlite state/recorder.sqlite
--audit-sqlite state/audit.sqlite
```

---

## 43. Основные таблицы

Минимальный набор:

```text
devices
connections

tls_observations
tls_fingerprint_variants
tls_fingerprint_families

server_tls_observations

http1_observations
http2_observations

tcp_observations
dns_observations
quic_observations

tls_profiles
routes
upstream_proxies

users
api_tokens
audit_log

runtime_events
```

Все таблицы с protocol-derived данными MUST содержать `schema_version`, а algorithm-derived данные — также `algorithm_version`. Миграции SQLite имеют один logical version и проверяются на пустой БД и на предыдущей поддерживаемой версии.

Минимальные инварианты:

- один `connection_id` создаётся до protocol detection;
- observation не существует без connection, кроме импортированной library sample;
- inbound/outbound различаются enum, а не nullable booleans;
- profile, route и config ссылаются на immutable version records;
- audit events append-only на уровне приложения и DB permissions;
- raw blob и normalized variant хранятся раздельно и имеют независимый retention.

---

## 44. connections

Основные поля:

```text
id
device_id

started_at
finished_at

source_ip
source_port

destination_host
destination_ip
destination_port

protocol

mode
route_id

tls_profile_id
upstream_id

bytes_up
bytes_down

status
error_code
error_text
```

`error_text` является redacted diagnostic text. Для фильтрации используются отдельные `error_stage` и `error_code`. Поля destination MUST различать заявленный host, SNI и resolved IP.

---

## 45. tls_observations

```text
id
connection_id

direction
  inbound
  outbound

captured_at

raw_sha256
normalized_sha256

ja3
ja3_hash
ja4

tls_version
sni
alpn

raw_client_hello
decoded_json

fingerprint_variant_id
```

Также обязательны:

```text
capture_point
completeness
schema_version
algorithm_versions
records_sha256 nullable
raw_storage_ref nullable
parse_error_code nullable
```

---

## 46. Дедупликация

Не нужно хранить огромный decoded JSON для каждого миллиона одинаковых соединений.

Схема:

```text
tls_fingerprint_variants
```

содержит:

```text
normalized_sha256
canonical_json
first_seen
last_seen
count
```

а:

```text
tls_observations
```

содержит ссылку:

```text
fingerprint_variant_id
```

Raw ClientHello хранится согласно retention policy.

---

## 47. Политика хранения raw-данных

Настройки:

```text
Store metadata:          ALWAYS
Store decoded hello:     ALWAYS
Store raw hello:         configurable
Store request headers:   configurable
Store response headers:  configurable
Store bodies:            OFF
Store packet payload:    OFF
```

По умолчанию тела HTTP **не хранить**.

Raw TLS records, ClientHello, SNI, DNS names, IP addresses, usernames и header hashes считаются потенциально чувствительными telemetry data. Доступ к raw data MUST быть отдельным permission scope. Экспорт raw data создаёт audit event.

---

## 48. Чувствительные заголовки

По умолчанию не хранить plaintext:

```text
Authorization
Proxy-Authorization
Cookie
Set-Cookie
X-Auth-Token
```

Вместо этого:

```text
present: true
length: ...
sha256: ...
```

---

## 49. Дамп трафика

Traffic dump оставить как специальный debug режим.

По умолчанию:

```text
Traffic dump = OFF
```

При включении показывать предупреждение:

```text
WARNING
Sensitive payload capture enabled
```

---

## 50. Сроки хранения

Настраиваемые периоды:

```text
connection metadata     180 days
fingerprint variants    unlimited
raw ClientHello          30 days
HTTP metadata            30 days
full payload              1 day
packet captures           7 days
```

Все значения пользователь может изменить.

---

## 51. Веб-интерфейс — обзорная панель

Главный экран:

```text
JA3Proxy Fingerprint Center

Proxy          ● RUNNING
Packet sensor  ● RUNNING
Database       ● OK

Active connections            48
TLS handshakes today      42,813
Unique fingerprints          137
Devices online                31

Inbound
  TLS 1.3                  96.7%
  TLS 1.2                   3.3%

Protocols
  HTTP/2                   81.4%
  HTTP/1.1                 14.1%
  QUIC                      4.5%
```

---

## 52. Активные соединения

Таблица:

```text
TIME
DEVICE
HOST
MODE
IN JA4
OUT PROFILE
OUT JA4
UPSTREAM
STATUS
```

Обновление через WebSocket без перезагрузки страницы.

---

## 53. Карточка соединения

При открытии соединения:

```text
Overview
TLS Inbound
TLS Outbound
TLS Server
HTTP
TCP
DNS
QUIC
Timing
Raw
Events
```

---

## 54. Временные показатели

Записывать временные метрики:

```text
accept
clienthello_received
client_tls_complete
upstream_connect_start
upstream_connect_complete
outbound_tls_start
outbound_tls_complete
first_http_request
first_response_byte
connection_close
```

---

## 55. Страница fingerprints

Таблица:

```text
JA4
JA3
Normalized hash
TLS
ALPN
Devices
Hosts
Count
First seen
Last seen
```

Фильтры:

```text
device
host
date
TLS version
JA3
JA4
ALPN
profile
source
```

---

## 56. Поиск

Поддержать:
- exact;
- contains;
- wildcard.

Например:

```text
host:*.example.com
device:iphone*
ja4:t13*
tls:1.3
```

---

## 57. Страница устройства

Например:

```text
iphone017

First seen: ...
Last seen: ...

TLS fingerprints: 7
JA4 fingerprints: 3
HTTP/2 fingerprints: 2
TCP fingerprints: 1

Applications:
AppA
AppB
```

---

## 58. Временная шкала fingerprints

Показывать изменение fingerprint во времени и diff между вариантами.

---

## 59. Версии приложений

Разрешить вручную или через API привязывать:

```text
device
application
application version
```

к периоду времени.

Система должна уметь показать изменение fingerprint после обновления приложения.

---

## 60. Создание профиля из наблюдения

Кнопка:

```text
Create profile from fingerprint
```

Wizard должен показывать:
- source fingerprint;
- samples;
- dynamic-field policy;
- статическую структуру.

После этого создаётся:

```text
Profile Template
```

---

## 61. Экспорт fingerprint

Форматы:

```text
JSON
CSV
PCAP reference
raw ClientHello
hex
```

JSON должен включать:

```text
schema_version
capture_version
algorithm versions
decoded structure
normalized structure
hashes
```

---

## 62. Импорт

Принимать:

```text
our JSON format
JA3 string
uTLS preset
JA3Proxy profile JSON
```

---

## 63. Веб-интерфейс — профили

Экран:

```text
NAME                 TYPE        USED     LAST USED
Chrome133            uTLS        12893    now
iOS14                uTLS        4211     2m
AppNative-471        observed    -        -
Custom-Test-A        custom      213      1h
```

---

## 64. Веб-интерфейс — маршруты

Drag/reorder priority.

Перед сохранением:

```text
Validate
```

---

## 65. Конфигурация во время работы

Из UI без рестарта должны меняться:

```text
default TLS profile
routing rules
upstream proxy
proxy authentication
logging level
recording policies
retention
```

Существующие соединения продолжают работать со старой конфигурацией.

Новые получают новую.

Изменение конфигурации публикуется атомарно: validation → immutable version → compare-and-swap active version. API MUST принимать `expected_version`; конфликт возвращает HTTP 409 и не применяет частичное изменение. Rollback создаёт новую version, ссылающуюся на предыдущую, а не удаляет историю.

---

## 66. Версионирование конфигурации

Любое изменение:

```text
config version N
```

Записывать:
- кто;
- когда;
- old value;
- new value.

Должна существовать кнопка:

```text
Rollback
```

---

## 67. Аутентификация веб-интерфейса

Наша web-панель должна иметь обязательную авторизацию при non-loopback binding.

Роли:

```text
Admin
Operator
Viewer
```

### Администратор
Полный доступ.

### Оператор
Управление profiles, routes, upstreams, sessions без users/CA.

### Наблюдатель
Только чтение.

Bootstrap первого Admin MUST быть описан явно. Пароль или one-time token не должен попадать в обычный log. Удаление или блокировка последнего активного Admin запрещается без отдельной recovery procedure.

---

## 68. Безопасность веб-интерфейса

Обязательно:

```text
Argon2id password hashes
HttpOnly cookies
Secure cookies
SameSite
CSRF protection
rate limiting
audit log
session expiration
API tokens with scopes
```

Дополнительно обязательны:

```text
TLS для non-loopback web binding
CORS deny by default
Content-Security-Policy
Origin validation для WebSocket
rotation/revocation API tokens
login lockout/backoff
separate permissions для raw/export/CA/config
```

`Secure` cookie MUST использоваться только через HTTPS. Допустимые deployment modes:

1. встроенный HTTPS; или
2. loopback/private binding за явно настроенным trusted reverse proxy с проверкой forwarded headers.

Запуск web UI на non-loopback без authentication и HTTPS MUST завершаться ошибкой конфигурации, если оператор не указал отдельный explicit unsafe development flag.

---

## 69. Управление CA

Раздел:

```text
Certificates
```

Показывать:

```text
CA subject
SHA256 fingerprint
created
expires
```

Кнопки:

```text
Download CA certificate
Rotate CA
```

Private key **никогда не отдавать через web UI**.

CA private key и upstream credentials MUST быть зашифрованы at rest либо храниться во внешнем secret provider. В БД сохраняется только ciphertext и key reference. Master key не хранится в той же БД. CA rotation MUST описывать overlap period, cache invalidation, влияние на активные соединения и ограничения rollback.

---

## 70. Certificate pinning

Если клиент отверг MITM certificate:

```text
status:
MITM_CLIENT_REJECTED_CERT
```

В интерфейсе:

```text
TLS ClientHello captured: YES
HTTP captured: NO

Reason:
client terminated TLS after certificate
```

---

## 71. Автоматический сквозной режим

Опционально:

```text
Fallback to passthrough
```

но только для **следующих новых соединений**.

Алгоритм:

```text
1. MITM failed.
2. Record domain/device combination.
3. Mark candidate as pinned.
4. Following connection may use PASSTHROUGH if policy permits.
```

Кандидат pinning MUST иметь TTL, confidence, failure count и подтверждение отсутствия иных очевидных причин (`unknown_ca`, protocol error, timeout). Автоматическое правило не становится постоянным без явной policy. Событие содержит исходную route/config version. Текущий failed connection никогда не replay-ится автоматически.

---

## 72. Подсистема событий

События:

```text
DEVICE_FIRST_SEEN
FINGERPRINT_FIRST_SEEN
FINGERPRINT_CHANGED
MITM_FAILED
ROUTE_CHANGED
UPSTREAM_DOWN
UPSTREAM_RECOVERED
OUTBOUND_PROFILE_MISMATCH
DB_ERROR
PACKET_SENSOR_DOWN
QUIC_NEW_VARIANT
```

---

## 73. Оповещения

Настраиваемые alerts:
- Fingerprint changed for device X;
- New TLS fingerprint appeared;
- Outbound fingerprint != selected profile;
- MITM failure rate > threshold;
- Proxy unavailable;
- Database queue growing.

В первой версии достаточно:
- web notifications;
- event log.

---

## 74. API

Версионированный namespace:

```text
/api/v1/
```

Основные endpoints:

```text
GET  /api/v1/status

GET  /api/v1/devices
POST /api/v1/devices
GET  /api/v1/devices/{id}

GET  /api/v1/connections
GET  /api/v1/connections/{id}

GET  /api/v1/fingerprints
GET  /api/v1/fingerprints/{id}
POST /api/v1/fingerprints/diff

GET  /api/v1/profiles
POST /api/v1/profiles
PUT  /api/v1/profiles/{id}
DELETE /api/v1/profiles/{id}

GET  /api/v1/routes
POST /api/v1/routes
PUT  /api/v1/routes/{id}

POST /api/v1/routes/test

GET  /api/v1/upstreams
POST /api/v1/upstreams
POST /api/v1/upstreams/{id}/test

GET  /api/v1/events

GET  /api/v1/export/...
```

До реализации UI MUST быть создан OpenAPI 3.1 contract. Он определяет:

- request/response schemas и enums;
- единый error envelope с `code`, `message`, `request_id`, `details`;
- cursor pagination, stable sort и максимальный page size;
- UTC timestamps и duration units;
- filter grammar;
- idempotency для повторяемых POST operations;
- optimistic concurrency (`expected_version`/ETag) для config objects;
- permissions/scopes каждого endpoint;
- limits и формат streaming export.

Нормативные list endpoints не должны возвращать неограниченный массив. Unknown JSON fields в config-changing requests отклоняются. Secrets никогда не возвращаются; вместо них используется `has_secret` и отдельная replace/clear operation.

---

## 75. API реального времени

Использовать:

```text
/api/v1/ws
```

или SSE.

Передавать:

```text
connection_opened
connection_closed
fingerprint_detected
stats_updated
event_created
```

Не передавать каждый сетевой пакет.

Каждое realtime event содержит `event_id`, `event_type`, `schema_version`, `occurred_at`, `connection_id` при наличии и monotonically increasing stream cursor. Клиент после reconnect выполняет replay по cursor или получает явный `resync_required`. Slow consumer не должен блокировать data plane.

---

## 76. Внутренняя шина событий

Proxy data plane не должен напрямую писать каждое событие синхронным SQL INSERT.

Архитектура:

```text
Capture
  ↓
Event
  ↓
Buffered queue
  ↓
Batch writer
  ↓
SQLite
```

Значения batch size и flush interval должны быть конфигурируемыми.

Queue MUST быть bounded и публиковать occupancy/drop/spool metrics. Для каждого event type задаётся delivery class:

```text
CRITICAL   connection metadata, TLS metadata, errors
IMPORTANT  decoded/raw ClientHello, verification, audit
OPTIONAL   payload samples, packet dumps, duplicated raw samples
```

При заполнении очереди OPTIONAL events отбрасываются первыми. Для CRITICAL events применяется disk spool. Data plane никогда не ожидает SQL transaction; максимальное допустимое время enqueue задаётся конфигурацией и измеряется.

---

## 77. Отказ БД

При временной недоступности SQLite proxy должен по возможности продолжать обслуживать соединения.

Использовать:

```text
memory queue
      ↓
disk spool
```

При восстановлении:

```text
replay spool
```

Spool MUST:

- иметь bounded disk quota;
- быть crash-safe на уровне завершённых records;
- обнаруживать checksum corruption;
- поддерживать idempotent replay по `event_id`;
- шифровать sensitive/raw records at rest;
- не содержать plaintext credentials;
- иметь quarantine для неисправимых records.

Политика при исчерпании memory и disk quota задаётся явно: `fail_open_drop_capture` по умолчанию для proxy traffic и `fail_closed` для audit/config mutations. Потеря telemetry создаёт счётчик и high-severity runtime event, когда снова доступен канал записи.

---

## 78. Приоритет данных

При нехватке места никогда сознательно не терять:
- connection metadata;
- TLS fingerprint metadata;
- errors.

Можно первым отключать:
- full payload;
- raw packet dump;
- duplicated raw ClientHello samples.

Фраза «никогда не терять» означает приоритет и попытку durable spool, но не математическую гарантию при полном отказе диска. API/status MUST показывать `recording_degraded`, объём потерь по классам и временной интервал degradation.

---

## 79. Производительность

Минимальные целевые показатели на:

```text
4 vCPU
8 GB RAM
SSD
```

при отключённых body dumps:

```text
1000 concurrent TCP connections
200 new TLS handshakes/sec
```

Цель:

```text
capture enabled throughput degradation < 10%
```

относительно того же fork с recorder disabled.

Benchmark contract MUST фиксировать:

- commit и build flags;
- ОС, CPU model, storage и Go version;
- direct или upstream mode;
- TLS 1.2/1.3 distribution;
- keep-alive, HTTP/1 и HTTP/2 workload;
- размер requests/responses;
- локальность и настройки БД;
- warm-up и длительность измерения;
- p50/p95/p99 connection setup latency;
- throughput, CPU, peak RSS, queue depth и drops.

Критерий `< 10%` применяется к throughput и p95 handshake latency отдельно. Во время acceptance run не допускаются потерянные CRITICAL events, unbounded growth или data races.

---

## 80. Ограничения памяти

Все очереди bounded.

Нужны:

```text
worker pools
bounded channels
batch writes
```

Для каждой bounded structure MUST быть указаны default capacity, maximum configurable capacity, overflow policy и metric. Нельзя скрыто создавать goroutine на каждое событие или копить неограниченный список активных connections.

---

## 81. Ограничения raw-захвата

Настройки:

```text
max_clienthello_size
max_header_size
max_event_size
max_raw_capture_size
```

При превышении:

```text
truncated = true
original_length = ...
```

---

## 82. Метрики

Endpoint:

```text
/metrics
```

Prometheus format.

Минимум:

```text
proxy_active_connections
proxy_connections_total

tls_handshakes_total
tls_mitm_failures_total

fingerprints_unique_total

db_queue_depth
db_write_latency

packet_sensor_packets_total
packet_sensor_drops_total

bytes_up_total
bytes_down_total
```

---

## 83. Методы проверки состояния

```text
/health/live
/health/ready
```

---

## 84. Журналирование

Structured logs.

Форматы:

```text
JSON
pretty console
```

---

## 85. Маскирование секретов

В logs нельзя выводить:

```text
proxy passwords
Authorization
Cookie
CA private key
API token
```

Даже при debug.

Masking MUST происходить до передачи значения logger backend. Security tests используют canary secrets и проверяют logs, runtime events, API errors, traces и exported diagnostics. Высококардинальные значения (`host`, `device_id`, JA3/JA4, connection_id) запрещены как Prometheus labels.

---

## 86. Технологии backend

Основной backend оставить:

```text
Go
```

Рекомендуемые компоненты:
- Go;
- SQLite;
- `modernc.org/sqlite`;
- database migrations.

---

## 87. Frontend

Рекомендуется:

```text
TypeScript
React
Vite
```

В production:

```text
npm build
        ↓
dist/
        ↓
go:embed
        ↓
single ja3proxy binary
```

Итог: Node.js на сервере не требуется.

---

## 88. Основная структура Go-проекта

```text
cmd/
  ja3proxy/

internal/
  proxy/
    http/
    socks5/
    tunnel/

  capture/
    tls/
    http1/
    http2/
    tcp/
    dns/
    quic/

  fingerprint/
    ja3/
    ja4/
    ja3s/
    ja4s/
    tlsnorm/
    h2norm/
    diff/

  recorder/
    event/
    queue/
    spool/

  storage/
    sqlite/

  control/
    api/
    websocket/
    auth/

  profiles/
  routes/
  upstream/
  devices/
  certificates/
  metrics/
  web/
```

---

## 89. Не смешивать плоскость данных и плоскость управления

Строго разделить:

```text
DATA PLANE
proxy
TLS
capture
forward

CONTROL PLANE
API
DB
UI
configuration
```

Если web UI упал — proxy продолжает работать.

Если recorder temporarily degraded — proxy продолжает работать.

---

## 90. Тесты parser ClientHello

Создать corpus из реальных ClientHello:

```text
Chrome
Firefox
Safari
iOS
Android
Go
OpenSSL
OkHttp
uTLS
```

Проверять:
- fragmentation;
- multiple TLS records;
- unknown extensions;
- GREASE;
- ECH;
- malformed ClientHello;
- oversized ClientHello.

---

## 91. Эталонные тесты

Для фиксированного `clienthello.bin`:

```text
JA3 == expected
JA4 == expected
TLS-NORM == expected
decoded JSON == expected
```

Изменение результата должно ломать тест.

---

## 92. Интеграционный тест исходящего соединения

Запустить:

```text
test client
 ↓
JA3Proxy
 ↓
local TLS server
```

Проверить:

```text
selected profile = Chrome@120

recorder outbound ClientHello
==
ClientHello received by test server
```

Это один из главных acceptance tests.

---

## 93. Тесты MITM

Проверить:

```text
HTTP CONNECT
SOCKS5

TLS1.2
TLS1.3

HTTP1
HTTP2
```

---

## 94. Тесты следующего прокси

Автоматические e2e:

```text
client
 ↓
JA3Proxy
 ↓
SOCKS5 upstream
 ↓
TLS server
```

и:

```text
client
 ↓
JA3Proxy
 ↓
HTTP CONNECT upstream
 ↓
TLS server
```

Убедиться, что записан именно TLS внутри туннеля.

---

## 95. Тест certificate pinning

Клиент отвергает proxy certificate.

Ожидается:

```text
ClientHello recorded       YES
TLS metadata               YES
HTTP metadata              NO
correct failure reason     YES
```

---

## 96. Тесты базы данных

Обязательно:
- migration up/down;
- deduplication;
- concurrent inserts;
- database reconnect;
- disk spool;
- spool recovery;
- retention.

---

## 97. Тесты веб-интерфейса

Минимум:
- login;
- permissions;
- profiles;
- route creation;
- route test;
- fingerprint search;
- diff;
- upstream editing;
- config rollback.

---

## 98. Тесты безопасности

Проверить:
- unauthorized API access;
- CSRF;
- session fixation;
- path traversal;
- SQL injection;
- XSS through SNI/headers/device names;
- secret leaking in API;
- secret leaking in logs.

---

## 99. Windows и Linux

Core proxy должен собираться:

```text
Windows x64
Linux x64
```

Packet sensor:
- Linux → AF_PACKET/eBPF;
- Windows → Npcap.

Функциональность TLS/HTTP recorder не должна зависеть от packet sensor.

---

## 100. Резервное копирование

Экспорт конфигурации:

```text
config
devices
profiles
routes
upstreams without plaintext passwords
```

В JSON/ZIP.

Database backup отдельно.

---

## 101. Журнал аудита

Любое изменение:
- route;
- profile;
- upstream;
- user;
- security settings;
- CA rotation

создаёт immutable audit event:

```text
timestamp
user
action
object
old value
new value
source IP
```

---

## 102. Флаги функций

Модули включаются отдельно:

```yaml
capture:
  tls: true
  http1: true
  http2: true
  tcp: false
  dns: false
  quic: false
```

---

## 103. Релизы и приоритет реализации

Каждый релиз принимается отдельно. Функции более позднего релиза не являются неявными требованиями раннего. Любая experimental feature выключена по умолчанию и не блокирует acceptance предыдущего релиза.

### 103.1. MVP-0 — ядро recorder

Цель: доказать корректность захвата и расчёта fingerprint без зависимости от UI и production database.

Обязательно:

```text
существующие HTTP/HTTPS/SOCKS5 regression tests проходят
bounded TLS detection и ClientHello reassembly
CLIENT_IN raw + decoded capture
PROXY_OUT raw + decoded capture
JA3 + JA4 + TLS-NORM-1
structured diff inbound ↔ outbound
RecordingConn не меняет bytes и network semantics
in-memory sink + JSON test/export sink
golden corpus, fragmentation tests, fuzz tests
independent outbound wire verification
```

Не входит: web UI, users/auth, automatic families, HTTP fingerprints, packet sensor, DNS, QUIC.

### 103.2. MVP-1 — постоянное хранение

Цель: получить используемый single-node инструмент наблюдения.

```text
SQLite + migrations
connection/observation data model
bounded event queue
retention и raw policy
device identity: proxy username → IP fallback + confidence
read-only REST API
Connections UI, Fingerprints UI, Diff UI
поиск по device/host/JA3/JA4
metrics и health endpoints
```

Web UI в MVP-1 привязывается к loopback. Non-loopback deployment переносится в Release 1 вместе с authentication.

### 103.3. MVP-2 — маршрутизация и профили

```text
двухфазный routing
MITM_REISSUE / PASSTHROUGH / OBSERVE_ONLY / BLOCK
profile library и immutable profile versions
upstream manager: DIRECT / SOCKS5 / HTTP CONNECT
runtime config snapshots
outbound verification MATCH/PARTIAL_MATCH/MISMATCH/UNKNOWN
route tester
```

### 103.4. Release 1 — промышленный центр управления

```text
SQLite
users, roles, API tokens
HTTPS/non-loopback web security
config versioning + optimistic concurrency + rollback
audit log
WebSocket/SSE recovery semantics
disk spool + DB reconnect/replay
backup/export/import
load, fault-injection и security acceptance
```

### 103.5. Release 2 — HTTP fingerprints

```text
HTTP/1 raw header order/capitalization
HTTP/2 preface, SETTINGS и frame-level metadata
HTTP/2 pseudo-header order
H2-NORM
```

### 103.6. Release 3 — сетевые сенсоры

```text
packet sensor
TCP SYN analysis и JA4T
DNS collection
versioned probabilistic flow correlation
```

### 103.7. Release 4 — QUIC Initial

```text
UDP passive sensor
QUIC v1/v2 Initial parser
Initial key derivation
CRYPTO reassembly
TLS ClientHello и transport parameters
```

HTTP/3 application payload не входит без отдельного secrets/decryption design.

### 103.8. Release 5 — расширенный конструктор профилей

```text
Observed Fingerprint
        ↓
Template Builder
        ↓
uTLS/custom ClientHello spec
        ↓
PROXY_OUT capture
        ↓
versioned Diff and Verification
```

Byte-for-byte replay не обещается. Builder показывает unsupported или non-replayable fields до публикации template.

---

## 104. Главный процесс работы системы

```text
1. Proxy принимает transport flow и создаёт connection_id.

2. Выполняются authentication и Device identity resolution.

3. PRE_TLS routing использует device, CONNECT/SOCKS destination и port.

4. Bounded sniffer/reassembler фиксирует CLIENT_IN ClientHello,
   не теряя bytes для следующего TLS/passthrough consumer.

5. Система рассчитывает из captured bytes:
   JA3
   JA4
   TLS-NORM.

6. POST_CLIENTHELLO routing использует SNI/ALPN/TLS metadata
   и фиксирует immutable route/profile/upstream/config versions.

7. Выбранный mode выполняет MITM_REISSUE, PASSTHROUGH,
   OBSERVE_ONLY или BLOCK.

8. Для MITM_REISSUE JA3Proxy создаёт established upstream tunnel,
   затем uTLS connection поверх RecordingConn.

9. Recorder фиксирует фактически записанный PROXY_OUT ClientHello.

10. Из PROXY_OUT captured bytes рассчитываются:
    OUT JA3
    OUT JA4
    OUT TLS-NORM.

11. Versioned verification сравнивает Profile Template ↔ PROXY_OUT,
    а Diff Engine — CLIENT_IN ↔ PROXY_OUT.

12. SERVER_IN capture фиксирует доступные ServerHello/negotiated data
    с source и availability reason.

13. Event queue сохраняет metadata асинхронно; при отказе БД
    применяются memory queue и bounded encrypted spool.

14. API/UI получают persisted или live events, не блокируя data plane.
```

---

## 105. Главный экран конкретного соединения

Должен показывать:

```text
CONNECTION <ID>

Device
Destination
Mode
Connection state
Config / Route / Profile versions

INBOUND
Capture point / completeness
TLS
JA3
JA4
TLS-NORM
ALPN
Extensions

OUTBOUND
Capture point / completeness
Profile
TLS
JA3
JA4
TLS-NORM
Verification

DIFF
Ciphers
Extension set
Extension order
Supported groups
ALPN
GREASE positions

HTTP/2
SETTINGS fingerprint
Pseudo header order

NETWORK
TCP fingerprint
DNS

DIAGNOSTICS
Error stage / code
Recording health
Availability reasons
```

Недоступные данные отображаются как `UNAVAILABLE: <reason>`, а не как пустое значение. Raw/secret-bearing вкладки доступны только пользователям с отдельным permission scope и каждое открытие/export может аудироваться согласно policy.

---

## 106. Критерии готовности MVP-0

MVP-0 принимается только при одновременном выполнении следующих условий:

1. Существующие HTTP/HTTPS/SOCKS5 regression tests JA3Proxy проходят без изменения ожидаемого поведения.
2. ClientHello reassembler проходит corpus для TLS 1.2/1.3, произвольную TCP/TLS-record fragmentation, unknown extensions, GREASE, malformed lengths и declared limits.
3. Для `CLIENT_IN` сохраняются точные complete handshake bytes, decoded structure и parse status.
4. Для `PROXY_OUT` сохраняются bytes, которые RecordingConn успешно передал underlying connection.
5. Независимый test server/packet capture подтверждает byte equality PROXY_OUT capture.
6. JA3, JA4 и TLS-NORM-1 вычисляются только из captured bytes и проходят versioned golden vectors.
7. Сохраняются SNI, ALPN, ordered ciphers/extensions/groups/signature algorithms, GREASE contexts и dynamic field descriptors.
8. `raw_sha256`, `records_sha256` и `normalized_sha256` имеют однозначно описанные byte inputs.
9. Diff выдаёт deterministic machine-readable operations и корректно различает add/remove/replace/move.
10. PASSTHROUGH не изменяет bytes и не отображается как applied profile.
11. Capture timeout/overflow/malformed input не вызывает panic, unbounded allocation или зависание.
12. Recorder отключаем feature flag; отключённый recorder сохраняет исходное proxy behavior.
13. Race-enabled tests ключевых concurrent components проходят.
14. Sensitive test canaries отсутствуют в обычных logs и error text.

Артефакты приёмки MVP-0:

```text
test report с commit hash
clienthello corpus manifest и лицензии/provenance
golden vectors с algorithm versions
benchmark baseline recorder-off vs recorder-on
описание известных ограничений
```

Критерии MVP-1, MVP-2 и Release 1 определены соответствующими границами в разделе 103 и MUST быть детализированы отдельными идентификаторами трассируемых требований до начала реализации каждого релиза.

---

## 107. Что считать полной версией

Полная версия считается законченной после появления:

```text
TLS inbound/outbound
JA3
JA4
JA3S
JA4S

TLS normalized fingerprints

HTTP/1 fingerprints
HTTP/2 fingerprints

TCP fingerprints
JA4T

DNS collection

QUIC Initial fingerprints

Device profiling

Fingerprint families

Profile builder

Routing

Upstream manager

Diff engine

Timeline

Alerts

Web control center

SQLite

Audit

API

Metrics
```

---

## 108. Критические требования, которые нельзя упростить

**MUST NOT BREAK:**

1. Не считать выбранный uTLS preset доказательством фактически отправленного fingerprint.
   Всегда capture OUTBOUND ClientHello.

2. Не хранить только JA3.
   Хранить исходную структуру ClientHello.

3. Не считать raw ClientHello стабильным fingerprint.
   Делать normalization.

4. Не терять порядок:
   - ciphers;
   - extensions;
   - ALPN;
   - supported groups;
   - HTTP headers;
   - HTTP/2 SETTINGS.

5. Не использовать `net/http.Request` как единственный источник HTTP/2 fingerprint.

6. Не блокировать proxy синхронной записью в БД.

7. Не хранить пароли/upstream secrets в plaintext API.

8. Не включать body capture по умолчанию.

9. Не обещать, что observed ClientHello можно автоматически воспроизвести byte-for-byte через uTLS.

10. Не смешивать PASSTHROUGH и MITM: в интерфейсе всегда должно быть видно, какой режим использовался.

11. Не распознавать TLS только по порту или одному байту. Использовать bounded replayable sniffing/reassembly.

12. Не представлять недоступное или зашифрованное поле как отсутствующее. Хранить availability и reason.

13. Не менять semantics `net.Conn`: partial write, error и deadline должны корректно проходить через recorder wrappers.

14. Не изменять опубликованный normalized hash без нового algorithm name/version.

15. Не позволять UI, realtime subscriber или БД блокировать data plane.

### 108.1. Трассируемость требований

Перед реализацией требования получают стабильные IDs:

```text
FR-*    functional
PR-*    protocol
SEC-*   security/privacy
REL-*   reliability
PERF-*  performance
AC-*    acceptance scenario
```

Каждый MUST связывается минимум с одним test ID. Рекомендуемый формат сценария:

```text
AC-TLS-OUT-001

Given:
  mode = MITM_REISSUE
  profile = Chrome@120
  upstream = HTTP CONNECT

When:
  proxy завершает outbound TLS handshake

Then:
  PROXY_OUT ClientHello captured completely
  raw bytes equal bytes independently received by test server
  JA3/JA4/TLS-NORM calculated from captured bytes
  observation references connection/profile/config versions

Failure behavior:
  unavailable DB does not terminate proxy connection
  event is queued or durably spooled

Limits:
  ClientHello <= 256 KiB
  capture timeout = 5s
```

Документ считается готовым к разработке конкретного релиза, когда для всех его MUST заполнена матрица `requirement ID → implementation component → test ID → acceptance evidence`.

---

## 109. Итоговая концепция

В результате должна получиться не просто модификация JA3Proxy, а полноценная лаборатория сетевых отпечатков:

```text
                         Fingerprint DB
                              ▲
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
       TCP                   TLS                   HTTP
      JA4T              JA3 / JA4             H1 / H2
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                           Device
                              │
                              ▼
                     Fingerprint Family
                              │
                              ▼
                       Profile Template
                              │
                              ▼
                          JA3Proxy
                              │
                              ▼
                    Actual Outbound Hello
                              │
                              ▼
                            Diff
```

Самая важная часть всей архитектуры — связка:

```text
INBOUND RAW
    ↓
NORMALIZED PROFILE
    ↓
OUTBOUND RAW
    ↓
DIFF
```

Благодаря этому система должна видеть и сохранять не «ожидаемый» fingerprint, а то, что реально пришло от клиента и реально ушло наружу.
