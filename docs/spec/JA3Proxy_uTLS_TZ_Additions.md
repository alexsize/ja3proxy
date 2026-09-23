# Нормативное приложение A: архитектура и профили uTLS
## JA3Proxy Fingerprint Recorder & Control Center
### С учётом анализа `refraction-networking/utls`

> Статус: обязательная составная часть ТЗ версии 3.0.
> Базовая версия движка: `github.com/refraction-networking/utls v1.8.2`.
> Область: outbound TLS generation, Profile Compiler, replay и verification.

Формулировки «добавить», «изменить», «уточнить», «нужно» и «должен» в этом
приложении имеют силу **MUST**, если конкретный пункт явно не помечен как
рекомендация или будущая возможность. При конфликте с ТЗ v2 это приложение
имеет приоритет только в вопросах uTLS, генерации ClientHello, replay-профилей
и проверки фактического outbound wire.

Ниже приведены нормативные поправки и дополнения после изучения
`https://github.com/refraction-networking/utls`.

---

## 1. Зафиксировать uTLS как основной TLS-движок проекта

Добавить отдельный раздел после архитектуры.

### TLS Engine

Основным движком формирования исходящих TLS ClientHello является:

```text
github.com/refraction-networking/utls
```

Проект **не должен разрабатывать собственную реализацию TLS ClientHello generation**, если требуемое поведение уже поддерживается uTLS.

Текущий JA3Proxy уже использует:

```go
utls.UClient(...)
utls.ClientHelloID
utls.UTLSIdToSpec(...)
utls.HelloCustom
utls.ClientHelloSpec
utls.ApplyPreset(...)
```

На момент подготовки ТЗ JA3Proxy закрепляет:

```text
github.com/refraction-networking/utls v1.8.2
```

Следовательно, архитектура проекта должна строиться **вокруг uTLS**, а не параллельно ему.

```text
Profile Manager
       ↓
ClientHelloSpec
       ↓
uTLS
       ↓
RecordingConn
       ↓
Network
```

---

## 2. Изменить архитектуру Profile Builder

В первоначальном ТЗ было заложено:

```text
Captured ClientHello
        ↓
наш parser
        ↓
наш profile
        ↓
генерация ClientHello
```

Исправить на:

```text
                         ┌─► Our Parser
                         │       ↓
RAW ClientHello ─────────┤     JA3
                         │     JA4
                         │     TLS-NORM
                         │     Analytics
                         │
                         └─► uTLS Fingerprinter
                                 ↓
                         ClientHelloSpec
                                 ↓
                         Profile Template
                                 ↓
                              uTLS
```

То есть использовать **два независимых пути анализа**.

### Аналитический путь

Наш код:

```text
Raw ClientHello
   ↓
TLS Parser
   ↓
canonical representation
   ↓
JA3 / JA4 / TLS-NORM
   ↓
DB
```

### Генерационный путь

uTLS:

```text
Raw ClientHello
   ↓
utls.Fingerprinter
   ↓
ClientHelloSpec
   ↓
HelloCustom
   ↓
ApplyPreset()
```

Это принципиально разные задачи, их нельзя объединять в один компонент.

---

## 3. Добавить использование `utls.Fingerprinter`

В раздел Profile creation from observation добавить.

Для создания воспроизводимого профиля из захваченного ClientHello использовать встроенный механизм uTLS:

```go
fingerprinter := &utls.Fingerprinter{}

spec, err := fingerprinter.FingerprintClientHello(
    rawClientHello,
)
```

Результат:

```text
*utls.ClientHelloSpec
```

затем применяется:

```go
uConn := utls.UClient(
    conn,
    config,
    utls.HelloCustom,
)

err := uConn.ApplyPreset(spec)
```

Таким образом:

```text
Captured ClientHello
        ↓
uTLS Fingerprinter
        ↓
ClientHelloSpec
        ↓
Profile Template
```

Но `utls.Fingerprinter` **не заменяет наш fingerprint analyzer**.

Он используется для:

```text
capture → replay
```

Наш parser используется для:

```text
capture → analyze → compare → store
```

---

## 4. Важное ограничение `Fingerprinter`

Добавить отдельное MUST-требование.

`utls.Fingerprinter` не должен получать произвольный кусок TCP stream.

Сначала наш TLS Capture Layer должен корректно восстановить полный ClientHello.

Нужно поддерживать:

```text
ClientHello fragmented across TCP packets
ClientHello fragmented across TLS records
partial socket reads
coalesced TLS records
```

Pipeline:

```text
TCP stream
   ↓
TLS record reassembler
   ↓
Handshake reassembler
   ↓
complete ClientHello
   ↓
canonical raw representation
   ↓
uTLS Fingerprinter
```

Нельзя предполагать:

```text
one Read() == one ClientHello
```

и нельзя напрямую передавать случайный `Read()` buffer в uTLS Fingerprinter.

---

## 5. `ClientHelloSpec` сделать основной runtime-моделью генерации

Добавить к разделу Profiles.

Для исполнения TLS-профиля основной runtime-структурой должна быть:

```go
utls.ClientHelloSpec
```

Наш собственный JSON-формат предназначен для:

```text
storage
versioning
editing
import/export
diff
audit
```

Перед применением:

```text
Our Profile JSON
       ↓
Profile compiler
       ↓
utls.ClientHelloSpec
       ↓
utls.HelloCustom
       ↓
ApplyPreset()
```

Не следует реализовывать собственный TLS serializer, если профиль может быть представлен через `ClientHelloSpec`.

---

## 6. Ввести Profile Compiler

Добавить новый компонент:

```text
internal/profiles/compiler
```

Назначение:

```text
Stored Profile
      ↓
validation
      ↓
dynamic-field policy
      ↓
uTLS ClientHelloSpec
```

Интерфейс концептуально:

```go
Compile(profile Profile) (*utls.ClientHelloSpec, error)
```

Компилятор должен:

- проверять совместимость extensions с текущей версией uTLS;
- проверять cipher suites;
- проверять supported groups;
- обрабатывать GREASE placeholders;
- применять dynamic-field policy;
- проверять ALPN;
- проверять ALPS;
- проверять TLS version constraints;
- возвращать понятную ошибку при невозможности воспроизведения.

---

## 7. Добавить четыре типа TLS-профилей

В первоначальном ТЗ были:

```text
uTLS preset
Observed fingerprint
Custom template
Imported profile
```

Уточнить типы:

```text
PRESET
OBSERVED
CUSTOM
RANDOMIZED
```

### PRESET

Например:

```text
Chrome@133
Firefox@148
Safari@26.3
```

Реализуется через:

```text
ClientHelloID
```

или:

```text
UTLSIdToSpec()
```

### OBSERVED

Создан из настоящего ClientHello:

```text
raw capture
   ↓
Fingerprinter
   ↓
ClientHelloSpec
```

### CUSTOM

Создан вручную пользователем.

Использует:

```text
HelloCustom
+
ClientHelloSpec
```

### RANDOMIZED

Использует:

```go
HelloRandomized
HelloRandomizedALPN
HelloRandomizedNoALPN
```

---

## 8. Randomized profile должен быть отдельным режимом

Добавить в UI:

```text
Profile type:
  Preset
  Observed
  Custom
  Randomized
```

Для `Randomized`:

```text
ALPN:
  Automatic
  Required
  Disabled
```

Сопоставление:

```text
Automatic → HelloRandomized
Required  → HelloRandomizedALPN
Disabled  → HelloRandomizedNoALPN
```

При этом randomized fingerprint должен записываться как **фактически сгенерированный fingerprint**, а не просто:

```text
profile = RANDOMIZED
```

То есть:

```text
Randomized
   ↓
uTLS generates hello
   ↓
OUTBOUND Recorder
   ↓
actual JA3/JA4/TLS-NORM
```

---

## 9. Добавить режим Strict и Adaptive

Это особенно важно после анализа текущего JA3Proxy.

Сейчас JA3Proxy получает preset:

```go
spec := utls.UTLSIdToSpec(clientHelloID)
```

а затем делает:

```go
limitSpecALPN(&spec, nextProtos)
```

То есть меняет:

```text
ALPN
ALPS/ApplicationSettings
```

до отправки.

Следовательно:

```text
Chrome@120
```

может фактически отправить **не исходный Chrome@120 ClientHello**.

Добавить для TLS-профиля настройку:

```text
profile_mode:
    STRICT
    ADAPTIVE
```

### STRICT

ClientHello должен максимально соответствовать сохранённому/preset профилю.

Нельзя автоматически менять:

```text
cipher order
extension order
ALPN
ALPS
supported_groups
signature algorithms
```

Если application-layer configuration несовместима с профилем — соединение завершается понятной ошибкой:

```text
PROFILE_PROTOCOL_CONFLICT
```

### ADAPTIVE

Proxy может менять параметры, необходимые для работы текущего соединения.

Например:

```text
ALPN
ALPS
```

Но изменения обязательно записываются.

```text
base_profile = Chrome@120
runtime_modified = true

modifications:
  ALPN changed
  ALPS changed
```

---

## 10. Разделить три понятия профиля

В БД и UI нельзя смешивать:

```text
SELECTED PROFILE
COMPILED PROFILE
ACTUAL WIRE FINGERPRINT
```

Пример:

```text
Selected Profile:
Chrome@120

Compiled ClientHelloSpec:
Chrome@120 + ALPN modification

Actual Wire:
JA3 = ...
JA4 = ...
TLS-NORM = ...
```

---

## 11. Outbound Recorder оставить обязательным

Несмотря на наличие uTLS, **не заменять outbound capture чтением `ClientHelloSpec`**.

Нужно иметь:

```text
uTLS
 ↓
RecordingConn
 ↓
real socket
```

и записывать именно байты, фактически переданные через `Write()`.

Причина:

```text
ClientHelloSpec
     ≠ гарантированно
actual network bytes
```

Изменения могут появиться при:

```text
BuildHandshakeState()
MarshalClientHello()
dynamic GREASE
key generation
session handling
padding
PSK
ALPN adaptations
future uTLS changes
```

Поэтому источником истины является:

```text
ACTUAL OUTBOUND WIRE BYTES
```

---

## 12. Добавить двухуровневую outbound verification

Нужно сравнивать сразу три объекта:

```text
Stored Profile
      ↓
Compiled ClientHelloSpec
      ↓
Actual ClientHello
```

### Проверка A

```text
STORED PROFILE
vs
COMPILED SPEC
```

Показывает изменения компилятора.

### Проверка B

```text
COMPILED SPEC
vs
ACTUAL WIRE
```

Показывает изменения uTLS/runtime.

### Проверка C

```text
INBOUND CLIENT
vs
ACTUAL OUTBOUND
```

Показывает итоговую трансформацию прокси.

В UI:

```text
PROFILE → SPEC       MATCH / MODIFIED
SPEC → WIRE          MATCH / MODIFIED
INBOUND → OUTBOUND   MATCH / DIFFERENT
```

---

## 13. Добавить Round-trip Test

Для любого Observed Profile должна быть кнопка:

```text
Validate Replay
```

Алгоритм:

```text
Captured Raw ClientHello
        ↓
uTLS Fingerprinter
        ↓
ClientHelloSpec
        ↓
uTLS
        ↓
local capture server
        ↓
actual ClientHello
        ↓
Diff
```

Результат:

```text
Structure match:       YES
JA3 match:             YES
JA4 match:             YES
Extension order:       YES
Cipher order:          YES
ALPN:                  YES
GREASE positions:      YES
Byte-for-byte:         NO
```

Byte-for-byte равенство **не является обязательным**, потому что динамические поля должны меняться.

---

## 14. Добавить Replay Fidelity

Для Observed/Custom profile вычислять показатель не как «процент качества», а как набор конкретных свойств:

```text
Replay Fidelity

TLS version               MATCH
Cipher list               MATCH
Cipher order              MATCH
Extension set             MATCH
Extension order           MATCH
Supported groups          MATCH
Signature algorithms      MATCH
ALPN                      MATCH
ALPS                      MATCH
GREASE positions          MATCH
Padding behavior          MATCH
JA3                       MATCH
JA4                       MATCH
```

Не делать один непрозрачный:

```text
98% compatible
```

---

## 15. Добавить поддержку dynamic field policy на уровне uTLS

Для профиля:

```json
{
  "dynamic": {
    "client_random": "generate",
    "session_id": "generate",
    "key_share": "generate",
    "grease": "generate",
    "psk": "runtime",
    "padding": "profile"
  }
}
```

Profile Compiler должен преобразовывать эту политику в соответствующую конфигурацию uTLS.

Не копировать буквально из захваченного соединения:

```text
ClientRandom
key share public key
PSK binders
session IDs
tickets
```

---

## 16. GREASE — дополнить ТЗ

uTLS уже имеет представление:

```text
GREASE_PLACEHOLDER
```

Поэтому в canonical profile конкретное значение:

```text
0x1a1a
```

не должно считаться стабильной частью профиля.

Нормализовать:

```text
0x0a0a
0x1a1a
0x2a2a
...
```

в:

```text
GREASE
```

при этом отдельно хранить:

```text
position
context
actual_wire_value
```

То есть:

```text
Normalized:
extension[2] = GREASE

Actual:
extension[2] = 0x4a4a
```

---

## 17. Версионировать uTLS вместе с fingerprint

Каждая outbound observation должна содержать:

```text
tls_engine = "utls"
tls_engine_version = "v1.8.2"
```

Каждый profile должен содержать:

```text
created_with_utls
last_validated_with_utls
```

Например:

```text
created_with_utls: v1.8.2
last_validated_with_utls: v1.8.2
```

Причина: изменение uTLS может менять фактический fingerprint.

---

## 18. При обновлении uTLS автоматически выполнять regression validation

Добавить CI-задачу:

```text
uTLS upgrade
     ↓
build
     ↓
golden ClientHello tests
     ↓
outbound wire capture
     ↓
compare previous version
```

Для каждого встроенного профиля:

```text
Chrome@120
Chrome@133
Firefox@120
iOS@14
...
```

проверять:

```text
previous actual fingerprint
vs
new actual fingerprint
```

Изменение должно явно попадать в CI report.

Нельзя обновлять:

```bash
go get utls@latest
```

и считать upgrade безопасным только потому, что код компилируется.

---

## 19. Закрепить стабильную версию uTLS

В production:

```text
uTLS dependency MUST be pinned
```

Например:

```text
github.com/refraction-networking/utls v1.8.2
```

Запрещено:

```text
@master
@latest
```

для production builds.

Разрешить отдельный:

```text
experimental/canary build
```

для тестирования master/new release.

---

## 20. Добавить Engine Compatibility Test

При загрузке сохранённого профиля система должна проверять:

```text
Profile created with: uTLS X
Current runtime:       uTLS Y
```

Если версии отличаются:

```text
PROFILE_REVALIDATION_REQUIRED
```

Затем выполнить local replay test.

Статусы:

```text
VALID
VALID_WITH_DIFFERENCES
INCOMPATIBLE
NOT_VALIDATED
```

---

## 21. Каталог preset'ов нельзя хранить только вручную

Текущий JA3Proxy имеет собственный список поддерживаемых preset'ов.

Это может расходиться с фактической версией uTLS.

Поэтому UI должен показывать только preset'ы, которые реально поддерживает **скомпилированная версия uTLS**.

API:

```text
GET /api/v1/tls/engine
```

Пример:

```json
{
  "engine": "utls",
  "version": "v1.8.2",
  "profiles": [
    "..."
  ]
}
```

---

## 22. Preset catalog должен иметь источник

Для каждой записи:

```text
Chrome@133
```

хранить:

```text
source = utls
engine_version = ...
client = Chrome
version = 133
```

Не смешивать с:

```text
Observed Chrome 133
```

Это разные сущности.

---

## 23. Добавить возможность raw custom extension

uTLS поддерживает custom TLS extensions.

Поэтому Custom Profile должен позволять advanced users задавать:

```text
extension ID
raw extension data
position
```

Тип:

```text
GenericExtension
```

Но UI должен помечать:

```text
Advanced / potentially incompatible
```

---

## 24. Добавить unsupported-extension policy

При превращении захваченного ClientHello в replay profile некоторые extensions могут не иметь полноценной реализации.

Для каждого extension хранить:

```text
type
id
support_level
```

Статусы:

```text
FULL
GENERIC
PLACEHOLDER
UNSUPPORTED
```

Profile Builder должен явно показывать:

```text
Extension 0xXXXX:
captured: YES
replay support: GENERIC
```

Нельзя молча выбрасывать extension.

---

## 25. Добавить поле `replayable`

Для fingerprint variant:

```text
replayable:
  YES
  PARTIAL
  NO
  UNKNOWN
```

и причины:

```text
unsupported extension
unsupported PSK behavior
unsupported protocol feature
invalid profile
engine mismatch
```

---

## 26. Не использовать `ClientHelloSpec` как аналитический источник истины

Это отдельное MUST NOT.

Нельзя:

```text
ClientHelloSpec
   ↓
JA3/JA4
```

использовать как единственный источник того, что было отправлено.

JA3/JA4 outbound должны вычисляться из:

```text
captured actual wire bytes
```

Причина:

```text
Spec = intent
Wire = reality
```

---

## 27. Добавить pre-marshaled ClientHello capture

Помимо `RecordingConn`, полезно получить внутреннее представление uTLS после:

```text
BuildHandshakeState()
MarshalClientHello()
```

Сохранять при debug/validation:

```text
utls_marshaled_clienthello
```

Тогда получится цепочка:

```text
Profile
 ↓
ClientHelloSpec
 ↓
uTLS Marshaled ClientHello
 ↓
RecordingConn Wire ClientHello
```

И можно диагностировать:

```text
Spec → Marshal
Marshal → Wire
```

Но источником истины всё равно остаётся Wire Capture.

---

## 28. Добавить uTLS mutation audit

Любые runtime-изменения исходного preset должны фиксироваться.

Например текущий:

```go
limitSpecALPN()
```

должен создавать событие:

```json
{
  "type": "PROFILE_RUNTIME_MUTATION",
  "field": "ALPN",
  "before": ["h2", "http/1.1"],
  "after": ["http/1.1"],
  "reason": "downstream protocol compatibility"
}
```

То же самое для ALPS.

---

## 29. Изменить модель ALPN

ALPN должен иметь policy:

```text
PROFILE
DOWNSTREAM
INTERSECTION
CUSTOM
```

### PROFILE

Использовать ALPN профиля без изменения.

### DOWNSTREAM

Использовать ALPN клиента.

### INTERSECTION

Использовать пересечение:

```text
profile ALPN ∩ client ALPN
```

### CUSTOM

Задаётся вручную.

Текущая логика JA3Proxy фактически близка к `DOWNSTREAM/INTERSECTION`, но теперь это должно быть явной настройкой.

---

## 30. То же самое сделать для ALPS

Поскольку `ApplicationSettingsExtension` связан с ALPN, политика должна быть согласованной.

Если:

```text
h2
```

удалён из ALPN, связанная ALPS-конфигурация не должна оставаться неконсистентной.

Validation должен проверять это до handshake.

---

## 31. Session Resumption добавить в Fingerprint Model

uTLS поддерживает session cache/state.

Поэтому в дальнейшем нельзя анализировать только первый full handshake.

Добавить:

```text
handshake_type:
    FULL
    RESUMED
    PSK
```

и:

```text
session_resumption
psk_present
psk_identity_count
early_data
```

если доступны.

Fingerprint Family должна учитывать:

```text
first connection fingerprint
resumed connection fingerprint
```

как связанные варианты одного клиента.

---

## 32. Preset с PSK не считать обычным preset

uTLS имеет специальные варианты вида:

```text
Chrome*_PSK
```

Их в UI нужно помечать:

```text
PSK / resumption profile
```

а не ставить в общий список рядом с обычным full-handshake профилем без пояснений.

---

## 33. Post-Quantum группы учитывать отдельно

uTLS уже поддерживает современные PQ/ML-KEM-related группы.

Поэтому `supported_groups` и `key_share` нельзя ограничивать классическими:

```text
x25519
P-256
P-384
```

Парсер/БД должны поддерживать неизвестные и будущие numeric IDs.

Хранить всегда:

```text
numeric_id
resolved_name
```

Неизвестный ID не должен приводить к ошибке parsing.

---

## 34. ECH также хранить как opaque extension при необходимости

Если parser не понимает конкретную новую версию ECH:

```text
extension_id
raw_data
length
position
```

всё равно должны сохраняться.

Общее правило:

> Неизвестный TLS extension никогда не должен теряться.

---

## 35. Добавить Generic Extension Preservation

Любой unknown extension:

```text
id
position
raw bytes
```

должен попадать в capture.

Это позволит позднее:

```text
reparse historical captures
```

после обновления parser.

---

## 36. Разделить parser version и engine version

Каждая observation:

```text
capture_version
parser_version
ja3_version
ja4_version
tls_norm_version
utls_version
```

Например:

```json
{
  "capture_version": 1,
  "parser_version": "1.3.0",
  "ja3_version": "1",
  "ja4_version": "2026-x",
  "tls_norm_version": "TLS-NORM-1",
  "tls_engine": "utls",
  "tls_engine_version": "v1.8.2"
}
```

---

## 37. Добавить возможность повторного разбора RAW

Если parser обновился, система должна уметь:

```text
stored raw ClientHello
       ↓
new parser
       ↓
new decoded representation
```

при этом старую запись не уничтожать.

Нужно хранить:

```text
analysis_revision
```

---

## 38. Добавить `Replay Lab`

Отдельный раздел Web UI:

```text
Replay Lab
```

В нём:

```text
Captured fingerprint
        ↓
Choose:
  original observed profile
  uTLS preset
  custom profile
  randomized
        ↓
Target test endpoint
        ↓
Run
```

Результат:

```text
Expected
Compiled
Actual
Server response
Diff
```

---

## 39. Добавить Compatibility Matrix

Для выбранного endpoint:

```text
Profile          TLS     HTTP    Result
Chrome133        1.3     h2      OK
Firefox148       1.3     h2      OK
iOS14            1.3     h2      OK
Safari26.3       1.3     h2      FAIL
Randomized #1    1.3     h2      OK
```

Это может использовать идеи `uTLS Roller`, но **не заменять deterministic routing**.

---

## 40. Roller разрешить только в лабораторном режиме

`utls.Roller` нельзя использовать автоматически в production proxy routing.

Причина:

```text
один destination
→ несколько разных fingerprints
```

что разрушит воспроизводимость эксперимента.

Разрешить Roller только в:

```text
Replay Lab
Compatibility Test
```

---

## 41. Обновить раздел MUST NOT BREAK

Добавить следующие пункты:

```text
11. uTLS является основным outbound TLS engine.
    Не писать параллельный ClientHello generator без необходимости.

12. uTLS Fingerprinter использовать для capture→ClientHelloSpec,
    но не как замену аналитическому TLS parser.

13. ClientHelloSpec не является доказательством wire fingerprint.

14. Outbound JA3/JA4 вычислять только из фактически записанных
    сетевых ClientHello bytes.

15. Любые изменения preset после UTLSIdToSpec должны
    фиксироваться как runtime mutations.

16. Не обновлять uTLS dependency без fingerprint regression tests.

17. Любой saved observed profile должен иметь информацию
    о версии uTLS, на которой он был создан/проверен.

18. Неизвестные TLS extensions нельзя отбрасывать.

19. Randomized profile всегда должен сохранять фактически
    сгенерированный ClientHello.

20. STRICT и ADAPTIVE profile behavior должны различаться явно.
```

---

## 42. Обновить главный workflow

Новая правильная схема:

```text
CLIENT
  │
  ▼
TCP/TLS Reassembler
  │
  ▼
RAW INBOUND CLIENTHELLO
  │
  ├─────────────► Our TLS Parser
  │                    │
  │                    ├─ JA3
  │                    ├─ JA4
  │                    ├─ TLS-NORM
  │                    └─ DB
  │
  └─────────────► uTLS Fingerprinter
                       │
                       ▼
                 ClientHelloSpec
                       │
                       ▼
               Observed Profile
```

При исходящем соединении:

```text
Selected Profile
       │
       ▼
Profile Compiler
       │
       ▼
ClientHelloSpec
       │
       ▼
runtime modifications
(ALPN/ALPS/etc.)
       │
       ▼
uTLS
       │
       ▼
Marshal
       │
       ▼
RecordingConn
       │
       ▼
RAW OUTBOUND CLIENTHELLO
       │
       ├─ JA3
       ├─ JA4
       ├─ TLS-NORM
       └─ Diff
```

---

## 43. Обновить концепцию источников истины

Для проекта установить такой приоритет:

```text
1. Actual network bytes
2. Parsed actual network bytes
3. Compiled ClientHelloSpec
4. Stored profile
5. Selected preset name
```

То есть:

```text
Chrome@133
```

является только намерением.

```text
ClientHelloSpec
```

является скомпилированным намерением.

А:

```text
RecordingConn capture
```

является фактом.

---

## 44. Итоговая поправка к архитектуре

После изучения uTLS **не нужно разрабатывать свой собственный TLS ClientHello generation engine**.

Правильная архитектура проекта теперь:

```text
                  JA3Proxy Fingerprint Center
                            │
          ┌─────────────────┴──────────────────┐
          │                                    │
      ANALYSIS                             GENERATION
          │                                    │
   Our TLS Parser                       uTLS Fingerprinter
          │                                    │
  JA3 / JA4 / TLS-NORM                  ClientHelloSpec
          │                                    │
      Database                          Profile Compiler
                                               │
                                               ▼
                                             uTLS
                                               │
                                               ▼
                                         RecordingConn
                                               │
                                               ▼
                                          Actual Wire
                                               │
                                               ▼
                                       JA3 / JA4 / Diff
```

Самое существенное изменение относительно первой версии ТЗ:

> **uTLS становится не просто одной из библиотек проекта, а официальным TLS execution/generation engine. Наш код отвечает за capture, normalization, analytics, persistence, profile management и verification.**

И второе критическое изменение:

> **`utls.Fingerprinter + ClientHelloSpec + HelloCustom + ApplyPreset` необходимо использовать как основной путь `Observed ClientHello → Replay Profile`, но результат всегда проверяется через фактический outbound wire capture.**

Это убирает значительный объём ненужной собственной реализации и одновременно делает исходное требование **`INBOUND RAW → PROFILE → OUTBOUND RAW → DIFF`** ещё более строгим.
