# Регистратор TLS: состояние реализации

Обновлено: 2026-09-22. Основа: `JA3Proxy_Fingerprint_Recorder_TZ_v2.md`.

Реализовано ядро первого этапа и локальный интерфейс для его проверки. Это не завершённый Control Center и не заявление о выполнении всех релизов ТЗ.

## Запуск

```powershell
.\bin\ja3proxy.exe --listen 127.0.0.1:8080 --capture-tls --web-panel 127.0.0.1:9090 --tls-fingerprint chrome@120
```

Открыть `http://127.0.0.1:9090/recorder.html`. Для passthrough добавить `--tls-mode PASSTHROUGH`, для наблюдения без MITM — `--tls-mode OBSERVE_ONLY`. `--tls-mode BLOCK` запрещает CONNECT/SOCKS-туннели до исходящего dial; обычный HTTP не относится к этой настройке.

Постоянный поток наблюдений в новый файл:

```powershell
.\bin\ja3proxy.exe --capture-tls --capture-jsonl capture-001.jsonl
```

`--capture-raw` дополнительно сохраняет raw handshake и TLS records (base64 в JSON). Без него raw хранится только временно для вычисления fingerprint. JSONL ограничен 256 MiB; существующий файл не перезаписывается. При достижении лимита экспорт прекращается, счётчик ошибок растёт, proxy продолжает работу. Окно памяти и файл экспорта — разные источники: HTTP export выгружает только текущее окно памяти.

JSONL пока не шифруется. Размещайте экспорт в контролируемом каталоге; raw содержит session identifiers/tickets. Шифрованный spool и secret provider относятся к незавершённому Release 1.

## Реализованные компоненты

| Требование | Компонент | Проверка |
| --- | --- | --- |
| PR-TLS-001: TCP/TLS-record fragmentation | `capture/tlshello.Stream` | `TestReassemblyEveryBoundary`, `FuzzStream` |
| PR-TLS-002: bounded parsing и replay | `Stream`, `Sniff`, `Parse` | `TestMalformedAndLimits`, `TestSniffReplayAndTimeout`, `FuzzParse` |
| FR-CAP-001: входящий ClientHello | tunnel sniffer | `TestRecorderOutboundWireThroughProxyMatrix` |
| FR-CAP-002: успешные outbound Write bytes | `tlshello.Conn` | `TestRecordingConnShortWrites`, серверная проверка raw в matrix |
| FR-FP-001: JA3/JA4 | `Calculate` | `TestGoldenMinimal`, `TestJA4PublishedVector`, независимый e2e JA3 parser |
| FR-FP-002: TLS-NORM-1 | `Normalize` | `TestGoldenMinimal`, `TestNormalizationDynamicAndUnknown`, `TestPSKIdentityRedaction` |
| FR-MODE-001: passthrough/observe | `TunnelHandler.Connect` | matrix: 2 клиентских × 3 upstream × 3 режима |
| FR-FAIL-001: отказ MITM-клиента | capture до TLS termination | `TestRecorderKeepsHelloWhenClientRejectsCA` |
| FR-DIFF-001: структурный diff | `recorder.Compare` | `TestDiff` |
| REL-QUEUE-001: bounded queue | `Recorder.TryCapture` | `TestQueueOverflowIsNonblocking`, `TestRecorderBoundsAndConcurrentClose` |
| SEC-RAW-001: raw opt-in | `Recorder.Options.Raw` | `TestRecorderExportAndPrivacy`, `TestParseExtensionVectorsAndPrivacy` |
| FR-EXPORT-001: JSONL и quota | recorder worker | `TestRecorderExportAndPrivacy`, `TestOutputQuotaAndMalformedCapture` |
| FR-API-001: поиск/detail/export/diff | `webpanel/recorder.go` | `TestRecorderAPI` |
| SEC-API-001: локальный доступ | bind/Host/peer/Origin checks | `TestRecorderRejectsRemoteAndRebinding` |
| FR-CLI-001: feature flag | runtime/CLI | `TestRecorderCLI` |
| FR-PROFILE-001: шаблон из пресета/наблюдения | `tlsprofile`, profile API/UI | `TestPresetPreviewAndJA4Editing`, `TestTLSProfileAPIWorkflow` |
| FR-PROFILE-002: версионирование/CAS | append-only profile store | `TestStoreVersioningPersistenceAndRouting`, `TestTLSProfileAPIWorkflow` |
| FR-VERIFY-001: expected ↔ фактический PROXY_OUT | `VerifyExpected` | `TestExpectedProfileVerificationStatuses`, `TestCustomTLSProfileProducesExpectedJA4AndVerification` |

### Границы захвата

`CLIENT_IN` наблюдает TLS после CONNECT/SOCKS, `PROXY_OUT` — после согласования upstream-протокола. Захватывается первый ClientHello; полный record, содержащий его конец, сохраняется целиком. Второй ClientHello после HelloRetryRequest/renegotiation пока не анализируется.

Успех `Write` означает приём байтов нижележащим `net.Conn`; он не доказывает получение удалённым сервером. В e2e-тестах есть независимое подтверждение с сервера.

Sniffer читает до 5 секунд, сохраняет прочитанное и возвращает replay connection. При non-TLS, malformed/oversized или timeout в режиме MITM применяется passthrough и фиксируется причина. Это может задержать server-first протокол на нестандартном SOCKS-порту до timeout. PASSTHROUGH/OBSERVE_ONLY используют пассивные wrappers без предварительного чтения.

При выключенном `--capture-tls` используется прежний путь распознавания TLS. Изменения глобального `--tls-mode` применяются при старте. Общая двухфазная таблица routing ещё не реализована.

### Версии fingerprints

- JA3: `JA3/1`; MD5 используется только как требуемый формат fingerprint, не как средство защиты.
- JA4: `FoxIO-JA4-TCP/2026-09-22`; только TLS/TCP. Реализация написана для этого проекта по [публичному описанию JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md); исходный код внешней реализации не импортируется. Опубликованный пример используется как внешний test vector.
- Реализация: `ja3proxy-recorder/1`.
- Нормализация: `TLS-NORM-1`.

JA3 учитывает extension 21 (padding). Прежний тестовый helper, восстанавливавший extension IDs через uTLS, терял padding; теперь он считывает IDs непосредственно из record bytes. Это исправление тестового oracle, а не изменение uTLS-пресетов.

### Точная схема TLS-NORM-1

Верхний объект: `ciphers`, `compression_methods`, `extensions`, `legacy_version`, `session_id_length`. Extension — ordered object `{id, fields}`; повторяющиеся IDs сохраняются. `id` — число либо строка `GREASE`. Наборы чисел и ALPN сохраняют исходный порядок.

Домен канонизации ограничен ASCII-ключами, ASCII-строками, целыми, booleans и arrays/objects. Opaque byte strings кодируются lowercase hex. В этом домене отсортированная сериализация JSON совпадает с требуемой канонической формой; общий Unicode/JCS serializer не заявляется.

- SNI исключается из hash по значению и длине; остаётся факт наличия extension.
- Random и session ID bytes исключаются, длина session ID сохраняется.
- Key shares сохраняют group и длину, без публичных ключей.
- PSK сохраняет длины identities/binders, без identities/binders/возраста tickets.
- GREASE нормализуется во всех распознанных числовых списках.
- ALPN — ordered hex strings, что сохраняет не-UTF-8 значения без потерь.
- Неизвестные extensions и ECH payload не интерпретируются; сохраняется тип/структурная длина. Равенство TLS-NORM не доказывает равенство этих opaque payloads.
- Padding сохраняет длину и позицию; ticket extension сохраняет длину; renegotiation_info — длину.

`normalized_sha256 = SHA256(UTF8("TLS-NORM-1\n") || canonical_json)`.
`raw_sha256` — SHA-256 handshake header + ClientHello body; `records_sha256` — SHA-256 record headers + полные захваченные record payloads. Для incomplete/malformed capture обычные JA3/JA4/normalized hashes не публикуются.

`Compare` сравнивает два наблюдения и возвращает MATCH, MISMATCH или UNKNOWN.
Отдельная проверка активного шаблона сравнивает materialized expected с
независимо захваченным `PROXY_OUT` по MUST/SHOULD политике и возвращает MATCH,
PARTIAL_MATCH, MISMATCH или UNKNOWN. В запись входят версии шаблона,
материализатора и нормализации, обе стороны сравнения и полный структурный
diff. Для массивов до 256 элементов обнаруживаются move; более длинные
изменённые массивы возвращаются как replace для ограничения стоимости.

### Редактируемые TLS-профили

Шаблон строится из uTLS-пресета или наблюдаемого ClientHello. Статические поля
редактируются в `/profiles.html`; preview материализует ClientHello и вычисляет
ожидаемые JA3/JA4/TLS-NORM. Неподдерживаемое расширение не игнорируется, а
помечает шаблон `UNSUPPORTED`. Случайные bytes, session ID, GREASE и key shares
явно считаются динамическими.

Конфигурация хранится как append-only последовательность полных snapshot в
`profiles/tls-templates.jsonl` (путь можно изменить). Записи защищены
`config_version` CAS. Для соединения snapshot профиля выбирается один раз;
изменения не переименовывают уже начатый handshake. Один активный профиль
может действовать для всех хостов или exact/`*.` patterns. Его ALPN на каждом
соединении пересекается с ALPN входящего клиента, а expected рассчитывается уже
по этому эффективному шаблону.

### Лимиты и отказоустойчивость

По умолчанию: ClientHello 256 KiB, TLS record 18 432 bytes, 64 records; queue 64 observations; окно 256 observations и максимум 32 MiB сериализованных данных. Поддерживаются limits через Go Options; CLI пока предоставляет основные switches. Очередь не ждёт свободного места, dropped events явно считаются. Закрытие recorder дренирует уже принятую очередь.

Это fail-open memory recorder; durable spool, безусловное сохранение critical events, SQL storage, config audit ещё отсутствуют. Статус `recording_degraded` показывает переполнение очереди или ошибки JSONL. JSONL после частичной ошибки записи больше не дописывается.

## Оставшиеся этапы ТЗ

1. Для полной приёмки MVP-0: реальный лицензированный corpus Safari/iOS/Android/OkHttp/OpenSSL, полная performance-матрица recorder-on/off (p95/throughput), lifecycle ID до protocol detection и дополнительные handshake-сценарии.
2. MVP-1: SQLite, миграции/retention, Device identity и привязка приложений; сейчас ID объединяет только пару TLS observations и создаётся при входе в tunnel handler.
3. MVP-2: остаются общий двухфазный route manager, приоритеты/несколько
   активных profiles/upstreams и полноценные runtime snapshots. Версионируемый
   TLS template, материализация expected и verification уже реализованы для
   одного активного профиля.
4. Release 1: PostgreSQL, users/roles/tokens, HTTPS, audit, encrypted spool, backup/recovery.
5. Поздние релизы: HTTP/1/2 fingerprints, ServerHello/JA3S/JA4S, TCP/DNS/QUIC
   sensors и families; базовый TLS template builder уже реализован.

Текущая панель доступна только локально; authentication/roles ещё нет. Контракт
реализованных read/write endpoints приведён в
[recorder-openapi.json](recorder-openapi.json). Он не описывает будущий полный
API центра управления из ТЗ.

## Проверки

```text
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
go test ./internal/ja3proxy/capture/tlshello -run ^$ -fuzz ^FuzzParse$ -fuzztime=15s -parallel=2
go test ./internal/ja3proxy/capture/tlshello -run ^$ -fuzz ^FuzzStream$ -fuzztime=15s -parallel=2
go test ./internal/ja3proxy/capture/tlshello -run ^$ -bench ^BenchmarkReassembly$ -benchmem
```

Для Windows race проверок требуется C compiler. В локальной проверке используется portable LLVM-MinGW с Go 1.26.6. SDK/кэши находятся в игнорируемых `.tools`, `.gocache`, `.gomodcache`.
