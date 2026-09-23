# Регистратор TLS: состояние реализации

Обновлено: 2026-09-23. Основа:
`JA3Proxy_Fingerprint_Recorder_TZ_v3.md` и его нормативные части.

Реализовано ядро первого этапа и локальный интерфейс для его проверки. Это не завершённый Control Center и не заявление о выполнении всех релизов ТЗ.
Текущий формальный статус критериев и benchmark baseline приведены в
[MVP0_ACCEPTANCE.md](MVP0_ACCEPTANCE.md).

## Запуск

```powershell
.\bin\ja3proxy.exe --listen 127.0.0.1:8080 --capture-tls --web-panel 127.0.0.1:9090 --tls-fingerprint chrome@120
```

Открыть `http://127.0.0.1:9090/recorder.html`. Для passthrough добавить `--tls-mode PASSTHROUGH`, для наблюдения без MITM — `--tls-mode OBSERVE_ONLY`. `--tls-mode BLOCK` запрещает CONNECT/SOCKS-туннели до исходящего dial; обычный HTTP не относится к этой настройке.

Постоянный поток наблюдений в новый файл:

```powershell
.\bin\ja3proxy.exe --capture-tls --capture-jsonl capture-001.jsonl
```

Для durable-хранилища добавьте `--capture-sqlite recordings/recorder.db`.
SQLite открывается повторно после перезапуска, применяет versioned migration и
удерживает по умолчанию 100 000 последних observations.

Для явного device mapping добавьте `--device-map-file devices.json`. Реестр
имеет схему `device-registry/1`; username имеет приоритет над source IP,
неоднозначный mapping оставляет `resolved_device_id` пустым.

`--capture-raw` дополнительно сохраняет raw handshake и TLS records (base64 в JSON). Без него raw хранится только временно для вычисления fingerprint. JSONL ограничен 256 MiB; существующий файл не перезаписывается. При достижении лимита экспорт прекращается, счётчик ошибок растёт, proxy продолжает работу. Окно памяти и файл экспорта — разные источники: HTTP export выгружает только текущее окно памяти.

JSONL пока не шифруется. Размещайте экспорт в контролируемом каталоге; raw содержит session identifiers/tickets. Шифрованный spool и secret provider относятся к незавершённому Release 1.

## Реализованные компоненты

| Требование | Компонент | Проверка |
| --- | --- | --- |
| PR-TLS-001: TCP/TLS-record fragmentation | `capture/tlshello.Stream` | `TestReassemblyEveryBoundary`, `FuzzStream` |
| PR-TLS-002: bounded parsing и replay | `Stream`, `Sniff`, `Parse` | `TestMalformedAndLimits`, `TestSniffReplayAndTimeout`, `FuzzParse` |
| FR-CAP-001: входящий ClientHello | tunnel sniffer | `TestRecorderOutboundWireThroughProxyMatrix` |
| FR-CAP-002: успешные outbound Write bytes | `tlshello.Conn` | `TestRecordingConnShortWrites`, серверная проверка raw в matrix |
| FR-CONN-001: ID до protocol detection | `flowid`, `MixedProxyListener` | `TestMixedProxyListenerAssignsConnectionIDBeforeProtocolDetection`, `TestWrapAssignsOneStableIDThroughWrappers` |
| FR-IDENTITY-001: proxy username → source IP fallback с confidence | `flowid`, proxy auth, recorder metadata | `TestProxyUsernameSurvivesTransparentWrappers`, `TestApplyIdentityEvidenceUsesUsernameThenSourceIP` |
| FR-DEVICE-001: explicit device mapping с username/IP priority и CAS CRUD | `device.Store`, tunnel resolver, Device Manager API | `TestOpenAndResolveDeviceMappings`, `TestAmbiguousUsernameDoesNotFallBackToIP`, `TestMutationsPersistAndRejectStaleVersions`, `TestDeviceManagerAPI` |
| FR-DEVICE-002: time-bound device/application/version assignment | `device.Store`, recorder identity metadata, assignment API | `TestApplicationAssignmentsAreTimeBound`, `TestDeviceAssignmentAPI` |
| FR-DEVICE-003: application catalog and assignment references | `device.Store`, application API | `TestApplicationCatalogAssignmentReference`, `TestApplicationCatalogAPI` |
| FR-TIMELINE-001: fingerprint timeline and change markers | `fingerprintTimeline`, timeline API | `TestFingerprintTimelineMarksChangesAndAppliesFilters` |
| FR-EXPORT-002: filtered JSONL/CSV observation export | observation filters, export API | `TestRecorderAPI` |
| FR-FP-001: JA3/JA4 | `Calculate` | `TestGoldenMinimal`, `TestJA4PublishedVector`, независимый e2e JA3 parser |
| FR-SESSION-001: варианты FULL/RESUMED/PSK и PSK metadata | `Hello`/`Fingerprints` model | `TestPSKIdentityRedaction`, `TestResumedHandshakeVariantCanBeDeclared` |
| FR-SESSION-002: PSK presets явно отделены от full-handshake | fingerprint catalog/API/UI | `TestPSKPresetsAreMarkedAsResumptionProfiles` |
| FR-PQ-001: PQ/unknown groups сохраняют numeric ID и имя | parser decoded metadata | `TestPostQuantumAndUnknownGroupsKeepNumericNames` |
| FR-FP-002: TLS-NORM-1 | `Normalize` | `TestGoldenMinimal`, `TestNormalizationDynamicAndUnknown`, `TestPSKIdentityRedaction` |
| FR-MODE-001: passthrough/observe | `TunnelHandler.Connect` | matrix: 2 клиентских × 3 upstream × 3 режима |
| FR-MODE-002: доказательство forwarded unchanged | forwarding verification | `TestForwardingVerification`, matrix passthrough/observe |
| FR-FAIL-001: отказ MITM-клиента | capture до TLS termination | `TestRecorderKeepsHelloWhenClientRejectsCA` |
| FR-DIFF-001: структурный diff | `recorder.Compare` | `TestDiff` |
| REL-QUEUE-001: bounded queue | `Recorder.TryCapture` | `TestQueueOverflowIsNonblocking`, `TestRecorderBoundsAndConcurrentClose` |
| SEC-RAW-001: raw opt-in | `Recorder.Options.Raw` | `TestRecorderExportAndPrivacy`, `TestParseExtensionVectorsAndPrivacy` |
| FR-EXPORT-001: JSONL и quota | recorder worker | `TestRecorderExportAndPrivacy`, `TestOutputQuotaAndMalformedCapture` |
| FR-STORE-001: SQLite persistence/migrations/retention | `recorder.sqliteStore` | `TestSQLitePersistenceReopenAndRetention`, `TestSQLitePreservesPrivacyPolicyAcrossReopen` |
| FR-API-001: поиск/detail/export/diff | `webpanel/recorder.go` | `TestRecorderAPI` |
| SEC-API-001: локальный доступ | bind/Host/peer/Origin checks | `TestRecorderRejectsRemoteAndRebinding` |
| SEC-CANARY-001: секреты не отражаются в API/error | config API, HTTP upstream dialer | `TestConfigAPIUpdatesRuntimeConfiguration`, `TestHTTPUpstreamCONNECTErrorDoesNotExposeResponseBodyCanary` |
| SEC-CANARY-002: секреты не отражаются в логах | централизованный `logutil.NewSanitizedHandler` | `TestSanitizedHandlerRedactsAttributesAndErrors`, `TestSanitizedHandlerRedactsNestedGroups` |
| FR-CLI-001: feature flag | runtime/CLI | `TestRecorderCLI` |
| FR-PROFILE-001: шаблон из пресета/наблюдения | `tlsprofile`, profile API/UI | `TestPresetPreviewAndJA4Editing`, `TestTLSProfileAPIWorkflow` |
| FR-PROFILE-002: immutable versions/CAS/rollback | append-only profile store | `TestStoreVersioningPersistenceAndRouting`, `TestTLSProfileHistoryAndRollbackAPI` |
| FR-PROFILE-003: source replayability/constraints | materializer + verification | `TestObservedSourceMustMatchIsCheckedBeforePublish`, `TestTemplateConstraintsAreValidated` |
| FR-PROFILE-004: multiple active profiles with host priority | `tlsprofile.Store.ResolveWithVersion`, `ActivateMany` | `TestStoreResolvesMultipleActiveProfilesByHostPriority`, `TestTLSProfileMultiActivationAPI` |
| FR-UPSTREAM-001: explicit upstream TLS route priority | `upstreamtls.UpstreamTLSProfileStore` | `TestUpstreamTLSRoutesUsePriorityThenHostSpecificity` |
| FR-RUNTIME-001: immutable upstream TLS config snapshot per connection | `UpstreamTLSProfileStore.GetWithVersion`, recorder metadata | `TestUpstreamTLSStoreVersionsAreImmutableSnapshots`, `TestConfiguredUpstreamTLSProfileReturnsSnapshotVersion` |
| FR-ROUTE-OBS-001: matched upstream route evidence | `UpstreamTLSProfileStore.Resolve`, recorder metadata | `TestUpstreamTLSResolveReturnsRouteEvidence`, `TestConfiguredUpstreamTLSResolutionReturnsRouteEvidence`, e2e verification |
| FR-ROUTING-001: two-phase route resolver and route tester | `routing.Store`, `POST /api/v1/routes/test` | `TestStoreResolvesTwoPhaseRulesByPriorityAndSpecificity`, `TestStoreMatchesCIDRPortDeviceTagAndUsername`, `TestRouteTestAPIResolvesConfiguredRule` |
| FR-ROUTING-002: PRE_TLS route action applies per connection | contextual tunnel request, `TunnelHandler.ConnectWithRequest` | `TestConnectWithRequestAppliesRouteBlock`, proxy/e2e matrix |
| FR-VERIFY-001: expected ↔ фактический PROXY_OUT | `VerifyExpected` | `TestExpectedProfileVerificationStatuses`, `TestCustomTLSProfileProducesExpectedJA4AndVerification` |
| FR-ENGINE-001.1: раздельные версии capture/parser/fingerprints/engine | version envelope observation/API | `TestRecorderExportAndPrivacy`, `TestObservationAttributesUTLSEngineOnlyToMITMOutbound`, `TestTLSEngineVersionMatchesModulePin`, `TestRecorderAPI` |
| FR-REPARSE-001.1: повторный разбор сохранённого RAW с immutable revision | `Recorder.Reparse`, `POST /api/v1/observations/{id}/reparse` | `TestRecorderReparseCreatesNewAnalysisRevision`, `TestReparseRequiresRaw`, `TestRecorderReparseAPI` |
| FR-DYNAMIC-001.1: runtime ALPN/ALPS mutations фиксируются | `RuntimeMutation`, outbound recorder metadata | `TestLimitSpecALPN` |
| FR-DYNAMIC-001.2: явная ALPN policy PROFILE/DOWNSTREAM/INTERSECTION/CUSTOM | `StaticFields.ALPNPolicy`, `ConstrainALPN`, profile UI | `TestALPNPolicies`, `TestCustomALPNPolicyMaterializesConfiguredProtocols` |
| FR-DYNAMIC-001.3: ALPS согласован с ALPN и имеет явную policy | `StaticFields.ALPSPolicy`, wire parser, materializer | `TestALPSPolicies`, `TestALPSCannotOutliveEffectiveALPN` |

### Границы захвата

`CLIENT_IN` наблюдает TLS после CONNECT/SOCKS, `PROXY_OUT` — после согласования upstream-протокола. Захватывается первый ClientHello; полный record, содержащий его конец, сохраняется целиком. Второй ClientHello после HelloRetryRequest/renegotiation пока не анализируется.

Успех `Write` означает приём байтов нижележащим `net.Conn`; он не доказывает получение удалённым сервером. В e2e-тестах есть независимое подтверждение с сервера.

Transport-flow получает ULID сразу после `Accept`, до чтения первого байта и
определения HTTP/SOCKS5. ID проходит через buffered/traffic wrappers и
используется обеими TLS-observation; прямой вызов tunnel handler сохраняет
совместимый fallback.

Sniffer читает до 5 секунд, сохраняет прочитанное и возвращает replay connection. При non-TLS, malformed/oversized или timeout в режиме MITM применяется passthrough и фиксируется причина. Это может задержать server-first протокол на нестандартном SOCKS-порту до timeout. PASSTHROUGH/OBSERVE_ONLY используют пассивные wrappers без предварительного чтения. Для них outbound observation содержит `forwarding`: только полное совпадение SHA-256 handshake bytes и TLS records получает `FORWARDED_UNCHANGED`; неполный захват получает `UNVERIFIED`. `byte_source` различает чтение client socket и успешную запись upstream socket.

При выключенном `--capture-tls` используется прежний путь распознавания TLS. Изменения глобального `--tls-mode` применяются при старте. Upstream TLS store выдаёт новую версию immutable snapshot при каждой конфигурации; исходящий MITM observation сохраняет `upstream_config_version` и evidence выбранного маршрута. Общая двухфазная таблица routing ещё не реализована.

### Версии fingerprints

- JA3: `JA3/1`; MD5 используется только как требуемый формат fingerprint, не как средство защиты.
- JA4: `FoxIO-JA4-TCP/2026-09-22`; только TLS/TCP. Реализация написана для этого проекта по [публичному описанию JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md); исходный код внешней реализации не импортируется. Опубликованный пример используется как внешний test vector.
- Реализация: `ja3proxy-recorder/1`.
- Формат capture: `1`; parser: `1.0.0`; schema observation: `tls-observation/2`.
- Нормализация: `TLS-NORM-1`.

Каждая observation содержит отдельные `capture_version`, `parser_version`,
`ja3_version`, `ja4_version`, `tls_norm_version`, `tls_engine` и
`tls_engine_version`. Только исходящий `MITM_REISSUE` помечается как
`utls@v1.8.2`; входящие и транзитные ClientHello честно отмечаются как
`external@unknown`.

При включённом raw capture сохранённую observation можно повторно разобрать
через `POST /api/v1/observations/{id}/reparse`. Исходная запись не меняется;
создаётся новая запись с `analysis_revision` и `analysis_parent_id`. Если RAW
не сохранялся, API возвращает `422`. При включённом SQLite сохраняется тот же
versioned JSON envelope и после перезапуска восстанавливается последнее bounded
окно; отдельный исторический SQL-поиск и reparse всей базы остаются следующим
этапом.

При runtime-ограничении preset под downstream-протокол recorder сохраняет
`runtime_mutations` с типом события, полем, значениями `before`/`after` и
причиной. Сейчас покрыты ALPN и ALPS-изменения в uTLS preset path.

TLS-профиль теперь явно задаёт `fields.alpn_policy`: `PROFILE` сохраняет
ALPN профиля, `DOWNSTREAM` использует ALPN клиента, `INTERSECTION` оставляет
пересечение, а `CUSTOM` использует `fields.custom_alpn`. Пустая policy у
старых snapshot нормализуется в `INTERSECTION`.

Для ALPS действует отдельная `fields.alps_policy` с теми же четырьмя режимами.
ALPS разбирается из wire как ordered protocol list. Перед materialization и
handshake список ALPS пересекается с эффективным ALPN; поэтому протокол,
удалённый из ALPN, не может остаться в ApplicationSettingsExtension. Режим
`CUSTOM` отклоняется при несовместимости, а профильные режимы безопасно
отбрасывают недоступные downstream-протоколы.

JA3 учитывает extension 21 (padding). Прежний тестовый helper, восстанавливавший extension IDs через uTLS, терял padding; теперь он считывает IDs непосредственно из record bytes. Это исправление тестового oracle, а не изменение uTLS-пресетов.

Fingerprint model также публикует `handshake_type` (`FULL`, `RESUMED` или
`PSK`), `session_resumption`, `psk_present`, `psk_identity_count` и
`early_data`. В ClientHello-only capture тип `PSK` определяется по
`pre_shared_key`, а `RESUMED` может быть выставлен только внешним handshake
state, когда он подтверждён последующими сообщениями. Сами PSK identities,
ticket и binder bytes не публикуются. Автоматическое объединение наблюдений в
Fingerprint Family намеренно не включено без утверждённого алгоритма family.

Каталог uTLS-пресетов публикует тот же признак `handshake_type`: версии с
`PSK` в идентификаторе отображаются в UI отдельной группой `PSK / resumption
profile`, а обычные версии — как `full-handshake profile`. Старые JSON-файлы
без этого поля нормализуются по версии пресета.

`supported_groups` и `key_share` сохраняют numeric ID без ограничения
классическими группами. Для известных значений добавляется
`resolved_name` (включая `x25519_mlkem768`), а для будущих/неизвестных —
`resolved_name: "unknown"`; это decoded metadata и не меняет стабильный
numeric TLS-NORM-1.

Источники golden/runtime-векторов, их лицензии и тесты перечислены в
`internal/ja3proxy/capture/tlshello/testdata/clienthello-corpus/manifest.json`.
Манифест является проверяемым тестом и не называет uTLS materialization
реальным браузерным capture.

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
Проверка также применяет constraints `present`, `equals`, `one_of` и отклоняет
несовместимые версии profile schema, materializer и normalization.

### Редактируемые TLS-профили

Шаблон строится из uTLS-пресета или наблюдаемого ClientHello. Статические поля
редактируются в `/profiles.html`; preview материализует ClientHello и вычисляет
ожидаемые JA3/JA4/TLS-NORM. Неподдерживаемое расширение не игнорируется, а
помечает шаблон `UNSUPPORTED`. Случайные bytes, session ID, GREASE и key shares
явно считаются динамическими.

Для профиля из observation сохраняются source JA3/JA4/TLS-NORM и SNI,
использованный для preview. Materialized MUST-поля сравниваются с source до
публикации; невоспроизводимый payload не маскируется базовым пресетом.

Конфигурация хранится как append-only последовательность полных snapshot в
`profiles/tls-templates.jsonl` (путь можно изменить). Записи защищены
`config_version` CAS. Для соединения snapshot профиля выбирается один раз;
изменения не переименовывают уже начатый handshake. Один активный профиль
может действовать для всех хостов или exact/`*.` patterns. Его ALPN на каждом
соединении пересекается с ALPN входящего клиента, а expected рассчитывается уже
по этому эффективному шаблону.
Все опубликованные profile versions остаются доступны после update/delete.
Rollback создаёт очередную immutable version и записывает `based_on_version`.
Outbound observation содержит одновременно `profile_version` и
`config_version` выбранного snapshot.

### Лимиты и отказоустойчивость

По умолчанию: ClientHello 256 KiB, TLS record 18 432 bytes, 64 records; queue 64 observations; окно 256 observations и максимум 32 MiB сериализованных данных. Поддерживаются limits через Go Options; CLI пока предоставляет основные switches. Очередь не ждёт свободного места, dropped events явно считаются. Закрытие recorder дренирует уже принятую очередь.

Это fail-open recorder. По явному `--capture-sqlite` наблюдения сохраняются в
SQLite с versioned migration, индексами по времени/connection/capture point и
bounded retention (по умолчанию 100 000 записей); после перезапуска последние
наблюдения восстанавливаются в memory window. SQLite payload сохраняет тот же
versioned JSON envelope, а raw остаётся под флагом `--capture-raw`. Ошибка
SQLite не останавливает прокси и увеличивает `write_errors`; статус
`recording_degraded` показывает переполнение очереди или ошибки JSONL/SQLite.
JSONL после частичной ошибки записи больше не дописывается.

Логирование проходит через центральный sanitizing `slog.Handler`: секретные
атрибуты (`password`, `token`, `authorization`, raw/data, ticket/binder и
подобные) заменяются на `[REDACTED]`, включая значения из `Logger.With` и
вложенных групп. В строках ошибок дополнительно удаляются credentials из URL и
Bearer/Basic значения до передачи записи в backend.

## Оставшиеся этапы ТЗ

1. Для полной приёмки MVP-0: реальные лицензированные captures Safari/iOS и
   Android/OkHttp, полная performance-матрица
   recorder-on/off (p95/throughput) и дополнительные handshake-сценарии.
   Текущий versioned corpus manifest честно отделяет runtime wire captures,
   published vector и synthetic fixtures и перечисляет оставшиеся пробелы.
2. MVP-1: SQLite, миграции и retention реализованы через `--capture-sqlite`;
   identity evidence username/IP, явный mapping и time-bound application
   assignments сохраняются с confidence. Application catalog, timeline и
   фильтруемый JSONL/CSV export реализованы; автоматический сбор версии
   приложения ещё остаётся. Сейчас ID объединяет
   только пару TLS observations и создаётся при входе в tunnel handler.
3. MVP-2: остаётся POST_CLIENTHELLO action transition, выбор upstream по route
   action, несколько одновременно активных upstreams и полный runtime snapshot
   всех route-фаз. Ядро resolver, локальный route tester и применение PRE_TLS
   mode/block уже реализованы; для
   upstream TLS уже реализованы immutable config snapshots на connection и явная priority с
   детерминированным выбором
   `priority → exact host → wildcard → порядок в JSON`; TLS profile library
   также поддерживает несколько активных profiles с exact/wildcard priority.
   Версионируемый TLS template, материализация expected и verification также
   реализованы.
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
go test ./internal/ja3proxy/capture/tlshello -run ^$ -bench ^BenchmarkRecordingConnOnOff$ -benchmem -count=5
```

Для Windows race проверок требуется C compiler. В локальной проверке используется portable LLVM-MinGW с Go 1.26.6. SDK/кэши находятся в игнорируемых `.tools`, `.gocache`, `.gomodcache`.
