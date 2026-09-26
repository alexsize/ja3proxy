# Регистратор TLS: состояние реализации

Обновлено: 2026-09-25. Основа:
`JA3Proxy_Fingerprint_Recorder_TZ_v3.md` и его нормативные части.

Реализовано ядро первого этапа и локальный интерфейс для его проверки. Это не завершённый Control Center и не заявление о выполнении всех релизов ТЗ.
Текущий формальный статус критериев и benchmark baseline приведены в
[MVP0_ACCEPTANCE.md](MVP0_ACCEPTANCE.md).

## Единый backlog: текущая точка выполнения

Нормативный упорядоченный список задач находится в разделе 10
`JA3Proxy_Fingerprint_Recorder_TZ_v3.md`.

| № | Статус | Проверяемое основание / следующий шаг |
| --- | --- | --- |
| 1 | Реализовано локально; CI-прогон после публикации не проверен | Go 1.27.1 установлен в пользовательский каталог и добавлен первым в пользовательский PATH; имеющийся w64devkit 2.10.0 с GCC 16.2.0 также доступен через пользовательский PATH. На Windows/amd64 с `CGO_ENABLED=1` выполнены `gofmt` изменённых файлов, `go test ./...`, `go build ./...`, `go vet ./...` и полный `go test -race ./...` — все команды прошли. Нового CI-прогона после публикации изменений ещё нет. |
| 2 | Реализовано | Общая SQLite-БД используется для наблюдений при включённом `--capture-tls` (по умолчанию `state/ja3proxy.db`, путь задаётся через `--state-sqlite`; `--capture-sqlite` оставлен как явный alias/переопределение), TLS-отпечатка по умолчанию, устройств/назначений, TLS-профилей, маршрутов, upstream TLS и аудита. Snapshot store применяет версионируемую миграцию; legacy JSON/JSONL импортируется при отсутствии снимка, история TLS-профилей переносится. Есть тесты импорта, rollback, `integrity_check`, восстановления после перезапуска и runtime-конфигурации в одной БД: `TestControlStoresShareOneSQLiteDatabaseAcrossRestart`, `TestRuntimePersistsManagedStoresInSharedSQLite`, `TestSQLiteStoreSnapshotFailureRollsBackAndKeepsDatabaseHealthy`. Backup/recovery всей БД — отдельная задача Release 1, не часть критерия этого пункта. |
| 3 | Реализовано | Reassembly по фрагментам TCP/TLS record и границы parser покрыты `TestReassemblyEveryBoundary`, `TestMalformedAndLimits`, `FuzzStream`; passthrough/observe фиксирует последовательные ClientHello. MITM наблюдает HRR и следующий ClientHello даже при coalesced/fragmented ChangeCipherSpec; `TestRecordingConnCapturesSecondClientHelloAfterCompatibilityCCS` проверяет границы записи, `TestMITMClientHelloAfterHelloRetryRequestIsRecorded` — реальный TLS 1.3 handshake. |
| 4 | Реализовано | `TestRecorderOutboundWireThroughProxyMatrix` сравнивает PROXY_OUT record bytes с независимым захватом на тестовом TLS endpoint во всех комбинациях downstream/upstream/mode; дополнительно повторно разбирает те же raw bytes и проверяет JA4 и TLS-NORM. `TestCustomTLSProfileProducesExpectedJA4AndVerification` отделяет выбранный профиль и expected от реально вычисленного outbound fingerprint и проверяет фактический JA3 по wire. |
| 5 | Реализовано | TLS-шаблоны имеют `profile_mode: STRICT|ADAPTIVE` (старые шаблоны по умолчанию остаются ADAPTIVE). STRICT отклоняет конфликт ALPN/ALPS и изменения статических полей при сборке ClientHello с кодом `PROFILE_PROTOCOL_CONFLICT`; RANDOMIZED в STRICT запрещён как недетерминированный. ADAPTIVE записывает before/after/reason для ALPN, ALPS, extensions и иных статических полей при изменении uTLS. Старые hex-значения ALPS нормализуются при чтении JSONL/SQLite с обновлением expected fingerprint в памяти. Режим доступен в API/UI; проверки включают `TestStrictCompatiblePresetMaterializesWithoutMutation`, `TestMaterializationAuditsExtensionChangeAndStrictRejectsIt`, `TestStrictProfileProtocolConflictIsReported`, `TestOpenRepairsLegacyHexALPSWithoutChangingSourceHistory`. |
| 6 | Реализовано | TunnelHandler использует общий bounded uTLS session cache для upstream TLS с отдельными namespace по эффективному профилю и ALPN, исключая reuse ticket после смены профиля. `TestUpstreamTLS13SessionCacheRecordsResumptionClientHello` выполняет два отдельных TLS 1.3 соединения к loopback-серверу: первое FULL, второе предлагает PSK и реально возобновляет сессию на сервере и клиенте; каждый outbound ClientHello повторно разбирается и fingerprint рассчитывается с wire records. `TestUpstreamSessionCacheIsolatedByEffectiveProfile` проверяет изоляцию. Negotiated-state observation содержит `FULL`/`RESUMED` (`TLS-NEGOTIATED/2`), а ClientHello fingerprint отдельно сохраняет предложение `PSK`. |
| 7 | Реализовано | GET `/api/v1/fingerprint-families` и Recorder UI строят автоматические группы из всей сохранённой SQLite-истории постранично, добавляя незаписанные свежие события без дублирования; при отключённой SQLite используют окно памяти и явно возвращают scope. Группируются только входящие `CLIENT_IN` с разрешёнными `device_id` и приложением; варианты включают JA3/JA4, TLS-state и профиль/версию. HTTP-наблюдения присоединяются только по точному `connection_id`. Явные связи задаются одинаковым `family_id` в TLS-профилях, сохраняются в snapshot и истории версий; UI, API и OpenAPI показывают связанные профили, fingerprint и основание, а observation variant содержит ссылку на управляемое семейство. Проверки: `TestFingerprintFamiliesOnlyGroupStronglyIdentifiedInboundClientVariants`, `TestFingerprintFamiliesReadDurableHistoryBeyondMemoryWindow`, `TestManagedProfileFamiliesRequireMatchingExplicitID`, `TestFingerprintFamiliesAPIIncludesExplicitProfileLinks`, `TestTemplateRejectsMalformedExplicitFamilyID`; `TestOpenWithStateImportsLegacySnapshotsAndPreservesProfileHistory` проверяет миграцию/перезапуск SQLite. |
| 8 | Реализовано | CI отдельно запускает baseline-тесты профилей и фактического outbound wire. `internal/ja3proxy/tlsprofile/testdata/utls-profile-baseline.json` закрепляет версию uTLS, материализатор, JA3/JA4/TLS-NORM, cipher suites и порядок extensions для детерминированных профилей. `internal/ja3proxy/e2e/testdata/utls-wire-baseline.json` фиксирует JA3/JA4/TLS-NORM outbound ClientHello; `TestRecorderOutboundWireThroughProxyMatrix` сверяет fingerprint с независимым захватом на loopback TLS endpoint. При несовпадении тест сообщает expected/actual JSON, а изменение pin uTLS требует явного обновления baseline после ревью diff. |
| 9 | Частично реализовано; ждёт лицензированные fixtures | Бинарный opt-in тест `TestProxyBinaryLoadMatrix` повторно прошёл 2026-09-25 на Windows amd64 / Go 1.26.6: HTTP и SOCKS5, recorder off/on, 1600 запросов на вариант; все завершились, в recorder-on записано по 9600 наблюдений без потерь. Метрики текущего прогона внесены в `MVP0_ACCEPTANCE.md`. Один последовательный прогон не доказывает лимит overhead `<10%`. Реальные Safari/iOS и Android/OkHttp captures с подтверждённым правом распространения не предоставлены и не подменяются синтетикой. |
| 10 | Реализовано для lifecycle API-токенов и ролей | JSON token-file используется для первоначального импорта в общую SQLite, после чего SQLite является источником истины; секрет хранится как SHA-256. API и `/tokens.html` поддерживают list/create/update role+scopes/revoke/rotate без перезапуска, возвращая секрет только один раз при выдаче/ротации. Изменения проходят audit middleware и fail closed при недоступном audit store; last active admin нельзя отозвать или понизить. Loopback остаётся без обязательных auth/HTTPS; non-loopback требует HTTPS/Bearer и для token admin API — роль admin. Проверки: `TestTokenRegistryLifecyclePersistsHashesAndTakesEffectImmediately`, `TestEmptySQLiteTokenRegistryImportsBootstrapOnNextStart`, `TestTokenManagementRequiresAdminOutsideLoopback`, `TestLoopbackTokenManagementDoesNotRequireBearer`, `TestTokenMutationFailsClosedWithoutAudit`. Это token principals, не отдельная password/session учётная запись человека. |
| 11 | Реализовано в границах privacy-safe header fingerprint | HTTP/1-NORM-2 analyzer skips bounded Content-Length и chunked payload, валидирует framing/trailer syntax и продолжает поток; тела и trailer values не fingerprint-ятся. `Message` и recorder observation выставляют `completeness: partial`, `body_captured: false`, `body_framing` (`content_length`, `chunked`, `close_delimited`, `upgrade`, `unsupported_transfer_encoding`) и `trailer_status: not_fingerprinted`; bodyless messages остаются complete. Close-delimited/upgrade и неизвестные request transfer codings останавливают analyzer, чтобы не классифицировать body bytes как следующий запрос. Проверки: `TestAnalyzerSkipsContentLengthAndReadsNextMessage`, `TestAnalyzerSkipsFragmentedContentLengthBodyBeforeNextRequest`, `TestAnalyzerSkipsChunkedBodyAndTrailersAcrossFragments`, `TestAnalyzerRejectsMalformedChunkTrailer`, `TestAnalyzerStopsAtCloseDelimitedResponseBody`, `TestAnalyzerLabelsUnsupportedTransferEncoding`, `TestRecorderHTTP1Observation`. |
| 12 | Реализовано в документированных границах | H2-NORM-2 всегда помечен `partial`, HTTP/2 observation переносит этот статус в recorder. Добавлена coverage matrix: observed/not_observed/not_recorded/not_measured; закреплены SETTINGS/WINDOW_UPDATE и HPACK/PRIORITY golden hash-вектора; OpenAPI обновлён. Проверки: `TestAnalyzerCapturesPrefaceSettingsAndFrameOrder`, `TestAnalyzerCapturesPriorityAndKeepsHPACKStateAcrossBlocks`, `TestAnalyzerRejectsSettingsAckWithPayload`, `TestRecorderHTTP2Observation`. |
| 13 | Реализовано для целевых Windows/Linux сборок | `capture/tcp.ParsePacket` разбирает полные IPv4/IPv6 пакеты, отбирает начальный SYN (включая ECN-вариант), извлекает порядок TCP options и вычисляет `JA4T/1` в формате `window_options_mss_wscale`; пустые/отсутствующие поля `00`, дубли MSS/window-scale разрешаются последним значением. Windows использует Npcap source, Linux — native AF_PACKET; оба предоставляют список интерфейсов и runtime service `--capture-tcp-interface`. Перед TCP/DNS-анализом `FragmentReassembler` собирает IPv4/IPv6 fragments, поддерживает reorder/дубликаты, отклоняет overlap и ограничивает время/память. Linux capture требует системное право `CAP_NET_RAW`. Recorder сохраняет только метаданные и timestamp, без raw packet/payload. Другие ОС вне целевых Windows/Linux пока не поддержаны. Проверки: `TestParseIPv4SYNOptionsAndPrivacy`, `TestJA4TFormattingForMissingAndDuplicateOptions`, `TestParseIPv6WithDestinationOptions`, `TestParsePacketRejectsFragmentsAndMalformedOptions`, `TestFragmentReassemblerIPv4OutOfOrderAndDuplicate`, `TestFragmentReassemblerIPv6RemovesFragmentHeader`, `TestFragmentReassemblerRejectsOverlapAndEnforcesLimits`, `TestFragmentReassemblerExpiresIncompleteDatagrams`, `TestRunTCPRecordsCorrelatedLiveDNSUDP`; Windows Npcap interface enumeration проверена локально, Linux pcap package компилируется cross-target. |
| 14 | Реализовано | `capture/dns.Sensor` принимает UDP payload и полные length-prefixed TCP frames; `TCPStreamAssembler` собирает DNS-over-TCP из сегментов по sequence numbers, включая reorder и retransmit, с ограничениями на число потоков, буфер и срок жизни. Если capture начинается без SYN посреди DNS сообщения, assembler ищет следующий полностью валидный length-prefixed DNS frame и синхронизируется на нём; незавершённый начальный фрагмент пропускается, framing потока с наблюдаемым SYN остаётся строгим. Correlator сопоставляет запрос/ответ по client key, bidirectional flow ID, transport, DNS ID, вопросу и временному окну; потеря и неоднозначность явны. Windows Npcap и Linux AF_PACKET live capture передают IPv4/IPv6 UDP и TCP пакеты после IP fragment reassembly. Общий correlator связан с proxy TLS recorder: для фактических CLIENT_IN/PROXY_OUT ClientHello сохраняется имя только при совпадении client IP и destination A/AAAA answer с учётом TTL; CNAME-цепочки разрешаются до 16 переходов с учётом TTL каждой записи, включая ответы из разных DNS exchanges одного клиента; циклы завершаются без зацикливания, неоднозначность не угадывается. Если alias-имя активно, CNAME-target считается промежуточным и не создаёт ложную неоднозначность; после истечения TTL alias target снова может выступать самостоятельным именем. CNAME сохраняется как нормализованная запись, raw DNS bytes не сохраняются. Включать одновременно `--capture-tls` и `--capture-tcp-interface`. Проверки: `TestParseDNSQueryAndCompressedAResponse`, `TestParseDNSCompressedCNAMEAndRejectsMalformedRData`, `TestParseDNSTCPFrameAndRejectsMalformedCompression`, `TestCorrelatorHandlesReorderedEventsAndTTL`, `TestCorrelatorFollowsCNAMEAcrossExchangesAndHonorsEveryTTL`, `TestCorrelatorCNAMECycleAndAmbiguity`, `TestCorrelatorReportsAmbiguityAndPacketLoss`, `TestSensorAcceptsReorderedUDPAndProducesTLSCorrelation`, `TestParseDNSIPv4UDPPacketsAndBidirectionalFlow`, `TestParseDNSIPv6UDPAndRejectFragment`, `TestTCPStreamAssemblerReordersSegmentsAndExtractsMultipleFrames`, `TestTCPStreamAssemblerHandlesWraparoundAndRetransmission`, `TestTCPStreamAssemblerResynchronizesAfterMidstreamCapture`, `TestRunTCPRecordsDNSOverTCPAcrossSegments`, `TestTLSObservationPersistsMatchingDNSContext`. |
| 15 | Реализовано в границах QUIC Initial v1/v2 | `capture/quic` разбирает Initial-заголовок и Initial-пакет client-to-server, выводит ключи по RFC 9001/9369 (включая v2 salt/labels), снимает AES header protection, проверяет AEAD AES-128-GCM и обрабатывает PADDING/PING/ACK/ACK_ECN/CRYPTO/CONNECTION_CLOSE. Проверяются минимальный UDP payload 1200 bytes, обязательные transport parameters и нулевые reserved bits. CRYPTO chunks собираются по offset вне порядка в bounded per-flow буфере; запись создаётся только после полной проверки и разбора ClientHello. Из ClientHello извлекаются TLS metadata/SNI и QUIC transport parameters в wire-порядке: числовые параметры получают числовое значение, непрозрачные — только длину, raw token/CID/packet/CRYPTO bytes не сохраняются; connection ID observation — хэш потока. Live Windows/Linux capture использует тот же `--capture-tcp-interface`, результат сохраняется в общей recorder/SQLite как `QUIC_CLIENT_INITIAL`, OpenAPI описывает поля. Версии вне v1/v2, неверная AEAD authentication, неизвестные Initial frames и некорректные/неполные ClientHello не маркируются успешным наблюдением. Поддержка ограничена client Initial: Retry/version negotiation/server Initial, Handshake/0-RTT/1-RTT и JA4 для QUIC не реализованы; серверные transport parameters из EncryptedExtensions недоступны. Проверки: `TestDerivePublishedInitialKeysV1AndV2`, `TestDecryptInitialAndRejectUnsupportedVariants`, `TestParseIPv6UDPPacket`, `TestParseCryptoFramesAndRejectsUnsupportedFrame`, `TestSensorReassemblesClientHelloAndParsesTransportParameters`, `TestSensorRecognizesQUICv2AndRejectsShortInitialDatagrams`, `TestSensorDoesNotClaimAuthenticationFailureAsRecognized`, `TestRecorderQUICObservationStoresParsedMetadataWithoutRawBytes`. |
| 16 | Реализация внесена; проверки запуском ожидают toolchain | `--tls-keylog-file` требует `--capture-tls`; только upstream TLS 1.3 в `PASSTHROUGH`/`OBSERVE_ONLY` обрабатывает `SERVER_HANDSHAKE_TRAFFIC_SECRET` и расшифровывает AEAD record первого handshake message (EncryptedExtensions) для AES-128-GCM, AES-256-GCM и ChaCha20-Poly1305. Проверяются целостность AEAD, ClientHello random, размеры и структура extension vector, дубли extension IDs и ALPN. Расшифрованные поля объединяются с тем же ServerHello observation, JA3S/JA4S пересчитываются по дополненным данным; запись не утверждает успешное расшифрование без ключа. Key-log/secret/raw plaintext не сохраняются и очищаются из используемых буферов после обработки. Не покрыты renegotiation/post-handshake key updates и произвольный capture вне proxy TLS stream. Добавлены проверки: `TestParseEncryptedExtensionsAndRejectsDuplicateIDs`, `TestEncryptedExtensionsConnDecryptsWithMatchingKeyLogSecret`, `TestEncryptedExtensionsConnReportsMissingSecret`, `TestRecorderMergesDecryptedEncryptedExtensionsIntoServerHello`, плюс предыдущие проверки ServerHello; прогнать их нельзя до восстановления Go toolchain. |
| 17 | Реализация внесена; проверки запуском ожидают toolchain | HTTP/1 requests и HTTP/2 client header blocks извлекают до 8 структурированных product/version claims без сохранения исходного User-Agent; claims видны в JSON карточке наблюдения. Каждый claim содержит источник `http_user_agent`, `confidence=low`, `status=unverified`; общие маркеры Mozilla/WebKit/Gecko/Safari отфильтровываются, повторные пары удаляются, значение ограничено 4 КиБ. Наблюдаемый claim не назначается автоматически приложению/устройству и не используется маршрутизацией; подтверждённую версию оператор задаёт временным `device-assignment` через API, и только эта запись попадает в `application_version` и fingerprint families. User-Agent является самодекларируемым и может называть библиотеку/подменённое значение; автоматическая атрибуция каталогу приложений и OS/build inference не выполняются. Добавлены проверки: `TestFromUserAgentReturnsOnlyUnverifiedStructuredClaims`, `TestFromUserAgentIgnoresGenericTokensAndBoundsResults`, `TestAppendUserAgentDeduplicatesAndBoundsAcrossRequests`, `TestFromUserAgentRejectsOversizedHeaderValue`, `TestAnalyzerExtractsUnverifiedApplicationVersionWithoutRetainingUserAgent`, `TestAnalyzerExtractsUnverifiedVersionFromClientUserAgent`, `TestRecorderHTTP1Observation`, `TestRecorderHTTP2Observation`, существующие device assignment tests; прогнать их нельзя до восстановления Go toolchain. |

| 18 | Реализовано; полный локальный quality gate пройден | Recorder UI имеет выбор bounded-memory/полной SQLite-истории, поиск по безопасным полям наблюдения, фильтры устройства/приложения/подтверждённой версии/revision/интервала времени, типизированные карточки семи семейств с раскрываемым JSON, сравнение и повторный разбор ClientHello. API поддерживает `storage=sqlite` для деталей, сравнения и единичного reparse. Compare различает TLS ClientHello/ServerHello, HTTP/1, HTTP/2, TCP SYN/JA4T, DNS exchange и QUIC Initial; для сенсорных данных возвращает `PARTIAL_MATCH`, сравнивая профильные поля и игнорируя flow endpoints, timestamps, HTTP request target и sequence/stream/correlation IDs. OpenAPI и руководство описывают семейства, статусы и границы. Полный `go test ./...`, `go build ./...`, `go vet ./...` и `go test -race ./...` прошли в этой сессии на Windows/amd64 с Go 1.27.1 и `CGO_ENABLED=1`; новые unit/API-тесты включены в прогон. |
| 19 | Частично реализовано; Go quality gate пройден | Добавлен общий `secrets.Provider` и локальный `FileProvider` с проверкой regular-file и лимитом 1 МиБ. Интегрирован в загрузку bootstrap token file, ключа encrypted spool, CA key pair и HTTPS panel key pair; HTTPS-сертификат перечитывается на каждый новый TLS handshake. Срок действия MITM CA и HTTPS-сертификата панели вычисляется со статусами `VALID`/`EXPIRING`/`EXPIRED`/`NOT_YET_VALID` и отображается в `/api/state` и настройках панели; предупреждение `EXPIRING` выдаётся за 30 дней. Upstream username/password разрешаются через Provider из `file:` ссылок в URL userinfo при создании dialer, поддерживаются динамическим и route-specific upstream. Входящая proxy-аутентификация принимает пары `--proxy-username-file`/`--proxy-password-file` через Provider. Backup redaction удаляет URL userinfo целиком, включая ссылки и credentials. Целевые и полные unit-тесты, build, vet и race-прогон проверены. Не реализованы управляемая ротация MITM CA и spool key, атомарная публикация согласованных TLS key pairs, автоматическое продление сертификатов, expiry для spool key и других секретов и внешний secret backend. |

Проверка последних пунктов выявила и закрыла ошибки: DNS/TCP сверяет
перекрывающиеся сегменты и освобождает поглощённые chunks
(`TestTCPStreamAssemblerChecksPendingOverlapAndReleasesConsumedChunk`);
DNS-наблюдение получает `captured_at` из времени ответа или запроса
(`TestRecorderDNSExchangeObservationCopiesParsedFieldsOnly`). QUIC sensor
обрабатывает несколько Initial в одном UDP datagram, продолжает после
неаутентифицированного пакета и восстанавливает полный packet number по
наибольшему ранее проверенному в том же потоке
(`TestSensorProcessesCoalescedInitialsAndReconstructsPacketNumber`,
`TestSensorContinuesAfterInvalidCoalescedInitial`). Серверный TLS 1.3
`legacy_session_id_echo` больше не трактуется как доказательство resumption;
выбранный PSK без дополнительных данных имеет статус неопределённости
(`TestTLS13LegacySessionIDEchoDoesNotMeanResumption`,
`TestTLS13SelectedPSKDoesNotProveResumption`).

Остальные пункты backlog требуют повторной проверки непосредственно перед их
выполнением; этот документ не объявляет их выполненными или невыполненными без
сверки с критериями и тестами соответствующего пункта.

## Запуск

```powershell
.\bin\ja3proxy.exe --listen 127.0.0.1:8080 --capture-tls --web-panel 127.0.0.1:9090 --tls-fingerprint chrome@120
```

Открыть `http://127.0.0.1:9090/recorder.html`. Для passthrough добавить `--tls-mode PASSTHROUGH`, для наблюдения без MITM — `--tls-mode OBSERVE_ONLY`. `--tls-mode BLOCK` запрещает CONNECT/SOCKS-туннели до исходящего dial; обычный HTTP не относится к этой настройке.

Постоянный поток наблюдений в новый файл:

```powershell
.\bin\ja3proxy.exe --capture-tls --capture-jsonl capture-001.jsonl
```

Единая SQLite-база состояния по умолчанию находится в `state/ja3proxy.db`;
путь меняется через `--state-sqlite`. В ней хранятся профили, устройства,
маршруты, upstream TLS и аудит. Для хранения наблюдений в этой же БД включите
`--capture-tls`; по умолчанию наблюдения пишутся в `state/ja3proxy.db` вместе
с остальными данными проекта. Для явного выбора общей БД используйте
`--state-sqlite state/ja3proxy.db`; `--capture-sqlite` оставлен для обратной
совместимости и выбора пути общей БД. Retention по умолчанию —
100 000 observations.

Старый реестр можно однократно импортировать через `--device-map-file devices.json`.
После импорта источник истины — SQLite. Реестр имеет схему `device-registry/1`;
username имеет приоритет над source IP, неоднозначный mapping оставляет
`resolved_device_id` пустым.

`--capture-raw` дополнительно сохраняет raw handshake и TLS records (base64 в JSON). Без него raw хранится только временно для вычисления fingerprint. JSONL ограничен 256 MiB; существующий файл не перезаписывается. При достижении лимита экспорт прекращается, счётчик ошибок растёт, proxy продолжает работу. Окно памяти и файл экспорта — разные источники: HTTP export выгружает только текущее окно памяти.

JSONL пока не шифруется. Размещайте экспорт в контролируемом каталоге; raw содержит session identifiers/tickets. Для отказоустойчивости SQLite доступен явно включаемый AES-256-GCM spool с bounded quota; секретный provider и централизованное управление ключами относятся к следующим этапам.

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
| FR-STATE-001: единая SQLite-база managed state и versioned snapshots | `state.SQLiteStore`, device/TLS-profile/routing/upstream TLS stores | `TestSQLiteStorePersistsSnapshotsAndHistory`, `TestOpenWithStateImportsLegacyAndUsesSQLiteAsPrimary`, `TestOpenWithStateImportsLegacySnapshotsAndPreservesProfileHistory`, `TestStoreRestoresAndPersistsSQLiteRouteSnapshot`, `TestUpstreamTLSStoreRestoresAndPersistsSQLiteSnapshot`, `TestControlStoresShareOneSQLiteDatabaseAcrossRestart` |
| FR-SPOOL-001: зашифрованный bounded spool и replay после сбоя SQLite | `recorder.spoolStore` | `TestEncryptedSpoolRoundTripAndQuarantine`, `TestSpoolReplaysSQLiteAfterTransientFailure` |
| FR-QUEUE-002: классы доставки и наблюдаемость потерь/spool quota | `recorder.Stats`, `/metrics` | `TestQueueOverflowIsNonblocking`, `TestCriticalDeliveryUsesBoundedSpillQueue` |
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
| FR-ROUTING-003: POST_CLIENTHELLO route block before upstream handshake | `TunnelHandler.resolvePostTLSRoute` | `TestResolvePostTLSRouteUsesClientSNI` |
| FR-ROUTING-004: route action pins explicit TLS profile | `tlsprofile.Store.ResolveByID`, tunnel profile selection | TLS profile routing/e2e coverage |
| FR-ROUTING-005: PRE_TLS route selects upstream per tunnel | request-aware proxy dialer, cached route dialers | `TestDialRoutedTunnelUsesRouteUpstream`, proxy tunnel coverage |
| FR-ROUTING-006: recorder stores immutable two-phase route evidence | `recorder.RoutingSnapshot`, observation metadata | `TestRoutingSnapshotKeepsTwoPhaseEvidenceWithoutActionSecrets` |
| FR-ROUTING-007: POST_CLIENTHELLO route transitions tunnel mode after SNI | bounded ClientHello replay, `applyRouteMode` | `TestConnectWithRequestAppliesPostClientHelloPassthrough` |
| FR-ROUTING-008: POST_CLIENTHELLO route can replace upstream | `TunnelHandler.DialUpstream` | `TestConnectWithRequestAppliesPostClientHelloPassthrough` |
| FR-ROUTING-009: route references fail fast at startup | `App.validateRouteReferences` | `TestValidateRouteReferencesRejectsInvalidUpstream`, `TestValidateRouteReferencesRejectsUnavailableTLSProfile` |
| FR-ROUTING-010: OBSERVE_ONLY сохраняет режим и не эскалируется POST route | `applyPostRouteMode`, route evidence action metadata | `TestObserveOnlyRouteCannotBeEscalatedByPostRoute`, `TestRoutingSnapshotKeepsTwoPhaseEvidenceWithoutActionSecrets` |
| FR-ROUTING-011: route-specific capture failure policy | `capture_failure_policy`, bounded ClientHello failure handling | `TestCaptureFailurePolicy`, `TestValidateCaptureFailurePolicy` |
| FR-VERIFY-001: expected ↔ фактический PROXY_OUT | `VerifyExpected` | `TestExpectedProfileVerificationStatuses`, `TestCustomTLSProfileProducesExpectedJA4AndVerification` |
| FR-ENGINE-001.1: раздельные версии capture/parser/fingerprints/engine | version envelope observation/API | `TestRecorderExportAndPrivacy`, `TestObservationAttributesUTLSEngineOnlyToMITMOutbound`, `TestTLSEngineVersionMatchesModulePin`, `TestRecorderAPI` |
| FR-REPARSE-001.1: повторный разбор сохранённого RAW с immutable revision | `Recorder.Reparse`, `POST /api/v1/observations/{id}/reparse` | `TestRecorderReparseCreatesNewAnalysisRevision`, `TestReparseRequiresRaw`, `TestRecorderReparseAPI` |
| FR-SERVER-001: upstream ServerHello/JA3S observation | `WrapServerHello`, `SERVER_IN`, `ServerHelloFields` | `TestParseServerHelloAndCalculateJA3S`, `TestRecorderServerHelloObservation` |
| FR-SERVER-002: negotiated upstream TLS state after owned MITM handshake | `NegotiatedState`, `NEGOTIATED_STATE`, uTLS `ConnectionState` | `TestRecorderNegotiatedStateObservation`, `TestConnectMITMHandshakeAndRoundTrip` |
| FR-HTTP1-001: raw HTTP/1.x order/capitalization fingerprint with value privacy | `capture/http1`, MITM pipe wrappers, `HTTP1Fingerprint` | `TestAnalyzerPreservesHeaderOrderAndSpellingWithoutValues`, `TestAnalyzerSkipsChunkedBodyAndTrailersAcrossFragments`, `TestAnalyzerRejectsMalformedChunkFraming`, `TestRecorderHTTP1Observation` |
| FR-HTTP2-001: bounded H2-NORM-2 transport fingerprint with explicit coverage | `capture/http2`, MITM pipe wrappers, `HTTP2Fingerprint.availability` | `TestAnalyzerCapturesPrefaceSettingsAndFrameOrder`, `TestAnalyzerDecodesPseudoHeaderOrder`, `TestAnalyzerCapturesPriorityAndKeepsHPACKStateAcrossBlocks`, `TestAnalyzerRejectsPrioritySelfDependency`, `TestAnalyzerRejectsSettingsAckWithPayload`, `TestRecorderHTTP2Observation` |
| SEC-WEB-001: безопасный non-loopback web panel | `web-panel-cert/key`, bearer auth, HTTPS enforcement | `TestParseFlagsWebPanelTLS`, `TestServeRejectsRemoteWithoutAuthOrTLS` |
| FR-DYNAMIC-001.1: runtime ALPN/ALPS mutations фиксируются | `RuntimeMutation`, outbound recorder metadata | `TestLimitSpecALPN` |
| FR-DYNAMIC-001.2: явная ALPN policy PROFILE/DOWNSTREAM/INTERSECTION/CUSTOM | `StaticFields.ALPNPolicy`, `ConstrainALPN`, profile UI | `TestALPNPolicies`, `TestCustomALPNPolicyMaterializesConfiguredProtocols` |
| FR-DYNAMIC-001.3: ALPS согласован с ALPN и имеет явную policy | `StaticFields.ALPSPolicy`, wire parser, materializer | `TestALPSPolicies`, `TestALPSCannotOutliveEffectiveALPN` |
| FR-DYNAMIC-001.4: padding profile сохраняет presence/length/position при replay | `StaticFields.PaddingLength`, materializer | `TestCustomTLSProfileProducesExpectedJA4AndVerification` (5 повторов) |
| FR-RUNTIME-002: runtime config optimistic concurrency | `ConfigUpdate.ExpectedVersion`, runtime config version, HTTP 409 | `TestConfigAPIRequiresExpectedVersion`, `TestConfigAPIReportsVersionConflict`, `TestUpdateProxyConfigRejectsStaleExpectedVersionWithoutMutation` |
| FR-BACKUP-001: безопасный JSON/ZIP экспорт control-plane конфигурации | `GET /api/v1/export/config`, redaction upstream credentials | `TestConfigBackupRedactsUpstreamCredentials`, `TestConfigBackupZIPContainsJSON` |
| FR-AUDIT-001: append-only audit journal с SQLite и хеш-цепочкой | `audit.Store`, общая `--state-sqlite` база | `TestAppendQueryReopenAndRedact`, `TestSQLiteAuditReopenQueryAndIntegrity`, `TestSQLiteAuditImportsLegacyLogAndThenUsesDatabaseAsPrimary` |
| FR-AUDIT-002: локальный API аудита и фиксация действий панели | `GET /api/v1/audit`, audit request middleware | `TestAuditAPIRecordsMutationWithoutRequestSecrets` |
| SEC-AUTH-003: отзыв registry-токена без удаления записи | `AuthToken.Revoked`, file-backed registry | `TestTokenAuthRejectsRevokedRegistryToken` |

### Границы захвата

#### Матрица покрытия HTTP/2 `H2-NORM-2`

| Данные | Статус | Примечание |
|---|---|---|
| Client preface и типы фреймов | `observed` / `not_observed` | Только в пределах доступного bounded prefix; не является полным HTTP/2 trace. |
| Значения и порядок SETTINGS | `observed` / `not_observed` | ACK-фрейм проверяется отдельно и не считается набором настроек. |
| WINDOW_UPDATE: stream ID и increment | `observed` / `not_observed` | Время отправки не измеряется. |
| PRIORITY параметры и их позиция | `observed` / `not_observed` | Включая priority-параметры в HEADERS. |
| HPACK dynamic table size updates | `observed` / `not_observed` | Dynamic table хранится только в ограниченном decoder state для разбора блоков. |
| Порядок pseudo headers | `observed` / `not_observed` | Regular header names не попадают в fingerprint. |
| Значения заголовков и frame payload | `not_recorded` | Декодер читает HPACK значения только временно; в observation они не сериализуются. |
| Семантика неизвестных фреймов | `not_recorded` | Фиксируется только тип фрейма. |
| Timing/RTT и полный flow-control процесс | `not_measured` | Это не активный сетевой датчик и не packet capture. |

Каждое HTTP/2 observation имеет `completeness: partial`. Матрица и два
закреплённых hash-вектора проверяются тестами
`TestAnalyzerCapturesPrefaceSettingsAndFrameOrder` и
`TestAnalyzerCapturesPriorityAndKeepsHPACKStateAcrossBlocks`; при изменении
нормализации нужно обновить `H2-NORM` и намеренно пересмотреть эталонные hash.

TCP-парсер (`capture/tcp`) принимает IPv4/IPv6 пакеты и формирует `JA4T/1`;
на Windows Npcap и на Linux AF_PACKET capture service передают SYN metadata в
`Recorder.TryCaptureTCPSYN`. Для Linux требуется `CAP_NET_RAW`. Перед разбором
собираются IPv4/IPv6 fragments с проверкой перекрытий и ограничением памяти.
Сервис также передаёт собранные UDP DNS datagrams в DNS sensor. Захват
интерфейсов вне Windows/Linux, DNS-over-TCP stream reassembly и прикрепление
DNS/TLS correlation к proxy TLS observations ещё не реализованы; forwarding
не меняется.

DNS-NORM-1 принимает UDP DNS payload и length-prefixed DNS-over-TCP frames.
Windows Npcap и Linux AF_PACKET capture подают UDP/TCP DNS packets после IP
fragment reassembly; TCP stream assembler собирает кадры с учётом sequence
numbers, reorder и повторной передачи. Сопоставление query/response ограничено client key, нормализованным
двунаправленным flow ID, transport, transaction ID, вопросом и окном по
умолчанию 5 секунд. TLS destination сопоставляется с A/AAAA answer того же
client key с учётом TTL; если адресу соответствуют разные имена, результат
`ambiguous`. Потерянные половины отражаются как `unmatched_query` или
`unmatched_response` при вызове `Expire`. При совместном включении TLS recorder
и packet capture фактические CLIENT_IN/PROXY_OUT ClientHello получают связь с
недавними DNS A/AAAA ответами и CNAME-цепочками того же client IP и TLS
destination IP. Каждая запись учитывается только в пределах собственного TTL
(с общим верхним пределом хранения корреляции); цепочка ограничена 16 переходами,
циклы не обходятся бесконечно, неоднозначное имя не угадывается. Сохраняются
только разобранные вопросы, адресные ответы и CNAME-записи, не raw DNS datagrams.

`CLIENT_IN` наблюдает TLS после CONNECT/SOCKS, `PROXY_OUT` — после согласования upstream-протокола, а `SERVER_IN` — upstream ServerHello при чтении ответа сервера. Захватываются первый ClientHello и ServerHello-сообщения до завершения начального TLS 1.3 выбора (включая HRR); полный record, содержащий конец каждого сообщения, сохраняется целиком. Для passthrough/observe wrapper распознаёт последующие complete ClientHello и присваивает им `handshake_sequence`; в `MITM_REISSUE` фиксируются HRR локального TLS-сервера и следующий ClientHello с событием `CLIENT_HELLO_AFTER_HRR`. Application records не принимаются за ClientHello.

ServerHello-поля сериализуются как `value/source/available/reason`. ALPN, если
он отсутствует в ServerHello TLS 1.3, помечается `available=false` с причиной
`encrypted_without_keys`, а не удаляется без объяснения. Для server-side
наблюдений рассчитываются JA3S и versioned JA4S по доступным ServerHello-полям;
расшифровка passthrough EncryptedExtensions выполняется только с явным
`--tls-keylog-file`; без него сохраняется статус недоступности. После
завершённого собственного upstream handshake добавляется отдельное событие
`handshake_event=NEGOTIATED_STATE` с полем `negotiated_state`; в нём сохраняются
только version, cipher, ALPN, SNI, resumption и размер ALPS без raw bytes. В JA4S
используется `t` для TLS over TCP, negotiated version, число расширений,
first/last selected ALPN, выбранный cipher и ordered extension hash. При
недоступном ALPN используется `00`.
HelloRetryRequest и следующий ServerHello записываются отдельными
`SERVER_IN`-наблюдениями с `handshake_event` и порядковым
`handshake_sequence` в пределах соединения.
TLS 1.3 compatibility `ChangeCipherSpec`, который некоторые реализации
передают между этими двумя сообщениями, не считается ServerHello и
пропускается ограниченным parser-ом.

Успех `Write` означает приём байтов нижележащим `net.Conn`; он не доказывает получение удалённым сервером. В e2e-тестах есть независимое подтверждение с сервера.

Transport-flow получает ULID сразу после `Accept`, до чтения первого байта и
определения HTTP/SOCKS5. ID проходит через buffered/traffic wrappers и
используется обеими TLS-observation; прямой вызов tunnel handler сохраняет
совместимый fallback.

Sniffer читает до 5 секунд, сохраняет прочитанное и возвращает replay connection. При non-TLS, malformed/oversized или timeout в режиме MITM применяется passthrough и фиксируется причина. Это может задержать server-first протокол на нестандартном SOCKS-порту до timeout. PASSTHROUGH/OBSERVE_ONLY используют пассивные wrappers без предварительного чтения. Для них outbound observation содержит `forwarding`: только полное совпадение SHA-256 handshake bytes и TLS records получает `FORWARDED_UNCHANGED`; неполный захват получает `UNVERIFIED`. `byte_source` различает чтение client socket и успешную запись upstream socket.

При выключенном `--capture-tls` используется прежний путь распознавания TLS. Изменения глобального `--tls-mode` применяются при старте. Upstream TLS store выдаёт новую версию immutable snapshot при каждой конфигурации; исходящий MITM observation сохраняет `upstream_config_version` и evidence выбранного маршрута. Двухфазная таблица routing разрешается на immutable snapshot; PRE_TLS `action.upstream` выбирается до отправки успешного ответа CONNECT/SOCKS5. Для записанных наблюдений поле `routing` содержит версии snapshot и match evidence обеих фаз; секретные значения action туда не копируются.

### Версии fingerprints

- JA3: `JA3/1`; MD5 используется только как требуемый формат fingerprint, не как средство защиты.
- JA4: `FoxIO-JA4-TCP/2026-09-22`; только TLS/TCP. Реализация написана для этого проекта по [публичному описанию JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md); исходный код внешней реализации не импортируется. Опубликованный пример используется как внешний test vector.
- JA4S: `FoxIO-JA4S-TCP/2026-09-24`; только upstream TLS/TCP ServerHello. Реализация использует публично описанный формат JA4S: negotiated version, число server extensions, ALPN first/last, selected cipher и ordered extension hash; исходный код внешней реализации не импортируется. EncryptedExtensions учитываются только после явного расшифрования разрешённым key-log; без него ALPN остаётся недоступным.
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
окно; `GET /api/v1/observations?storage=sqlite` выполняет bounded paged search
по durable retention, а `/api/v1/export/observations?storage=sqlite` потоково
экспортирует JSONL/CSV. Полный reparse выполняется bounded-страницами через
`POST /api/v1/reparse/sqlite`: клиент повторяет запрос с `next_cursor`, пока
курсор не исчезнет. Обрабатываются только исходные `analysis_revision=1`, поэтому
повторный запуск не создаёт бесконечные цепочки производных ревизий; исходные
наблюдения не изменяются.

Для резервного копирования control-plane доступен `GET /api/v1/export/config`.
Форматы `json` и `zip` содержат runtime-состояние, device/application registry,
TLS profiles, routes и upstream TLS profiles, но не содержат telemetry; пароли и
секретные query-параметры upstream URL удаляются перед экспортом.

Перед восстановлением backup можно проверить через
`POST /api/v1/import/config/validate`. Endpoint принимает JSON или ZIP,
проверяет версии схем, device registry, TLS profiles, routes и upstream TLS,
но намеренно ничего не применяет; это отдельный безопасный preflight перед
будущим restore workflow.

После успешного preflight backup можно применить через
`POST /api/v1/import/config`. Для каждого компонента обязательна отдельная
`expected_*_version`; при конфликте возвращается `409`. Восстанавливаются
registry, TLS profiles, routes и upstream TLS snapshot. Runtime settings не
применяются, потому что backup намеренно не содержит proxy credentials.

Durable telemetry SQLite резервируется отдельно через
`GET /api/v1/export/telemetry`. Используется SQLite `VACUUM INTO`, поэтому
snapshot согласован даже при работающем recorder и не зависит от ручного
копирования WAL-файлов. Запись пачек и backup/restore сериализованы внутри
процесса, чтобы snapshot не конкурировал с незавершённой транзакцией recorder.
Endpoint требует scopes `export` и `raw`; активная
база намеренно не заменяется через web API во время записи.

Восстановление выполняется через `POST /api/v1/import/telemetry` с body
`application/vnd.sqlite3` или `application/octet-stream`. Snapshot сначала
проходит integrity/schema validation, затем observations импортируются
идемпотентно по `observation_id`; существующие записи не дублируются,
retention применяется после объединения. Endpoint требует scopes `write` и
`raw`, а активный SQLite-файл не подменяется.

Панель также ведёт append-only аудит действий и экспортов. События доступны
через `GET /api/v1/audit` и хранятся в общей `--state-sqlite` базе;
`--audit-sqlite` должен указывать на тот же файл. JSONL через `--audit-log`
используется только для однократного импорта старого журнала. Тела
HTTP-запросов в журнал не попадают, а значения полей с признаками
password/token/secret/raw заменяются на `[REDACTED]`. SQLite сохраняет ту же
SHA-256 хеш-цепочку, проверяет её при старте и поддерживает cursor pagination
после перезапуска.

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

Конфигурация хранится как версионируемая история snapshot в общей SQLite-БД;
старый `profiles/tls-templates.jsonl` импортируется однократно, если снимка в
БД ещё нет. Записи защищены `config_version` CAS. Для соединения snapshot
профиля выбирается один раз; изменения не переименовывают уже начатый
handshake. Один активный профиль может действовать для всех хостов или
exact/`*.` patterns.

`profile_mode=STRICT` запрещает несовместимую автоматическую адаптацию ALPN/ALPS;
handshake завершается с `PROFILE_PROTOCOL_CONFLICT`, а причина сохраняется в
observation с `completeness=policy_conflict`. `ADAPTIVE` (значение по умолчанию
для обратной совместимости) применяет заданные ALPN/ALPS policies. Каждый
фактический runtime diff записывается с before/after/reason в metadata outbound
наблюдения; expected вычисляется после адаптации.
Все опубликованные profile versions остаются доступны после update/delete.
Rollback создаёт очередную immutable version и записывает `based_on_version`.
Outbound observation содержит одновременно `profile_version` и
`config_version` выбранного snapshot.

Для явного связывания нескольких TLS-профилей задайте им одинаковое поле
`family_id` (1–64 символа: латиница, цифры, `._:-`). Одинаковое значение
сохраняется вместе с каждой версией профиля; одиночная метка не считается
семейством, пока к ней не привязаны минимум два профиля. Автоматические
наблюдаемые семейства доступны через `GET /api/v1/fingerprint-families`:
используются только входящие `CLIENT_IN` с разрешёнными устройством и
приложением; HTTP-наблюдения связываются только точным `connection_id`.
При включённой SQLite API странично читает всю retained history и дополняет её
свежими событиями памяти; raw ClientHello не включается в ответ семейства.

### Лимиты и отказоустойчивость

По умолчанию: ClientHello 256 KiB, TLS record 18 432 bytes, 64 records; две bounded очереди recorder по 8192 observations (настраиваемый предел — 65 536 каждая); окно 256 observations и максимум 32 MiB сериализованных данных. Поддерживаются limits через Go Options; CLI пока предоставляет основные switches. Очередь не ждёт свободного места, dropped events явно считаются. Закрытие recorder дренирует уже принятую очередь; SQLite получает готовую пачку до 1024 событий одной транзакцией.

Это fail-open recorder. При включённом `--capture-tls` наблюдения сохраняются в
общую SQLite-базу с versioned migration, индексами по времени/connection/capture point и
bounded retention (по умолчанию 100 000 записей); после перезапуска последние
наблюдения восстанавливаются в memory window. SQLite payload сохраняет тот же
versioned JSON envelope, а raw остаётся под флагом `--capture-raw`. Ошибка
SQLite не останавливает прокси и увеличивает `write_errors`; статус
`recording_degraded` показывает переполнение очереди или ошибки JSONL/SQLite.
JSONL после частичной ошибки записи больше не дописывается.

При явном `--capture-spool` ошибка SQLite дополнительно сохраняет observation в
зашифрованном AES-256-GCM spool с ограничением размера. При следующем запуске
spool replay-ится в SQLite, повторная вставка по `observation_id` безопасна,
повреждённые записи изолируются в `quarantine/`. Переполнение spool не
останавливает proxy и учитывается в `recording_degraded` и полях `spool_*`.

Каждое recorder-событие имеет класс доставки `CRITICAL`, `IMPORTANT` или
`OPTIONAL`; если класс не указан, TLS metadata считается `CRITICAL`. Статус
публикует `dropped_by_class` и `lost_by_class`, а `/metrics` — фиксированные метрики потерь по
классам, occupancy spool, quarantine и `spool_quota_failures`. Исчерпание
spool один раз создаёт high-severity событие `RECORDER_SPOOL_FULL`; data plane
при этом не ждёт записи на диск и остаётся fail-open.

При переполнении основной очереди `CRITICAL`-события сначала попадают в отдельную
bounded spill-очередь; `IMPORTANT` и `OPTIONAL` отбрасываются сразу. Spill также
неблокирующий и имеет отдельные `critical_queue_depth` и
`critical_spill_accepted` в статусе.

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
2. MVP-1: SQLite, миграции и retention для наблюдений включаются вместе с `--capture-tls`;
   identity evidence username/IP, явный mapping и time-bound application
   assignments сохраняются с confidence. Application catalog, timeline и
   фильтруемый JSONL/CSV export реализованы; автоматический сбор версии
   приложения ещё остаётся. Transport-flow ID создаётся сразу после `Accept`,
   до чтения протокола; прямой вызов tunnel handler без ID сохраняет fallback.
3. MVP-2: несколько одновременно активных upstreams и runtime snapshot всех
   route-фаз уже поддерживаются. Ядро resolver,
   локальный route tester, PRE_TLS mode/block/upstream и
   POST_CLIENTHELLO block до upstream handshake и явный `action.tls_profile`
   уже реализованы; для
   upstream TLS уже реализованы immutable config snapshots на connection и явная priority с
   детерминированным выбором
   `priority → exact host → wildcard → порядок в JSON`; TLS profile library
   также поддерживает несколько активных profiles с exact/wildcard priority.
   Версионируемый TLS template, материализация expected и verification также
   реализованы.
4. Release 1: полноценный lifecycle users/roles/tokens, централизованный secret provider и
   SQLite-based backup/recovery.
   Безопасный control-plane export/import, HTTPS, encrypted bounded spool,
   SQLite-backed audit и runtime token lifecycle реализованы. Token principals
   управляются из UI/API; отдельные password/session учётные записи людей и
   внешний secret provider остаются вне текущего контракта.
5. Поздние релизы: расширение покрытия TCP/JA4T и дальнейших TLS handshake-сообщений
   и DNS sensors (см. backlog 13–14), QUIC server/Handshake observation и остальные расширенные
   fingerprint families остаются нереализованными.
   HTTP/1 analyzer пропускает chunked-body/trailers и content-length body без
   сохранения payload; такие observations явно помечаются `partial`, trailers
   — `not_fingerprinted`. Close-delimited и upgrade bodies, а также неизвестные
   request transfer codings не разбираются дальше текущего сообщения и также
   не считаются полными. HTTP/2 сохраняет ограниченный fingerprint H2-NORM-2;
   его coverage/status поля и непокрываемые данные описаны в матрице выше.
   Сохраняются HPACK dynamic-table size updates и псевдозаголовки с
   непрерывным decoder state, а также priority/dependency и позиция WINDOW_UPDATE в последовательности фреймов. Декодер временно держит
   bounded HPACK dynamic table в памяти только для разбора последующих блоков;
   decoded values не входят в observation. Снимок ограничен 64 фреймами,
   1 МиБ на header block/table и 4096 metadata elements; wall-clock timing
   WINDOW_UPDATE не измеряется.
   TLS template builder поддерживает PRESET/OBSERVED/CUSTOM и отдельные
   RANDOMIZED-профили с режимами ALPN AUTO/REQUIRED/DISABLED; для RANDOMIZED
   expected fingerprint не подменяет фактически записанный PROXY_OUT JA3/JA4.
   Replay Lab реализован как отдельная проверка выбранного профиля против TLS
   endpoint с outbound wire capture и diff; он не участвует в production
   routing. Compatibility Matrix реализована как последовательный лабораторный
   прогон выбранных сохранённых профилей на одном endpoint; лабораторный Roller
   последовательно проверяет выбранный порядок и останавливается на первом
   успешном handshake, не участвуя в proxy routing. CI отдельным шагом
   проверяет закреплённые deterministic profile и фактический outbound wire
   baselines (`TestUTLSProfileBaseline` и `TestRecorderOutboundWireThroughProxyMatrix`);
   при drift тест печатает expected/actual JSON, а pin uTLS проверяется против
   fixture. Библиотечный
   `utls.Roller` не используется: его самостоятельный dial/handshake не проходит
   через захватный wrapper, необходимый для фиксации фактического wire fingerprint.
   Сохранённые профили версионируют uTLS при создании и последней проверке;
   runtime mismatch выставляет `PROFILE_REVALIDATION_REQUIRED` и исключает
   профиль из activation/resolution до успешного Replay Lab. Результаты
   `VALID`, `VALID_WITH_DIFFERENCES` и `INCOMPATIBLE` сохраняются, изменения
   профиля сбрасывают последнюю проверку. Replay Lab применяет MUST/SHOULD policy
   при классификации фактического wire ClientHello и возвращает конкретные
   несовпавшие пути MUST/SHOULD, нарушения constraints и normalized changes;
   Compatibility Matrix показывает эту классификацию для каждой попытки.

Loopback-панель работает без обязательных TLS и Bearer-аутентификации даже
при настроенном token registry. Non-loopback панель требует Bearer-токен и
HTTPS-сертификат. Поддерживается локальный
JSON-файл первичной загрузки нескольких токенов с ролями `viewer`, `operator`,
`investigator`, `admin` и scopes; затем token registry управляется через API/UI
и хранится в общей SQLite как SHA-256 digest. Создание, изменение роли/scopes,
отзыв, ротация и срок действия применяются без перезапуска. Внешний
secret provider и password/session учётные записи людей в этот контракт не
входят. Контракт
реализованных read/write endpoints приведён в
[recorder-openapi.json](recorder-openapi.json). Он не описывает будущий полный
API центра управления из ТЗ.

Audit middleware фиксирует `requested` до выполнения аудируемой операции и
итоговое `success`/`rejected` после неё. Если append-only журнал недоступен,
изменяющий обработчик не вызывается (`fail_closed`).

## Проверки

Регрессионный gate uTLS запускается отдельно в CI и локально так:

```powershell
go test ./internal/ja3proxy/tlsprofile -run '^TestUTLSProfileBaseline$' -count=1 -v
go test ./internal/ja3proxy/e2e -run '^TestRecorderOutboundWireThroughProxyMatrix$' -count=1 -v
```

При намеренном обновлении uTLS сначала проверьте diff тестов по профилям и
wire golden. Baseline следует менять только вместе с обновлением версии и
проверкой причин каждого изменившегося поля. Случайные/динамические wire-байты
не сравниваются целиком: gate фиксирует профильные поля и fingerprint,
вычисленный из ClientHello, который независимо увиден тестовым endpoint.

```text
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
go test ./internal/ja3proxy/capture/tlshello -run ^$ -fuzz ^FuzzParse$ -fuzztime=15s -parallel=2
go test ./internal/ja3proxy/capture/tlshello -run ^$ -fuzz ^FuzzStream$ -fuzztime=15s -parallel=2
go test ./internal/ja3proxy/capture/tlshello -run ^$ -bench ^BenchmarkReassembly$ -benchmem
go test ./internal/ja3proxy/capture/tlshello -run ^$ -bench ^BenchmarkRecordingConnOnOff$ -benchmem -count=5

# opt-in lower-level recorder load baseline
$env:JA3PROXY_PERF = "1"
$env:JA3PROXY_PERF_CONCURRENCY = "1000"
$env:JA3PROXY_PERF_DURATION = "5s"
go test ./internal/ja3proxy/recorder -run '^TestRecorderLoadBaseline$' -v
```

Для Windows race-проверок требуется C-компилятор и `CGO_ENABLED=1`. Локально используется GCC 16.2.0 из w64devkit 2.10.0 с Go 1.26.6; оба каталога добавлены в пользовательский PATH. После изменения PATH откройте новый терминал.
