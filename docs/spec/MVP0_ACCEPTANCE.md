# Отчёт приёмки MVP-0

Дата проверки: 2026-09-24

Проверенный кодовый baseline: `d36903e806c1e836edb6f75f02cc44e7d0b8cd63`

Среда: Windows amd64, Go 1.26.6, OpenSSL 3.5.5.

Статус: **условно готово, формальная приёмка ещё не закрыта**. Реализованы и
автоматически проверяются runtime-требования ядра. Для окончательной приёмки
нужны реальные лицензированные Safari/iOS и Android/OkHttp captures, а также
полный нагрузочный recorder-off/recorder-on прогон с throughput и latency
percentiles.

## Критерии ТЗ

| № | Критерий | Статус | Доказательство |
| --- | --- | --- | --- |
| 1 | HTTP/HTTPS/SOCKS5 regression | PASS | `go test ./...`; e2e и proxy packages |
| 2 | TLS 1.2/1.3, fragmentation, unknown, GREASE, malformed, limits | PARTIAL | unit/fuzz/OpenSSL golden проходят; реальных Safari/Android fixtures пока нет |
| 3 | точный CLIENT_IN capture | PASS | reassembly tests и recorder e2e matrix |
| 4 | фактически записанный PROXY_OUT | PASS | `TestRecordingConnShortWrites` |
| 5 | независимая wire-проверка | PASS | `TestRecorderOutboundWireThroughProxyMatrix` |
| 6 | JA3/JA4/TLS-NORM из captured bytes | PASS | golden tests, включая OpenSSL fixture |
| 7 | ordered TLS structure и dynamic descriptors | PASS | parser/normalization privacy tests |
| 8 | однозначные hash inputs | PASS | документированный TLS-NORM и golden hashes |
| 9 | deterministic structured diff | PASS | `TestDiff` |
| 10 | PASSTHROUGH не меняет bytes | PASS | forwarding verification и e2e matrix |
| 11 | bounded timeout/overflow/malformed | PASS | limits, queue overflow и fuzz tests |
| 12 | recorder feature flag | PASS | runtime/CLI tests |
| 13 | race-enabled tests | PASS | `go test -race ./... -count=1` |
| 14 | sensitive canaries | PASS | raw/API/upstream-error и централизованный `slog.Handler` sanitizer покрыты тестами |

Дополнительно закрыт реальный in-process TLS 1.3 сценарий с
`HelloRetryRequest`: upstream-сервер выбирает P-256 после первого X25519
key share, а `SERVER_IN` сохраняет HRR и финальный `ServerHello` как события с
последовательностями 1 и 2. Между ними корректно пропускается обязательный
compatibility `ChangeCipherSpec` record.

Transport-flow ID теперь создаётся сразу после `Accept`, до чтения первого
байта и protocol detection. Формат — ULID; одно значение проходит через
buffered и traffic wrappers до CLIENT_IN/PROXY_OUT observation.

## Corpus и provenance

Нормативный manifest находится в
`internal/ja3proxy/capture/tlshello/testdata/clienthello-corpus/manifest.json`.
Его полнота и уникальность ID проверяются тестом. Сохранённый реальный OpenSSL
TLS 1.3 record имеет закреплённые результаты:

```text
JA3 hash:          7c5d0596cedb9c086e8bebef099e73dc
JA4:               t13d031100_55b375c5d22e_199193a2bd39
TLS-NORM-1 SHA256: 95d6362dbb1528cc15537663a9d82b8f463cb36c1cb6361594779fe694ccc8d1
```

## Выполненные проверки

```text
go test ./... -count=1                                      PASS
go vet ./...                                                PASS
go test -race ./... -count=1                                PASS (baseline; current host requires gcc/clang)
FuzzParse, 5 секунд                                         PASS
FuzzStream, 5 секунд                                        PASS
OpenSSL corpus golden                                       PASS
TLS 1.3 HelloRetryRequest через MITM и `SERVER_IN`           PASS
```

Команда сценария HRR:

```powershell
go test ./internal/ja3proxy/tunnel -run '^TestConnectMITMHandshakeRecordsTLS13HelloRetryRequest$' -count=1 -v
```

## Microbenchmark baseline

Команда:

```powershell
go test ./internal/ja3proxy/capture/tlshello -run '^$' `
  -bench 'Benchmark(Reassembly|RecordingConnOnOff)$' -benchmem -count=5
```

| Benchmark | min | median | max | memory |
| --- | ---: | ---: | ---: | ---: |
| Reassembly | 77.08 ns/op | 91.77 ns/op | 102.3 ns/op | 128 B/op, 4 allocs |
| RecordingConn, recorder on | 186.8 ns/op | 201.8 ns/op | 223.5 ns/op | 352 B/op, 6 allocs |

Ветка `recorder_off` измеряет практически пустой `net.Conn.Write` и попадает в
compiler/timer floor, поэтому отношение on/off намеренно не заявляется как
производственный overhead. Этот microbenchmark ловит регрессии parser/wrapper,
но не заменяет требуемый нагрузочный тест с реальными соединениями,
throughput и p50/p95/p99.

Для воспроизводимого lower-level baseline добавлен opt-in тест очереди recorder:

```powershell
$env:JA3PROXY_PERF = "1"
$env:JA3PROXY_PERF_CONCURRENCY = "1000"
$env:JA3PROXY_PERF_DURATION = "5s"
go test ./internal/ja3proxy/recorder -run '^TestRecorderLoadBaseline$' -v
```

Он выводит JSON с recorder-off/on, throughput, p50/p95/p99, accepted/processed,
queue depth, drops и memory. Это нижнеуровневый baseline; окончательная
приёмка теперь дополнительно покрывается opt-in матрицей HTTP CONNECT/SOCKS5:

```powershell
$env:JA3PROXY_E2E_PERF = "1"
$env:JA3PROXY_E2E_PERF_CONCURRENCY = "16"
$env:JA3PROXY_E2E_PERF_REQUESTS = "100"
go test ./internal/ja3proxy/e2e -run '^TestProxyLoadMatrix$' -v
```

Матрица выполняет recorder-off/on для обоих входных протоколов; перед измерением
каждый вариант прогревает TLS/proxy path, затем каждое HTTPS-обращение создаёт
новое downstream-соединение, поэтому учитывается стоимость proxy/TLS handshake,
а не только запросы по уже открытому туннелю. Тест проверяет
каждый ответ, дренирует recorder перед чтением счётчиков и выводит throughput,
nearest-rank p50/p95/p99, число измерений и нулевых длительностей,
completed/errors и recorder accepted/processed/dropped.

Предшествующий пакетному SQLite writer локальный smoke-run 2026-09-25,
Windows amd64, Go 1.26.6, concurrency=16,
100 запросов на worker (1600 на вариант), loopback HTTPS target:

| Вход | Recorder | Throughput req/s | p50 ms | p95 ms | p99 ms | Recorder dropped |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| HTTP CONNECT | off | 1557 | 10.07 | 12.57 | 14.43 | 0 |
| HTTP CONNECT | on | 2226 | 7.01 | 9.49 | 10.60 | 36 |
| SOCKS5 | off | 1959 | 7.49 | 9.68 | 24.29 | 0 |
| SOCKS5 | on | 2091 | 7.45 | 10.10 | 11.25 | 0 |

Это один in-process прогон, пригодный для проверки работоспособности сценария,
но не для вывода о влиянии recorder на производительность: варианты запускались
последовательно, а показатели заметно зависят от прогрева и фоновой нагрузки.
Все 1600 запросов каждого варианта завершились; у измерений не было нулевых
длительностей. Recorder был закрыт и drained до снятия счётчиков. Для окончательной
проверки установлен opt-in сценарий против собранного бинарника —
`TestProxyBinaryLoadMatrix`:

```powershell
$env:JA3PROXY_E2E_BINARY_PERF = "1"
$env:JA3PROXY_E2E_PERF_CONCURRENCY = "16"
$env:JA3PROXY_E2E_PERF_REQUESTS = "100"
go test ./internal/ja3proxy/e2e -run '^TestProxyBinaryLoadMatrix$' -v
```

Он собирает `cmd/ja3proxy`, запускает отдельный процесс для каждого варианта,
использует временную SQLite-базу и одноразовые CA-файлы, проверяет ответы через
HTTP CONNECT/SOCKS5 и сверяет recorder status API с числом строк в SQLite.
Файлы теста создаются только в `t.TempDir()`.

Локальный бинарный прогон 2026-09-25, Windows amd64, Go 1.26.6, concurrency=16,
100 запросов на worker:

| Вход | Recorder | Throughput req/s | p50 ms | p95 ms | p99 ms | Accepted | Dropped | SQLite rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP CONNECT | off | 1743 | 8.86 | 11.94 | 17.40 | 0 | 0 | 0 |
| HTTP CONNECT | on | 2151 | 7.28 | 9.53 | 10.47 | 9600 | 0 | 9600 |
| SOCKS5 | off | 1802 | 8.71 | 10.96 | 12.42 | 0 | 0 | 0 |
| SOCKS5 | on | 2114 | 7.39 | 9.50 | 10.43 | 9600 | 0 | 9600 |

Запросы завершились успешно; в обоих recorder-on вариантах принято и обработано
по 9600 событий, потерь нет, число SQLite rows совпадает с `processed`.
Очереди по умолчанию увеличены до 8192 событий каждая, SQLite batch insert — до
1024 строк в одной транзакции. Это подтверждает критерий на указанной локальной
нагрузке; показатели скорости остаются ориентиром одного прогона, а не
универсальной характеристикой для других машин и профилей.

Повторный бинарный прогон текущего рабочего дерева 2026-09-25, Windows amd64,
Go 1.26.6, concurrency=16, 100 запросов на worker (1600 HTTPS-запросов на
каждый вариант):

| Вход | Recorder | Throughput req/s | p50 ms | p95 ms | p99 ms | Accepted | Dropped | SQLite rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP CONNECT | off | 1737 | 8.87 | 11.75 | 20.12 | 0 | 0 | 0 |
| HTTP CONNECT | on | 2145 | 7.20 | 9.51 | 11.82 | 9600 | 0 | 9600 |
| SOCKS5 | off | 1793 | 8.79 | 11.00 | 12.00 | 0 | 0 | 0 |
| SOCKS5 | on | 2045 | 7.62 | 9.92 | 13.16 | 9600 | 0 | 9600 |

Все запросы завершились без ошибок; recorder-on обработал и сохранил 9600
наблюдений на протокол, потерь нет. Как и предыдущие single-run результаты,
это проверка работоспособности бинарного сценария, а не контролируемое
доказательство порога overhead `< 10%`: варианты выполнялись последовательно,
и recorder-on в этом прогоне оказался быстрее recorder-off.

## Что блокирует окончательный PASS

1. Реальные Safari/iOS и Android/OkHttp ClientHello fixtures с разрешённым
   распространением, source version, capture method и SHA-256 файла.
