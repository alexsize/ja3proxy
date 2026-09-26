# Отчёт приёмки MVP-0

Дата первоначальной проверки baseline: 2026-09-24

Проверенный кодовый baseline: `d36903e806c1e836edb6f75f02cc44e7d0b8cd63`

Среда: Windows amd64, Go 1.26.6, OpenSSL 3.5.5.

Статус: **условно готово, формальная приёмка ещё не закрыта**. Реализованы и
автоматически проверяются runtime-требования ядра. Для окончательной приёмки
нужны реальные Safari/iOS и Android/OkHttp captures для проверки соответствия
отпечатков устройствам. Нагрузочная матрица recorder-off/recorder-on выполнена;
последний результат приведён ниже.

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

Повторная серия бинарного теста 2026-09-26, Windows/amd64, Go 1.26.6,
concurrency=16, 100 запросов на worker; `go test -count=3` выполнил три
полных последовательных матрицы. В каждой паре сначала шёл recorder-off,
затем recorder-on:

| Протокол | Прогон | Off req/s | On req/s | Off p95 ms | On p95 ms | Ошибки / dropped | Записано событий |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP CONNECT | 1 | 1415 | 1782 | 14.86 | 11.28 | 0 / 0 | 9600 |
| HTTP CONNECT | 2 | 1392 | 1666 | 14.58 | 12.37 | 0 / 0 | 9600 |
| HTTP CONNECT | 3 | 1332 | 1629 | 15.43 | 13.37 | 0 / 0 | 9600 |
| SOCKS5 | 1 | 1406 | 1748 | 14.32 | 11.50 | 0 / 0 | 9600 |
| SOCKS5 | 2 | 1374 | 1583 | 14.49 | 13.38 | 0 / 0 | 9600 |
| SOCKS5 | 3 | 1207 | 1510 | 17.13 | 14.12 | 0 / 0 | 9600 |

Все 12 вариантов завершились успешно; queue drained, `accepted == processed ==
SQLite rows`, `dropped == 0`. Во всех трёх последовательных парах recorder-on
показал throughput выше recorder-off. Это нельзя трактовать как отрицательный
overhead: фиксированный порядок off→on и колебания loopback/планировщика
показывают, что такой smoke-run не изолирует влияние recorder. Порог overhead
`<10%` остаётся **не доказанным**; для него нужен чередующийся/рандомизированный
порядок и контролируемый целевой стенд с достаточным числом повторов.

Пересмотренное измерение 2026-09-26, Windows/amd64, Go 1.26.6:
`TestProxyBinaryLoadMatrix` запущен с пятью раундами (16 workers, 100 запросов
на worker). Обе стороны теперь явно работают в `--tls-mode PASSTHROUGH`, чтобы
`--capture-tls` не менял MITM/inspection mode только у recorder-on; порядок
recorder-on/off чередуется. `throughput on/off` и `p95 on/off` ниже — изменение
в процентах, отрицательное throughput означает более низкую скорость с recorder,
положительный p95 — большую задержку:

| Протокол | Раунд | Recorder первым | Δ throughput % | Δ p95 % |
| --- | ---: | :---: | ---: | ---: |
| HTTP CONNECT | 1 | нет | -15.56 | +24.06 |
| SOCKS5 | 1 | да | +0.62 | -6.73 |
| HTTP CONNECT | 2 | да | -14.98 | +18.02 |
| SOCKS5 | 2 | нет | -10.42 | +12.42 |
| HTTP CONNECT | 3 | нет | -9.47 | +10.61 |
| SOCKS5 | 3 | да | -10.26 | +16.53 |
| HTTP CONNECT | 4 | да | +2.88 | -10.78 |
| SOCKS5 | 4 | нет | -16.23 | +21.42 |
| HTTP CONNECT | 5 | нет | -0.12 | -1.18 |
| SOCKS5 | 5 | да | -4.99 | +6.80 |

Медианные paired changes: HTTP CONNECT — throughput `-9.47%`, p95 `+10.61%`;
SOCKS5 — throughput `-10.26%`, p95 `+12.42%`. Benchmark теперь также выводит
`pass_under_10_percent`: PASS только если медианное падение throughput меньше
10% и медианное увеличение p95 строго меньше 10%. В этой серии оба протокола
получили FAIL по p95. В пяти раундах вариативность
велика и медиана p95 превышает целевые 10%; результат пока **не PASS** и не
является универсальной характеристикой других машин. Старые измерения выше,
где режимы TLS отличались, не подходят для сравнения overhead и приведены
только как исторические smoke-runs.

Повторный полный прогон той же бинарной матрицы 2026-09-26 на этом же локальном
стенде, с теми же пятью раундами, 16 workers и 100 запросами на worker:

| Протокол | Медиана Δ throughput | Медиана Δ p95 | Ошибки | Потери / записано на enabled-прогон | Порог <10% |
| --- | ---: | ---: | ---: | ---: | :---: |
| HTTP CONNECT | -7.32% | +9.14% | 0 | 0 / 4800 | PASS |
| SOCKS5 | -2.37% | +2.94% | 0 | 0 / 4800 | PASS |

Порядок recorder-on/off в парах чередовался, а обе стороны работали в
`PASSTHROUGH`. Это подтверждает критерий на данном конкретном запуске; предыдущая
неудачная серия и разброс между отдельными раундами показывают, что результат
зависит от локальной нагрузки и не гарантирует такой же overhead на другой
машине или при другом профиле трафика. Тест выводит полные paired-результаты и
сводку медиан в JSON, чтобы повтор можно было проверить без округлений таблицы.

## Что блокирует окончательный PASS

1. Локальные реальные Safari/iOS и Android/OkHttp ClientHello captures с
   указанием устройства/версии ОС, source version и метода захвата. Raw captures
   служат только локальной проверке и в репозиторий не включаются.
