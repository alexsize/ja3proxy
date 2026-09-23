# Отчёт приёмки MVP-0

Дата проверки: 2026-09-23

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
| 14 | sensitive canaries | PARTIAL | raw/API/upstream-error tests проходят; централизованного log sanitizer ещё нет |

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
go test -race ./... -count=1                                PASS
FuzzParse, 5 секунд                                         PASS
FuzzStream, 5 секунд                                        PASS
OpenSSL corpus golden                                       PASS
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

## Что блокирует окончательный PASS

1. Реальные Safari/iOS и Android/OkHttp ClientHello fixtures с разрешённым
   распространением, source version, capture method и SHA-256 файла.
2. Нагрузочный сценарий recorder off/on для HTTP CONNECT и SOCKS5 с
   фиксированными concurrency, payload, duration, throughput и p50/p95/p99.
3. Централизованный sanitizer для log attributes/errors и canary-проверка всех
   diagnostic/export путей.
