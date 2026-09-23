# Техническое задание версии 3.0
## Регистратор TLS-отпечатков и центр управления JA3Proxy

> Версия: 3.0
> Статус: каноническая нормативная спецификация реализации
> Дата выпуска: 2026-09-23
> Базовый репозиторий: `alexsize/ja3proxy`
> Закреплённый TLS engine: `github.com/refraction-networking/utls v1.8.2`

## 1. Состав полного ТЗ

Версия 3.0 является единым нормативным комплектом из двух частей:

1. [Основное ТЗ версии 2](JA3Proxy_Fingerprint_Recorder_TZ_v2.md) — capture,
   fingerprints, хранение, routing, UI/API, безопасность, релизы и общие
   критерии приёмки.
2. [Нормативное приложение A: архитектура и профили uTLS](JA3Proxy_uTLS_TZ_Additions.md)
   — TLS generation engine, Profile Compiler, replay, fidelity, engine
   compatibility и дополнительные критерии проверки.

Обе части обязательны. Ссылка на «ТЗ v3» означает весь комплект, а не только
этот индекс. Версия 2 остаётся в репозитории как неизменяемая историческая
основа и самостоятельно больше не является канонической спецификацией.

## 2. Нормативные термины

Ключевые слова **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** и **MAY**
имеют смысл, установленный в разделе «Как читать документ» основного ТЗ.

В приложении A формулировки «добавить», «изменить», «уточнить», «нужно» и
«должен» означают **MUST**, если пункт явно не отнесён к рекомендации или
будущему релизу.

## 3. Разрешение конфликтов

При конфликте действует следующий приоритет:

1. безопасность, приватность и запреты MUST NOT BREAK;
2. actual network bytes и parsed actual network bytes;
3. приложение A для uTLS generation, replay и Profile Compiler;
4. критерии приёмки конкретного релиза;
5. основное ТЗ v2;
6. UI-примеры и рекомендуемые имена пакетов.

`ClientHelloSpec`, stored profile и preset name не могут отменить факт,
полученный из `RecordingConn`. Unknown extension не может быть молча отброшен.
При невозможности одновременно выполнить два MUST реализация прекращается с
явной ошибкой, а конфликт оформляется поправкой к ТЗ до продолжения работ.

## 4. Зафиксированная архитектура

```text
                         ANALYSIS
RAW CLIENTHELLO ──► наш parser ──► JA3 / JA4 / TLS-NORM / storage
       │
       └──────────────── GENERATION
                         uTLS Fingerprinter
                                │
                         ClientHelloSpec
                                │
                         Profile Compiler
                                │
                              uTLS
                                │
                         RecordingConn
                                │
                      ACTUAL OUTBOUND WIRE
                                │
                         JA3 / JA4 / Diff
```

Наш код отвечает за bounded capture/reassembly, parser, normalization,
analytics, persistence, profile management, audit и verification. uTLS
является единственным штатным execution/generation engine ClientHello. Свой
TLS serializer допускается только для функции, которую невозможно корректно
представить через закреплённую версию uTLS, после отдельного изменения ТЗ и
набора wire-level regression tests.

## 5. Источники истины

Нормативный порядок:

```text
1. Actual network bytes
2. Parsed actual network bytes
3. Compiled ClientHelloSpec
4. Stored profile
5. Selected preset name
```

Outbound JA3, JA4 и TLS-NORM MUST вычисляться из фактически записанных байтов.
Preset и spec выражают намерение, но не доказывают результат.

## 6. Трассируемые группы требований v3

| ID | Требование | Источник |
| --- | --- | --- |
| ARCH-UTLS-001 | uTLS v1.8.2 — основной и pinned TLS engine | приложение A, 1, 19, 44 |
| ARCH-UTLS-002 | независимые analysis и generation pipelines | приложение A, 2, 3, 26, 42–43 |
| PR-UTLS-001 | Fingerprinter получает только полный reassembled ClientHello | приложение A, 4 |
| FR-COMPILER-001 | stored profile компилируется в `ClientHelloSpec` с явной validation | приложение A, 5–6 |
| FR-PROFILE-004 | PRESET, OBSERVED, CUSTOM и RANDOMIZED различаются | приложение A, 7–8 |
| FR-PROFILE-005 | STRICT и ADAPTIVE имеют разные контракты | приложение A, 9–10 |
| FR-VERIFY-002 | profile→spec, spec→wire и inbound→outbound проверяются отдельно | приложение A, 11–14 |
| FR-DYNAMIC-001 | dynamic fields, GREASE, ALPN и ALPS управляются политиками | приложение A, 15–16, 28–30 |
| FR-ENGINE-001 | engine/version metadata и compatibility status сохраняются | приложение A, 17–22, 36 |
| REL-UTLS-001 | обновление uTLS блокируется regression validation | приложение A, 18–20 |
| FR-EXT-001 | custom/unknown extensions имеют support level и raw preservation | приложение A, 23–25, 33–35 |
| FR-REPLAY-001 | observed profile проходит local round-trip validation | приложение A, 13–14 |
| FR-REPARSE-001 | raw ClientHello допускает versioned повторный разбор | приложение A, 37 |
| FR-LAB-001 | Replay Lab и Compatibility Matrix изолированы от production routing | приложение A, 38–40 |
| FR-SESSION-001 | full/resumed/PSK handshakes различаются | приложение A, 31–32 |
| SEC-WIRE-001 | spec никогда не подменяет outbound wire evidence | приложение A, 11, 26–27 |

Каждый реализуемый MUST должен получить более узкий requirement ID и минимум
один автоматический test ID до merge. Таблица выше задаёт родительские группы,
а не заменяет покомпонентную трассировку.

## 7. Привязка к релизам

### MVP-0

К существующим критериям добавляются архитектурные инварианты:

- `ARCH-UTLS-001`, `ARCH-UTLS-002`, `PR-UTLS-001`;
- `SEC-WIRE-001` для каждого outbound handshake;
- engine/parser/fingerprint version metadata в observation;
- unknown numeric IDs не вызывают parse failure;
- uTLS dependency закреплена точной версией.

MVP-0 не обязан публиковать Profile Compiler UI или Replay Lab.

### MVP-2

Дополнительно обязательны:

- Profile Compiler и `ClientHelloSpec` runtime model;
- PRESET, OBSERVED, CUSTOM, RANDOMIZED;
- STRICT/ADAPTIVE и явные ALPN/ALPS policies;
- selected/compiled/actual separation;
- трёхуровневая verification;
- engine compatibility status и mutation audit;
- support level для extensions;
- local round-trip validation перед публикацией observed profile.

### Release 5

Обязательны Replay Lab, Compatibility Matrix, controlled Roller, расширенная
fidelity matrix, pre-marshaled diagnostics, reparse workflow и связанные
варианты full/resumed/PSK fingerprints.

Требования безопасности, wire capture и versioning применяются с первого
релиза, в котором появляется соответствующая функция, и не откладываются до
Release 5.

## 8. Дополнительные критерии приёмки

1. CI подтверждает, что `go.mod` содержит точную версию uTLS, не branch/latest.
2. Golden report сравнивает actual wire до и после обновления uTLS.
3. Observed Profile создаётся через reassembled raw → `utls.Fingerprinter`.
4. STRICT profile не изменяет ALPN/ALPS молча и возвращает
   `PROFILE_PROTOCOL_CONFLICT` при несовместимости.
5. ADAPTIVE profile сохраняет каждую runtime mutation с before/after/reason.
6. RANDOMIZED observation содержит фактические JA3/JA4/TLS-NORM.
7. Engine mismatch даёт `PROFILE_REVALIDATION_REQUIRED`, пока local replay не
   завершится статусом VALID или VALID_WITH_DIFFERENCES.
8. Unknown extension сохраняет ID, position, raw bytes и support level.
9. Profile→spec, spec→wire и inbound→outbound diff доступны отдельно.
10. Production routing не использует Roller.

## 9. Правило сопровождения

Изменения реализации выполняются относительно этого ТЗ v3. Документы
состояния реализации обязаны различать `реализовано`, `частично`,
`не реализовано` и не могут объявлять весь релиз готовым без всех его
артефактов приёмки. Любое обновление uTLS сначала изменяет compatibility
baseline и golden report, затем код и только после этого production pin.
