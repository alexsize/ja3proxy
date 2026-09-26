# Правила репозитория

## Структура проекта

JA3Proxy — консольное приложение на Go. Точка входа находится в
`cmd/ja3proxy/`, основная реализация и тесты — в `internal/ja3proxy/`.
Корневой пакет связывает конфигурацию, CLI и жизненный цикл приложения.
Специализированные пакеты отвечают за `proxy/`, `tunnel/`, `capture/`,
`recorder/`, `fingerprint/`, `upstreamtls/`, `certstore/`, `traffic/`,
`dialer/`, `pipe/`, `tui/`, `webpanel/`, `netutil/` и `e2e/`.

Описание модуля находится в `go.mod` и `go.sum`, сценарии нативной сборки — в
`makefile`, статические ресурсы — в `assets/`, документация — в `docs/`.

## Сборка и тестирование

- `go mod download` — загрузить зависимости;
- `go mod verify` — проверить загруженные модули;
- `go build -v ./...` — собрать все пакеты так же, как CI;
- `go test -v ./...` — выполнить полный набор тестов;
- `go test -race ./...` — проверить гонки данных;
- `go build -o ja3proxy ./cmd/ja3proxy` — собрать локальный бинарный файл;
- `make` или `make all` — собрать Windows и Linux amd64 в `bin/`;
- `make clean` — удалить артефакты, созданные Makefile.

Пример локального запуска:

```bash
./ja3proxy --listen :8080 --tls-fingerprint Chrome@120
```

## Стиль кода

Соблюдайте стандартное форматирование Go. Перед коммитом запускайте `gofmt` для
изменённых файлов и сохраняйте порядок импортов, принятый `go fmt`/`goimports`.
Предпочитайте небольшие файлы с одной зоной ответственности и существующие
границы протокольных пакетов. Экспортируйте только действительно публичные
символы. Локальные функции именуйте в `lowerCamelCase`, тесты — по шаблону
`TestFeatureOrBehavior`.

## Требования к тестам

Тесты используют стандартный пакет `testing` и находятся рядом с исходным кодом
в файлах `*_test.go`. Добавляйте целевые тесты при изменении маршрутизации,
SOCKS5 parsing, TLS fingerprints, сертификатов, recorder, API, жизненного цикла
или обновления конфигурации. Для parser обязательны отрицательные границы и fuzz,
для конкурентного кода — race detector. Перед pull request выполняйте
`go test -v ./...` и `go vet ./...`.

## Коммиты и запросы на слияние

Используйте короткие повелительные сообщения Conventional Commits, например:

```text
feat(recorder): добавить сравнение TLS-наблюдений
fix(socks5): отклонять блокируемый туннель до dial
test(tlshello): покрыть фрагментацию ClientHello
chore(deps): обновить зависимости Go
```

Желательная длина заголовка — до 72 символов. Один коммит должен описывать одно
логическое изменение. В pull request укажите изменение поведения, выполненные
проверки, связанные задачи и безопасный пример воспроизведения.

## Безопасность

Не коммитьте сгенерированные CA, закрытые ключи, пароли, raw-трафик, JSONL с
реальными сессиями и локальные базы. Репозиторий исключает `credentials/`,
`*.pem`, `bin/` и рабочие кэши. Для HTTPS MITM используйте одноразовые локальные
сертификаты и явно документируйте установку доверия тестового клиента.

Файл `mitm_mcp_traffic.db`, если он присутствует локально, не относится к
исходному коду и не должен попадать в коммиты.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **ja3proxy** (4883 symbols, 17694 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "master"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/ja3proxy/context` | Codebase overview, check index freshness |
| `gitnexus://repo/ja3proxy/clusters` | All functional areas |
| `gitnexus://repo/ja3proxy/processes` | All execution flows |
| `gitnexus://repo/ja3proxy/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
