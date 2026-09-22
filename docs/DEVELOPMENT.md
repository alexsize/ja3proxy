# Разработка и проверка

## Базовые команды

```bash
go mod download
go mod verify
go vet ./...
go test -count=1 ./...
go build -o bin/ja3proxy ./cmd/ja3proxy
```

Перед коммитом отформатируйте изменённые Go-файлы через `gofmt`.

## Поиск гонок данных

```bash
go test -race -count=1 ./...
```

В Windows для race detector требуется C compiler, совместимый с текущей
архитектурой Go. Обычная сборка JA3Proxy выполняется с `CGO_ENABLED=0` и такого
компилятора не требует.

## Fuzz-тесты TLS parser

```bash
go test ./internal/ja3proxy/capture/tlshello \
  -run '^$' -fuzz '^FuzzParse$' -fuzztime=30s -parallel=2

go test ./internal/ja3proxy/capture/tlshello \
  -run '^$' -fuzz '^FuzzStream$' -fuzztime=30s -parallel=2
```

## Измерение производительности сборщика фрагментов

```bash
go test ./internal/ja3proxy/capture/tlshello \
  -run '^$' -bench '^BenchmarkReassembly$' -benchmem
```

## Обязательные области тестирования

Изменения следующих компонентов должны сопровождаться целевыми тестами:

- HTTP CONNECT и SOCKS5 parsing;
- выбор и автообновление TLS-профиля;
- выпуск и загрузка сертификатов;
- границы и fragmentation ClientHello;
- raw privacy и нормализация fingerprints;
- переполнение очереди и ошибки JSONL;
- локальные ограничения API;
- lifecycle приложения и остановка recorder;
- матрица downstream/upstream/mode в `internal/ja3proxy/e2e`.

## Выпуск бинарных файлов

Workflow релиза собирает нативные архивы Windows, Linux и macOS для amd64 и
arm64 и публикует контрольные суммы SHA-256. Перед созданием релиза тег должен
соответствовать semantic version, например `v0.7.0` или `v0.7.0-rc.1`.

## Безопасность тестовых данных

Не коммитьте:

- `credentials/` и файлы `*.pem`;
- JSONL с реальным трафиком;
- raw ClientHello с рабочими session identifiers;
- пароли следующего прокси;
- локальные базы и диагностические дампы.

Для тестов используйте синтетические или лицензированные fixtures с указанным
происхождением. MD5 в JA3 является частью формата fingerprint и не должен
использоваться как криптографическая защита.
