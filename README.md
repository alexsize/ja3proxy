<p align="center">
  <img src="assets/logo.svg" alt="Логотип JA3Proxy" width="520">
</p>

# JA3Proxy

JA3Proxy — локальный HTTP/SOCKS5-прокси на Go для контролируемого перехвата TLS,
эмуляции ClientHello через [uTLS](https://github.com/refraction-networking/utls)
и записи фактических TLS-отпечатков. Проект предназначен для тестовых стендов,
исследования сетевого поведения приложений и проверки соответствия входящего и
исходящего TLS-профиля.

> Используйте прокси только для трафика, который вы вправе перехватывать.
> Закрытый ключ локального центра сертификации позволяет расшифровывать TLS-трафик
> доверяющих ему клиентов и поэтому требует такой же защиты, как другие секреты.

## Возможности

- единая точка входа для HTTP, HTTPS `CONNECT` и SOCKS5;
- динамические сертификаты для TLS MITM;
- автоматическое создание локального центра сертификации;
- эмуляция браузерных ClientHello с помощью пресетов uTLS;
- отдельные исходящие TLS-профили для разных хостов;
- HTTP- или SOCKS5-прокси следующего уровня;
- аутентификация клиентов HTTP Basic и SOCKS5 username/password;
- терминальная панель и встроенная локальная веб-панель;
- запись входящего `CLIENT_IN` и исходящего `PROXY_OUT` ClientHello;
- вычисление JA3, JA4 и нормализованного TLS-NORM-1;
- режимы `MITM_REISSUE`, `PASSTHROUGH`, `OBSERVE_ONLY` и `BLOCK`;
- ограниченная по памяти неблокирующая очередь и необязательный JSONL-экспорт;
- локальный API поиска, просмотра, сравнения и экспорта наблюдений.

## Быстрый запуск

Требуется Go версии, указанной в [go.mod](go.mod), или более новой совместимой
версии.

```bash
git clone https://github.com/alexsize/ja3proxy.git
cd ja3proxy
go build -o ja3proxy ./cmd/ja3proxy
./ja3proxy --listen 127.0.0.1:8080 --tls-fingerprint chrome@120
```

В Windows PowerShell:

```powershell
git clone https://github.com/alexsize/ja3proxy.git
Set-Location ja3proxy
go build -o bin/ja3proxy.exe ./cmd/ja3proxy
.\bin\ja3proxy.exe --listen 127.0.0.1:8080 --tls-fingerprint chrome@120
```

При первом запуске создаются:

```text
credentials/cert.pem
credentials/key.pem
```

Проверка через HTTP-прокси и SOCKS5:

```bash
curl -vk --proxy http://127.0.0.1:8080 https://example.com
curl -vk --proxy socks5h://127.0.0.1:8080 https://example.com
```

Ключ `-k` отключает проверку сертификата только для быстрой диагностики.
Для штатного тестирования импортируйте `credentials/cert.pem` в доверенное
хранилище тестового клиента.

Подробная установка описана в [docs/INSTALLATION.md](docs/INSTALLATION.md).

## TLS Recorder

Запуск записи ClientHello и локальной панели:

```bash
./ja3proxy \
  --listen 127.0.0.1:8080 \
  --capture-tls \
  --web-panel 127.0.0.1:9090 \
  --tls-fingerprint chrome@120
```

Откройте:

- `http://127.0.0.1:9090/` — трафик и текущая конфигурация;
- `http://127.0.0.1:9090/recorder.html` — TLS-наблюдения и сравнение;
- `http://127.0.0.1:9090/profiles.html` — редактор версионируемых TLS-профилей и ожидаемого JA4;
- `http://127.0.0.1:9090/health/live` — проверка процесса;
- `http://127.0.0.1:9090/health/ready` — готовность recorder;
- `http://127.0.0.1:9090/metrics` — метрики recorder.

JSONL-экспорт создаётся только в новый файл и никогда не перезаписывает
существующий:

```bash
./ja3proxy --capture-tls --capture-jsonl recordings/session-001.jsonl
```

Raw ClientHello и TLS records сохраняются только после явного включения:

```bash
./ja3proxy --capture-tls --capture-raw
```

Raw-данные могут содержать идентификаторы сессий и tickets. Не включайте этот
режим без необходимости и не публикуйте полученный JSONL.

Подробности алгоритмов, лимитов и API приведены в
[docs/TLS_RECORDER.md](docs/TLS_RECORDER.md). Точное состояние реализации и
оставшиеся этапы ТЗ — в
[docs/spec/RECORDER_IMPLEMENTATION.md](docs/spec/RECORDER_IMPLEMENTATION.md).
Каноническое полное техническое задание —
[ТЗ версии 3](docs/spec/JA3Proxy_Fingerprint_Recorder_TZ_v3.md).

## Режимы TLS

| Режим | Поведение |
| --- | --- |
| `MITM_REISSUE` | Принимает TLS клиента, создаёт новый исходящий ClientHello по выбранному профилю и записывает обе стороны. Режим по умолчанию. |
| `PASSTHROUGH` | Передаёт TLS-байты без MITM и пассивно записывает входящий и исходящий ClientHello. |
| `OBSERVE_ONLY` | Передаёт трафик без MITM; используется для наблюдения без изменения ClientHello. |
| `BLOCK` | Отклоняет HTTP CONNECT и SOCKS5 CONNECT до исходящего сетевого подключения. |

Пример:

```bash
./ja3proxy --capture-tls --tls-mode PASSTHROUGH
```

## Параметры командной строки

```text
Сервер:
  --listen string                 адрес прослушивания, по умолчанию :8080

Центр сертификации:
  --ca-cert string                путь к сертификату CA
  --ca-key string                 путь к закрытому ключу CA

TLS-профиль:
  --tls-fingerprint string        глобальный пресет uTLS, например chrome@120
  --tls-fingerprint-file string   JSON-файл глобального профиля с автообновлением
  --tls-profile-file string       JSON-файл маршрутизации TLS-профилей по хостам
  --route-config-file string      JSON-таблица двухфазных маршрутов
  --tls-template-file string      журнал редактируемых TLS-профилей
  --list-tls-fingerprints         вывести поддерживаемые пресеты и завершить работу

Прокси:
  --proxy-username string         имя пользователя для входящих клиентов
  --proxy-password string         пароль для входящих клиентов
  --upstream-proxy string         следующий HTTP- или SOCKS5-прокси

Recorder и диагностика:
  --capture-tls                   включить ограниченную запись ClientHello
  --capture-raw                   сохранять чувствительные raw TLS-данные
  --capture-jsonl string          создать новый JSONL-файл, лимит 256 МиБ
  --tls-mode string               режим обработки TLS
  --log-level string              debug, info, warn или error
  --dump-traffic                  записывать содержимое трафика в журнал
  --tui                           включить терминальную панель
  --web-panel string              адрес локальной веб-панели
```

Актуальную справку конкретной сборки можно получить командой:

```bash
./ja3proxy --help
```

## TLS-профили

Глобальный пресет задаётся в формате `клиент@версия`:

```bash
./ja3proxy --tls-fingerprint chrome@120
./ja3proxy --tls-fingerprint firefox@120
./ja3proxy --list-tls-fingerprints
```

Имена клиентов регистронезависимы. Значения `auto`, `default` и `latest`
выбирают версию по умолчанию из текущей зависимости uTLS.

### Автообновление одного профиля

Файл `fingerprint.json`:

```json
{
  "client": "Chrome",
  "version": "120"
}
```

```bash
./ja3proxy --tls-fingerprint-file fingerprint.json
```

При корректном изменении файла новые соединения получают новый профиль.
Активные туннели продолжают работать со старым. При ошибке разбора остаётся
последняя действующая конфигурация.

### Профили по хостам

Файл `upstream-tls.json`:

```json
{
  "default": {
    "protocol": "utls",
    "client": "Chrome",
    "version": "120"
  },
  "routes": [
    {
      "host": "*.example.com",
      "priority": 10,
      "protocol": "utls",
      "client": "Firefox",
      "version": "120"
    },
    {
      "host": "api.example.org",
      "protocol": "utls",
      "client": "Safari",
      "version": "16.0"
    }
  ]
}
```

```bash
./ja3proxy --tls-profile-file upstream-tls.json
```

Поддерживаются точные имена и шаблоны вида `*.example.com`. Значение
`protocol` в текущей версии — только `utls`. Поле `priority` необязательно и
по умолчанию равно `0`: при совпадении нескольких маршрутов выбирается маршрут
с большей priority, затем точное имя хоста выигрывает у wildcard, а при полном
равенстве сохраняется порядок маршрутов в JSON. Версия выбранной upstream
конфигурации фиксируется в `upstream_config_version` исходящей MITM observation.
Там же сохраняются `matched_route_id`, `matched_route_priority` и
`route_match_reason`; для старого маршрута без `id` используется стабильный
идентификатор `upstream-tls:<normalized-host>`.

### Редактирование JA4 через шаблоны

Страница `/profiles.html` создаёт шаблон из uTLS-пресета либо из полного
наблюдения recorder. Можно менять порядок cipher suites и extensions, ALPN,
supported versions/groups и signature algorithms. Перед сохранением сервер
материализует ClientHello и показывает ожидаемые JA3, JA4 и TLS-NORM.

Сохранённые версии пишутся append-only в файл `--tls-template-file`
(`profiles/tls-templates.jsonl` по умолчанию). Изменение требует актуальной
версии конфигурации: устаревшая вкладка получает `409`, а не перезаписывает
чужие изменения. Активный шаблон применяется только к новым соединениям и
имеет приоритет над обычным `--tls-fingerprint`/`--tls-profile-file` для
совпавших host patterns.

JA4 нельзя задавать произвольной строкой: он вычисляется из ClientHello.
Редактор меняет воспроизводимые поля ClientHello, а recorder независимо
захватывает фактически отправленные байты `PROXY_OUT` и присваивает проверке
`MATCH`, `PARTIAL_MATCH`, `MISMATCH` или `UNKNOWN`. Если поле нельзя выразить
через выбранный базовый uTLS-пресет, профиль получает статус `UNSUPPORTED` и
не может быть активирован. ALPN активного шаблона на каждом соединении
ограничивается протоколами, предложенными входящим клиентом.

Профиль из наблюдения сохраняет исходные JA3/JA4/TLS-NORM и до публикации
проверяет, действительно ли базовый пресет воспроизводит обязательные поля.
Дополнительные constraints поддерживают `present`, `equals` и `one_of`.
История версий неизменяема; откат создаёт новую версию. В PASSTHROUGH и
OBSERVE_ONLY recorder отдельно показывает `FORWARDED_UNCHANGED` либо
`UNVERIFIED`, а не выдаёт передачу за применённый профиль.
Единый `connection_id` назначается transport flow сразу после `Accept`, до
распознавания HTTP/SOCKS5/TLS, и связывает входящее и исходящее наблюдения.

## Следующий прокси

SOCKS5:

```bash
./ja3proxy --upstream-proxy socks5://127.0.0.1:1080
```

HTTP CONNECT с аутентификацией:

```bash
./ja3proxy --upstream-proxy http://user:password@127.0.0.1:3128
```

Значение без схемы трактуется как SOCKS5. TLS-профиль применяется внутри
созданного туннеля.

Для загрузки двухфазных правил используйте `--route-config-file routes.json`.
Маршруты поддерживают фазы `PRE_TLS` и `POST_CLIENTHELLO`, exact/wildcard host,
CIDR, порт, device/device tag и proxy username. Проверить решение без открытия
соединения можно через `POST /api/v1/routes/test`. В `action` можно указать
`mode`, `upstream` и `tls_profile`: `upstream` выбирает SOCKS5/HTTP upstream
для нового HTTP CONNECT или SOCKS5-туннеля, а `tls_profile` закрепляет ID
профиля TLS для MITM.

## Аутентификация клиентов

```bash
./ja3proxy \
  --proxy-username client \
  --proxy-password secret
```

Оба параметра обязательны одновременно. HTTP-клиенты используют Proxy Basic,
SOCKS5-клиенты — username/password по RFC 1929. Не передавайте реальные пароли
в общедоступных скриптах и журналах оболочки.

## Веб-панель

```bash
./ja3proxy --web-panel 127.0.0.1:9090
```

Панель встроена в бинарный файл и не требует отдельной сборки frontend.
Изменения настроек применяются к новым соединениям, не прерывая открытые
туннели. Если TLS-профиль управляется файлом, веб-панель не подменяет этот
источник конфигурации.

При включённом TLS Recorder панель обязана слушать loopback-адрес. API recorder
дополнительно проверяет адрес клиента, заголовок `Host` и `Origin` для защиты от
удалённого доступа и DNS rebinding. В текущем этапе у панели нет пользователей
и ролей, поэтому не выставляйте её непосредственно в общедоступную сеть.

## Сертификаты

- если сертификат и ключ существуют, они загружаются;
- если отсутствуют оба файла, создаётся новая пара;
- если существует только один файл, запуск завершается ошибкой;
- недостающие родительские каталоги создаются автоматически.

Закрытый ключ по умолчанию находится в `credentials/key.pem`. Каталог
`credentials/` исключён из Git. После тестирования удалите тестовый CA из
доверенных хранилищ клиентов, если он больше не нужен.

## Сборка и проверка

```bash
go mod download
go mod verify
go vet ./...
go test -count=1 ./...
go build -o bin/ja3proxy ./cmd/ja3proxy
```

На Windows имя файла обычно задают как `bin/ja3proxy.exe`. Команда `make`
собирает бинарные файлы Linux и Windows amd64 в `bin/`.

Дополнительные проверки parser/recorder описаны в
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Структура проекта

```text
cmd/ja3proxy/                       точка входа
internal/ja3proxy/proxy/            HTTP и SOCKS5
internal/ja3proxy/tunnel/           TLS MITM и режимы туннеля
internal/ja3proxy/capture/tlshello/ parser и fingerprints ClientHello
internal/ja3proxy/recorder/         очередь, хранение, diff и JSONL
internal/ja3proxy/tlsprofile/       шаблоны, материализация и журнал версий
internal/ja3proxy/webpanel/         локальная панель и API
internal/ja3proxy/e2e/              сквозные тесты
docs/                               эксплуатационная документация
docs/spec/                          ТЗ, контракты и состояние реализации
```

## Ограничения текущего этапа

- наблюдения хранятся в ограниченном окне памяти;
- постоянное SQL-хранилище ещё не реализовано;
- JSONL не шифруется;
- recorder API локальный и пока не имеет RBAC;
- upstream TLS-маршруты поддерживают явную priority, exact/wildcard host
  matching и детерминированное разрешение конфликтов; общий двухфазный route
  manager и runtime snapshots ещё не реализованы;
- анализируется первый ClientHello соединения.

## Диагностика

Частые проблемы и безопасные способы проверки собраны в
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Участие в разработке

Перед pull request запустите форматирование, vet и полный набор тестов. Для
изменений TLS parser, recorder, proxy routing или безопасности добавляйте
целевые и сквозные тесты. Правила репозитория приведены в [AGENTS.md](AGENTS.md).

## Лицензия

Проект распространяется по лицензии [MIT](LICENSE).
