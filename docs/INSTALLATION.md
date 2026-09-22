# Установка и первый запуск

## Требования

- Windows x64 или Linux x64;
- Go версии из `go.mod` либо новее в пределах совместимости модуля;
- Git для получения исходного кода;
- `make` необязателен и нужен только для готовых сценариев сборки.

## Сборка из исходного кода

```bash
git clone https://github.com/alexsize/ja3proxy.git
cd ja3proxy
go mod download
go mod verify
go build -o bin/ja3proxy ./cmd/ja3proxy
```

Windows PowerShell:

```powershell
git clone https://github.com/alexsize/ja3proxy.git
Set-Location ja3proxy
go mod download
go mod verify
go build -o bin/ja3proxy.exe ./cmd/ja3proxy
```

Проверка бинарного файла:

```powershell
.\bin\ja3proxy.exe --list-tls-fingerprints
```

## Первый запуск

```powershell
.\bin\ja3proxy.exe `
  --listen 127.0.0.1:8080 `
  --tls-fingerprint chrome@120
```

Если пути CA не переопределены, приложение создаёт сертификат и ключ в каталоге
`credentials`. Права на каталог и ключ следует ограничить учётной записью,
которая запускает прокси.

## Подключение клиента

HTTP-прокси:

```bash
curl -vk --proxy http://127.0.0.1:8080 https://example.com
```

SOCKS5 с разрешением DNS через прокси:

```bash
curl -vk --proxy socks5h://127.0.0.1:8080 https://example.com
```

Для постоянного тестового стенда установите `credentials/cert.pem` только в
хранилище доверия тестового клиента. Не устанавливайте тестовый CA на рабочие
устройства без отдельного согласования.

## Запуск с локальной панелью

```powershell
.\bin\ja3proxy.exe `
  --listen 127.0.0.1:8080 `
  --web-panel 127.0.0.1:9090 `
  --capture-tls
```

После запуска доступны страницы:

- `http://127.0.0.1:9090/`;
- `http://127.0.0.1:9090/recorder.html`.

## Обновление

Перед обновлением сохраните собственные конфигурационные файлы и каталог CA.
Затем обновите исходный код, проверьте модули и пересоберите бинарный файл:

```bash
git pull --ff-only
go mod download
go mod verify
go test ./...
go build -o bin/ja3proxy ./cmd/ja3proxy
```

Не заменяйте действующий процесс новой сборкой без предварительной проверки на
отдельном порту. Формат SQL-миграций пока не применяется: текущий recorder
использует память и необязательный JSONL.

## Удаление

Остановите процесс, удалите бинарный файл и ненужные записи. Отдельно удалите
сертификат тестового CA из доверенных хранилищ клиентов. Каталог `credentials`
следует архивировать или уничтожать согласно правилам обращения с секретами.
