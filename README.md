# Threat Information Exchange Service

REST-сервис обмена информацией об угрозах на Go. Контракт: [api/openapi.yaml](api/openapi.yaml).

## Запуск в Docker

Нужны Docker и Docker Compose v2:

```sh
cp .env.example .env
make up
curl http://localhost:8000/health
```

Либо напрямую: `docker compose up --build --wait --wait-timeout 120`.
В `.env` можно поменять `HTTP_PORT`, `POSTGRES_PASSWORD` и `LOG_LEVEL`.
Это локальное окружение с демонстрационным паролем. HTTP-порт доступен только на `127.0.0.1`,
порт PostgreSQL наружу не публикуется.

Compose сначала дожидается готовности PostgreSQL. Приложение применяет встроенные миграции,
после чего открывает HTTP-порт. `--wait` проверяет готовность обоих контейнеров.
Приложение работает от непривилегированного пользователя с файловой системой только для чтения.

```sh
make logs                 # логи приложения
make down                 # остановить и удалить контейнеры, данные БД сохранятся
make up                   # поднять снова с прежними данными
```

Данные хранятся в именованном Docker volume. Для полного удаления **вместе с данными**:

```sh
docker compose down --volumes
```

После инициализации БД смена `POSTGRES_PASSWORD` в `.env` не меняет пароль уже созданной роли.
Для существующей БД пароль меняется через PostgreSQL; для пустого демонстрационного окружения
можно удалить volume и создать его заново.

## Пример запросов

```sh
curl -i -X POST http://localhost:8000/info \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic"}'

curl -i http://localhost:8000/info/d41d8cd98f00b204e9800998ecf8427e

curl -i -X PUT http://localhost:8000/info/d41d8cd98f00b204e9800998ecf8427e \
  -H 'Content-Type: application/json' \
  -d '{"name":"Trojan.Win32.Generic","severity":"high"}'
```

MD5 нормализуется в нижний регистр. Повторный POST возвращает 409.
PUT полностью заменяет редактируемые поля: опущенные значения очищаются или получают дефолты.

## Разработка и проверки

Локальный запуск без контейнера приложения описан в [db/README.md](db/README.md).

```sh
make all               # линтер, юнит-тесты с -race, сборка
make test-integration  # настоящий PostgreSQL в testcontainers; нужен Docker
make generate          # генерация типов и echo-сервера из OpenAPI
make check-generate    # проверка актуальности сгенерированного кода
```
