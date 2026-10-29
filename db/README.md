# PostgreSQL

Для локального запуска можно поднять отдельную БД:

```sh
docker run -d --name kaspersky-postgres \
  -e POSTGRES_USER=threatintel \
  -e POSTGRES_PASSWORD=threatintel \
  -e POSTGRES_DB=threatintel \
  -p 127.0.0.1:5432:5432 postgres:17-alpine
make run-local
```

Это тестовые реквизиты. Для другой БД передай строку подключения:

```sh
DATABASE_URL='postgres://user:password@host:5432/database?sslmode=require' make run-local
```

Параметры пула и таймауты находятся в `config/local/config.yaml`.
Миграции из `db/migration` встроены в бинарник и применяются при старте приложения.
Повторный запуск безопасен: уже применённые версии пропускаются.
Ошибка подключения или миграции останавливает запуск до открытия HTTP-порта.
`migration_timeout` ограничивает ожидание блокировки мигратора и выполнение каждого SQL-файла.
При остановке сначала завершаются HTTP-запросы, затем закрывается пул БД.

```sh
make test-unit         # без Docker
make test-integration  # нужен запущенный Docker
```

Интеграционные тесты сами создают PostgreSQL на случайном порту и удаляют контейнер после теста.
Они не используют локальную БД приложения.

HTTP-методы используют сервис и PostgreSQL: POST создаёт запись, GET читает её, PUT полностью заменяет редактируемые поля.
