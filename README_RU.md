# RegAuth

**Registry Authentication Provider** — самостоятельный сервер токенов для Docker
Registry (`distribution/distribution`) v2 и v3.

`regauth` выдаёт JWT-токены по протоколу Docker Registry v2 Bearer Token. Реестр
проверяет подпись токена публичным ключом: для v2 через `rootcertbundle`
(PEM-сертификат), для v3 через `jwks` (JSON).

## Содержание

- [Что делает](#что-делает)
- [Компоненты](#компоненты)
- [Установка](#установка)
- [Первый запуск](#первый-запуск)
- [Конфигурация](#конфигурация)
  - [config.yaml](#configyaml)
  - [keystore.yaml](#keystoreyaml)
  - [accounts.yaml](#accountsyaml)
- [Справочник CLI](#справочник-cli)
- [Политики доступа](#политики-доступа)
- [Управление ключами](#управление-ключами)
- [Настройка реестра](#настройка-реестра)
- [Развёртывание в Docker](#развёртывание-в-docker)
- [Эксплуатация](#эксплуатация)
- [Диагностика](#диагностика)
- [Безопасность](#безопасность)
- [Лицензия](#лицензия)

## Что делает

Docker Registry поддерживает делегированную аутентификацию через сервер токенов.
Когда клиент (например, `docker push`) обращается к реестру, реестр отвечает
`401 Unauthorized` и заголовком `WWW-Authenticate` с указанием `realm` (сервер
токенов). Клиент запрашивает токен у `regauth`, передавая `service` и `scope`.
`regauth`:

1. Проверяет, что `service` входит в `allowed_services` (если список не пуст).
2. Аутентифицирует пользователя (Basic Auth) или считает запрос анонимным.
   - Заблокированный (`locked: true`) пользователь получает `401`.
   - Учётные данные `ANONYMOUS` трактуются как анонимные; пароль игнорируется.
3. Вычисляет права доступа для каждого запрошенного scope.
4. Выпускает подписанный JWT, содержащий только разрешённые действия.
5. Возвращает клиенту `{"token": "..."}`.

Клиент передаёт токен реестру. Реестр проверяет подпись публичным ключом и
применяет разрешённые действия.

`regauth` не хранит образы и не проксирует трафик реестра. Он только выдаёт и
подписывает токены.

## Компоненты

В проекте два бинарника:

- **`regauth`** — сервер токенов и управление ключами.
  - `server` — запускает HTTP(S) сервер токенов.
  - `keystore` — управляет ключами подписи (`list`, `rotate`, `rotate-v2`,
    `revoke`, `delete`, `cleanup`).
- **`reguser`** — менеджер учётных записей для `accounts.yaml`
  (`list`, `add`, `edit`, `del`, `lock`, `clean`, `hash`).

Вспомогательные файлы:

- `config.yaml` — конфигурация сервера (пути, порт, TLS, логирование,
  `keys_version`, `allowed_services`, exec-хуки).
- `keystore.yaml` — **единственный источник истины** для всех приватных ключей
  (v2 и v3).
- `accounts.yaml` — пользователи, хэши паролей, правила доступа, флаг `locked`.
- `public-v2.key` — X.509 сертификат, производный от keystore (для `rootcertbundle`
  v2).
- `public-v3.key` — JWKS JSON, производный от keystore (для `jwks` v3).

`public-*.key` всегда пересоздаются из `keystore.yaml`. Потеря этих файлов не
критична.

## Установка

### Требования

- Go 1.26 или новее (для сборки из исходников).
- Linux (для `flock`-блокировки pid-файла и проверок через `/proc`).
- Для Docker-развёртывания: Docker и Docker Compose.

### Сборка из исходников

```bash
git clone <repository-url> regauth
cd regauth
make check          # проверить версию Go
make build          # собрать bin/regauth и bin/reguser
make test           # запустить юнит-тесты
```

Статические бинарники (без зависимости от libc):

```bash
make static
```

### Системная установка

```bash
sudo make install               # установить в /usr/local/bin
sudo make install-completion    # установить bash-completion в /etc/bash_completion.d
```

Удаление:

```bash
sudo make uninstall
```

### Сборка и запуск в Docker

См. [Развёртывание в Docker](#развёртывание-в-docker).

## Первый запуск

Запустите сервер без аргументов, чтобы увидеть справку:

```bash
regauth
```

Если `config.yaml` не существует, `regauth` создаст его рядом с бинарником с
дефолтными значениями и сгенерирует keystore:

```bash
regauth server
```

Если `server.registry` в `config.yaml` не задан, сервер печатает сообщение со
списком созданных файлов и завершается с кодом `0`. Укажите `server.registry` в
конфиге и запустите снова:

```bash
regauth server
```

Сервер слушает `server.port` (по умолчанию `5100`), по HTTP, если TLS не настроен.

## Конфигурация

`regauth` читает три файла. Все пути разрешаются относительно каталога с
`config.yaml`, если не абсолютные.

### config.yaml

```yaml
server:
  registry: "https://registry.tld"
  port: 5100
  insecure: false
  pid_file: "/var/run/regauth.pid"
  logfile: "/var/log/regauth.log"
  logterm: true
  keys_version: 3
  allowed_services:
    - "registry.tld"
  keystore:
    rotate: []
    rotate_v2: []
    revoke: []
    delete: []
    cleanup: []
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

paths:
  accounts: "accounts.yaml"
  keystore: "keystore.yaml"
  public_v2: "public-v2.key"
  public_v3: "public-v3.key"
```

| Поле | По умолчанию | Описание |
|------|--------------|----------|
| `server.registry` | — | URL реестра, который обслуживает экземпляр. Обязателен для запуска. Используется только в логах и стартовой сводке. |
| `server.port` | `5100` | Порт прослушивания. |
| `server.insecure` | `false` | Отключает проверку заголовка `Origin`. Только для тестов. Перекрывается флагом `-insecure`. |
| `server.pid_file` | `/var/run/regauth.pid` | Pid-файл для блокировки единственного экземпляра и для отправки SIGHUP из `keystore rotate`. |
| `server.logfile` | `/var/log/regauth.log` | Лог-файл. Если файл создать не удалось — fallback на терминал (с предупреждением). |
| `server.logterm` | `true` | Дублировать лог в stderr. Не влияет на баннер и стартовую сводку: они всегда идут в терминал. |
| `server.keys_version` | `3` | Версия ключа подписи для всех выпускаемых токенов: `2` или `3`. См. [Управление ключами](#управление-ключами). |
| `server.allowed_services` | `[]` | **Опциональный** белый список допустимых `service` в запросах `/token`. **Если пуст или отсутствует — разрешены ЛЮБЫЕ `service` (fail-open).** Если задан — запросы с другим `service` отвергаются с `400 Bad Request`. **Для production ОБЯЗАТЕЛЬНО укажите точное внешнее имя реестра.** |
| `server.keystore.rotate` | `[]` | argv-список, выполняемый после успешного `keystore rotate` (без shell). |
| `server.keystore.rotate_v2` | `[]` | argv-список, выполняемый после успешного `keystore rotate-v2`. |
| `server.keystore.revoke` | `[]` | argv-список, выполняемый после успешного `keystore revoke`. |
| `server.keystore.delete` | `[]` | argv-список, выполняемый после успешного `keystore delete`. |
| `server.keystore.cleanup` | `[]` | argv-список, выполняемый после успешного `keystore cleanup`. |
| `server.tls.enabled` | — | Если задано, TLS работает явно: `true` требует `cert_file` и `key_file`; `false` принудительно HTTP. Если не задано, TLS автоопределяется (включается, когда оба файла заданы). |
| `server.tls.cert_file` | `""` | TLS-сертификат. |
| `server.tls.key_file` | `""` | TLS-приватный ключ. |
| `paths.accounts` | `accounts.yaml` | Пользователи и политики. |
| `paths.keystore` | `keystore.yaml` | Приватные ключи и метаданные. |
| `paths.public_v2` | `public-v2.key` | X.509 сертификат для v2 (`rootcertbundle`). |
| `paths.public_v3` | `public-v3.key` | JWKS JSON для v3 (`jwks`). |

**Коды возврата при старте:**

- Если `config.yaml` отсутствует, `regauth` создаёт его. Если после этого
  `server.registry` всё ещё пуст, печатает список созданных файлов и выходит с
  кодом `0`.
- Если `config.yaml` уже существовал, а `server.registry` пуст, выходит с кодом `1`.
- Если pid-файл создать не удалось (например, `/var/run` недоступен для записи),
  выходит с кодом `1`. Для non-root запуска задайте `server.pid_file` в
  доступное место.

### Exec-хуки

`server.keystore.*` — argv-списки (без shell), выполняемые после успешной
соответствующей операции keystore. Примеры:

```yaml
keystore:
  rotate: ["docker", "restart", "registry-v3"]
  rotate_v2: ["docker", "restart", "registry-v2"]
  revoke: ["systemctl", "reload", "registry-v3"]
```

Пустой список (или отсутствие) — ничего не запускается. Дочерний процесс
получает переменные окружения, описывающие операцию:

| Переменная | Описание |
|------------|----------|
| `REGAUTH_OPERATION` | `rotate`, `rotate-v2`, `revoke`, `delete`, `cleanup` |
| `REGAUTH_KEY_VERSION` | `3` (v3-операции) или `2` (`rotate-v2`) |
| `REGAUTH_KID` | `kid` ключа (для `rotate`, `revoke`, `delete`) |
| `REGAUTH_REMOVED` | число удалённых ключей (для `cleanup`) |

Ненулевой код возврата хука валит команду `keystore`. Изменение keystore уже
применено и не откатывается.

### keystore.yaml

`keystore.yaml` — **единственный источник истины** для всех приватных ключей.
`config.yaml` не содержит ключей. Производные файлы `public-v2.key` и
`public-v3.key` пересоздаются из keystore при каждом старте и каждой операции
keystore.

```yaml
v2:
  created_at: "2026-01-01T00:00:00Z"
  private: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----

v3:
  keys:
    - kid: "AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:GGGG:HHHH:IIII:JJJJ:KKKK:LLLL"
      created_at: "2026-01-01T00:00:00Z"
      current: true
      revoked: false
      private: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
```

- **`v2`** — ровно один ключ. Отзыва нет; `keystore rotate-v2` заменяет его
  целиком.
- **`v3.keys`** — список ключей. Ровно один имеет `current: true`. У отозванного
  ключа `private: ""` (приватный ключ стирается).

`keystore.yaml` должен иметь права `0600`. Не коммитить, не логировать, не
публиковать.

### accounts.yaml

`accounts.yaml` хранит пользователей, хэши паролей, правила доступа и флаг
`locked`.

```yaml
users:
  alice:
    password: "$2a$12$..."
    locked: false
    rules:
      - pattern: "actions/**"
        actions: ["pull", "push"]
        access: allow
      - pattern: "actions/secret/**"
        actions: ["*"]
        access: deny
      - pattern: "catalog"
        access: allow

  bob:
    password: "$2a$12$..."
    locked: true           # заблокирован; правила сохранены
    rules:
      - pattern: "library/*"
        actions: ["pull"]
        access: allow

  ANONYMOUS:
    rules:
      - pattern: "**"
        actions: ["pull"]
        access: allow
```

- **`password`** — bcrypt-хэш (cost 12). Plaintext не хранится и не логируется.
- **`locked`** — `true` блокирует аутентификацию (даже с верным паролем). Правила
  сохраняются. По умолчанию `false`. Управляется через
  `reguser lock <user> -lock|-unlock` или вручную. **Для `ANONYMOUS` игнорируется**
  (см. ниже).
- **`rules`** — список правил. Каждое правило: `pattern`, `actions`, `access`.
  Пользователь с `rules: []` существует, но не имеет прав (deny by default). Это
  не ошибка: логин проходит, но любое действие запрещено.
  **Для `pattern: "catalog"` поле `actions` можно опустить** (трактуется как
  `["*"]`). Для остальных pattern `actions` обязателен.
- **`ANONYMOUS`** — техническая учётка для неаутентифицированных запросов. Без
  пароля. Если пароль указан, он игнорируется с предупреждением.
  **`ANONYMOUS` нельзя удалить.** Если его нет в `accounts.yaml`, `regauth` при
  следующей загрузке пересоздаст его с дефолтными правилами
  (`**`/`pull`/`allow`) и сохранит на диск. Это значит, что анонимный доступ
  **включается (только чтение)** после пересоздания.
  **`locked` для `ANONYMOUS` игнорируется.** `reguser lock` отказывается менять
  его. Чтобы **запретить** анонимный доступ, не удаляйте `ANONYMOUS` и не
  пытайтесь его заблокировать; задайте `rules: []` (deny by default) или явные
  правила с `access: deny`.

## Справочник CLI

### regauth

```
regauth server [-c <config>] [-insecure]
regauth keystore list      [-c <config>]
regauth keystore rotate    [-c <config>]
regauth keystore rotate-v2 [-c <config>]
regauth keystore revoke    <kid> [-c <config>]
regauth keystore delete    <kid> [-c <config>]
regauth keystore cleanup   [-c <config>]
regauth -h
regauth                         # без аргументов — справка (exit 0)
```

| Флаг | Описание |
|------|----------|
| `-c <path>` | Путь к `config.yaml`. По умолчанию: `config.yaml` рядом с бинарником. |
| `-insecure` | Только `server`. Отключает проверку `Origin`. Перекрывает конфиг. Для тестов. |
| `-h` | Показать справку. |

**Принцип:** все настройки сервера — в `config.yaml`. CLI перекрывает только `-c`
и `-insecure`.

### reguser

```
reguser list [-c <config>] [-all] [-count]
reguser add <username> [-p <password>] [-c <config>]
reguser edit <username> [-p <new-password>] [-c <config>]
reguser del <username> [-c <config>]
reguser lock <username> -lock|-unlock [-c <config>]
reguser clean [-f] [-c <config>]
reguser hash [-p <password>]
reguser -h
```

| Команда | Описание |
|---------|----------|
| `list` | Показать список пользователей. По умолчанию `ANONYMOUS` **исключён**. Колонки: `USERNAME`, `TYPE`, `LOCKED`, `RULES`. `-all` включает `ANONYMOUS` в таблицу и подсчёт. `-count` печатает только число пользователей (учитывает `-all`). Пароли/хэши не выводятся. |
| `add` | Создать пользователя с `locked: false` и пустым списком правил (`rules: []` — deny by default). Ошибка, если пользователь уже есть. |
| `edit` | Сменить пароль. Ошибка, если пользователя нет. Не трогает `locked` и `rules`. |
| `del` | Удалить пользователя. Ошибка, если пользователя нет. `ANONYMOUS` удалить нельзя. |
| `lock` | Установить `locked: true` (`-lock`) или `false` (`-unlock`). Правила сохраняются. Ошибка, если пользователя нет. `ANONYMOUS` блокировать нельзя. |
| `clean` | Удалить ВСЕХ пользователей и пересоздать `ANONYMOUS` с дефолтными правилами. Требует `-f` или интерактивного подтверждения. |
| `hash` | Напечатать bcrypt-хэш пароля. Конфиг не нужен. |

`ANONYMOUS` нельзя добавить, отредактировать, удалить или заблокировать через
`reguser`. Управляйте им напрямую в `accounts.yaml`. Если его удалить, `regauth`
пересоздаст его с дефолтными правилами.

`-p` передаёт пароль в plaintext (для автоматизации). Без `-p` пароль читается с
терминала (дважды, с подтверждением) или из пайпа (один раз).

## Политики доступа

### Семантика правил

- `pattern` — glob по сегментам имени ресурса.
  - `*` совпадает ровно с одним сегментом.
  - `**` совпадает с любым числом сегментов (включая ноль).
  - `?` совпадает ровно с одним символом в сегменте.
- `actions` — список `pull`, `push`, `delete` или `*`.
  **Для `pattern: "catalog"` поле `actions` можно опустить** — трактуется как
  `["*"]` (реестр всегда запрашивает `registry:catalog:*`).
  Для остальных pattern `actions` обязателен.
- `access` — `allow` или `deny`.

### Вычисление

Для запроса `(пользователь, тип, имя, действие)`:

1. Собрать все правила, у которых тип ресурса совпадает с запросом, `pattern`
   совпадает с `name`, а `actions` содержит `action`.
2. Если есть хоть одно совпавшее правило с `access: deny` — **запрет**.
3. Если есть хоть одно совпавшее правило с `access: allow` — **разрешение**.
4. Если ни одно правило не совпало — **запрет** (deny by default).

### Типы ресурсов

`repository` и `registry` (catalog) независимы:

- **`repository`** — правила совпадают с именами репозиториев (`actions/project`,
  `library/ubuntu`).
- **`registry`** — правила совпадают только с `pattern: "catalog"` и управляют
  `registry:catalog:*` (список всех репозиториев).

Они не пересекаются. Правило `**` **не** даёт доступ к каталогу. Правило `catalog`
**не** даёт доступ к репозиториям. **Каталог требует явного правила.**

**`actions` необязателен для `catalog`.** Эти два правила эквивалентны:

```yaml
- pattern: "catalog"
  actions: ["*"]
  access: allow
```

```yaml
- pattern: "catalog"
  access: allow
```

Для правил репозиториев (`pattern: "**"`, `"actions/*"`, ...) `actions` всегда
обязателен. `ValidateRule` отвергает правило репозитория с пустым `actions`.

### Примеры

**Полный администратор:**

```yaml
admin:
  password: "$2a$12$..."
  locked: false
  rules:
    - pattern: "**"
      actions: ["pull", "push", "delete"]
      access: allow
    - pattern: "catalog"
      access: allow
```

**Read-only пользователь для namespace, с исключением:**

```yaml
bob:
  password: "$2a$12$..."
  locked: false
  rules:
    - pattern: "team/**"
      actions: ["pull"]
      access: allow
    - pattern: "team/secret/**"
      actions: ["*"]
      access: deny
```

**Пользователь без прав (`rules: []`):**

```yaml
charlie:
  password: "$2a$12$..."
  locked: false
  rules: []
```

`charlie` может логиниться, но любое действие запрещено (deny by default). Это не
ошибка.

**Заблокированный пользователь (правила сохранены, логин запрещён):**

```yaml
dave:
  password: "$2a$12$..."
  locked: true
  rules:
    - pattern: "team/**"
      actions: ["pull"]
      access: allow
```

`dave` не может логиниться, пока `locked: true`, даже с верным паролем. Правила
сохраняются и начинают действовать после `-unlock`.

**Анонимный доступ на чтение:**

```yaml
ANONYMOUS:
  rules:
    - pattern: "**"
      actions: ["pull"]
      access: allow
```

**Анонимный доступ отключён (запись `ANONYMOUS` сохранена):**

```yaml
ANONYMOUS:
  rules: []
```

Анонимные запросы получают токен с пустым `access` (deny by default).

## Управление ключами

`keystore.yaml` — источник истины. Операции:

### Список ключей

```bash
regauth keystore list
```

Печатает `created_at` для v2 и таблицу v3-ключей: `KID`, `CREATED`, `CURRENT`,
`REVOKED`.

### Ротация v3 ключа подписи

```bash
regauth keystore rotate
```

- Генерирует новый v3-ключ.
- Добавляет его публичную часть в `public-v3.key` (старые ключи сохраняются).
- Обновляет текущий ключ в `keystore.yaml`.
- Отправляет `SIGHUP` работающему `regauth` (если найден через pid-файл), чтобы
  сервер начал подписывать новые токены новым ключом.
- Запускает `server.keystore.rotate` (если задан).

Старые токены (подписанные предыдущим ключом) остаются валидными до истечения
`exp`. Реестр должен перечитать `public-v3.key` — используйте
`server.keystore.rotate` (например, `docker restart registry-v3`).

### Ротация v2 ключа подписи

```bash
regauth keystore rotate-v2
```

- Генерирует новый v2-ключ.
- **Заменяет** старый v2-ключ (у v2 один ключ).
- Пересоздаёт `public-v2.key` как новый X.509 сертификат.
- Запускает `server.keystore.rotate_v2` (всегда, даже если сервер не запущен).

Старые v2-токены перестают проверяться после того, как реестр перечитает
`rootcertbundle`. Используйте `server.keystore.rotate_v2` (например,
`docker restart registry-v2`).

### Отзыв v3 ключа

```bash
regauth keystore revoke <kid>
```

- Помечает ключ как отозванный.
- Стирает его приватный ключ.
- Убирает его из `public-v3.key`.
- Запускает `server.keystore.revoke` (если задан).

Текущий ключ отозвать нельзя (сначала `rotate`). Реестр должен перечитать
`public-v3.key`, чтобы изменение вступило в силу — используйте
`server.keystore.revoke`.

### Удаление отозванного v3 ключа

```bash
regauth keystore delete <kid>
```

Удалять можно только отозванные ключи. Удаляет запись из `keystore.yaml`.

### Очистка отозванных v3 ключей

```bash
regauth keystore cleanup
```

Удаляет все отозванные v3-записи из `keystore.yaml`.

### keys_version

`server.keys_version` выбирает ключ подписи для **всех** выпускаемых токенов:

- `3` (по умолчанию) — все токены подписываются текущим v3-ключом. Используйте
  для `registry-v3` (`jwks`).
- `2` — все токены подписываются v2-ключом. Используйте для `registry-v2`
  (`rootcertbundle`).

Один экземпляр `regauth` обслуживает один тип реестра (v2 **или** v3). Для обоих
запустите два экземпляра (каждый со своим конфигом и keystore) или переключайте
конфиг.

## Настройка реестра

> **Предупреждение безопасности (fail-open по умолчанию):**
> Если `server.allowed_services` пуст или отсутствует, `regauth` выдаёт токены для
> **любого** `service`, который запросит клиент (например, `registry.tld`,
> `nonexistent.example.com`). Для production **обязательно** задайте
> `server.allowed_services` с точным внешним именем реестра. См.
> [config.yaml](#configyaml).

### registry v2

```yaml
auth:
  token:
    realm: https://regauth.tld/token
    service: registry.tld
    issuer: regauth
    rootcertbundle: /etc/registry/public-v2.key
```

`public-v2.key` — X.509 сертификат. `distribution` v2 требует сертификат, а не
публичный ключ (`BEGIN CERTIFICATE`, не `BEGIN PUBLIC KEY`).

После `keystore rotate-v2` реестр должен перечитать сертификат. Используйте
`server.keystore.rotate_v2`.

### registry v3

```yaml
auth:
  token:
    realm: https://regauth.tld/token
    service: registry.tld
    issuer: regauth
    jwks: /etc/registry/public-v3.key
```

`distribution` v3 читает JWKS **из файла**, не по HTTP. `public-v3.key` должен
быть доступен реестру на диске. После `keystore rotate`/`revoke`/`cleanup` реестр
должен перечитать файл. Используйте `server.keystore.*`.

### HTTP JWKS-эндпоинт (опционально)

`regauth` также отдаёт `GET /.well-known/jwks.json` на порту токенов. Возвращает
тот же JSON, что `public-v3.key` (только активные ключи). `distribution` v3 его
не использует, но он полезен для отладки и других потребителей, поддерживающих
HTTP JWKS.

### Проверка через curl

`docker` автоматически запрашивает Bearer-токен из realm. `curl` — нет.
`curl -u user:pass https://registry.tld/v2/_catalog` вернёт `401 Unauthorized`,
потому что реестр ожидает Bearer-токен, а не Basic Auth.

Чтобы запросить каталог через `curl`, сначала получите токен:

```bash
TOKEN=$(curl -s -u admin:password \
  "https://regauth.tld/token?service=registry.tld&scope=registry:catalog:*" \
  | jq -r .token)

curl -H "Authorization: Bearer $TOKEN" https://registry.tld/v2/_catalog
```

## Развёртывание в Docker

Типичное развёртывание — четыре контейнера на одной ВМ: `caddy`, `regauth`,
`registry-v2`, `registry-v3`. Caddy терминирует TLS и проксирует запросы к
контейнерам по внутренней Docker-сети. Все внешние имена резолвятся в один и тот
же хост (split DNS допустим).

### Структура на хосте

```
.
├── docker-compose.yml
├── Caddyfile
├── certs/
│   ├── fullchain.pem
│   └── privkey.pem
├── config/
│   ├── regauth.yaml        # -> /etc/regauth/config.yaml (ro)
│   ├── registry-v2.yml     # -> /etc/docker/registry/config.yml (ro)
│   └── registry-v3.yml     # -> /etc/distribution/config.yml (ro)
├── data/
│   ├── regauth/            # -> /var/lib/regauth (rw)
│   ├── registry-v2/        # -> /var/lib/registry (rw)
│   └── registry-v3/        # -> /var/lib/registry (rw)
├── caddy/
│   ├── data/
│   └── config/
└── regauth-source/         # клон репозитория regauth
```

### Dockerfile

Multi-stage, `golang:1.26-alpine` → `alpine:latest`. Бинарники в `/usr/local/bin`.
Рабочий каталог `/var/lib/regauth`. `ENTRYPOINT ["/usr/local/bin/regauth"]`,
`CMD ["server", "-c", "/etc/regauth/config.yaml"]`. Пользователь `regauth` должен
иметь UID/GID, совпадающий с владельцем `./data/regauth` на хосте (обычно 1000).

### docker-compose.yml

```yaml
version: "3.8"

services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./certs:/certs:ro
      - ./caddy/data:/data
      - ./caddy/config:/config
    networks:
      - regnet

  regauth:
    build:
      context: ./regauth-source
      dockerfile: Dockerfile
    image: regauth:latest
    restart: unless-stopped
    expose:
      - "5100"
    volumes:
      - ./config/regauth.yaml:/etc/regauth/config.yaml:ro
      - ./data/regauth:/var/lib/regauth
    healthcheck:
      test: ["CMD-SHELL", "test -s /var/lib/regauth/public-v2.key && test -s /var/lib/regauth/public-v3.key"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
    networks:
      - regnet

  registry-v2:
    image: registry:2
    restart: unless-stopped
    expose:
      - "5000"
    volumes:
      - ./config/registry-v2.yml:/etc/docker/registry/config.yml:ro
      - ./data/regauth:/etc/registry:ro
      - ./data/registry-v2:/var/lib/registry
    depends_on:
      regauth:
        condition: service_healthy
    networks:
      - regnet

  registry-v3:
    image: registry:3
    restart: unless-stopped
    expose:
      - "5000"
    volumes:
      - ./config/registry-v3.yml:/etc/distribution/config.yml:ro
      - ./data/regauth:/etc/registry:ro
      - ./data/registry-v3:/var/lib/registry
    depends_on:
      regauth:
        condition: service_healthy
    networks:
      - regnet

networks:
  regnet:
    driver: bridge
```

**Примечания:**

- Вся папка `./data/regauth` монтируется в реестры (только чтение), чтобы
  `public-v2.key` / `public-v3.key` были доступны как
  `/etc/registry/public-*.key`. Монтирование отдельных файлов не рекомендуется:
  Docker создаёт папки для отсутствующих источников bind-mount.
- `depends_on: condition: service_healthy` гарантирует, что реестры запустятся
  только после того, как `regauth` сгенерирует ключи.
- Контейнер `regauth` работает не от root. `server.pid_file` и `server.logfile`
  должны указывать в `/var/lib/regauth/...` (writable volume), а не в `/var/run` /
  `/var/log`.

### Caddyfile

```caddy
regauth.tld {
    tls /certs/fullchain.pem /certs/privkey.pem
    reverse_proxy regauth:5100
}
registry-v2.tld {
    tls /certs/fullchain.pem /certs/privkey.pem
    reverse_proxy registry-v2:5000
}
registry-v3.tld {
    tls /certs/fullchain.pem /certs/privkey.pem
    reverse_proxy registry-v3:5000
}
```

### Перед `docker compose up`

1. Создайте пустые файлы конфигов (иначе Docker создаст папки):

   ```bash
   mkdir -p config data/regauth data/registry-v2 data/registry-v3 caddy/data caddy/config certs
   touch config/regauth.yaml config/registry-v2.yml config/registry-v3.yml Caddyfile
   ```

2. Заполните `config/registry-v2.yml`, `config/registry-v3.yml` и `Caddyfile`
   реальным содержимым (примеры выше). `config/regauth.yaml` может остаться пустым
   при самом первом запуске: `regauth` заполнит его дефолтами (но
   `server.registry` нужно будет задать afterwards).

3. Положите TLS-сертификаты в `./certs/`.

4. Убедитесь, что `./data/regauth` принадлежит UID, от которого работает контейнер
   `regauth` (обычно 1000):

   ```bash
   chown -R 1000:1000 data/regauth
   ```

### Запуск

```bash
docker compose up -d --build
```

При первом запуске в `./data/regauth` появятся `keystore.yaml`, `public-v2.key`,
`public-v3.key`, `accounts.yaml`.

## Эксплуатация

### Список пользователей

```bash
reguser list -c /etc/regauth/config.yaml
```

По умолчанию `ANONYMOUS` **исключён**. Вывод (колонки):

```
USERNAME             TYPE       LOCKED RULES
--------------------------------------------
alice                user       no     2
bob                  user       yes    1
```

- **USERNAME** — имя пользователя.
- **TYPE** — `user` для обычных пользователей.
- **LOCKED** — `yes`, если `locked: true`, иначе `no`.
- **RULES** — число правил доступа. `0` значит, что пользователь существует, но
  не имеет прав (deny by default). Это не ошибка.

Включить `ANONYMOUS`:

```bash
reguser list -all -c /etc/regauth/config.yaml
```

```
USERNAME             TYPE       LOCKED RULES
--------------------------------------------
ANONYMOUS            anonymous  no     1
alice                user       no     2
bob                  user       yes    1
```

Посчитать пользователей:

```bash
reguser list -count -c /etc/regauth/config.yaml        # без ANONYMOUS
reguser list -all -count -c /etc/regauth/config.yaml   # включая ANONYMOUS
```

Примечания:

- Пароли и bcrypt-хэши **никогда** не выводятся.
- Если `accounts.yaml` пуст или отсутствует, `regauth` пересоздаёт его с
  `ANONYMOUS` (дефолт `**`/`pull`/`allow`), поэтому `list -all` всегда покажет
  хотя бы `ANONYMOUS`.
- Если вы удалили `ANONYMOUS` вручную, следующий `list` (который вызывает `Load`)
  пересоздаст его с дефолтными правилами и сохранит на диск.
- Проверить наличие пользователя в скрипте:
  ```bash
  reguser list -all -c /etc/regauth/config.yaml | awk 'NR>2 {print $1}' | grep -qx alice
  ```
- Найти заблокированных пользователей:
  ```bash
  reguser list -all -c /etc/regauth/config.yaml | awk 'NR>2 && $3=="yes" {print $1}'
  ```
- Найти пользователей без правил (без прав):
  ```bash
  reguser list -all -c /etc/regauth/config.yaml | awk 'NR>2 && $4==0 {print $1}'
  ```

### Добавить пользователя

```bash
reguser add alice -p secret -c /etc/regauth/config.yaml
```

Создаёт пользователя с `locked: false` и пустым списком правил (`rules: []` —
deny by default). Затем отредактируйте `accounts.yaml` (или используйте внешний
инструмент), чтобы добавить правила. Перезапуск не требуется: `regauth` читает
`accounts.yaml` на каждом запросе.

Если `-p` не задан, пароль читается с терминала (дважды, с подтверждением) или
из пайпа (один раз).

### Сменить пароль пользователя

```bash
reguser edit alice -p newsecret -c /etc/regauth/config.yaml
```

Ошибка, если пользователя нет. Не трогает `locked` и `rules`.

### Удалить пользователя

```bash
reguser del alice -c /etc/regauth/config.yaml
```

Ошибка, если пользователя нет. `ANONYMOUS` удалить нельзя.

### Заблокировать / разблокировать пользователя

```bash
reguser lock alice -lock -c /etc/regauth/config.yaml     # locked: true
reguser lock alice -unlock -c /etc/regauth/config.yaml   # locked: false
```

- `locked: true` блокирует аутентификацию (даже с верным паролем). Реестр
  получает `401`, потому что токен не выпускается.
- **Правила сохраняются.** После `-unlock` права пользователя те же, что были до
  блокировки.
- `ANONYMOUS` заблокировать нельзя (`reguser lock ANONYMOUS ...` завершится
  ошибкой). Чтобы отключить анонимный доступ, задайте `rules: []` или
  `access: deny` в `accounts.yaml`.

### Сбросить всех пользователей (clean)

```bash
reguser clean -f -c /etc/regauth/config.yaml
```

Удаляет ВСЕХ пользователей и пересоздаёт `ANONYMOUS` с дефолтными правилами
(`**`/`pull`/`allow`). Без `-f` запрашивает интерактивное подтверждение.

### Хэш пароля

```bash
reguser hash -p secret
# или интерактивно:
reguser hash
```

Печатает bcrypt-хэш для вставки в `accounts.yaml`. Конфиг не нужен.

## Диагностика

### `server.registry is required in config`

Задайте `server.registry` в `config.yaml` (или запустите с конфигом, где оно уже
есть).

### `service is required` / `service not allowed`

Эндпоинт `/token` требует параметр `service`, и если `server.allowed_services`
не пуст, значение должно быть в списке. Проверьте конфиг реестра
(`auth.token.service`) и `server.allowed_services`.

### Токены выдаются для неизвестных `service`

Это ожидаемое поведение, если `server.allowed_services` пуст или отсутствует
(fail-open). Чтобы запретить выдачу токенов для произвольных/неизвестных сервисов,
задайте `server.allowed_services` с точным внешним именем реестра. При непустом
списке `regauth` отвергает любой другой `service` с `400 Bad Request`.

### Анонимный доступ остаётся включённым после правки accounts.yaml

`ANONYMOUS` нельзя удалить. Если вы его удалили, `regauth` пересоздаст его с
дефолтными правилами (`**`/`pull`/`allow`), что **включает** анонимный доступ
на чтение. Чтобы отключить анонимный доступ, оставьте запись `ANONYMOUS` и
задайте `rules: []` (deny by default) или явные правила с `access: deny`.

### `locked: true` для ANONYMOUS не имеет эффекта

`locked` для `ANONYMOUS` игнорируется. `reguser lock ANONYMOUS ...` завершится
ошибкой `ErrAnonymous`. Чтобы отключить анонимный доступ, задайте `rules: []` или
`access: deny`.

### Пользователь может логиниться, но push/pull не работает

Пользователь существует, но у него `rules: []` или нет совпадающего `allow`.
Это deny by default. Добавьте правила в `accounts.yaml`. Логин при этом проходит
(токен выпускается), но `access` пуст, и реестр отклоняет действие.

### `cannot acquire lock at ...; set server.pid_file to a writable path`

Путь к pid-файлу недоступен для записи процессу `regauth`. В Docker используйте
`/var/lib/regauth/regauth.pid`. Нативно — запускайте от root или укажите
`server.pid_file` в доступное место.

### `another regauth instance is already running`

Живой `regauth` держит блокировку pid-файла. Остановите его или используйте другой
`server.pid_file`. Блокировка снимается ядром при завершении процесса (включая
`SIGKILL`).

### `token signed by untrusted key with ID: "..."` (v2)

`registry-v2` не может сопоставить токен с сертификатом. Проверьте:

- `server.keys_version` равен `2`.
- `public-v2.key` — X.509 сертификат (`BEGIN CERTIFICATE`).
- Реестр использует правильный путь `rootcertbundle`.
- Реестр перечитал `public-v2.key` после ротации.

### `malformed token` (v2)

`distribution` v2 отвергает токены, где `aud` — массив. `regauth` всегда отдаёт
`aud` строкой; если эта ошибка возникает, проверьте, что запущена сборка `regauth`
с исправлением string-`aud`.

### `token signed by untrusted key` / v3 не работает

- `public-v3.key` должен содержать ключ с совпадающим `kid`.
- Реестр должен перечитать `public-v3.key` после ротации/отзыва.
- Используйте `server.keystore.*` хуки для перезапуска/перечитывания реестра.

### `permission denied` при записи в `/var/lib/regauth` (Docker)

UID контейнера не совпадает с владельцем `./data/regauth`. Исправьте в
`Dockerfile` (задайте UID/GID 1000) или сделайте `chown` на хосте.

### `is a directory` для конфигов

Docker создал папку вместо файла, потому что источник bind-mount отсутствовал.
Создайте пустые файлы (`touch`) до `docker compose up` или заполните их реальным
содержимым.

### Логи идут в терминал вместо лог-файла

`regauth` не смог создать `server.logfile` (права, read-only ФС). Он пишет
предупреждение и продолжает вывод в терминал. Исправьте путь или права.

### Exec-хук зависает или падает

Exec-хуки запускаются как argv-списки (без shell), без таймаута. Зависшая команда
подвесит операцию keystore. Держите хуки короткими и надёжными. Ненулевой код
возврата валит команду keystore; изменение keystore уже применено.

## Безопасность

- `keystore.yaml` содержит приватные ключи. Держите `0600`, не коммитьте, не
  логируйте, не публикуйте.
- `accounts.yaml` содержит bcrypt-хэши. Не логируйте и не коммитьте.
- Хэши паролей — bcrypt cost 12. Не снижайте в production.
- `-insecure` отключает проверку `Origin`. Только для тестов.
- HTTP JWKS-эндпоинт публикует только публичные ключи. Публиковать его безопасно,
  но `distribution` v3 его не требует.
- **Всегда задавайте `server.allowed_services` с точным внешним именем реестра.**
  Если список пуст, `regauth` выдаст токен для **любого** `service`, который
  запросит клиент (fail-open). Это серьёзный риск в production.
- **`ANONYMOUS` нельзя удалить.** Если его нет в `accounts.yaml`, он
  пересоздаётся с дефолтными правилами (`**`/`pull`/`allow`) при следующей
  загрузке, что **включает** анонимный доступ на чтение. Чтобы отключить
  анонимный доступ, не удаляйте запись; задайте `rules: []` (deny by default)
  или явные правила с `access: deny` для нужных scope.
- **`locked` для `ANONYMOUS` игнорируется.** Блокировка обычного пользователя
  запрещает логин, но сохраняет правила. Для анонимного доступа используйте
  правила, а не `locked`.
- **`actions` необязателен для `pattern: "catalog"`.** Если опущен, трактуется
  как `["*"]`. Для правил репозиториев `actions` обязателен; `ValidateRule`
  отвергает пустой список.
- При компрометации ключа: ротируйте затронутый ключ (`keystore rotate` или
  `keystore rotate-v2`), обеспечьте перечитывание публичного ключа реестром,
  отзовите старые токены ротацией (для v3 старые токены остаются валидными до
  `exp`, пока ключ не удалён из JWKS — ротация оставляет старый ключ в JWKS,
  `revoke` удаляет его).
- `keystore.*` хуки запускают внешние команды без таймаута. Держите их короткими и
  надёжными. См. [Exec-хуки](#exec-хуки) для переменных окружения, передаваемых
  дочернему процессу.

## Лицензия

Проект распространяется под лицензией MIT. Полный текст — в файле [LICENSE](LICENSE).
