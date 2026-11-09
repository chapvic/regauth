# RegAuth

**Registry Authentication Provider** — a standalone token server for Docker Registry
(`distribution/distribution`) v2 and v3.

`regauth` issues JWT tokens according to the Docker Registry v2 Bearer Token protocol.
The registry verifies the token signature using a public key: for v2 via
`rootcertbundle` (PEM certificate), for v3 via `jwks` (JSON).

## Contents

- [What it does](#what-it-does)
- [Components](#components)
- [Installation](#installation)
- [First run](#first-run)
- [Configuration](#configuration)
  - [config.yaml](#configyaml)
  - [keystore.yaml](#keystoreyaml)
  - [accounts.yaml](#accountsyaml)
- [CLI reference](#cli-reference)
- [Access policies](#access-policies)
- [Key management](#key-management)
- [Registry setup](#registry-setup)
- [Docker deployment](#docker-deployment)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [License](#license)

## What it does

Docker Registry supports delegated authentication via a token server. When a client
(e.g. `docker push`) accesses a registry, the registry responds with `401 Unauthorized`
and a `WWW-Authenticate` header pointing to a `realm` (the token server). The client
requests a token from `regauth`, providing `service` and `scope`. `regauth`:

1. Verifies that `service` is in `allowed_services` (if the list is non-empty).
2. Authenticates the user (Basic Auth) or treats the request as anonymous.
   - A locked user (`locked: true`) is rejected with `401`.
   - `ANONYMOUS` credentials are treated as anonymous; the password is ignored.
3. Evaluates access policies for each requested scope.
4. Issues a signed JWT containing only the actions the user is allowed to perform.
5. Returns `{"token": "..."}` to the client.

The client then sends the token to the registry. The registry verifies the signature
with a public key and enforces the granted actions.

`regauth` does not store images and does not proxy registry traffic. It only issues
and signs tokens.

## Components

The project contains two binaries:

- **`regauth`** — the token server and key management tool.
  - `server` — runs the HTTP(S) token server.
  - `keystore` — manages signing keys (`list`, `rotate`, `rotate-v2`, `revoke`,
    `delete`, `cleanup`).
- **`reguser`** — account manager for `accounts.yaml`
  (`list`, `add`, `edit`, `del`, `lock`, `clean`, `hash`).

Supporting files:

- `config.yaml` — server configuration (paths, ports, TLS, logging, `keys_version`,
  `allowed_services`, exec hooks).
- `keystore.yaml` — **single source of truth** for all private keys (v2 and v3).
- `accounts.yaml` — users, password hashes, access rules, `locked` flag.
- `public-v2.key` — X.509 certificate derived from keystore (for v2 `rootcertbundle`).
- `public-v3.key` — JWKS JSON derived from keystore (for v3 `jwks`).

`public-*.key` are always regenerated from `keystore.yaml`. Losing them is not fatal.

## Installation

### Requirements

- Go 1.26 or newer (for building from source).
- Linux (for `flock`-based pid-file locking and `/proc`-based process checks).
- For Docker deployment: Docker and Docker Compose.

### Build from source

```bash
git clone <repository-url> regauth
cd regauth
make check          # verify Go version
make build          # produces bin/regauth and bin/reguser
make test           # run unit tests
```

Static binaries (no libc dependency):

```bash
make static
```

### Install system-wide

```bash
sudo make install               # installs to /usr/local/bin
sudo make install-completion    # installs bash completions to /etc/bash_completion.d
```

To uninstall:

```bash
sudo make uninstall
```

### Build and run in Docker

See [Docker deployment](#docker-deployment).

## First run

Run the server without arguments to see help:

```bash
regauth
```

If no `config.yaml` exists, `regauth` creates one next to the binary with default
values and generates a keystore:

```bash
regauth server
```

If `server.registry` is not set in `config.yaml`, the server prints a message listing
the created files and exits with code 0. Set `server.registry` in the config and run
again:

```bash
regauth server
```

The server listens on `server.port` (default `5100`), using HTTP unless TLS is
configured.

## Configuration

`regauth` reads three files. All paths are resolved relative to the directory
containing `config.yaml` unless absolute.

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

| Field | Default | Description |
|-------|---------|-------------|
| `server.registry` | — | Registry URL this instance serves. Required to start. Used only in logs and the startup summary. |
| `server.port` | `5100` | Listen port. |
| `server.insecure` | `false` | Disables `Origin` header checks. Use only in tests. Can be overridden with `-insecure`. |
| `server.pid_file` | `/var/run/regauth.pid` | PID file for the single-instance lock and for SIGHUP delivery from `keystore rotate`. |
| `server.logfile` | `/var/log/regauth.log` | Log file. If the file cannot be created, logging falls back to the terminal (with a warning). |
| `server.logterm` | `true` | Duplicate log output to stderr. Does not affect the banner or startup summary: they always go to the terminal. |
| `server.keys_version` | `3` | Signing key version for all issued tokens: `2` or `3`. See [Key management](#key-management). |
| `server.allowed_services` | `[]` | **Optional** whitelist of allowed `service` values in `/token` requests. **If empty or omitted, `regauth` allows ANY service (fail-open).** If non-empty, requests with any other `service` are rejected with `400 Bad Request`. **For production, you MUST set this to the exact external registry hostname(s).** |
| `server.keystore.rotate` | `[]` | argv list run after a successful `keystore rotate` (no shell). |
| `server.keystore.rotate_v2` | `[]` | argv list run after a successful `keystore rotate-v2`. |
| `server.keystore.revoke` | `[]` | argv list run after a successful `keystore revoke`. |
| `server.keystore.delete` | `[]` | argv list run after a successful `keystore delete`. |
| `server.keystore.cleanup` | `[]` | argv list run after a successful `keystore cleanup`. |
| `server.tls.enabled` | — | If set, TLS works explicitly: `true` requires `cert_file` and `key_file`; `false` forces HTTP. If omitted, TLS is auto-detected (enabled when both files are set). |
| `server.tls.cert_file` | `""` | TLS certificate. |
| `server.tls.key_file` | `""` | TLS private key. |
| `paths.accounts` | `accounts.yaml` | Users and policies. |
| `paths.keystore` | `keystore.yaml` | Private keys and metadata. |
| `paths.public_v2` | `public-v2.key` | X.509 certificate for v2 (`rootcertbundle`). |
| `paths.public_v3` | `public-v3.key` | JWKS JSON for v3 (`jwks`). |

**Exit codes on start:**

- If `config.yaml` is missing, `regauth` creates it. If `server.registry` is still
  empty after that, it prints the created file list and exits with code `0`.
- If `config.yaml` already existed and `server.registry` is empty, it exits with
  code `1`.
- If the PID file cannot be created (e.g. `/var/run` is not writable), it exits with
  code `1`. Set `server.pid_file` to a writable path for non-root runs.

### Exec hooks

`server.keystore.*` hooks are argv lists (no shell) executed after the corresponding
keystore operation succeeds. Examples:

```yaml
keystore:
  rotate: ["docker", "restart", "registry-v3"]
  rotate_v2: ["docker", "restart", "registry-v2"]
  revoke: ["systemctl", "reload", "registry-v3"]
```

An empty list (or omitted) means "do nothing". The child process receives environment
variables describing the operation:

| Variable | Description |
|----------|-------------|
| `REGAUTH_OPERATION` | `rotate`, `rotate-v2`, `revoke`, `delete`, `cleanup` |
| `REGAUTH_KEY_VERSION` | `3` (v3 operations) or `2` (`rotate-v2`) |
| `REGAUTH_KID` | key id (for `rotate`, `revoke`, `delete`) |
| `REGAUTH_REMOVED` | number of removed keys (for `cleanup`) |

A non-zero exit code of the hook fails the `keystore` command. The keystore change
is already applied and is not rolled back.

### keystore.yaml

`keystore.yaml` is the **single source of truth** for all private keys. `config.yaml`
contains no keys. The derived files `public-v2.key` and `public-v3.key` are
regenerated from the keystore on every start and on every keystore operation.

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

- **`v2`** — exactly one key. No revocation; `keystore rotate-v2` replaces it
  entirely.
- **`v3.keys`** — list of keys. Exactly one has `current: true`. A revoked key has
  `private: ""` (the private key is wiped).

`keystore.yaml` must be `0600`. Do not commit it, do not log it, do not expose it.

### accounts.yaml

`accounts.yaml` stores users, password hashes, access rules, and the `locked` flag.

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
    locked: true           # blocked; rules are kept
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

- **`password`** — bcrypt hash (cost 12). Plaintext is never stored and never logged.
- **`locked`** — `true` blocks authentication (even with the correct password).
  Rules are preserved. Default `false`. Manage with `reguser lock <user> -lock|-unlock`
  or edit manually. **Ignored for `ANONYMOUS`** (see below).
- **`rules`** — list of rules. Each rule: `pattern`, `actions`, `access`.
  A user with `rules: []` exists but has no permissions (deny by default). This is
  not an error; the user can log in, but every action is denied.
  For `pattern: "catalog"` the `actions` field **may be omitted** (treated as `["*"]`).
  For all other patterns `actions` is required.
- **`ANONYMOUS`** — technical account for unauthenticated requests. No password.
  If a password is present, it is ignored with a warning.
  **`ANONYMOUS` cannot be deleted.** If it is missing from `accounts.yaml`, `regauth`
  recreates it with default rules (`**`/`pull`/`allow`) on the next load and saves
  it to disk. This means anonymous access is **enabled (read-only)** after
  recreation.
  **`locked` is ignored for `ANONYMOUS`.** `reguser lock` refuses to change it.
  To **disable** anonymous access, do not delete `ANONYMOUS` and do not try to lock
  it; instead set `rules: []` (deny by default) or explicit `access: deny` rules.

## CLI reference

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
regauth                         # no arguments — help (exit 0)
```

| Flag | Description |
|------|-------------|
| `-c <path>` | Path to `config.yaml`. Default: `config.yaml` next to the binary. |
| `-insecure` | `server` only. Disables `Origin` checks. Overrides config. For tests. |
| `-h` | Show help. |

**Principle:** all server settings live in `config.yaml`. The CLI only overrides `-c`
and `-insecure`.

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

| Command | Description |
|---------|-------------|
| `list` | List users. By default `ANONYMOUS` is **excluded**. Columns: `USERNAME`, `TYPE`, `LOCKED`, `RULES`. `-all` includes `ANONYMOUS` in the table and count. `-count` prints only the number of users (respects `-all`). Passwords/hashes are never shown. |
| `add` | Create a user with `locked: false` and an empty rule list (`rules: []` — deny by default). Fails if the user exists. |
| `edit` | Change password. Fails if the user does not exist. Does not touch `locked` or `rules`. |
| `del` | Delete a user. Fails if the user does not exist. `ANONYMOUS` cannot be deleted. |
| `lock` | Set `locked: true` (`-lock`) or `false` (`-unlock`). Rules are preserved. Fails if the user does not exist. `ANONYMOUS` cannot be locked. |
| `clean` | Delete ALL users and recreate `ANONYMOUS` with default rules. Requires `-f` or interactive confirmation. |
| `hash` | Print a bcrypt hash for a password. No config needed. |

`ANONYMOUS` cannot be added, edited, deleted, or locked via `reguser`. Manage it in
`accounts.yaml` directly, but note: if you remove it, `regauth` will recreate it.

`-p` passes the password in plaintext (for automation). Without `-p`, the password
is read from the terminal (twice, with confirmation) or from a pipe (once).

## Access policies

### Rule semantics

- `pattern` — glob over resource name segments.
  - `*` matches exactly one segment.
  - `**` matches any number of segments (including zero).
  - `?` matches exactly one character within a segment.
- `actions` — list of `pull`, `push`, `delete`, or `*`.
  **For `pattern: "catalog"` the `actions` field may be omitted**; it is treated
  as `["*"]` (the registry always requests `registry:catalog:*`).
  For all other patterns `actions` is required.
- `access` — `allow` or `deny`.

### Evaluation

For a request `(user, type, name, action)`:

1. Collect all rules whose resource type matches the request and whose `pattern`
   matches `name` and whose `actions` include `action`.
2. If any matching rule has `access: deny` — **deny**.
3. If any matching rule has `access: allow` — **allow**.
4. If no rule matched — **deny** (deny by default).

### Resource types

`repository` and `registry` (catalog) are independent:

- **`repository`** rules match repository names (`actions/project`, `library/ubuntu`).
- **`registry`** rules match only `pattern: "catalog"` and control
  `registry:catalog:*` (listing all repositories).

They do not overlap. A `**` rule does **not** grant catalog access. A `catalog` rule
does **not** grant repository access. **Catalog requires an explicit rule.**

**`actions` is optional for `catalog`.** These two rules are equivalent:

```yaml
- pattern: "catalog"
  actions: ["*"]
  access: allow
```

```yaml
- pattern: "catalog"
  access: allow
```

For repository rules (`pattern: "**"`, `"actions/*"`, ...) `actions` is always
required. `ValidateRule` rejects a repository rule with empty `actions`.

### Examples

**Full admin:**

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

**Read-only user for a namespace, with an exception:**

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

**User exists but has no permissions (`rules: []`):**

```yaml
charlie:
  password: "$2a$12$..."
  locked: false
  rules: []
```

`charlie` can log in, but every action is denied (deny by default). This is not an
error.

**Locked user (rules kept, login blocked):**

```yaml
dave:
  password: "$2a$12$..."
  locked: true
  rules:
    - pattern: "team/**"
      actions: ["pull"]
      access: allow
```

`dave` cannot log in while `locked: true`, even with the correct password. Rules
are preserved and take effect after `-unlock`.

**Anonymous read access:**

```yaml
ANONYMOUS:
  rules:
    - pattern: "**"
      actions: ["pull"]
      access: allow
```

**Anonymous access disabled (but `ANONYMOUS` entry kept):**

```yaml
ANONYMOUS:
  rules: []
```

Anonymous requests receive a token with empty `access` (deny by default).

## Key management

`keystore.yaml` is the source of truth. Operations:

### List keys

```bash
regauth keystore list
```

Prints v2 `created_at` and a table of v3 keys: `KID`, `CREATED`, `CURRENT`,
`REVOKED`.

### Rotate v3 signing key

```bash
regauth keystore rotate
```

- Generates a new v3 key.
- Adds its public part to `public-v3.key` (old keys are kept).
- Updates the current key in `keystore.yaml`.
- Sends `SIGHUP` to a running `regauth` (if found via the PID file), so the server
  starts signing new tokens with the new key.
- Runs `server.keystore.rotate` hook (if set).

Old tokens (signed with the previous key) remain valid until they expire. The
registry should re-read `public-v3.key` — use `server.keystore.rotate`
(e.g. `docker restart registry-v3`).

### Rotate v2 signing key

```bash
regauth keystore rotate-v2
```

- Generates a new v2 key.
- **Replaces** the old v2 key (v2 has a single key).
- Regenerates `public-v2.key` as a new X.509 certificate.
- Runs `server.keystore.rotate_v2` hook (always, even if the server is not running).

Old v2 tokens stop verifying after the registry re-reads `rootcertbundle`. Use
`server.keystore.rotate_v2` (e.g. `docker restart registry-v2`).

### Revoke a v3 key

```bash
regauth keystore revoke <kid>
```

- Marks the key as revoked.
- Wipes its private key.
- Removes it from `public-v3.key`.
- Runs `server.keystore.revoke` hook (if set).

The current key cannot be revoked (rotate first). The registry must re-read
`public-v3.key` to take effect — use `server.keystore.revoke`.

### Delete a revoked v3 key

```bash
regauth keystore delete <kid>
```

Only revoked keys can be deleted. Removes the entry from `keystore.yaml`.

### Cleanup revoked v3 keys

```bash
regauth keystore cleanup
```

Removes all revoked v3 entries from `keystore.yaml`.

### keys_version

`server.keys_version` selects the signing key for **all** issued tokens:

- `3` (default) — all tokens are signed with the current v3 key. Use for
  `registry-v3` (`jwks`).
- `2` — all tokens are signed with the v2 key. Use for `registry-v2`
  (`rootcertbundle`).

One `regauth` instance serves one registry type (v2 **or** v3). To serve both,
run two instances (each with its own config and keystore) or switch the config.

## Registry setup

> **Security warning (fail-open by default):**
> If `server.allowed_services` is empty or omitted, `regauth` will issue tokens for **any**
> `service` value a client requests (e.g. `registry.tld`, `nonexistent.example.com`).
> For production, **always** set `server.allowed_services` to the exact external
> registry hostname(s). See [config.yaml](#configyaml).

### registry v2

```yaml
auth:
  token:
    realm: https://regauth.tld/token
    service: registry.tld
    issuer: regauth
    rootcertbundle: /etc/registry/public-v2.key
```

`public-v2.key` is an X.509 certificate. `distribution` v2 requires a certificate,
not a public key (`BEGIN CERTIFICATE`, not `BEGIN PUBLIC KEY`).

After `keystore rotate-v2`, the registry must re-read the certificate. Use
`server.keystore.rotate_v2` hook.

### registry v3

```yaml
auth:
  token:
    realm: https://regauth.tld/token
    service: registry.tld
    issuer: regauth
    jwks: /etc/registry/public-v3.key
```

`distribution` v3 reads JWKS **from a file**, not over HTTP. `public-v3.key` must be
accessible to the registry on disk. After `keystore rotate`/`revoke`/`cleanup`, the
registry must re-read the file. Use `server.keystore.*` hooks.

### HTTP JWKS endpoint (optional)

`regauth` also serves `GET /.well-known/jwks.json` on the token port. It returns the
same JSON as `public-v3.key` (only active keys). `distribution` v3 does not use it,
but it is useful for debugging and other consumers that support HTTP JWKS.

### Verifying with curl

`docker` automatically requests a Bearer token from the realm. `curl` does not.
`curl -u user:pass https://registry.tld/v2/_catalog` returns `401 Unauthorized`
because the registry expects a Bearer token, not Basic Auth.

To query the catalog with `curl`, obtain a token first:

```bash
TOKEN=$(curl -s -u admin:password \
  "https://regauth.tld/token?service=registry.tld&scope=registry:catalog:*" \
  | jq -r .token)

curl -H "Authorization: Bearer $TOKEN" https://registry.tld/v2/_catalog
```

## Docker deployment

A typical deployment runs four containers on one host: `caddy`, `regauth`,
`registry-v2`, `registry-v3`. Caddy terminates TLS and proxies to the containers
over the internal Docker network. All external names resolve to the same host
(split DNS is fine).

### Host layout

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
└── regauth-source/         # cloned regauth repository
```

### Dockerfile

Multi-stage, `golang:1.26-alpine` → `alpine:latest`. Binaries in `/usr/local/bin`.
Working directory `/var/lib/regauth`. `ENTRYPOINT ["/usr/local/bin/regauth"]`,
`CMD ["server", "-c", "/etc/regauth/config.yaml"]`. The `regauth` user should have
UID/GID matching the owner of `./data/regauth` on the host (usually 1000).

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

**Notes:**

- The whole `./data/regauth` directory is mounted into the registries (read-only)
  so that `public-v2.key` / `public-v3.key` are available as
  `/etc/registry/public-*.key`. Mounting individual files is discouraged: Docker
  creates directories for missing bind-mount sources.
- `depends_on: condition: service_healthy` ensures registries start only after
  `regauth` has generated the keys.
- The `regauth` container is non-root. `server.pid_file` and `server.logfile` must
  point to `/var/lib/regauth/...` (writable volume), not `/var/run` / `/var/log`.

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

### Before `docker compose up`

1. Create empty files for configs (otherwise Docker will create directories):

   ```bash
   mkdir -p config data/regauth data/registry-v2 data/registry-v3 caddy/data caddy/config certs
   touch config/regauth.yaml config/registry-v2.yml config/registry-v3.yml Caddyfile
   ```

2. Fill `config/registry-v2.yml`, `config/registry-v3.yml`, and `Caddyfile` with
   real content (examples above). `config/regauth.yaml` may stay empty on the very
   first run: `regauth` will fill it with defaults (but `server.registry` must be
   set afterwards).

3. Place TLS certificates in `./certs/`.

4. Ensure `./data/regauth` is owned by the UID the `regauth` container runs as
   (usually 1000):

   ```bash
   chown -R 1000:1000 data/regauth
   ```

### Start

```bash
docker compose up -d --build
```

The first run creates `keystore.yaml`, `public-v2.key`, `public-v3.key`, and
`accounts.yaml` in `./data/regauth`.

## Operations

### List users

```bash
reguser list -c /etc/regauth/config.yaml
```

By default `ANONYMOUS` is **excluded**. Output (columns):

```
USERNAME             TYPE       LOCKED RULES
--------------------------------------------
alice                user       no     2
bob                  user       yes    1
```

- **USERNAME** — login name.
- **TYPE** — `user` for regular users.
- **LOCKED** — `yes` if `locked: true`, otherwise `no`.
- **RULES** — number of access rules. `0` means the user exists but has no
  permissions (deny by default). This is not an error.

Include `ANONYMOUS`:

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

Count users:

```bash
reguser list -count -c /etc/regauth/config.yaml        # without ANONYMOUS
reguser list -all -count -c /etc/regauth/config.yaml   # including ANONYMOUS
```

Notes:

- Passwords and bcrypt hashes are **never** printed.
- If `accounts.yaml` is empty or missing, `regauth` recreates it with `ANONYMOUS`
  (default `**`/`pull`/`allow`), so `list -all` always shows at least `ANONYMOUS`.
- If you removed `ANONYMOUS` manually, the next `list` (which calls `Load`) recreates
  it with default rules and saves it to disk.
- To check whether a user exists in a script:
  ```bash
  reguser list -all -c /etc/regauth/config.yaml | awk 'NR>2 {print $1}' | grep -qx alice
  ```
- To find locked users:
  ```bash
  reguser list -all -c /etc/regauth/config.yaml | awk 'NR>2 && $3=="yes" {print $1}'
  ```
- To find users with zero rules (no permissions):
  ```bash
  reguser list -all -c /etc/regauth/config.yaml | awk 'NR>2 && $4==0 {print $1}'
  ```

### Add a user

```bash
reguser add alice -p secret -c /etc/regauth/config.yaml
```

Creates the user with `locked: false` and an empty rule list (`rules: []` — deny by
default). Then edit `accounts.yaml` (or use an external tool) to add rules. No
restart required: `regauth` reads `accounts.yaml` on each request.

If `-p` is omitted, the password is read from the terminal (twice, with confirmation)
or from a pipe (once).

### Edit a user's password

```bash
reguser edit alice -p newsecret -c /etc/regauth/config.yaml
```

Fails if the user does not exist. Does not touch `locked` or `rules`.

### Delete a user

```bash
reguser del alice -c /etc/regauth/config.yaml
```

Fails if the user does not exist. `ANONYMOUS` cannot be deleted.

### Lock / unlock a user

```bash
reguser lock alice -lock -c /etc/regauth/config.yaml     # locked: true
reguser lock alice -unlock -c /etc/regauth/config.yaml   # locked: false
```

- `locked: true` blocks authentication (even with the correct password). The
  registry receives `401` because no token is issued.
- **Rules are preserved.** After `-unlock`, the user's permissions are the same as
  before locking.
- `ANONYMOUS` cannot be locked (`reguser lock ANONYMOUS ...` fails). To disable
  anonymous access, set `rules: []` or `access: deny` in `accounts.yaml`.

### Reset all users (clean)

```bash
reguser clean -f -c /etc/regauth/config.yaml
```

Deletes ALL users and recreates `ANONYMOUS` with default rules (`**`/`pull`/`allow`).
Without `-f`, asks for interactive confirmation.

### Hash a password

```bash
reguser hash -p secret
# or interactively:
reguser hash
```

Prints a bcrypt hash suitable for `accounts.yaml`. No config needed.

## Troubleshooting

### `server.registry is required in config`

Set `server.registry` in `config.yaml` (or run with a config that already has it).

### `service is required` / `service not allowed`

The `/token` endpoint requires a `service` parameter, and if
`server.allowed_services` is non-empty, the value must be in that list. Check the
registry config (`auth.token.service`) and `server.allowed_services`.

### Tokens are issued for unknown `service` values

This is expected if `server.allowed_services` is empty or omitted (fail-open). To
prevent tokens for arbitrary/unknown services, set `server.allowed_services` to
the exact external registry hostname(s). With a non-empty list, `regauth` rejects
any other `service` with `400 Bad Request`.

### Anonymous access is still enabled after editing accounts.yaml

`ANONYMOUS` cannot be removed. If you delete it, `regauth` recreates it with
default rules (`**`/`pull`/`allow`), which **enables** anonymous read access.
To disable anonymous access, keep the `ANONYMOUS` entry and set `rules: []`
(deny by default) or add explicit `access: deny` rules.

### `locked: true` for ANONYMOUS has no effect

`locked` is ignored for `ANONYMOUS`. `reguser lock ANONYMOUS ...` fails with
`ErrAnonymous`. To disable anonymous access, set `rules: []` or `access: deny`.

### A user can log in but every push/pull fails

The user exists but has `rules: []` or no matching `allow` rule. This is deny by
default. Add rules in `accounts.yaml`. The user can still authenticate (login
succeeds), but the token will have no `access` entries, and the registry rejects
the action.

### `cannot acquire lock at ...; set server.pid_file to a writable path`

The PID file path is not writable by the `regauth` process. In Docker, use
`/var/lib/regauth/regauth.pid`. Natively, either run as root or point
`server.pid_file` to a writable location.

### `another regauth instance is already running`

A live `regauth` holds the PID file lock. Stop it or use a different `server.pid_file`.
The lock is released by the kernel when the process exits (including `SIGKILL`).

### `token signed by untrusted key with ID: "..."` (v2)

`registry-v2` cannot match the token to a certificate. Check:

- `server.keys_version` is `2`.
- `public-v2.key` is an X.509 certificate (`BEGIN CERTIFICATE`).
- The registry uses the correct `rootcertbundle` path.
- The registry re-read `public-v2.key` after rotation.

### `malformed token` (v2)

`distribution` v2 rejects tokens where `aud` is an array. `regauth` always emits
`aud` as a string; if this error appears, verify you are running a `regauth` build
with the string-`aud` fix.

### `token signed by untrusted key` / v3 fails

- `public-v3.key` must contain the key with the matching `kid`.
- The registry must re-read `public-v3.key` after rotation/revocation.
- Use `server.keystore.*` hooks to restart/reload the registry.

### `permission denied` writing to `/var/lib/regauth` (Docker)

The container user UID does not match the owner of `./data/regauth`. Fix in the
Dockerfile (set UID/GID to 1000) or `chown` the host directory.

### `is a directory` for config files

Docker created a directory instead of a file because the bind-mount source did not
exist. Create empty files (`touch`) before `docker compose up`, or fill them with
real content.

### Logs go to terminal instead of the log file

`regauth` could not create `server.logfile` (permissions, read-only filesystem).
It logs a warning and continues with terminal output. Fix the path or permissions.

### Exec hook hangs or fails

Exec hooks run as argv lists (no shell), with no timeout. A hung command hangs the
keystore operation. Keep hooks short and reliable. A non-zero exit code fails the
keystore command; the keystore change is already applied.

## Security notes

- `keystore.yaml` contains private keys. Keep it `0600`, never commit it, never log
  it, never expose it over the network.
- `accounts.yaml` contains bcrypt hashes. Do not log or commit it.
- Password hashes use bcrypt cost 12. Do not lower it in production.
- `-insecure` disables `Origin` checks. Use only in tests.
- The HTTP JWKS endpoint exposes only public keys. It is safe to serve publicly,
  but it is not required by `distribution` v3.
- **Always set `server.allowed_services` to the exact external registry hostname(s).**
  If the list is empty, `regauth` issues tokens for **any** `service` a client
  requests (fail-open). This is a serious risk in production.
- **`ANONYMOUS` cannot be removed.** If it is missing from `accounts.yaml`, it is
  recreated with default rules (`**`/`pull`/`allow`) on the next load, which
  **enables** anonymous read access. To disable anonymous access, do not delete
  the entry; set `rules: []` (deny by default) or add explicit `access: deny`
  rules for the desired scopes.
- **`locked` is ignored for `ANONYMOUS`.** Locking a regular user blocks login but
  keeps rules. For anonymous access use rules, not `locked`.
- **`actions` is optional for `pattern: "catalog"`.** If omitted, it is treated as
  `["*"]`. For repository rules `actions` is required; `ValidateRule` rejects an
  empty list.
- After a key compromise: rotate the affected key (`keystore rotate` or
  `keystore rotate-v2`), ensure the registry re-reads the public key, and revoke
  old tokens by rotation (for v3, old tokens stay valid until `exp` unless the key
  is removed from JWKS — rotation keeps the old key in JWKS, `revoke` removes it).
- `keystore.*` hooks run external commands with no timeout. Keep them short and
  reliable. See [Exec hooks](#exec-hooks) for the environment variables passed to
  the child process.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
