# vaultd

Provides a secure signing store for BIP39 and siad seed phrases. Any number of phrases and keys can be stored and used for secure offline signing of transactions. Seed phrases are encrypted in the database for security.

## Configuration

The YAML config file is the recommended way to configure `vaultd`. Some settings can be overridden using CLI flags or environment variables.

### Default Paths

#### Data Directory

The vault database and log files are stored in the data directory.

Operating System | Path
---|---
Windows | `%APPDATA%/vaultd`
macOS | `~/Library/Application Support/vaultd`
Linux | `/var/lib/vaultd`
Docker | `/data`

#### Config File

Operating System | Path
---|---
Windows | `%APPDATA%/vaultd/vaultd.yml`
macOS | `~/Library/Application Support/vaultd/vaultd.yml`
Linux | `/etc/vaultd/vaultd.yml`
Docker | `/data/vaultd.yml`

The default config path can be changed using the `VAULTD_CONFIG_FILE` environment variable. For backwards compatibility with earlier versions, `vaultd` will also check for `vaultd.yml` in the current directory.

### Default Ports
+ `9980` - UI and API

### Example Config File

```yml
directory: /etc/vaultd
secret: my secret password
http:
  address: :9980
  password: sia is cool
log:
  stdout:
    enabled: true # enable logging to stdout
    level: info # log level for console logger
    format: human # log format (human, json)
    enableANSI: true # enable ANSI color codes (disabled on Windows)
  file:
    enabled: true # enable logging to file
    level: info # log level for file logger
    path: /var/log/vaultd/vaultd.log # the path of the log file
    format: human # log format (human, json)
```

### Environment Variables
+ `VAULTD_API_PASSWORD` - The password for the API
+ `VAULTD_SECRET` - The secret used to encrypt seed phrases
+ `VAULTD_CONFIG_FILE` - changes the path of the `vaultd` config file.

### CLI Flags

```
Flags:
  -http.addr string
        the address to listen on for the HTTP API (default "localhost:9980")
  -log.level value
        the log level for stdout (default info)
```

# Building

`vaultd` uses SQLite for its persistence. A gcc toolchain is required.

```sh
go generate ./...
CGO_ENABLED=1 go build -o bin/ -tags='netgo timetzdata' -trimpath -a -ldflags '-s -w'  ./cmd/vaultd
```

# Docker

`vaultd` includes a `Dockerfile` which can be used for building and running
vaultd within a docker container. The image can also be pulled from `ghcr.io/siafoundation/vaultd:latest`.

Be careful with port `9980` as Docker will expose it publicly by default. It is
recommended to bind it to `127.0.0.1` to prevent unauthorized access.

## Creating the container

Create a new file named `docker-compose.yml`. You can use the following as a template. The `/data` mount is where the database is stored.

```yml
services:
  vaultd:
    image: ghcr.io/siafoundation/vaultd:latest
    ports:
      - 127.0.0.1:9980:9980/tcp
    volumes:
      - vaultd-data:/data
    environment:
      VAULTD_API_PASSWORD: my auth password
      VAULTD_SECRET: my encryption secret
    restart: unless-stopped

volumes:
  vaultd-data:
```
