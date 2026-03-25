# Installation

ORES ships three deployment artifacts: the `ores` CLI, the `oresd` daemon, and the `ores.wasm` WASM module. Each has its own installation method depending on how you plan to use it.

## Prerequisites

- **CLI and daemon binaries**: No runtime dependencies. Statically linked.
- **Go library**: Go 1.25 or later.
- **WASM module**: A WASI-compatible runtime such as [wasmtime](https://wasmtime.dev/) or the Node.js/Python wasmtime package.

---

## CLI (`ores`)

The `ores` CLI evaluates risk signals from the terminal, scripts, and CI pipelines.

### Install with `go install`

If you have Go 1.25 or later:

```bash
go install github.com/rigsecurity/ores/cmd/ores@latest
```

The binary is placed in `$GOPATH/bin` (typically `~/go/bin`). Make sure that directory is on your `PATH`.

### Download a pre-built binary

Pre-built binaries for Linux, macOS, and Windows are attached to every [GitHub release](https://github.com/rigsecurity/ores/releases).

=== "Linux (x86_64)"

    ```bash
    curl -Lo ores https://github.com/rigsecurity/ores/releases/latest/download/ores_linux_amd64
    chmod +x ores
    sudo mv ores /usr/local/bin/ores
    ```

=== "macOS (Apple Silicon)"

    ```bash
    curl -Lo ores https://github.com/rigsecurity/ores/releases/latest/download/ores_darwin_arm64
    chmod +x ores
    sudo mv ores /usr/local/bin/ores
    ```

=== "macOS (Intel)"

    ```bash
    curl -Lo ores https://github.com/rigsecurity/ores/releases/latest/download/ores_darwin_amd64
    chmod +x ores
    sudo mv ores /usr/local/bin/ores
    ```

=== "Windows"

    Download `ores_windows_amd64.exe` from the [releases page](https://github.com/rigsecurity/ores/releases) and place it somewhere on your `%PATH%`.

### Verify the installation

```bash
ores version
```

Expected output:

```
ores version 0.1.0-preview (model: 0.1.0-preview)
```

---

## Daemon (`oresd`)

The `oresd` daemon exposes a long-running ConnectRPC/HTTP service. Use it to integrate ORES into SIEM, SOAR, ticketing, or any other system that can make HTTP calls.

### Docker (recommended)

```bash
docker pull ghcr.io/rigsecurity/oresd:latest
docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:latest
```

To pin a specific release:

```bash
docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:0.1.0-preview
```

### Install with `go install`

```bash
go install github.com/rigsecurity/ores/cmd/oresd@latest
```

### Download a pre-built binary

=== "Linux (x86_64)"

    ```bash
    curl -Lo oresd https://github.com/rigsecurity/ores/releases/latest/download/oresd_linux_amd64
    chmod +x oresd
    sudo mv oresd /usr/local/bin/oresd
    ```

=== "macOS (Apple Silicon)"

    ```bash
    curl -Lo oresd https://github.com/rigsecurity/ores/releases/latest/download/oresd_darwin_arm64
    chmod +x oresd
    sudo mv oresd /usr/local/bin/oresd
    ```

### Verify the installation

```bash
oresd &
curl -s http://localhost:8080/healthz
```

Expected output: `200 OK`

---

## WASM Module (`ores.wasm`)

The WASM module lets you embed the ORES engine directly in browsers, edge runtimes, Node.js, Python, or any environment that supports the WASI preview1 interface.

### Download from releases

The `ores.wasm` file is attached to every [GitHub release](https://github.com/rigsecurity/ores/releases).

```bash
curl -Lo ores.wasm https://github.com/rigsecurity/ores/releases/latest/download/ores.wasm
```

### Install wasmtime (to run locally)

```bash
# macOS / Linux
curl https://wasmtime.dev/install.sh -sSf | bash

# or via Homebrew
brew install wasmtime
```

### Verify

```bash
echo '{"apiVersion":"ores.dev/v1","kind":"EvaluationRequest","signals":{"cvss":{"base_score":7.5}}}' \
  | wasmtime ores.wasm
```

---

## Go Library

Embed the ORES engine directly in your Go application without any subprocess or network calls.

```bash
go get github.com/rigsecurity/ores
```

The primary entry point is `github.com/rigsecurity/ores/pkg/engine`. See the [Library guide](../guides/library.md) for a complete integration example.

---

## Building from Source

```bash
git clone https://github.com/rigsecurity/ores.git
cd ores

# Build CLI and daemon
task build

# Build WASM module
task build:wasm
```

Binaries are placed in the `bin/` directory. See [Contributing: Development](../contributing/development.md) for the full development setup, including prerequisites.
