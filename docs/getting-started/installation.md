# :material-download-circle: Installation

ORES ships **three deployment artifacts** — choose the one that fits your workflow:

| Artifact | What it does | Best for |
|----------|-------------|----------|
| **`ores`** CLI | Evaluate risk from the terminal | Scripts, CI pipelines, local triage |
| **`oresd`** daemon | Long-running HTTP/ConnectRPC service | SIEM, SOAR, ticketing integrations |
| **`ores.wasm`** module | Portable WASI binary | Browsers, edge runtimes, sandboxed envs |

You can also embed the scoring engine directly as a **Go library** — no subprocess or network call needed.

---

## :material-console: CLI (`ores`)

The `ores` CLI evaluates risk signals from the terminal, scripts, and CI pipelines.

!!! info "Prerequisites"
    **None.** The CLI is a single, statically linked binary with zero runtime dependencies.

=== ":material-apple: Homebrew"

    The fastest way to install on **macOS** or **Linux**:

    ```bash
    brew install rigsecurity/tap/ores
    ```

    **Verify:**

    ```bash
    ores version
    ```

=== ":material-microsoft-windows: Scoop"

    On **Windows**, use [Scoop](https://scoop.sh){ target=_blank }:

    ```powershell
    scoop bucket add rig https://github.com/rigsecurity/scoop-bucket
    scoop install ores
    ```

    **Verify:**

    ```powershell
    ores version
    ```

=== ":material-debian: deb / :material-redhat: rpm"

    Native packages for Debian/Ubuntu and Fedora/RHEL are attached to every [GitHub release](https://github.com/rigsecurity/ores/releases){ target=_blank }.

    === "Debian / Ubuntu"

        ```bash
        curl -LO https://github.com/rigsecurity/ores/releases/latest/download/ores_0.2.0_linux_amd64.deb
        sudo dpkg -i ores_0.2.0_linux_amd64.deb
        ```

    === "Fedora / RHEL"

        ```bash
        curl -LO https://github.com/rigsecurity/ores/releases/latest/download/ores_0.2.0_linux_amd64.rpm
        sudo rpm -i ores_0.2.0_linux_amd64.rpm
        ```

    **Verify:**

    ```bash
    ores version
    ```

=== ":material-language-go: Go Install"

    If you have **Go 1.25+** on your machine:

    ```bash
    go install github.com/rigsecurity/ores/cmd/ores@latest
    ```

    !!! tip "Make sure `$GOPATH/bin` is on your `PATH`"
        The binary lands in `$GOPATH/bin` (typically `~/go/bin`). Add it to your shell profile if it is not there already:

        ```bash
        export PATH="$PATH:$(go env GOPATH)/bin"
        ```

    **Verify:**

    ```bash
    ores version
    ```

=== ":material-download: Pre-built Binary"

    Pre-built binaries for Linux, macOS, and Windows are attached to every [GitHub release](https://github.com/rigsecurity/ores/releases){ target=_blank }.

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

        Download `ores_windows_amd64.exe` from the [releases page](https://github.com/rigsecurity/ores/releases){ target=_blank } and place it somewhere on your `%PATH%`.

    **Verify:**

    ```bash
    ores version
    ```

=== ":material-source-branch: From Source"

    ```bash
    git clone https://github.com/rigsecurity/ores.git
    cd ores
    task build          # builds CLI + daemon
    ```

    Binaries land in the `bin/` directory.

    !!! note "Build prerequisites"
        Building from source requires **Go 1.25+** and [Task](https://taskfile.dev){ target=_blank }. See [Contributing: Development](../contributing/development.md) for the full setup guide.

    **Verify:**

    ```bash
    ./bin/ores version
    ```

---

## :material-server: Daemon (`oresd`)

The `oresd` daemon exposes a long-running **ConnectRPC / HTTP** service. Use it to integrate ORES into SIEM, SOAR, ticketing, or any system that can make HTTP calls.

=== ":material-docker: Docker (recommended)"

    ```bash
    docker pull ghcr.io/rigsecurity/oresd:latest
    docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:latest
    ```

    !!! tip "Pin to a specific release for production"
        ```bash
        docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:0.2.0
        ```

    **Verify:**

    ```bash
    curl -s http://localhost:8080/healthz
    # 200 OK
    ```

=== ":material-language-go: Go Install"

    ```bash
    go install github.com/rigsecurity/ores/cmd/oresd@latest
    ```

    **Verify:**

    ```bash
    oresd &
    curl -s http://localhost:8080/healthz
    # 200 OK
    ```

=== ":material-debian: deb / :material-redhat: rpm"

    Native packages include a **systemd service file** for easy deployment:

    === "Debian / Ubuntu"

        ```bash
        curl -LO https://github.com/rigsecurity/ores/releases/latest/download/oresd_0.2.0_linux_amd64.deb
        sudo dpkg -i oresd_0.2.0_linux_amd64.deb
        sudo systemctl enable --now oresd
        ```

    === "Fedora / RHEL"

        ```bash
        curl -LO https://github.com/rigsecurity/ores/releases/latest/download/oresd_0.2.0_linux_amd64.rpm
        sudo rpm -i oresd_0.2.0_linux_amd64.rpm
        sudo systemctl enable --now oresd
        ```

    **Verify:**

    ```bash
    curl -s http://localhost:8080/healthz
    # 200 OK
    ```

=== ":material-download: Pre-built Binary"

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

    **Verify:**

    ```bash
    oresd &
    curl -s http://localhost:8080/healthz
    # 200 OK
    ```

---

## :material-web: WASM Module (`ores.wasm`)

The WASM module lets you embed the ORES engine directly in **browsers, edge runtimes, Node.js, Python**, or any environment that supports the WASI preview 1 interface.

!!! info "Runtime requirement"
    You need a **WASI-compatible runtime** such as [wasmtime](https://wasmtime.dev/){ target=_blank }, or the Node.js / Python wasmtime package.

**Step 1 — Download the module:**

```bash
curl -Lo ores.wasm https://github.com/rigsecurity/ores/releases/latest/download/ores.wasm
```

**Step 2 — Install a WASI runtime** (if you don't have one):

=== "curl (macOS / Linux)"

    ```bash
    curl https://wasmtime.dev/install.sh -sSf | bash
    ```

=== "Homebrew"

    ```bash
    brew install wasmtime
    ```

**Step 3 — Verify:**

```bash
echo '{"apiVersion":"ores.dev/v1","kind":"EvaluationRequest","signals":{"cvss":{"base_score":7.5}}}' \
  | wasmtime ores.wasm
```

!!! tip "Build WASM from source"
    ```bash
    git clone https://github.com/rigsecurity/ores.git && cd ores
    task build:wasm
    ```
    The module is written to `bin/ores.wasm`.

---

## :material-language-go: Go Library

Embed the ORES engine directly in your Go application — no subprocess, no network call.

```bash
go get github.com/rigsecurity/ores
```

The primary entry point is the `engine` package:

```go
import "github.com/rigsecurity/ores/pkg/engine"

eng := engine.New()
result, err := eng.Evaluate(ctx, req)
```

!!! example "Full integration walkthrough"
    See the [Go Library Guide](../guides/library.md) for a complete, production-ready example.

---

## :material-check-decagram: Quick Reference

| Method | Command | Platforms |
|--------|---------|-----------|
| Homebrew | `brew install rigsecurity/tap/ores` | macOS, Linux |
| Scoop | `scoop install ores` | Windows |
| deb / rpm | Download from [Releases](https://github.com/rigsecurity/ores/releases){ target=_blank } | Linux |
| Go install | `go install .../cmd/ores@latest` | Any (needs Go) |
| Pre-built binary | Download from [Releases](https://github.com/rigsecurity/ores/releases){ target=_blank } | All |
| Docker (daemon) | `docker run ghcr.io/rigsecurity/oresd` | All |
| Go library | `go get github.com/rigsecurity/ores` | Any (needs Go) |
| From source | `git clone` + `task build` | Any (needs Go) |

---

**Next up:** [Quickstart — score your first vulnerability in 60 seconds :material-arrow-right:](quickstart.md)
