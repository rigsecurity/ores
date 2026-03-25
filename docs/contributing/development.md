# :material-wrench: Development Guide

Welcome to the ORES contributor experience. This guide covers everything you need to set up a local development environment, run tests, and build all ORES artifacts.

---

## :material-clipboard-check-outline: Prerequisites

| Tool | Version | Purpose |
|:-----|:--------|:--------|
| [Go](https://go.dev/dl/) | 1.25+ | All Go code |
| [Task](https://taskfile.dev/#/installation) | 3.x | Task runner (replaces `make`) |
| [buf](https://buf.build/docs/installation) | 1.x | Protobuf code generation |
| [golangci-lint](https://golangci-lint.run/welcome/install/) | latest | Linting (bundled via `go tool`) |

!!! tip "golangci-lint is bundled"
    golangci-lint is configured as a `go tool` in `go.mod` — you do **not** need to install it separately.

### Install tools

=== "macOS (Homebrew)"

    ```bash
    # Go
    brew install go

    # Task
    brew install go-task/tap/go-task

    # buf
    brew install bufbuild/buf/buf
    ```

=== "Go install"

    ```bash
    # Task
    go install github.com/go-task/task/v3/cmd/task@latest

    # buf
    go install github.com/bufbuild/buf/cmd/buf@latest
    ```

=== "Direct download"

    ```bash
    # Go — download from https://go.dev/dl/

    # Task — see https://taskfile.dev/#/installation

    # buf
    curl -sSL https://github.com/bufbuild/buf/releases/latest/download/buf-Linux-x86_64 -o buf
    chmod +x buf && sudo mv buf /usr/local/bin/
    ```

---

## :material-source-branch: Clone and Build

```bash
git clone https://github.com/rigsecurity/ores.git
cd ores
task build
```

This produces `bin/ores` (CLI) and `bin/oresd` (daemon).

---

## :material-play-circle-outline: Available Tasks

Run `task` with no arguments to see all tasks, or use any of the following:

| Task | Description |
|:-----|:------------|
| `task build` | Build CLI (`bin/ores`) and daemon (`bin/oresd`) |
| `task build:wasm` | Build WASM module (`bin/ores.wasm`) |
| `task test` | Run all tests with race detector and coverage |
| `task test:short` | Run tests without race detector (faster) |
| `task lint` | Run golangci-lint |
| `task generate` | Regenerate protobuf code with `buf generate` |
| `task clean` | Remove `bin/`, `dist/`, `gen/`, `coverage.txt` |

### Running tests

```bash
task test
```

This runs `go test -race -coverprofile=coverage.txt ./...`. View coverage in your browser:

```bash
go tool cover -html=coverage.txt
```

### Running lint

```bash
task lint
```

!!! warning "Lint must pass"
    golangci-lint is configured in `.golangci.yml`. All rules must pass with **zero findings** before a PR is merged.

### Regenerating protobuf

```bash
task generate
```

This runs `buf generate` using the configuration in `buf.gen.yaml` and `buf.yaml`. Generated files land in `gen/proto/ores/v1/`.

!!! note "When to regenerate"
    You only need to run this if you modify `.proto` files in `api/proto/`.

---

## :material-file-tree: Project Structure

```
ores/
├── api/
│   └── proto/ores/v1/       # Protobuf service definition
├── bin/                     # Build output (gitignored)
├── cmd/
│   ├── ores/                # CLI entry point
│   └── oresd/               # Daemon entry point
├── gen/
│   └── proto/ores/v1/       # Generated protobuf Go code (gitignored)
├── pkg/
│   ├── engine/              # Pipeline orchestrator
│   ├── explain/             # Explanation builder
│   ├── model/               # Scoring model and confidence
│   ├── score/               # Core request/response types
│   ├── signals/             # Signal interface, registry, NormalizedSignal
│   │   └── parsers/         # Per-signal-type parsers
│   └── wasm/                # WASM entry point
├── buf.gen.yaml             # buf code generation config
├── buf.yaml                 # buf module config
├── go.mod                   # Go module definition
├── Taskfile.yml             # Task definitions
└── .golangci.yml            # Linter configuration
```

### Package Responsibilities

`pkg/score`
:   Defines the core types: `EvaluationRequest`, `EvaluationResult`, `Explanation`, `Factor`, `Label`, and `LabelForScore`. This package has **no dependencies** on other ORES packages — it is the shared type language.

`pkg/signals`
:   Defines the `Signal` interface, the `NormalizedSignal` type (`map[string]float64`), and the `Registry` that maps signal names to their implementations. Does not contain any specific signal parsers.

`pkg/signals/parsers`
:   Contains the eight built-in signal parser implementations (`CVSS`, `EPSS`, `NIST`, `Asset`, `ThreatIntel`, `BlastRadius`, `Patch`, `Compliance`) and the `RegisterAll` function that registers them with a `Registry`.

`pkg/model`
:   Implements the weighted composite scoring model. Accepts a slice of `NormalizedSignal` values, applies dimension scoring functions, and returns a `ScoreResult` with per-dimension contributions. Also implements confidence calculation (`CalculateConfidence`). The model version string is defined here.

`pkg/explain`
:   Builds the `score.Explanation` from model output and signal metadata. Maps dimension names to contributing signals and generates human-readable reasoning strings.

`pkg/engine`
:   Wires together `pkg/signals`, `pkg/signals/parsers`, `pkg/model`, and `pkg/explain` into a single `Evaluate` call. This is the public API for library consumers.

`cmd/ores`
:   The `ores` CLI. Implements `evaluate`, `signals`, and `version` subcommands using [cobra](https://github.com/spf13/cobra). Reads input from file or stdin (JSON and YAML), calls the engine, and writes results in JSON, YAML, or table format.

`cmd/oresd`
:   The `oresd` daemon. Implements the `OresService` ConnectRPC handler, wraps it with audit-logging middleware, and runs an HTTP server with health/readiness probes. Handles graceful shutdown on SIGINT/SIGTERM.

`pkg/wasm`
:   The WASM entry point. Reads JSON from stdin, calls the engine, writes JSON to stdout. Built with `GOOS=wasip1 GOARCH=wasm`.

---

## :material-format-list-checks: Coding Standards

### Logging

Use `log/slog` in `cmd/` code. Never use `fmt.Print*` or the `log` package for application logging.

```go
// Good
slog.Info("evaluation complete", "score", result.Score, "label", result.Label)

// Bad
fmt.Printf("evaluation complete: score=%d\n", result.Score)
log.Printf("evaluation complete: score=%d", result.Score)
```

### Error handling

Always wrap errors with context at call sites. Return errors from functions — do not `log.Fatal` in library code.

```go
// Good
if err := engine.Evaluate(ctx, req); err != nil {
    return fmt.Errorf("evaluating request: %w", err)
}

// Bad
if err := engine.Evaluate(ctx, req); err != nil {
    log.Fatal(err)
}
```

### Interfaces

All external dependencies (e.g., the engine passed to HTTP handlers) must be referenced through interfaces for testability.

### Tests

Table-driven tests using `github.com/stretchr/testify` (`assert` and `require`). Test files live alongside the code they test.

```go
func TestLabelForScore(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name  string
        score int
        want  Label
    }{
        {"critical", 95, LabelCritical},
        {"high", 75, LabelHigh},
        {"medium", 50, LabelMedium},
        {"low", 25, LabelLow},
        {"info", 5, LabelInfo},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            assert.Equal(t, tc.want, LabelForScore(tc.score))
        })
    }
}
```

### Linting

All code must pass `golangci-lint run ./...` with zero findings.

---

## :material-microsoft-visual-studio-code: Devcontainer

A `.devcontainer/devcontainer.json` is included for VS Code and GitHub Codespaces. It sets up Go 1.25, Task, and buf automatically.

!!! tip "One-click setup"
    Open the repository in VS Code and choose **"Reopen in Container"** to get a fully configured environment with all tools pre-installed.

---

## :material-source-pull: Making a Change

1. Create a feature branch from `main`:

    ```bash
    git checkout -b feat/my-change
    ```

2. Make your changes.

3. Run tests and lint:

    ```bash
    task test && task lint
    ```

4. Commit and open a pull request against `main`.

!!! info "Full PR process"
    See [CONTRIBUTING.md](https://github.com/rigsecurity/ores/blob/main/CONTRIBUTING.md) for the complete pull request process and code review guidelines.
