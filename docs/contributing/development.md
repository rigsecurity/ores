# Development Guide

This guide covers everything you need to set up a local development environment, run tests, and build all ORES artifacts.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Go](https://go.dev/dl/) | 1.25+ | All Go code |
| [Task](https://taskfile.dev/#/installation) | 3.x | Task runner (replaces `make`) |
| [buf](https://buf.build/docs/installation) | 1.x | Protobuf code generation |
| [golangci-lint](https://golangci-lint.run/welcome/install/) | latest | Linting (bundled via `go tool`) |

### Install Go

```bash
# macOS
brew install go

# or download from https://go.dev/dl/
```

### Install Task

```bash
# macOS
brew install go-task/tap/go-task

# or with Go
go install github.com/go-task/task/v3/cmd/task@latest
```

### Install buf

```bash
# macOS
brew install bufbuild/buf/buf

# or with Go
go install github.com/bufbuild/buf/cmd/buf@latest
```

golangci-lint is bundled as a `go tool` in `go.mod` — you do not need to install it separately.

---

## Clone the Repository

```bash
git clone https://github.com/rigsecurity/ores.git
cd ores
```

---

## Available Tasks

Run `task` with no arguments to see all available tasks:

```bash
task
```

| Task | Description |
|------|-------------|
| `task build` | Build CLI (`bin/ores`) and daemon (`bin/oresd`) |
| `task build:wasm` | Build WASM module (`bin/ores.wasm`) |
| `task test` | Run all tests with race detector and coverage |
| `task test:short` | Run tests without race detector (faster) |
| `task lint` | Run golangci-lint |
| `task generate` | Regenerate protobuf code with `buf generate` |
| `task clean` | Remove `bin/`, `dist/`, `gen/`, `coverage.txt` |

### Run tests

```bash
task test
```

This runs `go test -race -coverprofile=coverage.txt ./...`. Coverage is written to `coverage.txt`.

```bash
go tool cover -html=coverage.txt
```

### Run lint

```bash
task lint
```

golangci-lint is configured in `.golangci.yml`. All rules must pass before a PR is merged.

### Regenerate protobuf

```bash
task generate
```

This runs `buf generate` using the configuration in `buf.gen.yaml` and `buf.yaml`. Generated files land in `gen/proto/ores/v1/`.

You only need to run this if you modify `.proto` files in `api/proto/`.

---

## Project Structure

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

### Package responsibilities

**`pkg/score`**
Defines the core types: `EvaluationRequest`, `EvaluationResult`, `Explanation`, `Factor`, `Label`, and the `LabelForScore` function. This package has no dependencies on other ORES packages — it is the shared type language.

**`pkg/signals`**
Defines the `Signal` interface, the `NormalizedSignal` type (a `map[string]float64`), and the `Registry` that maps signal names to their implementations. Does not contain any specific signal parsers.

**`pkg/signals/parsers`**
Contains the eight built-in signal parser implementations (`CVSS`, `EPSS`, `NIST`, `Asset`, `ThreatIntel`, `BlastRadius`, `Patch`, `Compliance`) and the `RegisterAll` function that registers them all with a `Registry`.

**`pkg/model`**
Implements the weighted composite scoring model. Accepts a slice of `NormalizedSignal` values, applies dimension scoring functions, and returns a `ScoreResult` with per-dimension contributions. Also implements the confidence calculation (`CalculateConfidence`). The model version string is defined here.

**`pkg/explain`**
Builds the `score.Explanation` from model output and signal metadata. Maps dimension names to their contributing signals and generates human-readable reasoning strings.

**`pkg/engine`**
Wires together `pkg/signals`, `pkg/signals/parsers`, `pkg/model`, and `pkg/explain` into a single `Evaluate` call. This is the public API for library consumers.

**`cmd/ores`**
The `ores` CLI. Implements `evaluate`, `signals`, and `version` subcommands using [cobra](https://github.com/spf13/cobra). Reads input from file or stdin (JSON and YAML both supported), calls the engine, and writes results in JSON, YAML, or table format.

**`cmd/oresd`**
The `oresd` daemon. Implements the `OresService` ConnectRPC handler, wraps it with audit-logging middleware, and runs an HTTP server with health/readiness probes. Handles graceful shutdown on SIGINT/SIGTERM.

**`pkg/wasm`**
The WASM entry point. Reads JSON from stdin, calls the engine, writes JSON to stdout. Built with `GOOS=wasip1 GOARCH=wasm`.

---

## Coding Standards

- **Logging**: Use `log/slog` in `cmd/` code. Never use `fmt.Print*` or the `log` package for application logging.
- **Error handling**: Always wrap errors with `fmt.Errorf("context: %w", err)` at call sites. Return errors from functions; do not `log.Fatal` in library code.
- **Interfaces**: All external dependencies (e.g., the engine passed to HTTP handlers) must be referenced through interfaces for testability.
- **Tests**: Table-driven tests using `github.com/stretchr/testify` (`assert` and `require`). Test files live alongside the code they test.
- **Linting**: All code must pass `golangci-lint run ./...` with zero findings.

---

## Devcontainer

A `.devcontainer/devcontainer.json` is included for VS Code and GitHub Codespaces. It sets up Go 1.25, Task, and buf automatically. Open the repository in VS Code and choose "Reopen in Container" to get a fully configured environment.

---

## Making a Change

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

See [CONTRIBUTING.md](https://github.com/rigsecurity/ores/blob/main/CONTRIBUTING.md) for the full pull request process and code review guidelines.
