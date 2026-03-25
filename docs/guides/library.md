# :material-language-go: Go Library Guide

The `pkg/engine` package provides the ORES engine as an embeddable Go library. Use it when you want to evaluate risk signals **in-process** — no subprocess, no network call, no IPC overhead.

---

## Installation

```bash
go get github.com/rigsecurity/ores
```

!!! note "Go version"
    Requires **Go 1.25** or later.

---

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/rigsecurity/ores/pkg/engine"
    "github.com/rigsecurity/ores/pkg/score"
)

func main() {
    eng := engine.New()

    req := &score.EvaluationRequest{
        APIVersion: "ores.dev/v1",
        Kind:       "EvaluationRequest",
        Signals: map[string]any{
            "cvss": map[string]any{
                "base_score": 9.8,
                "vector":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "epss": map[string]any{
                "probability": 0.91,
                "percentile":  0.98,
            },
            "threat_intel": map[string]any{
                "actively_exploited":    true,
                "ransomware_associated": false,
            },
            "asset": map[string]any{
                "criticality":         "high",
                "network_exposure":    true,
                "data_classification": "pii",
            },
        },
    }

    result, err := eng.Evaluate(context.Background(), req)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Score: %d (%s)\n", result.Score, result.Label)
    fmt.Printf("Confidence: %.2f\n", result.Explanation.Confidence)

    for _, f := range result.Explanation.Factors {
        fmt.Printf("  %-25s +%d\n", f.Name, f.Contribution)
    }
}
```

---

## API Reference

### `engine.New`

```go
func New() *Engine
```

Creates a new `Engine` with all built-in signal parsers registered. This is the standard constructor. Creating an `Engine` is inexpensive and the returned instance is safe for concurrent use.

---

### `(*Engine).Evaluate`

```go
func (e *Engine) Evaluate(ctx context.Context, req *score.EvaluationRequest) (*score.EvaluationResult, error)
```

Runs the full evaluation pipeline:

1. Validates the request envelope (`apiVersion`, `kind`, at least one signal)
2. Looks up each signal name in the registry
3. Validates and normalizes each recognized signal
4. Computes the weighted composite score
5. Calculates confidence
6. Builds the explanation with contributing factors

Returns an error if the request envelope is invalid, or if **no** valid signals were found after parsing.

!!! info "Partial failures produce warnings, not errors"
    Invalid individual signals (bad field values, out-of-range numbers) produce warnings rather than errors. The evaluation continues with the remaining valid signals. Always check `result.Explanation.Warnings`.

---

### `(*Engine).Signals`

```go
func (e *Engine) Signals() []score.SignalDescriptor
```

Returns descriptors for all registered signal types, sorted alphabetically by name. Useful for dynamic documentation, validation UIs, or schema generation.

---

### `(*Engine).Version`

```go
func (e *Engine) Version() string
```

Returns the model version string (e.g., `"0.1.0-preview"`).

---

## Type Reference

### `score.EvaluationRequest`

```go
type EvaluationRequest struct {
    APIVersion string         `json:"apiVersion"`
    Kind       string         `json:"kind"`
    Signals    map[string]any `json:"signals"`
}
```

`APIVersion`
:   Must be `"ores.dev/v1"`.

`Kind`
:   Must be `"EvaluationRequest"`.

`Signals`
:   A map of signal type names to their payloads. Each value is a `map[string]any` with signal-specific fields. See [Signals](../concepts/signals.md) for the full catalog.

---

### `score.EvaluationResult`

```go
type EvaluationResult struct {
    APIVersion  string      `json:"apiVersion"`
    Kind        string      `json:"kind"`
    Score       int         `json:"score"`
    Label       Label       `json:"label"`
    Version     string      `json:"version"`
    Explanation Explanation `json:"explanation"`
}
```

`Score`
:   Composite risk score from 0 (no risk) to 100 (critical risk).

`Label`
:   Human-readable risk category: `none`, `low`, `medium`, `high`, or `critical`.

`Version`
:   The model version that produced this result.

`Explanation`
:   Detailed breakdown of how the score was computed.

---

### `score.Explanation`

```go
type Explanation struct {
    SignalsProvided int      `json:"signals_provided"`
    SignalsUsed     int      `json:"signals_used"`
    SignalsUnknown  int      `json:"signals_unknown"`
    UnknownSignals  []string `json:"unknown_signals"`
    Warnings        []string `json:"warnings"`
    Confidence      float64  `json:"confidence"`
    Factors         []Factor `json:"factors"`
}
```

`SignalsProvided`
:   Total number of signals in the request.

`SignalsUsed`
:   Number of signals that were valid and contributed to the score.

`Confidence`
:   A value between 0.0 and 1.0 reflecting signal coverage. See [Confidence](../concepts/confidence.md).

`Factors`
:   Ordered list of scoring factors, from highest contribution to lowest.

---

### `score.Factor`

```go
type Factor struct {
    Name         string   `json:"factor"`
    Contribution int      `json:"contribution"`
    DerivedFrom  []string `json:"derived_from"`
    Reasoning    string   `json:"reasoning"`
}
```

`Contribution`
:   Points this factor added to the composite score.

`DerivedFrom`
:   The signal types that fed into this factor. When a signal was not provided, `"defaults"` appears here.

`Reasoning`
:   Human-readable explanation of the factor's impact.

---

## :material-web: Embedding in an HTTP Handler

A complete example of wrapping the ORES engine in a custom HTTP service:

```go
package main

import (
    "context"
    "encoding/json"
    "log/slog"
    "net/http"
    "os"

    "github.com/rigsecurity/ores/pkg/engine"
    "github.com/rigsecurity/ores/pkg/score"
)

type ScoringServer struct {
    engine *engine.Engine
    logger *slog.Logger
}

func NewScoringServer() *ScoringServer {
    return &ScoringServer{
        engine: engine.New(),
        logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
    }
}

func (s *ScoringServer) HandleScore(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req score.EvaluationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
        return
    }

    result, err := s.engine.Evaluate(context.Background(), &req)
    if err != nil {
        s.logger.Error("evaluation failed", "err", err)
        http.Error(w, "evaluation failed: "+err.Error(), http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)

    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")

    if err := enc.Encode(result); err != nil {
        s.logger.Error("failed to write response", "err", err)
    }
}

func main() {
    srv := NewScoringServer()
    mux := http.NewServeMux()
    mux.HandleFunc("/score", srv.HandleScore)

    slog.Info("starting scoring server", "addr", ":8080")
    if err := http.ListenAndServe(":8080", mux); err != nil {
        slog.Error("server failed", "err", err)
        os.Exit(1)
    }
}
```

Test it:

```bash
curl -X POST http://localhost:8080/score \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "ores.dev/v1",
    "kind": "EvaluationRequest",
    "signals": {
      "cvss": { "base_score": 9.8 },
      "epss": { "probability": 0.91 },
      "threat_intel": { "actively_exploited": true }
    }
  }'
```

!!! tip "Use the daemon for production"
    This example shows how to embed the engine in your own service. If you just need a standalone scoring API, use `oresd` instead — it includes health checks, audit logging, graceful shutdown, and ConnectRPC/gRPC support out of the box.

---

## :material-lock: Concurrency & Thread Safety

!!! tip "The Engine is fully goroutine-safe"
    You can share a single `engine.New()` instance across all goroutines. The engine holds **no mutable state** after construction; every `Evaluate` call creates its own isolated working state.

```go
// Create once at startup
eng := engine.New()

// Use from many goroutines concurrently
for i := 0; i < 100; i++ {
    go func() {
        result, err := eng.Evaluate(ctx, req)
        // ...
    }()
}
```

There is no need for mutexes, sync pools, or per-goroutine engine instances. A single `Engine` handles unlimited concurrent evaluations.

---

## :material-alert-circle: Error Handling

`Evaluate` returns a non-nil error in exactly two cases:

1. **Invalid request envelope** — missing `apiVersion`, wrong `kind`, or no signals provided
2. **No valid signals** — all provided signals were either unknown or had invalid field values

When some signals are invalid but others succeed, the engine uses the valid ones and records warnings. Always check both the error return **and** the warnings slice:

```go
result, err := eng.Evaluate(ctx, req)
if err != nil {
    // Fatal: request could not be scored at all
    return fmt.Errorf("scoring failed: %w", err)
}

// Non-fatal: some signals were skipped
if len(result.Explanation.Warnings) > 0 {
    for _, w := range result.Explanation.Warnings {
        slog.Warn("signal skipped", "detail", w)
    }
}

// Non-fatal: unrecognized signal names
if len(result.Explanation.UnknownSignals) > 0 {
    slog.Warn("unknown signals in request",
        "signals", result.Explanation.UnknownSignals)
}
```

!!! warning "Do not ignore warnings in production"
    A successful evaluation with warnings means the score was computed from **fewer signals than intended**. This can result in lower confidence and less accurate risk assessment. Log warnings and alert on persistent patterns.
