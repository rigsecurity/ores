# :material-server-network: gRPC API Reference

The `oresd` daemon serves the `OresService` gRPC service over HTTP/2. The service is defined using Protocol Buffers and built with [buf](https://buf.build/). Clients can connect using native gRPC or the [ConnectRPC](https://connectrpc.com/) library.

---

## Proto Package

```
package: ores.v1
go_package: github.com/rigsecurity/ores/gen/proto/ores/v1;oresv1
```

---

## Service Definition

```protobuf
service OresService {
  // Evaluate risk signals and produce a composite score.
  rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);

  // List all recognized signal types and their fields.
  rpc ListSignals(ListSignalsRequest) returns (ListSignalsResponse);

  // Get the current model version string.
  rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);
}
```

---

## Messages

??? abstract "Full protobuf message definitions"

    ```protobuf
    message EvaluateRequest {
      string api_version = 1;
      string kind = 2;
      google.protobuf.Struct signals = 3;
    }

    message EvaluateResponse {
      string api_version = 1;
      string kind = 2;
      int32 score = 3;
      string label = 4;
      string version = 5;
      Explanation explanation = 6;
    }

    message Explanation {
      int32 signals_provided = 1;
      int32 signals_used = 2;
      int32 signals_unknown = 3;
      repeated string unknown_signals = 4;
      repeated string warnings = 5;
      double confidence = 6;
      repeated Factor factors = 7;
    }

    message Factor {
      string name = 1;
      int32 contribution = 2;
      repeated string derived_from = 3;
      string reasoning = 4;
    }

    message ListSignalsRequest {}

    message ListSignalsResponse {
      repeated SignalDescriptor signals = 1;
    }

    message SignalDescriptor {
      string name = 1;
      string description = 2;
      repeated string fields = 3;
    }

    message GetVersionRequest {}

    message GetVersionResponse {
      string version = 1;
    }
    ```

!!! info "Dynamic signals with `google.protobuf.Struct`"
    The `signals` field in `EvaluateRequest` uses `google.protobuf.Struct` — a dynamic JSON-compatible map. This allows any signal payload to be passed without requiring a fixed schema per signal type.

---

## RPC Methods

### :material-calculator-variant: `Evaluate`

Evaluate a set of risk signals and produce a composite score with a full explanation breakdown.

| Detail | Value |
|:-------|:------|
| **Method** | `ores.v1.OresService/Evaluate` |
| **Request** | `EvaluateRequest` |
| **Response** | `EvaluateResponse` |

=== "Go client"

    ```go
    package main

    import (
        "context"
        "fmt"
        "log"
        "net/http"

        "connectrpc.com/connect"
        "google.golang.org/protobuf/types/known/structpb"

        oresv1 "github.com/rigsecurity/ores/gen/proto/ores/v1"
        "github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
    )

    func main() {
        client := oresv1connect.NewOresServiceClient(
            http.DefaultClient,
            "http://localhost:8080",
        )

        signals, err := structpb.NewStruct(map[string]any{
            "cvss": map[string]any{
                "base_score": 9.8,
            },
            "epss": map[string]any{
                "probability": 0.91,
                "percentile":  0.98,
            },
            "threat_intel": map[string]any{
                "actively_exploited": true,
            },
            "asset": map[string]any{
                "criticality":      "high",
                "network_exposure": true,
            },
        })
        if err != nil {
            log.Fatalf("building signals struct: %v", err)
        }

        req := connect.NewRequest(&oresv1.EvaluateRequest{
            ApiVersion: "ores.dev/v1",
            Kind:       "EvaluationRequest",
            Signals:    signals,
        })

        resp, err := client.Evaluate(context.Background(), req)
        if err != nil {
            log.Fatalf("evaluate: %v", err)
        }

        msg := resp.Msg
        fmt.Printf("Score: %d (%s)\n", msg.Score, msg.Label)
        fmt.Printf("Confidence: %.2f\n", msg.Explanation.Confidence)

        for _, f := range msg.Explanation.Factors {
            fmt.Printf("  %-25s +%d - %s\n", f.Name, f.Contribution, f.Reasoning)
        }
    }
    ```

=== "grpcurl"

    ```bash
    grpcurl \
      -plaintext \
      -proto api/proto/ores/v1/ores.proto \
      -d '{
        "api_version": "ores.dev/v1",
        "kind": "EvaluationRequest",
        "signals": {
          "cvss": { "base_score": 9.8 },
          "epss": { "probability": 0.91, "percentile": 0.98 },
          "threat_intel": { "actively_exploited": true },
          "asset": { "criticality": "high", "network_exposure": true }
        }
      }' \
      localhost:8080 \
      ores.v1.OresService/Evaluate
    ```

---

### :material-format-list-bulleted: `ListSignals`

List all recognized signal types and their accepted input fields. Useful for discovery, documentation generation, and dynamic UI construction.

| Detail | Value |
|:-------|:------|
| **Method** | `ores.v1.OresService/ListSignals` |
| **Request** | `ListSignalsRequest` (empty) |
| **Response** | `ListSignalsResponse` |

=== "Go client"

    ```go
    listResp, err := client.ListSignals(
        context.Background(),
        connect.NewRequest(&oresv1.ListSignalsRequest{}),
    )
    if err != nil {
        log.Fatalf("list signals: %v", err)
    }

    for _, s := range listResp.Msg.Signals {
        fmt.Printf("%s: %v\n", s.Name, s.Fields)
    }
    ```

=== "grpcurl"

    ```bash
    grpcurl \
      -plaintext \
      -proto api/proto/ores/v1/ores.proto \
      -d '{}' \
      localhost:8080 \
      ores.v1.OresService/ListSignals
    ```

---

### :material-tag-outline: `GetVersion`

Get the current model version string. Useful for pinning evaluation results to a specific model revision.

| Detail | Value |
|:-------|:------|
| **Method** | `ores.v1.OresService/GetVersion` |
| **Request** | `GetVersionRequest` (empty) |
| **Response** | `GetVersionResponse` |

=== "Go client"

    ```go
    verResp, err := client.GetVersion(
        context.Background(),
        connect.NewRequest(&oresv1.GetVersionRequest{}),
    )
    if err != nil {
        log.Fatalf("get version: %v", err)
    }

    fmt.Println("Model version:", verResp.Msg.Version)
    ```

=== "grpcurl"

    ```bash
    grpcurl \
      -plaintext \
      -proto api/proto/ores/v1/ores.proto \
      -d '{}' \
      localhost:8080 \
      ores.v1.OresService/GetVersion
    ```

---

## :material-cog-outline: Connection Configuration

### Generating Client Code with buf

[buf](https://buf.build/) provides the easiest way to generate gRPC clients and explore the API.

=== "macOS"

    ```bash
    brew install bufbuild/buf/buf
    ```

=== "Linux"

    ```bash
    curl -sSL https://github.com/bufbuild/buf/releases/latest/download/buf-Linux-x86_64 -o buf
    chmod +x buf && sudo mv buf /usr/local/bin/
    ```

Then generate clients from the ORES repository:

```bash
git clone https://github.com/rigsecurity/ores.git
cd ores
buf generate
```

Generated files land in `gen/proto/ores/v1/`:

| Package | Contents |
|:--------|:---------|
| `gen/proto/ores/v1` | Protobuf message types |
| `gen/proto/ores/v1/oresv1connect` | ConnectRPC service stubs |

### HTTP/2 and TLS

!!! note "Transport protocol"
    The daemon listens on plain HTTP/1.1 and HTTP/2 (h2c — cleartext HTTP/2). For production deployments, terminate TLS at a load balancer or ingress controller and forward to the daemon over h2c.

ConnectRPC clients automatically negotiate between HTTP/1.1 and HTTP/2. For native gRPC clients that **require** HTTP/2, ensure your HTTP client has h2c support enabled:

```go
import "golang.org/x/net/http2"

transport := &http2.Transport{
    AllowHTTP: true,
    DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
        return net.Dial(network, addr)
    },
}

httpClient := &http.Client{Transport: transport}

client := oresv1connect.NewOresServiceClient(
    httpClient,
    "http://localhost:8080",
)
```

### Installing grpcurl

!!! tip "grpcurl without reflection"
    The ORES daemon does not expose gRPC reflection by default. Pass the `-proto` flag to point `grpcurl` at the proto file directly.

```bash
# macOS
brew install grpcurl

# or with Go
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

---

## :material-alert-circle-outline: Error Handling

The ConnectRPC client maps gRPC status codes to Go errors:

```go
resp, err := client.Evaluate(ctx, req)
if err != nil {
    var connectErr *connect.Error
    if errors.As(err, &connectErr) {
        fmt.Printf("Connect error: code=%s message=%s\n",
            connectErr.Code(), connectErr.Message())
    }
    return err
}
```

### Error Codes

| gRPC Code | Typical Cause |
|:----------|:--------------|
| `InvalidArgument` | Bad request envelope, missing required fields, no valid signals |
| `Internal` | Unexpected server-side error |

!!! warning "Production best practice"
    Always check the `unknownSignals` and `warnings` fields in a successful response. A `200 OK` with unknown signals may indicate a client-side typo or version mismatch.
