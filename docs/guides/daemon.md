# Daemon Guide

The `oresd` daemon exposes the ORES engine as a long-running HTTP service using [ConnectRPC](https://connectrpc.com/). It supports both ConnectRPC JSON calls (plain HTTP with `application/json`) and native gRPC binary framing.

## Installation

See [Installation](../getting-started/installation.md).

---

## Running the Daemon

### Local binary

```bash
oresd
```

The daemon starts on port `8080` by default and logs to stdout in JSON format:

```json
{"time":"2026-03-25T12:00:00Z","level":"INFO","msg":"oresd starting","addr":":8080"}
```

### Custom port

Set the `ORES_PORT` environment variable:

```bash
ORES_PORT=:9090 oresd
```

The value must include the leading colon (e.g., `:9090`).

### Docker

```bash
docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:latest
```

With a custom port:

```bash
docker run -e ORES_PORT=:9090 -p 9090:9090 ghcr.io/rigsecurity/oresd:latest
```

---

## Kubernetes Deployment

The daemon is stateless and runs well as a sidecar (for in-cluster scoring) or as a standalone deployment.

### Sidecar example

Add `oresd` as a sidecar to score vulnerabilities in-process without a separate network call:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: my-service
  template:
    metadata:
      labels:
        app: my-service
    spec:
      containers:
        - name: my-service
          image: my-registry/my-service:latest
          env:
            - name: ORES_ADDR
              value: "http://localhost:8080"

        - name: oresd
          image: ghcr.io/rigsecurity/oresd:latest
          ports:
            - containerPort: 8080
          env:
            - name: ORES_PORT
              value: ":8080"
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 2
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: "50m"
              memory: "32Mi"
            limits:
              cpu: "200m"
              memory: "64Mi"
```

### Standalone deployment

For centralized scoring shared across many services, deploy `oresd` as its own `Deployment` + `Service`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oresd
  namespace: risk
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oresd
  template:
    metadata:
      labels:
        app: oresd
    spec:
      containers:
        - name: oresd
          image: ghcr.io/rigsecurity/oresd:latest
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: oresd
  namespace: risk
spec:
  selector:
    app: oresd
  ports:
    - port: 8080
      targetPort: 8080
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ORES_PORT` | `:8080` | TCP address the daemon listens on. Must include the leading colon. |

---

## Health and Readiness Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | `GET` | Liveness probe. Returns `200 OK` when the server is running. |
| `/readyz` | `GET` | Readiness probe. Returns `200 OK` when the server is ready to serve traffic. |

Both endpoints return an empty body with status `200`.

---

## API Endpoints

The daemon serves the `OresService` ConnectRPC service. All RPC calls accept `application/json` (ConnectRPC unary POST).

### Evaluate

Score a set of signals.

```bash
curl -s -X POST http://localhost:8080/ores.v1.OresService/Evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "api_version": "ores.dev/v1",
    "kind": "EvaluationRequest",
    "signals": {
      "cvss": { "base_score": 9.8 },
      "epss": { "probability": 0.91, "percentile": 0.98 },
      "threat_intel": { "actively_exploited": true },
      "asset": { "criticality": "high", "network_exposure": true }
    }
  }'
```

!!! note
    ConnectRPC uses `snake_case` for JSON field names matching the proto definition. The `api_version` field in the HTTP request corresponds to `apiVersion` in the CLI/library format. See the [HTTP API reference](../api/http.md) for the full request and response schema.

Response:

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationResult",
  "score": 87,
  "label": "high",
  "version": "0.1.0-preview",
  "explanation": {
    "signalsProvided": 4,
    "signalsUsed": 4,
    "signalsUnknown": 0,
    "unknownSignals": [],
    "warnings": [],
    "confidence": 0.60,
    "factors": [...]
  }
}
```

### ListSignals

List all recognized signal types.

```bash
curl -s -X POST http://localhost:8080/ores.v1.OresService/ListSignals \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:

```json
{
  "signals": [
    {
      "name": "asset",
      "description": "Asset criticality, network exposure, and data classification context",
      "fields": ["criticality", "network_exposure", "data_classification"]
    },
    {
      "name": "cvss",
      "description": "Common Vulnerability Scoring System score and vector string",
      "fields": ["base_score", "vector"]
    }
  ]
}
```

### GetVersion

Get the model version string.

```bash
curl -s -X POST http://localhost:8080/ores.v1.OresService/GetVersion \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:

```json
{
  "version": "0.1.0-preview"
}
```

---

## Audit Logging

The daemon automatically logs every `Evaluate` call to stdout with the following fields:

```json
{
  "time": "2026-03-25T12:01:23Z",
  "level": "INFO",
  "msg": "audit",
  "procedure": "/ores.v1.OresService/Evaluate",
  "status": 200,
  "latency_ms": 1
}
```

All log output is JSON-structured (`log/slog` with `JSONHandler`), making it compatible with any log aggregation stack (Loki, Elasticsearch, Splunk, Datadog).

---

## Graceful Shutdown

The daemon handles `SIGINT` and `SIGTERM` with a 15-second graceful shutdown window. In-flight requests are completed before the process exits.

```bash
kill -TERM $(pgrep oresd)
```

Output:

```json
{"time":"2026-03-25T12:05:00Z","level":"INFO","msg":"shutting down","signal":"terminated"}
{"time":"2026-03-25T12:05:00Z","level":"INFO","msg":"oresd stopped"}
```
