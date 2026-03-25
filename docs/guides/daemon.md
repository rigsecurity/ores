# :material-server-network: Daemon Guide

The `oresd` daemon exposes the ORES engine as a long-running HTTP service using [ConnectRPC](https://connectrpc.com/). It supports both ConnectRPC JSON calls (plain HTTP with `application/json`) and native gRPC binary framing — making it easy to integrate from any language or tool.

---

## Installation

=== ":material-docker: Docker"

    ```bash
    docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:latest
    ```

    With a custom port:

    ```bash
    docker run -e ORES_PORT=:9090 -p 9090:9090 ghcr.io/rigsecurity/oresd:latest
    ```

=== ":material-download: Binary"

    Download a prebuilt binary from the [GitHub Releases](https://github.com/rigsecurity/ores/releases) page, or see [Installation](../getting-started/installation.md) for full details.

    ```bash
    oresd
    ```

=== ":material-language-go: go install"

    ```bash
    go install github.com/rigsecurity/ores/cmd/oresd@latest
    ```

    Requires Go 1.25 or later.

The daemon starts on port `8080` by default and logs to stdout in JSON format:

```json
{"time":"2026-03-25T12:00:00Z","level":"INFO","msg":"oresd starting","addr":":8080"}
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ORES_PORT` | `:8080` | TCP address the daemon listens on. Must include the leading colon. |
| `ORES_TLS_CERT` | _(unset)_ | Path to PEM-encoded server certificate. Enables TLS when set with `ORES_TLS_KEY`. |
| `ORES_TLS_KEY` | _(unset)_ | Path to PEM-encoded server private key. Required when `ORES_TLS_CERT` is set. |
| `ORES_TLS_CLIENT_CA` | _(unset)_ | Path to PEM-encoded CA bundle for client certificate verification. Enables mTLS. |
| `ORES_TLS_MIN_VERSION` | `1.2` | Minimum TLS version: `1.2` or `1.3`. |
| `ORES_MAX_REQUEST_BYTES` | `1048576` | Maximum request body size in bytes. Set to `0` to disable. |
| `ORES_RATE_LIMIT` | `0` | Maximum requests per second per source IP. `0` disables rate limiting. |
| `ORES_RATE_BURST` | _(= rate limit)_ | Token bucket burst size. Defaults to `ORES_RATE_LIMIT` value. |
| `ORES_CORS_ORIGINS` | _(unset)_ | Comma-separated allowed CORS origins, or `*` for any. |

---

## TLS / mTLS

The daemon supports built-in TLS and mutual TLS (mTLS) via environment variables. When TLS is not configured, the daemon serves plain HTTP (unchanged default behavior).

### TLS

Provide a certificate and key to enable HTTPS:

```bash
ORES_TLS_CERT=/path/to/server.crt \
ORES_TLS_KEY=/path/to/server.key \
oresd
```

Docker:

```bash
docker run -p 8443:8443 \
  -v /path/to/certs:/certs:ro \
  -e ORES_PORT=:8443 \
  -e ORES_TLS_CERT=/certs/server.crt \
  -e ORES_TLS_KEY=/certs/server.key \
  ghcr.io/rigsecurity/oresd:latest
```

### mTLS (mutual TLS)

Add a client CA to require and verify client certificates:

```bash
ORES_TLS_CERT=/path/to/server.crt \
ORES_TLS_KEY=/path/to/server.key \
ORES_TLS_CLIENT_CA=/path/to/ca.crt \
oresd
```

Clients must present a certificate signed by the specified CA. Connections without a valid client certificate are rejected at the TLS handshake level.

### TLS Version

By default, the minimum TLS version is 1.2. To require TLS 1.3:

```bash
ORES_TLS_MIN_VERSION=1.3 oresd
```

### Cipher Suites

When using TLS 1.2, only AEAD cipher suites are allowed (no CBC, no RC4):

- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

TLS 1.3 cipher suites are managed by Go's standard library and are always strong.

---

## Security

### Request Size Limits

The daemon limits request bodies to 1 MB by default. Override with `ORES_MAX_REQUEST_BYTES`:

```bash
ORES_MAX_REQUEST_BYTES=2097152 oresd   # 2 MB
ORES_MAX_REQUEST_BYTES=0 oresd         # disable limit
```

Requests exceeding the limit receive a `413 Request Entity Too Large` response.

### Rate Limiting

Per-IP rate limiting is disabled by default. Enable it with `ORES_RATE_LIMIT`:

```bash
ORES_RATE_LIMIT=100 oresd              # 100 requests/sec per IP
ORES_RATE_LIMIT=50 ORES_RATE_BURST=100 oresd  # 50 rps sustained, 100 burst
```

Rate-limited requests receive a `429 Too Many Requests` response with a `Retry-After: 1` header. Health and readiness probes (`/healthz`, `/readyz`) are exempt.

### Security Headers

The daemon automatically adds the following headers to every response:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'none'` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` _(TLS only)_ |

### CORS

CORS is disabled by default. Enable it by listing allowed origins:

```bash
ORES_CORS_ORIGINS="https://app.example.com,https://dashboard.example.com" oresd
ORES_CORS_ORIGINS="*" oresd  # allow all origins (development only)
```

```bash
ORES_PORT=:9090 oresd
```

---

## API Endpoints

The daemon serves the `OresService` ConnectRPC service. All RPC calls accept `application/json` via HTTP POST.

### Evaluate

Score a set of risk signals.

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

!!! note "Field naming convention"
    ConnectRPC uses `snake_case` for JSON field names matching the proto definition. The `api_version` field in the HTTP request corresponds to `apiVersion` in the CLI/library format. See the [HTTP API reference](../api/http.md) for the full request and response schema.

**Response:**

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

**Response:**

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

**Response:**

```json
{
  "version": "0.1.0-preview"
}
```

---

## :material-heart-pulse: Health and Readiness

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthz` | `GET` | **Liveness probe.** Returns `200 OK` when the server process is running. |
| `/readyz` | `GET` | **Readiness probe.** Returns `200 OK` when the server is ready to accept traffic. |

Both endpoints return an empty body with status `200`.

```bash
# Quick health check
curl -sf http://localhost:8080/healthz && echo "OK" || echo "DOWN"
```

!!! tip "Monitoring with Prometheus"
    The daemon's structured JSON logs include `latency_ms` on every `Evaluate` call. Pipe them to a log aggregation stack (Loki, Elasticsearch, Datadog) and build dashboards on scoring latency and throughput.

---

## :material-kubernetes: Kubernetes Deployment

The daemon is stateless — no volumes, no databases, no config files. It runs well as a **sidecar** (low-latency, in-pod scoring) or as a **standalone deployment** (shared scoring service).

=== ":material-application-brackets: Sidecar"

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

    !!! tip "When to use a sidecar"
        Choose sidecar mode when your service scores vulnerabilities in the hot path and you need sub-millisecond network overhead. The trade-off is that every pod carries its own `oresd` instance.

=== ":material-server: Standalone"

    For centralized scoring shared across many services, deploy `oresd` as its own Deployment + Service:

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
              resources:
                requests:
                  cpu: "100m"
                  memory: "64Mi"
                limits:
                  cpu: "500m"
                  memory: "128Mi"
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

    Other services call:

    ```
    http://oresd.risk.svc.cluster.local:8080/ores.v1.OresService/Evaluate
    ```

    !!! tip "When to use standalone"
        Choose standalone mode when multiple services need scoring but you want a single point of deployment, scaling, and version control. Scale the replica count based on request volume.

---

## :material-file-document: Audit Logging

Every `Evaluate` call is automatically logged to stdout:

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

All log output uses JSON-structured format (`log/slog` with `JSONHandler`), compatible with any log aggregation stack:

- **Loki** — pipe via Promtail or the Grafana Agent
- **Elasticsearch** — ship via Filebeat or Fluentd
- **Datadog** — auto-parsed via the Docker or Kubernetes integration
- **Splunk** — ingest via the Universal Forwarder

!!! info "No sensitive data in logs"
    Audit logs record the RPC method, HTTP status, and latency. Signal payloads and scores are **not** logged by default, keeping your vulnerability data out of log storage.

---

## :material-power: Graceful Shutdown

The daemon handles `SIGINT` and `SIGTERM` with a **15-second** graceful shutdown window. In-flight requests are completed before the process exits.

```bash
kill -TERM $(pgrep oresd)
```

```json
{"time":"2026-03-25T12:05:00Z","level":"INFO","msg":"shutting down","signal":"terminated"}
{"time":"2026-03-25T12:05:00Z","level":"INFO","msg":"oresd stopped"}
```

!!! warning "Kubernetes termination grace period"
    The default Kubernetes `terminationGracePeriodSeconds` is 30 seconds, which exceeds the daemon's 15-second shutdown window. No configuration change is needed. If you lower the pod grace period below 15 seconds, in-flight requests may be interrupted.
