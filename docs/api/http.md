# HTTP API Reference

The `oresd` daemon exposes the ORES engine via [ConnectRPC](https://connectrpc.com/), which supports both ConnectRPC JSON (plain HTTP POST with `application/json`) and gRPC binary framing over HTTP/2. This page covers the ConnectRPC JSON protocol, which works with any HTTP client — `curl`, `fetch`, `requests`, and so on.

## Base URL

```
http://<host>:8080
```

Default port is `8080`. Configure with the `ORES_PORT` environment variable.

## Content-Type

All requests must include:

```
Content-Type: application/json
```

All responses are `application/json`.

## Authentication

The daemon does not implement authentication. Deploy it behind your organization's API gateway, service mesh, or ingress controller if authentication is required.

---

## Procedures

### `POST /ores.v1.OresService/Evaluate`

Evaluate a set of risk signals and produce a score.

**Request:**

```json
{
  "api_version": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "<signal_name>": { ... }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_version` | `string` | yes | Must be `"ores.dev/v1"` |
| `kind` | `string` | yes | Must be `"EvaluationRequest"` |
| `signals` | `object` | yes | Map of signal name to signal payload. At least one signal required. |

**Example request:**

```bash
curl -s -X POST http://localhost:8080/ores.v1.OresService/Evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "api_version": "ores.dev/v1",
    "kind": "EvaluationRequest",
    "signals": {
      "cvss": {
        "base_score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "epss": {
        "probability": 0.91,
        "percentile": 0.98
      },
      "threat_intel": {
        "actively_exploited": true,
        "ransomware_associated": false
      },
      "asset": {
        "criticality": "high",
        "network_exposure": true,
        "data_classification": "pii"
      },
      "patch": {
        "patch_available": true,
        "patch_age_days": 45
      }
    }
  }'
```

**Response:**

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationResult",
  "score": 87,
  "label": "high",
  "version": "0.1.0-preview",
  "explanation": {
    "signalsProvided": 5,
    "signalsUsed": 5,
    "signalsUnknown": 0,
    "unknownSignals": [],
    "warnings": [],
    "confidence": 0.75,
    "factors": [
      {
        "name": "base_vulnerability",
        "contribution": 26,
        "derivedFrom": ["cvss"],
        "reasoning": "Base severity score from vulnerability data (high impact: 88%)"
      },
      {
        "name": "exploitability",
        "contribution": 22,
        "derivedFrom": ["epss", "threat_intel"],
        "reasoning": "Likelihood of exploitation based on threat landscape (high impact: 93%)"
      },
      {
        "name": "environmental_context",
        "contribution": 17,
        "derivedFrom": ["asset"],
        "reasoning": "Environmental risk based on asset criticality and exposure (high impact: 74%)"
      },
      {
        "name": "remediation_gap",
        "contribution": 13,
        "derivedFrom": ["patch"],
        "reasoning": "Remediation posture based on patch availability and compliance (moderate impact: 58%)"
      },
      {
        "name": "lateral_risk",
        "contribution": 9,
        "derivedFrom": ["defaults"],
        "reasoning": "Lateral movement potential based on blast radius (moderate impact: 30%)"
      }
    ]
  }
}
```

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `apiVersion` | `string` | Always `"ores.dev/v1"` |
| `kind` | `string` | Always `"EvaluationResult"` |
| `score` | `integer` | Risk score in `[0, 100]` |
| `label` | `string` | Severity label: `critical`, `high`, `medium`, `low`, or `info` |
| `version` | `string` | Model version string |
| `explanation.signalsProvided` | `integer` | Total number of signals in the request |
| `explanation.signalsUsed` | `integer` | Signals that were recognized and successfully parsed |
| `explanation.signalsUnknown` | `integer` | Signals not recognized by the engine |
| `explanation.unknownSignals` | `[]string` | Names of unrecognized signals |
| `explanation.warnings` | `[]string` | Validation warnings for skipped signals |
| `explanation.confidence` | `float` | Model coverage score in `[0.0, 1.0]` |
| `explanation.factors` | `[]Factor` | Per-dimension breakdown (see below) |

**Factor fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Dimension name |
| `contribution` | `integer` | Points contributed to the total score |
| `derivedFrom` | `[]string` | Signal types that fed this dimension |
| `reasoning` | `string` | Human-readable explanation of the dimension's raw score |

---

### `POST /ores.v1.OresService/ListSignals`

List all recognized signal types and their fields.

**Request:**

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
      "name": "blast_radius",
      "description": "Blast radius: number of affected systems and lateral movement potential",
      "fields": ["affected_systems", "lateral_movement_possible"]
    },
    {
      "name": "compliance",
      "description": "Compliance frameworks affected and regulatory impact severity",
      "fields": ["frameworks_affected", "regulatory_impact"]
    },
    {
      "name": "cvss",
      "description": "Common Vulnerability Scoring System score and vector string",
      "fields": ["base_score", "vector"]
    },
    {
      "name": "epss",
      "description": "Exploit Prediction Scoring System probability and percentile",
      "fields": ["probability", "percentile"]
    },
    {
      "name": "nist",
      "description": "NIST severity classification and optional CWE identifier",
      "fields": ["severity", "cwe"]
    },
    {
      "name": "patch",
      "description": "Patch availability, age, and compensating control status",
      "fields": ["patch_available", "patch_age_days", "compensating_control"]
    },
    {
      "name": "threat_intel",
      "description": "Threat intelligence: active exploitation and ransomware association",
      "fields": ["actively_exploited", "ransomware_associated"]
    }
  ]
}
```

---

### `POST /ores.v1.OresService/GetVersion`

Get the model version string.

**Request:**

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

## Error Format

Errors follow the ConnectRPC error format. The HTTP status code reflects the error type:

| HTTP Status | Connect Code | Typical Cause |
|-------------|--------------|---------------|
| `400 Bad Request` | `invalid_argument` | Invalid request envelope, invalid signal values, no valid signals |
| `405 Method Not Allowed` | — | Non-POST request to an RPC endpoint |

Error response body:

```json
{
  "code": "invalid_argument",
  "message": "invalid request: apiVersion is required"
}
```

**Example — missing `apiVersion`:**

```bash
curl -s -X POST http://localhost:8080/ores.v1.OresService/Evaluate \
  -H "Content-Type: application/json" \
  -d '{"kind": "EvaluationRequest", "signals": {"cvss": {"base_score": 7.5}}}'
```

```json
{
  "code": "invalid_argument",
  "message": "invalid request: apiVersion is required"
}
```

**Example — unrecognized signal (warning, not error):**

Unrecognized signal names do not cause an error. They appear in `unknownSignals` and the evaluation proceeds with any valid signals:

```bash
curl -s -X POST http://localhost:8080/ores.v1.OresService/Evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "api_version": "ores.dev/v1",
    "kind": "EvaluationRequest",
    "signals": {
      "cvss": { "base_score": 7.5 },
      "typo_signal": { "value": 1 }
    }
  }'
```

```json
{
  "score": 62,
  "label": "medium",
  "explanation": {
    "signalsProvided": 2,
    "signalsUsed": 1,
    "signalsUnknown": 1,
    "unknownSignals": ["typo_signal"],
    ...
  }
}
```

---

## Health and Readiness

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /healthz` | GET | Returns `200 OK` when the process is running |
| `GET /readyz` | GET | Returns `200 OK` when the server is ready to serve |

These are plain HTTP endpoints, not ConnectRPC procedures.

```bash
curl -o /dev/null -s -w "%{http_code}" http://localhost:8080/healthz
# 200
```
