# ORES

**Open Risk Evaluation & Scoring — A universal, open-source engine to standardize cybersecurity risk scoring**

[![Go version](https://img.shields.io/badge/go-1.25-blue)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/rigsecurity/ores/actions/workflows/ci.yml/badge.svg)](https://github.com/rigsecurity/ores/actions)

## Why ORES

Cybersecurity teams today juggle a patchwork of scoring standards — CVSS, EPSS, KEV, vendor severity, asset criticality — each living in a different tool with no common language. The result is alert fatigue, inconsistent prioritization, and risk decisions made on incomplete data.

ORES solves this by providing a single, deterministic pipeline that ingests any combination of signals, normalizes them to a common scale, produces an auditable composite score, and generates a plain-language explanation of every factor that contributed to the result. Because the engine is fully deterministic, the same inputs always produce the same score — making ORES suitable for automated pipelines, audit logs, and compliance workflows.

## Quick Start

### Install the CLI

```bash
go install github.com/rigsecurity/ores/cmd/ores@latest
```

### Run an evaluation

Create a signal input file:

```json
{
  "target": {
    "id": "CVE-2024-12345",
    "asset_criticality": "high"
  },
  "signals": {
    "cvss_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.91,
    "epss_percentile": 0.98,
    "kev": true,
    "exploit_maturity": "weaponized"
  }
}
```

```bash
ores evaluate --input signals.json --explain
```

Example output:

```
Score:    94.3 / 100  (CRITICAL)
Factors:
  cvss_base        +42.0   AV:N/AC:L/PR:N — network-reachable, no auth required
  epss             +28.0   91st percentile — high empirical exploit probability
  kev              +15.0   confirmed exploited in the wild
  exploit_maturity  +9.0   weaponized exploit publicly available
  asset_criticality +0.3   high-criticality asset multiplier applied
```

## Architecture

### Pipeline

ORES processes risk signals through a four-step pipeline:

1. **Ingest** — Accept signals in any supported format (JSON, protobuf, WASI memory). Each signal is parsed by a typed handler that validates and normalizes the raw value.
2. **Normalize** — Map every signal to a common `[0, 1]` scale using per-signal normalization functions. This ensures signals from different frameworks (e.g., CVSS base score vs. EPSS probability) are directly comparable.
3. **Score** — Apply a weighted composite model to produce a final score in `[0, 100]`. Weights are configurable; the default model reflects empirical exploit likelihood.
4. **Explain** — Emit a structured explanation listing each signal's contribution in absolute and relative terms, suitable for display in dashboards, audit logs, or API responses.

### Deployment Modes

| Mode | Binary | Use case |
|------|--------|----------|
| **CLI** | `ores` | One-shot evaluations from the terminal, scripts, and CI pipelines |
| **Daemon** | `oresd` | Long-running gRPC/HTTP service for integration with SIEM, SOAR, and ticketing systems |
| **WASM** | `ores.wasm` | Embed the scoring engine directly in browsers, edge runtimes, or language runtimes via WASI |

All three modes share the same core engine (`pkg/engine`) and produce bit-identical scores for identical inputs.

## Documentation

Full documentation is available at https://rigsecurity.github.io/ores (coming soon).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding standards, and the pull request process.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md). Do not open a public GitHub issue for security reports.

## License

Copyright 2026 Rig Security. Licensed under the [Apache License, Version 2.0](LICENSE).
