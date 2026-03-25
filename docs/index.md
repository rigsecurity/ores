# ORES — Open Risk Evaluation & Scoring

**A universal, open-source engine to standardize cybersecurity risk scoring.**

---

Cybersecurity teams today juggle a patchwork of scoring standards — CVSS, EPSS, KEV, vendor severity, asset criticality — each living in a different tool with no common language. The result is alert fatigue, inconsistent prioritization, and risk decisions made on incomplete data.

ORES solves this by providing a single, deterministic pipeline that ingests any combination of signals, normalizes them to a common scale, produces an auditable composite score, and generates a plain-language explanation of every factor that contributed to the result.

## Key Features

**Deterministic**
: The same inputs always produce the same score. ORES is suitable for automated pipelines, audit logs, and compliance workflows where reproducibility is a hard requirement.

**Universal**
: ORES accepts signals from any source — CVSS strings, EPSS probabilities, threat intelligence feeds, asset inventories, patch management systems, and compliance frameworks — through a single, typed signal interface.

**Explainable**
: Every score comes with a structured breakdown of each contributing dimension. You can trace exactly which signals drove the result and by how much.

**Polyglot**
: Run ORES as a CLI tool, a long-running gRPC/HTTP daemon, or a WASM module embedded in browsers, edge runtimes, and any language that supports WASI. All three modes share the same engine and produce bit-identical scores.

## Quick Example

Create a signal file `signals.json`:

```json
{
  "apiVersion": "ores.dev/v1",
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
    }
  }
}
```

Run the evaluation:

```bash
ores evaluate -f signals.json -o table
```

Output:

```
Score:          87
Label:          high
Version:        0.1.0-preview
Confidence:     0.60
Signals used:   4 / 4

FACTOR                  CONTRIBUTION  REASONING
------                  ------------  ---------
base_vulnerability      26            Base severity score from vulnerability data (high impact: 88%)
exploitability          22            Likelihood of exploitation based on threat landscape (high impact: 93%)
environmental_context   17            Environmental risk based on asset criticality and exposure (high impact: 74%)
remediation_gap         12            Remediation posture based on patch availability and compliance (moderate impact: 50%)
lateral_risk            10            Lateral movement potential based on blast radius (moderate impact: 50%)
```

## How It Works

ORES processes risk signals through a four-step pipeline:

1. **Ingest** — Accept signals in any supported format (JSON, YAML, protobuf). Each signal is parsed by a typed handler that validates and normalizes the raw value.
2. **Normalize** — Map every signal to a common `[0, 1]` scale using per-signal normalization functions. This ensures signals from different frameworks are directly comparable.
3. **Score** — Apply a weighted composite model across five dimensions to produce a final score in `[0, 100]`.
4. **Explain** — Emit a structured explanation listing each dimension's contribution in absolute terms, along with which signals drove each factor.

## Deployment Modes

| Mode | Binary | Use Case |
|------|--------|----------|
| **CLI** | `ores` | One-shot evaluations from the terminal, scripts, and CI pipelines |
| **Daemon** | `oresd` | Long-running gRPC/HTTP service for SIEM, SOAR, and ticketing integrations |
| **WASM** | `ores.wasm` | Embed the scoring engine in browsers, edge runtimes, or any WASI-capable runtime |

All three modes share the same core engine and produce bit-identical scores for identical inputs.

## Get Started

- [Install ORES](getting-started/installation.md) — Install the CLI, daemon, or WASM module
- [Quickstart](getting-started/quickstart.md) — Score your first vulnerability in 60 seconds
- [Signals Reference](concepts/signals.md) — See every supported signal type and its fields
- [How Scoring Works](concepts/scoring.md) — Understand the five scoring dimensions
