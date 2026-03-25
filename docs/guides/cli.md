# CLI Reference

The `ores` CLI is the simplest way to run evaluations. It reads signals from a file or stdin and writes results to stdout.

## Installation

See [Installation](../getting-started/installation.md).

---

## Commands

### `ores evaluate`

Evaluate a set of risk signals and produce a score.

```
ores evaluate [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--file` | `-f` | stdin | Input file (JSON or YAML). When omitted, reads from stdin. |
| `--output` | `-o` | `json` | Output format: `json`, `yaml`, or `table` |

**Input format:** Both JSON and YAML are supported. The input must be a valid `EvaluationRequest` envelope:

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "<signal_name>": { ... }
  }
}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Evaluation succeeded |
| `1` | Input error (invalid file, malformed JSON/YAML, no valid signals) or internal error |

---

#### Output: `json` (default)

Structured JSON output. Suitable for piping into `jq` or other tools.

```bash
ores evaluate -f signals.json -o json
```

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationResult",
  "score": 87,
  "label": "high",
  "version": "0.1.0-preview",
  "explanation": {
    "signals_provided": 4,
    "signals_used": 4,
    "signals_unknown": 0,
    "unknown_signals": [],
    "warnings": [],
    "confidence": 0.60,
    "factors": [
      {
        "factor": "base_vulnerability",
        "contribution": 26,
        "derived_from": ["cvss"],
        "reasoning": "Base severity score from vulnerability data (high impact: 88%)"
      },
      {
        "factor": "exploitability",
        "contribution": 22,
        "derived_from": ["epss", "threat_intel"],
        "reasoning": "Likelihood of exploitation based on threat landscape (high impact: 93%)"
      },
      {
        "factor": "environmental_context",
        "contribution": 17,
        "derived_from": ["asset"],
        "reasoning": "Environmental risk based on asset criticality and exposure (high impact: 74%)"
      },
      {
        "factor": "remediation_gap",
        "contribution": 13,
        "derived_from": ["defaults"],
        "reasoning": "Remediation posture based on patch availability and compliance (moderate impact: 50%)"
      },
      {
        "factor": "lateral_risk",
        "contribution": 9,
        "derived_from": ["defaults"],
        "reasoning": "Lateral movement potential based on blast radius (moderate impact: 30%)"
      }
    ]
  }
}
```

---

#### Output: `yaml`

YAML output. Useful when the result needs to feed into YAML-native pipelines (e.g., Kubernetes operators, GitOps workflows).

```bash
ores evaluate -f signals.yaml -o yaml
```

```yaml
apiVersion: ores.dev/v1
kind: EvaluationResult
score: 87
label: high
version: 0.1.0-preview
explanation:
  signals_provided: 4
  signals_used: 4
  signals_unknown: 0
  unknown_signals: []
  warnings: []
  confidence: 0.60
  factors:
    - factor: base_vulnerability
      contribution: 26
      derived_from: [cvss]
      reasoning: "Base severity score from vulnerability data (high impact: 88%)"
    - factor: exploitability
      contribution: 22
      derived_from: [epss, threat_intel]
      reasoning: "Likelihood of exploitation based on threat landscape (high impact: 93%)"
```

---

#### Output: `table`

Human-readable tabular output. Best for terminal use and ad-hoc analysis.

```bash
ores evaluate -f signals.yaml -o table
```

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
remediation_gap         13            Remediation posture based on patch availability and compliance (moderate impact: 50%)
lateral_risk            9             Lateral movement potential based on blast radius (moderate impact: 30%)
```

---

### `ores signals`

List all recognized signal types, including their fields.

```
ores signals
```

No flags. Output is always a tab-aligned table:

```
NAME          DESCRIPTION                                                           FIELDS
----          -----------                                                           ------
asset         Asset criticality, network exposure, and data classification context  criticality, network_exposure, data_classification
blast_radius  Blast radius: number of affected systems and lateral movement potential  affected_systems, lateral_movement_possible
compliance    Compliance frameworks affected and regulatory impact severity          frameworks_affected, regulatory_impact
cvss          Common Vulnerability Scoring System score and vector string            base_score, vector
epss          Exploit Prediction Scoring System probability and percentile           probability, percentile
nist          NIST severity classification and optional CWE identifier               severity, cwe
patch         Patch availability, age, and compensating control status               patch_available, patch_age_days, compensating_control
threat_intel  Threat intelligence: active exploitation and ransomware association    actively_exploited, ransomware_associated
```

Signal types are sorted alphabetically.

---

### `ores version`

Print the CLI version and model version.

```
ores version
```

Output:

```
ores version 0.1.0-preview (model: 0.1.0-preview)
```

---

## Practical Examples

### Score a single CVE using only CVSS

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "cvss": { "base_score": 7.5 }
  }
}
```

```bash
ores evaluate -f cve.json -o table
```

### Extract just the score with `jq`

```bash
ores evaluate -f signals.json | jq .score
```

### Extract the label and confidence

```bash
ores evaluate -f signals.json | jq '{score: .score, label: .label, confidence: .explanation.confidence}'
```

### Pipe from a vulnerability scanner

Many scanners (e.g., Grype, Trivy) can output structured JSON. You can transform their output into an ORES `EvaluationRequest` and pipe it directly:

```bash
grype --output json image:nginx:1.24 \
  | jq '
    .matches[0] |
    {
      apiVersion: "ores.dev/v1",
      kind: "EvaluationRequest",
      signals: {
        cvss: {
          base_score: .vulnerability.cvss[0].metrics.baseScore
        },
        epss: {
          probability: .vulnerability.epss.probability
        }
      }
    }
  ' \
  | ores evaluate -o table
```

### CI pipeline: fail on critical scores

```bash
SCORE=$(ores evaluate -f signals.json | jq .score)
if [ "$SCORE" -ge 90 ]; then
  echo "CRITICAL risk score: $SCORE - blocking pipeline"
  exit 1
fi
```

### Process a directory of signal files

```bash
for f in signals/*.yaml; do
  echo "=== $f ==="
  ores evaluate -f "$f" -o table
done
```

---

## Error Handling

When the input is malformed or no valid signals are found, `ores evaluate` exits with code `1` and prints an error to stderr:

```
Error: evaluation failed: no valid signals: all 2 signals were invalid or unknown
```

When a signal is recognized but contains invalid field values (e.g., `base_score: 15`), the signal is skipped with a warning, and the warning appears in the result's `explanation.warnings` array. The evaluation still succeeds if at least one valid signal remains.
