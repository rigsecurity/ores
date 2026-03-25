# Quickstart

Score your first vulnerability in 60 seconds.

This guide assumes you have the `ores` CLI installed. If not, see [Installation](installation.md).

---

## Example 1: Evaluate from a file

Create a file called `signals.yaml`:

```yaml
apiVersion: ores.dev/v1
kind: EvaluationRequest
signals:
  cvss:
    base_score: 9.8
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  epss:
    probability: 0.91
    percentile: 0.98
  threat_intel:
    actively_exploited: true
    ransomware_associated: false
  asset:
    criticality: high
    network_exposure: true
    data_classification: pii
  patch:
    patch_available: true
    patch_age_days: 45
    compensating_control: false
```

Run the evaluation:

```bash
ores evaluate -f signals.yaml -o table
```

Output:

```
Score:          87
Label:          high
Version:        0.1.0-preview
Confidence:     0.75
Signals used:   5 / 5

FACTOR                  CONTRIBUTION  REASONING
------                  ------------  ---------
base_vulnerability      26            Base severity score from vulnerability data (high impact: 88%)
exploitability          22            Likelihood of exploitation based on threat landscape (high impact: 93%)
environmental_context   17            Environmental risk based on asset criticality and exposure (high impact: 74%)
remediation_gap         13            Remediation posture based on patch availability and compliance (moderate impact: 58%)
lateral_risk             9            Lateral movement potential based on blast radius (moderate impact: 30%)
```

The `label` field maps the numeric score to a severity tier:

| Score | Label |
|-------|-------|
| 90–100 | `critical` |
| 70–89 | `high` |
| 40–69 | `medium` |
| 10–39 | `low` |
| 0–9 | `info` |

---

## Example 2: Evaluate from stdin (pipe from a scanner)

ORES reads from stdin when no `-f` flag is given, making it easy to pipe output from other tools.

```bash
cat signals.yaml | ores evaluate -o json
```

This produces a fully structured JSON result:

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationResult",
  "score": 87,
  "label": "high",
  "version": "0.1.0-preview",
  "explanation": {
    "signals_provided": 5,
    "signals_used": 5,
    "signals_unknown": 0,
    "unknown_signals": [],
    "warnings": [],
    "confidence": 0.75,
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
        "derived_from": ["patch"],
        "reasoning": "Remediation posture based on patch availability and compliance (moderate impact: 58%)"
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

The `derived_from` field tells you exactly which signals contributed to each scoring dimension. When a dimension falls back to defaults (no matching signals were provided), it shows `["defaults"]`.

---

## Example 3: Embed in a Go application

Add the library:

```bash
go get github.com/rigsecurity/ores
```

Score a vulnerability directly from Go code:

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

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
            },
            "epss": map[string]any{
                "probability":  0.91,
                "percentile":   0.98,
            },
            "threat_intel": map[string]any{
                "actively_exploited": true,
            },
        },
    }

    result, err := eng.Evaluate(context.Background(), req)
    if err != nil {
        fmt.Fprintln(os.Stderr, "evaluation failed:", err)
        os.Exit(1)
    }

    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    enc.Encode(result)
}
```

Run it:

```bash
go run main.go
```

---

## Next Steps

- **Explore all signal types**: [Signals Reference](../concepts/signals.md)
- **Understand the scoring model**: [How Scoring Works](../concepts/scoring.md)
- **Use the daemon for HTTP integration**: [Daemon Guide](../guides/daemon.md)
- **Embed in the browser or edge**: [WASM Guide](../guides/wasm.md)
- **Full CLI reference**: [CLI Guide](../guides/cli.md)
