# :material-rocket-launch: Quickstart

**Score your first vulnerability in 60 seconds.**

ORES takes a set of **signals** — CVSS score, EPSS probability, threat intel, asset context, patch status — and returns a single **prioritized risk score** with a full explanation of how it got there.

!!! info "Before you begin"
    This guide assumes the `ores` CLI is installed and on your `PATH`.
    If not, head to [Installation](installation.md) first — it takes under a minute.

---

## :material-numeric-1-circle: Prepare your signals

Create a file with the vulnerability signals you want to evaluate. ORES accepts both **YAML** and **JSON**.

=== ":material-file-document: signals.yaml"

    ```yaml title="signals.yaml"
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

=== ":material-code-json: signals.json"

    ```json title="signals.json"
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
        },
        "patch": {
          "patch_available": true,
          "patch_age_days": 45,
          "compensating_control": false
        }
      }
    }
    ```

!!! tip "You don't need all five signals"
    ORES works with **any subset** of signals. Pass just a CVSS score and you will still get a result — the engine fills in safe defaults for anything missing and adjusts its **confidence** score accordingly.

---

## :material-numeric-2-circle: Run the evaluation

=== "From a file"

    ```bash
    ores evaluate -f signals.yaml -o table
    ```

=== "From stdin (pipe)"

    ORES reads from stdin when no `-f` flag is given, so you can pipe output from scanners or other tools:

    ```bash
    cat signals.yaml | ores evaluate -o table
    ```

---

## :material-numeric-3-circle: Read the results

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

Every result includes:

:material-gauge: **Score**
:   A number from **0 - 100** representing overall prioritized risk.

:material-label: **Label**
:   A human-readable severity tier mapped from the score.

:material-chart-bar: **Factors**
:   A breakdown showing exactly which dimensions drove the score and why.

:material-shield-check: **Confidence**
:   How much signal the engine had to work with (more signals = higher confidence).

??? note "Severity tier mapping"
    The `label` field maps the numeric score to a tier:

    | Score | Label | |
    |------:|-------|---|
    | 90 - 100 | `critical` | <span class="ores-score ores-score--critical">Critical</span> |
    | 70 - 89 | `high` | <span class="ores-score ores-score--high">High</span> |
    | 40 - 69 | `medium` | <span class="ores-score ores-score--medium">Medium</span> |
    | 10 - 39 | `low` | <span class="ores-score ores-score--low">Low</span> |
    | 0 - 9 | `info` | <span class="ores-score ores-score--info">Info</span> |

---

## :material-numeric-4-circle: Get structured output

For programmatic use, switch to **JSON** output:

```bash
ores evaluate -f signals.yaml -o json
```

??? example "Full JSON response (click to expand)"

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

!!! tip "Understanding `derived_from`"
    Each factor lists the signals it drew from. When a factor shows `["defaults"]`, it means no matching signals were provided and the engine used safe built-in defaults. Supplying more signals will increase both accuracy and the **confidence** score.

---

## :material-numeric-5-circle: Embed in a Go application

Want to skip the CLI entirely? Use the Go library for **zero-overhead, in-process** scoring:

```bash
go get github.com/rigsecurity/ores
```

```go title="main.go"
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
                "probability": 0.91,
                "percentile":  0.98,
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

```bash
go run main.go
```

---

## :material-arrow-right-circle: What's next?

You have scored your first vulnerability. Here is where to go from here:

<div class="grid cards" markdown>

-   :material-signal-variant:{ .lg .middle } **Signals Reference**

    ---

    Explore every signal type ORES understands — CVSS, EPSS, threat intel, asset context, and more.

    [:octicons-arrow-right-24: Signals](../concepts/signals.md)

-   :material-calculator-variant:{ .lg .middle } **How Scoring Works**

    ---

    Understand the weighted factor model, confidence calculation, and default behaviors.

    [:octicons-arrow-right-24: Scoring Model](../concepts/scoring.md)

-   :material-server-network:{ .lg .middle } **Daemon Guide**

    ---

    Deploy `oresd` as an HTTP service for SIEM, SOAR, and ticketing integrations.

    [:octicons-arrow-right-24: Daemon](../guides/daemon.md)

-   :material-web:{ .lg .middle } **WASM Guide**

    ---

    Run ORES in the browser, at the edge, or inside sandboxed environments.

    [:octicons-arrow-right-24: WASM](../guides/wasm.md)

-   :material-console:{ .lg .middle } **CLI Reference**

    ---

    Every flag, output format, and advanced option for the `ores` command.

    [:octicons-arrow-right-24: CLI Guide](../guides/cli.md)

-   :material-shield-half-full:{ .lg .middle } **Confidence**

    ---

    Learn how signal completeness affects the confidence score and what it means for prioritization.

    [:octicons-arrow-right-24: Confidence](../concepts/confidence.md)

</div>
