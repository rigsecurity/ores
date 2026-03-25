<p align="center">
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/logo-light.png">
    <img alt="ORES" src=".github/assets/logo-dark.png" width="280">
  </picture>
  <br><br>
  <strong>Open Risk Evaluation & Scoring</strong><br>
  <em>Because "it depends" is not a risk score.</em>
  <br><br>
</p>

<p align="center">
  <a href="https://github.com/rigsecurity/ores/actions/workflows/ci.yml"><img src="https://github.com/rigsecurity/ores/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/rigsecurity/ores"><img src="https://goreportcard.com/badge/github.com/rigsecurity/ores" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/rigsecurity/ores"><img src="https://pkg.go.dev/badge/github.com/rigsecurity/ores.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://go.dev/dl/"><img src="https://img.shields.io/badge/go-%3E%3D1.25-00ADD8.svg" alt="Go Version"></a>
</p>

---

Every vendor scores risk differently. Every tool speaks a different language. Your SIEM says "critical," your scanner says "high," your CMDB says "meh," and your CISO says **"just tell me what to fix first."**

ORES is the answer. One engine. One score. Every signal. No opinions - just math.

Think of it as the **credit score for cybersecurity risk**. You wouldn't trust a bank that invented its own credit scoring - so why trust a security stack where every tool grades on a different curve?

## The Pitch

```text
                    ┌─────────────┐
   CVSS 9.8 ───────▶│             │
   EPSS 0.95 ──────▶│             │
   KEV: true ──────▶│    ORES     │──────▶ Score: 89 (high)
   Asset: crown ───▶│   Engine    │──────▶ Confidence: 1.0
   Blast: 142 ─────▶│             │──────▶ "Here's exactly why."
   Patch: 45d ─────▶│             │
                    └─────────────┘

   Feed it what you have. More signals = more confidence.
   Same input = same score. Always. Everywhere. Fight me.
```

## Quick Start

**Install:**
```bash
go install github.com/rigsecurity/ores/cmd/ores@latest
```

**Score something:**
```bash
echo '{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "cvss":         {"base_score": 9.8},
    "epss":         {"probability": 0.95, "percentile": 0.99},
    "threat_intel": {"actively_exploited": true, "ransomware_associated": true},
    "asset":        {"criticality": "crown_jewel", "network_exposure": true},
    "blast_radius": {"affected_systems": 142, "lateral_movement_possible": true}
  }
}' | ores evaluate -o json
```

<details>
<summary><strong>See the full output</strong></summary>

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationResult",
  "score": 80,
  "label": "high",
  "version": "0.1.0-preview",
  "explanation": {
    "signals_provided": 5,
    "signals_used": 5,
    "signals_unknown": 0,
    "unknown_signals": [],
    "warnings": [],
    "confidence": 0.7,
    "factors": [
      {
        "name": "base_vulnerability",
        "contribution": 25,
        "derived_from": ["cvss"],
        "reasoning": "Base severity score from vulnerability data (high impact: 84%)"
      },
      {
        "name": "exploitability",
        "contribution": 24,
        "derived_from": ["epss", "threat_intel"],
        "reasoning": "Likelihood of exploitation based on threat landscape (high impact: 97%)"
      },
      {
        "name": "environmental_context",
        "contribution": 18,
        "derived_from": ["asset", "blast_radius"],
        "reasoning": "Environmental risk based on asset criticality and exposure (high impact: 89%)"
      },
      {
        "name": "remediation_gap",
        "contribution": 4,
        "derived_from": ["defaults"],
        "reasoning": "Remediation posture based on patch availability and compliance (low impact: 28%)"
      },
      {
        "name": "lateral_risk",
        "contribution": 9,
        "derived_from": ["blast_radius"],
        "reasoning": "Lateral movement potential based on blast radius (high impact: 89%)"
      }
    ]
  }
}
```

Every point is accounted for. Factors sum to 80. No hand-waving. No black boxes.

</details>

## Real-World Use Case: Triage 10,000 Vulnerabilities in Seconds

Your vulnerability scanner just dumped 10,000 CVEs on your team. Half are "critical" by CVSS alone. Your team has capacity to fix 200 this sprint. **Which 200?**

CVSS can't tell you. It doesn't know that CVE-2024-1234 targets your crown jewel payment service, has a weaponized exploit in the wild, and there's no patch available. Meanwhile CVE-2024-5678 is also CVSS 9.8 but sits on an internal dev box with no network exposure and a patch deployed last week.

ORES can tell you. Feed it everything you know:

```bash
# Score a vulnerability on your payment service (crown jewel, internet-facing)
echo '{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "cvss":         {"base_score": 9.8},
    "epss":         {"probability": 0.92, "percentile": 0.98},
    "nist":         {"severity": "critical", "cwe": "CWE-502"},
    "threat_intel": {"actively_exploited": true, "ransomware_associated": true},
    "asset":        {"criticality": "crown_jewel", "network_exposure": true, "data_classification": "pii"},
    "blast_radius": {"affected_systems": 340, "lateral_movement_possible": true},
    "compliance":   {"frameworks_affected": ["pci_dss", "hipaa"], "regulatory_impact": "critical"},
    "patch":        {"patch_available": false}
  }
}' | ores evaluate -o table
```

```text
Score:         88
Label:         high
Version:       0.1.0-preview
Confidence:    1.00
Signals used:  8 / 8

FACTOR                 CONTRIBUTION  REASONING
------                 ------------  ---------
base_vulnerability     30            Base severity score from vulnerability data (high impact: 99%)
exploitability         24            Likelihood of exploitation based on threat landscape (high impact: 96%)
environmental_context  19            Environmental risk based on asset criticality and exposure (high impact: 95%)
remediation_gap        6             Remediation posture based on patch availability and compliance (moderate impact: 38%)
lateral_risk           9             Lateral movement potential based on blast radius (high impact: 94%)
```

Now score the same CVSS 9.8 on the internal dev box:

```bash
echo '{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "cvss":         {"base_score": 9.8},
    "epss":         {"probability": 0.92, "percentile": 0.98},
    "nist":         {"severity": "critical", "cwe": "CWE-502"},
    "threat_intel": {"actively_exploited": true, "ransomware_associated": true},
    "asset":        {"criticality": "low", "network_exposure": false, "data_classification": "internal"},
    "blast_radius": {"affected_systems": 1, "lateral_movement_possible": false},
    "patch":        {"patch_available": true, "patch_age_days": 3, "compensating_control": true}
  }
}' | ores evaluate -o table
```

```text
Score:         58
Label:         medium
Version:       0.1.0-preview
Confidence:    0.93
Signals used:  7 / 7

FACTOR                 CONTRIBUTION  REASONING
------                 ------------  ---------
base_vulnerability     30            Base severity score from vulnerability data (high impact: 99%)
exploitability         24            Likelihood of exploitation based on threat landscape (high impact: 96%)
environmental_context  2             Environmental risk based on asset criticality and exposure (low impact: 11%)
remediation_gap        2             Remediation posture based on patch availability and compliance (low impact: 16%)
lateral_risk           0             Lateral movement potential based on blast radius (low impact: 0%)
```

**Same CVE. Same CVSS. Completely different risk.** The payment service scores 88 (High). The dev box scores 58 (Medium). Now your team knows exactly where to focus.

### Pipe it into your workflow

```bash
# Score all CVEs from your scanner, sort by ORES score, take the top 200
cat scanner-output.json | jq -c '.cves[]' | while read cve; do
  echo "$cve" | ores evaluate -o json
done | jq -s 'sort_by(.score) | reverse | .[0:200]'
```

```bash
# Gate your CI pipeline - fail if any dependency has ORES score >= 90
ores evaluate -f dependency-signals.json -o json | jq -e '.score < 90'
```

```bash
# Feed scores into your ticketing system
ores evaluate -f signals.json -o json | \
  jq '{priority: (if .score >= 90 then "P0" elif .score >= 70 then "P1" elif .score >= 40 then "P2" else "P3" end), score: .score, label: .label}'
```

## How It Works

ORES doesn't care where your data comes from. It accepts **8 signal types** (and counting), normalizes them to a common scale, runs them through a fixed scoring model, and tells you exactly what drove the result.

| Signal | What It Captures | Example |
|--------|-----------------|---------|
| `cvss` | Vulnerability severity | `base_score: 9.8` |
| `epss` | Exploit probability | `probability: 0.95` |
| `nist` | NVD severity + CWE | `severity: "critical"` |
| `threat_intel` | Active exploitation | `actively_exploited: true` |
| `asset` | Asset criticality | `criticality: "crown_jewel"` |
| `blast_radius` | Impact scope | `affected_systems: 142` |
| `compliance` | Regulatory impact | `frameworks_affected: ["pci_dss"]` |
| `patch` | Remediation status | `patch_available: true, patch_age_days: 45` |

> **Don't have all 8?** That's fine. ORES gracefully degrades - two signals get you a score with lower confidence, eight signals get you the full picture. No signal is required. The engine scores what it gets.

## Three Ways to Deploy

| Mode | Binary | For When You... |
|------|--------|-----------------|
| **CLI** | `ores` | Just want to score something from the terminal. Like `curl` but for risk. |
| **Daemon** | `oresd` | Need a central scoring service. HTTP + gRPC via ConnectRPC. Health checks included because we're not savages. |
| **WASM** | `ores.wasm` | Want to embed scoring in browsers, edge runtimes, or that one microservice written in Rust that nobody wants to touch. |

All three use the **exact same engine**. Same input, same score, whether you're running `ores evaluate` on your laptop or calling the daemon from a Kubernetes pod in `us-east-1`.

<details>
<summary><strong>Daemon example (curl)</strong></summary>

```bash
# Start the daemon
docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:latest

# Score via HTTP
curl -s -X POST http://localhost:8080/ores.v1.OresService/Evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "api_version": "ores.dev/v1",
    "kind": "EvaluationRequest",
    "signals": {
      "fields": {
        "cvss": {"structValue": {"fields": {"base_score": {"numberValue": 9.8}}}},
        "epss": {"structValue": {"fields": {"probability": {"numberValue": 0.95}}}}
      }
    }
  }'
```

</details>

<details>
<summary><strong>Go library example</strong></summary>

```go
package main

import (
    "context"
    "fmt"

    "github.com/rigsecurity/ores/pkg/engine"
    "github.com/rigsecurity/ores/pkg/score"
)

func main() {
    e := engine.New()

    result, _ := e.Evaluate(context.Background(), &score.EvaluationRequest{
        APIVersion: score.APIVersion,
        Kind:       score.KindEvaluationRequest,
        Signals: map[string]any{
            "cvss":         map[string]any{"base_score": 9.8},
            "threat_intel": map[string]any{"actively_exploited": true},
            "asset":        map[string]any{"criticality": "crown_jewel"},
        },
    })

    fmt.Printf("Score: %d (%s)\n", result.Score, result.Label)
    // Output: Score: 56 (medium)
}
```

</details>

## Why Not Just Use CVSS?

| | The Status Quo | ORES |
|---|---|---|
| **Inputs** | One framework at a time | All signals, together |
| **Consistency** | "It depends on the vendor" | Deterministic. Always. |
| **Explainability** | A number and a prayer | Factor-by-factor breakdown |
| **Context** | Vulnerability in a vacuum | Asset, blast radius, remediation, compliance |
| **Confidence** | "Trust us" | Mathematically derived from signal coverage |
| **Deployment** | Vendor lock-in | CLI, daemon, WASM - your choice |

## For the Skeptics

**"Isn't this just another scoring framework?"**
No. Frameworks let everyone invent their own weights. That's the problem. ORES ships **one model** - deterministic, versioned, and the same everywhere. You can't customize the weights because that would defeat the entire purpose.

**"What if I disagree with the score?"**
Great. Look at the factor breakdown, find the signal that's wrong, fix your data. The score is a function of the input, not our opinion.

**"What about my proprietary risk model?"**
Keep it. Use ORES as a universal baseline for cross-tool comparison. Your model is for your decisions; ORES is for speaking a common language.

**"What about SSVC, CISA KEV, or other frameworks?"**
They're complementary, not competing. ORES can ingest signals from any framework. We plan to add dedicated parsers for SSVC decision points, KEV status, and CISA advisories. The more data you feed it, the better the score.

## Project Status

ORES is in **preview** (`v0.1.0-preview`). The architecture is production-ready; the scoring model weights are being refined through ongoing ML simulation research. The API surface is stable. The model will evolve - that's what semantic versioning is for.

**What's here today:**
- Core engine with 8 signal types
- CLI, daemon (ConnectRPC), and WASM module
- Full test suite with race detector
- CI/CD with GoReleaser, multi-platform releases, Cosign signing
- [Complete documentation](https://rigsecurity.github.io/ores/)

**What's next:**
- Finalized scoring weights from ML research
- Additional signal types (KEV, CISA advisories, cloud posture)
- Language SDKs (Python, TypeScript, Rust)
- Standard body engagement

## Contributing

We'd love your help. Whether it's a new signal parser, a bug fix, or telling us our scoring model is wrong (with math, please) - see [CONTRIBUTING.md](CONTRIBUTING.md).

**First time?** Look for issues labeled [`good-first-issue`](https://github.com/rigsecurity/ores/labels/good-first-issue).

## Security

Found something? Please don't open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Credits

ORES was born out of the research and vision of the Rig Security team.

**Core Team**

- **Hila Paz Herszfang** - Research & scoring model design
- **Lior Ben Dayan** - Architecture & engineering
- **Michal Haikov** - Signal design & validation
- **Nokky Goren** - Project lead & open-source strategy

**Community Contributors**

<!-- Add yourself here! We'd love to see your name. Format: -->
<!-- - **Your Name** - What you contributed -->

Want to see your name here? Check out [CONTRIBUTING.md](CONTRIBUTING.md) and send a PR.

## License

Apache 2.0 - because security infrastructure should be open.

Copyright 2026 [Rig Security](https://www.rig.security/).

---

<p align="center">
  <em>Built by <a href="https://www.rig.security/">Rig Security</a> - because the industry deserves a standard, not another vendor score.</em>
</p>
