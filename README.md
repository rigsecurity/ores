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
   KEV: true ──────▶│    ORES     │──────▶ Score: 89 (High)
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

**Get a score, get an explanation, get on with your life.**

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

## The Score

```json
{
  "score": 89,
  "label": "high",
  "explanation": {
    "confidence": 1.0,
    "factors": [
      {"factor": "base_vulnerability",    "contribution": 27, "reasoning": "..."},
      {"factor": "exploitability",         "contribution": 25, "reasoning": "..."},
      {"factor": "environmental_context",  "contribution": 21, "reasoning": "..."},
      {"factor": "remediation_gap",        "contribution": 10, "reasoning": "..."},
      {"factor": "lateral_risk",           "contribution":  6, "reasoning": "..."}
    ]
  }
}
```

Every point is accounted for. Factor contributions **always sum to the total score**. No hand-waving. No black boxes. Your auditors will love you. (Your auditors will still not be fun at parties, but that's not our problem.)

## Three Ways to Deploy

| Mode | Binary | For When You... |
|------|--------|-----------------|
| **CLI** | `ores` | Just want to score something from the terminal. Like `curl` but for risk. |
| **Daemon** | `oresd` | Need a central scoring service. HTTP + gRPC via ConnectRPC. Health checks included because we're not savages. |
| **WASM** | `ores.wasm` | Want to embed scoring in browsers, edge runtimes, or that one microservice written in Rust that nobody wants to touch. |

All three use the **exact same engine**. Same input, same score, whether you're running `ores evaluate` on your laptop or calling the daemon from a Kubernetes pod in `us-east-1`.

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
