---
hide:
  - navigation
  - toc
---

<div class="ores-hero" markdown>

<div class="ores-particles"><span class="ores-particle"></span><span class="ores-particle"></span><span class="ores-particle"></span><span class="ores-particle"></span><span class="ores-particle"></span><span class="ores-particle"></span><span class="ores-particle"></span><span class="ores-particle"></span></div>

<div class="ores-hero__brand">
  <img class="ores-hero__icon" alt="" src="assets/logo-dark.svg">
  <span class="ores-hero__wordmark">ORES</span>
</div>

<p class="ores-hero__tagline">
  Deterministic risk scoring engine. Feed it signals from any source —
  CVSS, EPSS, threat intel, asset context — get a single auditable score.
</p>

<div class="ores-hero__actions" markdown>

[Get Started](getting-started/installation.md){ .ores-btn-primary }
[GitHub](https://github.com/rigsecurity/ores){ .ores-btn-secondary }

</div>

<div class="ores-hero__badges" markdown>

[![CI](https://github.com/rigsecurity/ores/actions/workflows/ci.yml/badge.svg)](https://github.com/rigsecurity/ores/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rigsecurity/ores.svg)](https://pkg.go.dev/github.com/rigsecurity/ores)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/rigsecurity/ores/blob/main/LICENSE)

</div>

</div>

## The Problem

Your scanner says CVSS 9.8. But which 9.8 do you fix first — the one on your
internet-facing payment service with an active exploit and no patch, or the one
on an internal dev box that was patched last week?

CVSS can't tell you. ORES can.

```bash
# Same CVE, same CVSS 9.8 — different context, different score
ores evaluate -f payment-service.json   # → 88 (high)
ores evaluate -f dev-box.json           # → 58 (medium)
```

---

## How It Works

<div class="ores-pipeline" markdown>

<div class="ores-pipeline-step" markdown>
<span class="ores-pipeline-step__number">1</span>

#### Ingest

JSON, YAML, or protobuf. Any combination of the 8 signal types.
</div>

<div class="ores-pipeline-step" markdown>
<span class="ores-pipeline-step__number">2</span>

#### Normalize

Every signal mapped to `[0, 1]`. Frameworks become directly comparable.
</div>

<div class="ores-pipeline-step" markdown>
<span class="ores-pipeline-step__number">3</span>

#### Score

Weighted composite across 5 dimensions. Output: `[0, 100]`.
</div>

<div class="ores-pipeline-step" markdown>
<span class="ores-pipeline-step__number">4</span>

#### Explain

Factor-by-factor breakdown. Every point accounted for.
</div>

</div>

---

## Why ORES

<div class="ores-features" markdown>

<div class="ores-feature" markdown>
<span class="ores-feature__icon">:material-lock-check:</span>

### Deterministic

Same inputs, same score. Always. Suitable for automated pipelines, audit logs, and compliance workflows.
</div>

<div class="ores-feature" markdown>
<span class="ores-feature__icon">:material-puzzle:</span>

### Graceful Degradation

Feed it 2 signals or 8. Missing signals fall back to neutral defaults. Confidence tells you how much of the model is data-driven.
</div>

<div class="ores-feature" markdown>
<span class="ores-feature__icon">:material-chart-waterfall:</span>

### Explainable

Every score includes a factor-by-factor breakdown. Trace which signals drove the result and by how much. No black boxes.
</div>

<div class="ores-feature" markdown>
<span class="ores-feature__icon">:material-earth:</span>

### Universal Input

CVSS, EPSS, threat intel feeds, asset inventories, patch systems, compliance frameworks — all through a single typed signal interface.
</div>

<div class="ores-feature" markdown>
<span class="ores-feature__icon">:material-lan:</span>

### CLI, Daemon, or WASM

Run as a one-shot CLI, a long-running gRPC/HTTP service, or embed as a WASM module. All three produce bit-identical scores.
</div>

<div class="ores-feature" markdown>
<span class="ores-feature__icon">:material-open-source-initiative:</span>

### Apache 2.0

Security infrastructure should be open and auditable. No vendor lock-in. Contribute signal parsers, challenge the model, or embed it in your stack.
</div>

</div>

---

## See It in Action

=== "Crown Jewel — 88 (high)"

    ```bash
    echo '{
      "apiVersion": "ores.dev/v1",
      "kind": "EvaluationRequest",
      "signals": {
        "cvss":         {"base_score": 9.8},
        "epss":         {"probability": 0.92, "percentile": 0.98},
        "threat_intel": {"actively_exploited": true, "ransomware_associated": true},
        "asset":        {"criticality": "crown_jewel", "network_exposure": true, "data_classification": "pii"},
        "blast_radius": {"affected_systems": 340, "lateral_movement_possible": true},
        "patch":        {"patch_available": false}
      }
    }' | ores evaluate -o table
    ```

    ```text
    Score:         88 (high)      Confidence: 0.93
    Signals used:  6 / 6

    FACTOR                 CONTRIBUTION  REASONING
    base_vulnerability     30            High impact: 99%
    exploitability         24            High impact: 96%
    environmental_context  19            High impact: 95%
    remediation_gap        6             Moderate impact: 38%
    lateral_risk           9             High impact: 94%
    ```

=== "Internal Dev Box — 58 (medium)"

    ```bash
    echo '{
      "apiVersion": "ores.dev/v1",
      "kind": "EvaluationRequest",
      "signals": {
        "cvss":         {"base_score": 9.8},
        "epss":         {"probability": 0.92, "percentile": 0.98},
        "threat_intel": {"actively_exploited": true, "ransomware_associated": true},
        "asset":        {"criticality": "low", "network_exposure": false, "data_classification": "internal"},
        "blast_radius": {"affected_systems": 1, "lateral_movement_possible": false},
        "patch":        {"patch_available": true, "patch_age_days": 3, "compensating_control": true}
      }
    }' | ores evaluate -o table
    ```

    ```text
    Score:         58 (medium)    Confidence: 0.93
    Signals used:  6 / 6

    FACTOR                 CONTRIBUTION  REASONING
    base_vulnerability     30            High impact: 99%
    exploitability         24            High impact: 96%
    environmental_context  2             Low impact: 11%
    remediation_gap        2             Low impact: 16%
    lateral_risk           0             Low impact: 0%
    ```

Same CVE. Same CVSS. The payment service scores 88. The dev box scores 58.
Every point is accounted for — factors sum to the final score.

---

## 8 Signal Types

<div class="ores-signal-grid" markdown>

<div class="ores-signal-card" markdown>
#### :material-shield-bug: `cvss`

Severity score (0–10) and attack vector string
</div>

<div class="ores-signal-card" markdown>
#### :material-chart-bell-curve: `epss`

Exploit prediction probability and percentile
</div>

<div class="ores-signal-card" markdown>
#### :material-database-search: `nist`

NVD severity classification and CWE
</div>

<div class="ores-signal-card" markdown>
#### :material-alert-octagon: `threat_intel`

Active exploitation and ransomware flags
</div>

<div class="ores-signal-card" markdown>
#### :material-server: `asset`

Criticality, network exposure, data classification
</div>

<div class="ores-signal-card" markdown>
#### :material-radius-outline: `blast_radius`

Affected systems and lateral movement
</div>

<div class="ores-signal-card" markdown>
#### :material-bandage: `patch`

Patch availability, age, compensating controls
</div>

<div class="ores-signal-card" markdown>
#### :material-gavel: `compliance`

Affected frameworks and regulatory impact
</div>

</div>

Don't have all 8? That's fine. ORES scores what it gets and adjusts confidence accordingly.

[:material-arrow-right: Full signal reference](concepts/signals.md){ .md-button }

---

## Three Ways to Deploy

<div class="ores-deploy-grid" markdown>

<div class="ores-deploy-card" markdown>
<span class="ores-deploy-card__icon">:material-console:</span>

### CLI
<span class="ores-deploy-card__binary">ores</span>

One-shot evaluations from the terminal, scripts, and CI pipelines.

[:material-arrow-right: CLI Guide](guides/cli.md)
</div>

<div class="ores-deploy-card" markdown>
<span class="ores-deploy-card__icon">:material-server-network:</span>

### Daemon
<span class="ores-deploy-card__binary">oresd</span>

Long-running HTTP + gRPC service for SIEM, SOAR, and ticketing integrations.

[:material-arrow-right: Daemon Guide](guides/daemon.md)
</div>

<div class="ores-deploy-card" markdown>
<span class="ores-deploy-card__icon">:material-web:</span>

### WASM
<span class="ores-deploy-card__binary">ores.wasm</span>

Embed in browsers, edge runtimes, Node.js, Python, or Rust.

[:material-arrow-right: WASM Guide](guides/wasm.md)
</div>

</div>

All three use the same engine. Same input = same score.

---

## ORES vs. The Status Quo

<div class="ores-comparison" markdown>

| | Status Quo | ORES |
|---|---|---|
| :material-tray-full: **Inputs** | One framework at a time | All signals, together |
| :material-sync: **Consistency** | Depends on the vendor | Deterministic, always |
| :material-file-tree: **Explainability** | A number | Factor-by-factor breakdown |
| :material-target: **Context** | Vulnerability in a vacuum | Asset, blast radius, remediation, compliance |
| :material-chart-arc: **Confidence** | Implicit | Mathematically derived from signal coverage |
| :material-package-variant: **Deployment** | Vendor lock-in | CLI, daemon, WASM |

</div>

---

## Install

=== "Go"

    ```bash
    go install github.com/rigsecurity/ores/cmd/ores@latest
    ```

=== "Docker"

    ```bash
    docker run -p 8080:8080 ghcr.io/rigsecurity/oresd:latest
    ```

=== "Source"

    ```bash
    git clone https://github.com/rigsecurity/ores.git && cd ores
    go build ./cmd/ores
    ```

[:material-arrow-right: Installation guide](getting-started/installation.md){ .md-button .md-button--primary }
[:material-rocket-launch: Quickstart](getting-started/quickstart.md){ .md-button }

---

## Status

ORES is in **preview** (`v0.2.0`). The architecture and API surface are stable.
Scoring model weights are being refined through ML research.

**Shipping:** 8 signal types, CLI + daemon + WASM, full test suite, CI/CD with multi-platform releases and Cosign signing.

**Next:** Finalized weights, additional signals (KEV, cloud posture), language SDKs (Python, TypeScript, Rust).

---

<p style="text-align: center; color: var(--md-default-fg-color--light); font-size: 0.85rem;">
  Built by <a href="https://www.rig.security/">Rig Security</a>
</p>
