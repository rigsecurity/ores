# Scoring

ORES produces a single integer score in the range `[0, 100]`. This page explains how that score is constructed, what it means, and how to interpret the factor breakdown returned in every result.

---

## Score Range and Labels

Every score maps to a severity label:

| Score | Label | Interpretation |
|-------|-------|----------------|
| 90–100 | `critical` | Immediate action required. High-confidence exploit path with significant impact. |
| 70–89 | `high` | Prioritize within the current sprint. Significant risk with credible exploit activity. |
| 40–69 | `medium` | Plan remediation. Real risk but lower likelihood or lower environmental impact. |
| 10–39 | `low` | Monitor. Vulnerability exists but contextual factors reduce effective risk. |
| 0–9 | `info` | Informational. Risk is negligible given the available signals. |

---

## Five Scoring Dimensions

ORES decomposes risk into five dimensions. Each dimension is computed independently from its contributing signals, then combined using a weighted sum to produce the final score.

### 1. Base Vulnerability

**What it captures:** The intrinsic severity of the vulnerability itself, independent of environmental context.

**Signals that feed it:** `cvss`, `nist`

The base vulnerability dimension reflects how severe a flaw is according to established vulnerability scoring standards. A remotely exploitable, authentication-free, complete-system-compromise vulnerability scores at the top of this dimension. A locally-exploitable, low-impact issue with complex attack requirements scores at the bottom.

When you provide a CVSS base score, it is the primary driver of this dimension. The NIST severity label serves as a supplementary source — useful when only a qualitative classification is available, or to cross-validate a CVSS score from a different database.

### 2. Exploitability

**What it captures:** The probability and confirmed activity of real-world exploitation.

**Signals that feed it:** `epss`, `threat_intel`

This dimension answers the question: "Is this vulnerability actually being exploited?" A theoretical vulnerability with no public proof-of-concept scores low here, regardless of its CVSS base score. A vulnerability with high EPSS probability and a confirmed CISA KEV entry scores at the top.

EPSS probability is the primary continuous driver. Confirmed active exploitation (e.g., KEV status) and ransomware association act as strong binary amplifiers.

### 3. Environmental Context

**What it captures:** The risk contributed by your specific environment — who is exposed and what they protect.

**Signals that feed it:** `asset`, `blast_radius`

Two vulnerabilities with identical CVSS scores can have very different effective risk depending on where they live. A critical CVE on an air-gapped internal tool poses far less risk than the same CVE on a public-facing crown-jewel system that processes PII.

This dimension scales the base risk by asset criticality, network exposure, data sensitivity, and the scope of potential impact. It is the primary way to express that a vulnerability matters more in some environments than others.

### 4. Remediation Gap

**What it captures:** How far behind your remediation posture is relative to available mitigations.

**Signals that feed it:** `patch`, `compliance`

A vulnerability with an available patch that has been sitting undeployed for 90 days poses substantially more risk than one where no patch is yet available (and the team is unaware). This dimension captures that gap.

Patch staleness (days since the patch was released vs. whether it has been applied) is the primary driver. The presence of compensating controls reduces this dimension's contribution. Compliance scope and regulatory impact add to it — a vulnerability on a PCI-DSS in-scope system with no patch strategy carries regulatory consequence beyond the technical risk.

### 5. Lateral Risk

**What it captures:** The potential for a successful exploit to spread beyond the initial target.

**Signals that feed it:** `blast_radius`

Even a low-criticality host can serve as a pivot point into high-value systems. This dimension captures the amplification effect of lateral movement potential and the breadth of systems that could be affected if the vulnerability is exploited and the attacker moves laterally.

---

## Weight Distribution

The five dimensions do not contribute equally to the final score. The weight distribution reflects empirical research on what factors most reliably predict real-world security incidents:

| Dimension | Weight |
|-----------|--------|
| Base Vulnerability | 30% |
| Exploitability | 25% |
| Environmental Context | 20% |
| Remediation Gap | 15% |
| Lateral Risk | 10% |

!!! note
    The exact scoring formulas and weights are intentionally not published in this documentation. This prevents gaming the model by tuning inputs to hit specific score thresholds rather than accurately representing real-world risk. The weights and the approach are stable across the `0.x` model series; any change will be documented in the [CHANGELOG](https://github.com/rigsecurity/ores/blob/main/CHANGELOG.md) with a model version bump.

---

## Factor Decomposition

Every `EvaluationResult` includes an `explanation.factors` array. Each factor entry shows:

- **`factor`**: The dimension name
- **`contribution`**: The integer points this dimension contributed to the total score
- **`derived_from`**: Which signal types provided the input for this dimension
- **`reasoning`**: A plain-language description of the dimension's raw score level

The contributions across all five factors sum exactly to the total score. ORES uses the [largest-remainder method](https://en.wikipedia.org/wiki/Largest_remainder_method) to distribute integer contributions without rounding drift.

Example factor breakdown for a score of 87:

```json
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
```

When a dimension shows `"derived_from": ["defaults"]`, it means no signals were provided for that dimension and the engine used its built-in neutral defaults. Providing more signals always improves the accuracy and confidence of the score.

---

## Determinism Guarantee

ORES is fully deterministic: identical inputs always produce identical outputs.

This is guaranteed by:

1. **Signal processing order** — Signals are sorted alphabetically by name before processing. Map iteration order in Go is non-deterministic; ORES eliminates this by sorting.
2. **No timestamps or randomness** — The engine has no clock reads, random state, or external data fetches. It is a pure function of its inputs.
3. **Stable integer rounding** — The largest-remainder method is deterministic for a given set of dimension scores, eliminating floating-point rounding ambiguity in the factor breakdown.
4. **Versioned model** — The scoring model is versioned (`model.version` in every result). A given model version will always score a given input the same way, even across ORES upgrades.

This makes ORES suitable for audit logs, diff-based alerting ("the score changed from 72 to 91"), and compliance workflows where score reproducibility is required.
