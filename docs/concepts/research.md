# Scoring Model Research & Methodology

This document describes the research process, mathematical foundations, and design decisions behind the ORES scoring engine. It is intended for security researchers, contributors, and anyone who wants to understand not just *what* ORES computes, but *why* it computes it that way and what happens inside the lab before a formula reaches production.

---

## 1. The Problem

Vulnerability prioritization is broken. Organizations face thousands of CVEs per quarter, each scored by multiple systems that disagree:

- **CVSS** tells you how severe a vulnerability is *in theory*, but a CVSS 9.8 on an air-gapped dev box is not the same as a CVSS 9.8 on your internet-facing payment gateway.
- **EPSS** tells you how likely exploitation is *on average*, but doesn't know your environment.
- **CISA KEV** tells you it's actively exploited *somewhere*, but not whether your specific deployment is reachable.

No single framework captures the full picture. Security teams are left mentally compositing 3-5 data sources per vulnerability, multiplied by thousands of vulnerabilities, under time pressure.

ORES exists to replace that mental model with a deterministic, explainable formula that ingests all available signals and produces a single score.

---

## 2. Research Process

The ORES scoring model was developed through a structured simulation-driven research process led by Hila Paz Herszfang at Rig Security, with iterative refinement by the engineering team.

### 2.1. Approach Exploration

The research began by identifying three fundamentally different approaches to multi-signal risk scoring, each with distinct mathematical properties:

**Approach A — Decaying Weighted Average.** Sort inputs by severity, apply geometrically decaying weights (highest-severity input gets the most weight), and compute a weighted average. This approach treats all inputs as interchangeable contributors to a blended score. It is simple and predictable, but it dilutes extreme values: a single critical finding gets averaged down when combined with many low-severity ones.

**Approach B — Critical Finding + Additive.** Anchor the score on the single most severe input, then let additional inputs contribute a capped bonus. Environmental factors shift the score up or down from a neutral baseline. This approach preserves the "worst case" signal while rewarding breadth of exposure. It has the important property that the score is *capped at the highest input* — you cannot score 10 without a finding of 10.

**Approach C — Peak + Central Tendency + Volume.** Decompose the score into three independent signals (worst-case severity, average severity, and count of findings), blend them with tunable weights, then layer in environmental factors. This is the most expressive approach but also the hardest to interpret — users must understand three abstract components to make sense of the result.

### 2.2. Simulation Methodology

Each approach was tested across 10 synthetic identities with controlled inputs (blast radius and vulnerability held at 0.5 to isolate the effect of findings on ranking):

| Identity | Findings | Purpose |
|----------|----------|---------|
| `single_critical` | `[10]` | Worst-case single finding |
| `single_high` | `[8]` | High but not maximum |
| `single_low` | `[2]` | Low-risk baseline |
| `many_mixed` | `[8, 7, 4, 3, 2]` | Realistic severity spread |
| `many_high` | `[9, 8, 8, 7]` | Cluster of high-severity |
| `two_critical` | `[10, 9]` | Multiple critical findings |
| `moderate_cluster` | `[5, 5, 5, 5]` | Many moderate findings |
| `one_high_many_low` | `[9, 2, 1, 1, 1]` | One outlier in noise |
| `escalating` | `[7, 6, 5, 4, 3]` | Gradually increasing severity |
| `many_low` | `[3, 2, 2, 1, 1, 1]` | Volume of low-severity |

Each approach was run with 2-4 weight configurations. The simulation compared:

1. **Rank ordering** — Do the approaches agree on which identities are most risky?
2. **Score separation** — Is there enough distance between identities to support triage thresholds?
3. **Sensitivity to environmental factors** — How much do blast radius and vulnerability shift the score?
4. **Edge case behavior** — What happens with a single finding? With 20 findings? With all-zero inputs?

### 2.3. Model Selection: B4

After evaluating all configurations, **Approach B, Configuration 4 (B4)** was selected as the production model. The key reasons:

1. **Intuitive anchor.** The score starts from the most severe finding. Users can immediately see why the score is high or low — it's driven by the worst thing they found.

2. **Cap at max finding.** A score of 10 requires a finding of 10. An identity with `[9, 9, 9, 9]` approaches 9 but never exceeds it. This prevents volume from artificially inflating scores beyond the actual severity observed.

3. **Additive bonus rewards breadth.** Multiple findings increase the score, but with diminishing returns (geometric decay). This matches the security intuition that "many problems" is worse than "one problem," but not unboundedly so.

4. **Environmental adjustment is centered.** Blast radius and vulnerability shift the score symmetrically around a neutral point. An average environment (0.5) has zero effect. This means the score is *always grounded in actual findings* and environmental factors only modulate it.

5. **Base offset creates separation.** The `-0.5` offset means a single finding of `[10]` scores `9.5` before adjustments, while `[10, 9]` scores higher. This rewards the engine for having more data — a single data point should score slightly lower than multiple data points confirming the same severity level.

**Rejected approaches and why:**

- **A1/A2** (Decaying Weighted Average): Diluted extreme values. A single `[10]` scored lower than `[8, 7, 4, 3, 2]` under A2, which is counter-intuitive — the identity with a critical finding should score higher than one with a spread of medium findings.
- **B1/B2** (B without offset or cap): A single `[10]` immediately hit the ceiling at 10.0, leaving no room for environmental adjustment to increase it. B2's conservative parameters produced insufficient separation between identities.
- **B3** (Offset without cap): Allowed volume to push scores above the maximum finding. An identity with `[8, 8, 8, 8]` could score above 8, which misrepresents the actual severity.
- **C1/C2** (Peak + Central + Volume): More complex without producing better rankings. The volume component introduced a bias toward "many low-severity findings" that didn't match security team triage behavior in validation sessions.

---

## 3. The B4 Formula

### 3.1. Core Algorithm

Given a list of findings (severity scores on a 0–10 scale), a blast radius score (0–1), and a vulnerability score (0–1):

```
INPUTS:
  findings[]     — severity scores, each in [0, 10]
  blast_radius   — environmental blast radius, in [0, 1]
  vulnerability  — environmental vulnerability, in [0, 1]

PARAMETERS:
  decay_rate     = 0.5      — geometric decay for additional findings
  scale_factor   = 0.15     — contribution scaling for each additional finding
  max_add        = 2.0      — maximum bonus from additional findings
  max_adjust     = 2.0      — maximum shift from each environmental factor
  base_offset    = -0.5     — offset applied to the base finding

ALGORITHM:
  1. Sort findings descending
  2. base = findings[0] + base_offset
  3. bonus = Σ(findings[i] × decay_rate^(i-1) × scale_factor) for i = 1..n
     bonus = min(bonus, max_add)
  4. br_adjust  = (blast_radius  - 0.5) × 2 × max_adjust
  5. vuln_adjust = (vulnerability - 0.5) × 2 × max_adjust
  6. raw = base + bonus + br_adjust + vuln_adjust
  7. final = clip(raw, 0, findings[0])

OUTPUT:
  final — risk score in [0, max(findings)]
```

### 3.2. Parameter Rationale

Each parameter was tuned through simulation. Here is why each value was chosen:

**`decay_rate = 0.5`** — Each additional finding contributes half as much as the previous one. The 1st additional finding has full weight, the 2nd has 50%, the 3rd has 25%, and so on. This prevents a large number of low-severity findings from dominating the additive bonus while still rewarding coverage.

**`scale_factor = 0.15`** — Controls the magnitude of each additional finding's contribution. At 0.15, a second finding of severity 10 contributes `10 × 0.15 = 1.5` points. Combined with the decay rate, even an infinite number of max-severity findings converge to a finite bonus (bounded by `max_add`).

**`max_add = 2.0`** — Hard cap on the additive bonus. This means findings alone (base + bonus) can move the score by at most `max(findings) - 0.5 + 2.0` points. For a critical identity with `[10, ...]`, the findings component maxes at `9.5 + 2.0 = 11.5`, which gets clipped to 10.

**`max_adjust = 2.0`** — Each environmental factor can shift the score by up to ±2.0 points. At the neutral point (0.5), there is no adjustment. At the extremes (0.0 or 1.0), the full ±2.0 swing applies. Two factors × ±2.0 = up to ±4.0 total environmental swing.

**`base_offset = -0.5`** — A single finding starts 0.5 below its raw severity. This creates a natural incentive to provide more data: `[10]` alone scores 9.5, but `[10, 8]` scores higher thanks to the additive bonus. Without the offset, a single `[10]` would immediately hit the cap and environmental adjustments could only decrease it.

### 3.3. Why Cap at Max Finding

The `clip(raw, 0, findings[0])` step is one of B4's most important properties. It enforces a semantic guarantee: **the score can never exceed the severity of the most critical finding.**

This matters because:

- An identity with many medium findings (e.g., `[5, 5, 5, 5, 5]`) should not outscore one with a single critical finding (`[10]`). Without the cap, the additive bonus and environmental adjustments could push `[5, 5, 5, 5, 5]` above 5, which misrepresents the actual risk.
- It gives security teams a clear mental model: "the score is at most as bad as the worst thing we found."
- It prevents gaming — you cannot inflate a score by adding noise findings.

---

## 4. ORES Adaptation: Dual-Mode Engine

The research was conducted on identity-level risk (one identity with many findings). ORES extends this to support two modes:

### 4.1. Multi-Finding Mode (B4)

When the request includes a `findings` array, ORES uses the B4 algorithm directly. This is the identity-level use case from the research.

The original B4 formula used two environmental adjustment axes (blast radius and vulnerability). ORES extends this to three richer axes, each composed from multiple signals:

**Environmental Adjustment** (replaces B4's `vulnerability`):
```
env_score = asset_criticality × 0.4 + network_exposure × 0.3 + data_sensitivity × 0.3
env_adjust = (env_score - 0.5) × 2 × max_adjust
```
This captures "how exposed and important is this identity's environment?" An air-gapped internal system with public data scores low (below 0.5, negative adjustment). A crown-jewel internet-facing PII system scores high (above 0.5, positive adjustment).

**Blast Radius Adjustment** (enriched from B4's `blast_radius`):
```
br_score = blast_scope × 0.5 + lateral_movement × 0.5
br_adjust = (br_score - 0.5) × 2 × max_adjust
```
This captures "if exploited, how far does the damage spread?" A single isolated system has zero blast scope and no lateral movement (score near 0, negative adjustment). A system connected to 500 others with confirmed lateral movement paths scores high.

**Remediation Adjustment** (new in ORES):
```
rem_score = remediation_available × 0.3 + patch_staleness × 0.3
          + regulatory_severity × 0.2 + compliance_scope × 0.2
rem_adjust = (rem_score - 0.5) × 2 × max_adjust
```
This captures "how well-mitigated is the risk?" An identity with patches deployed and compensating controls scores low (negative adjustment — risk is reduced). One with a 90-day-old unpatched critical vulnerability under PCI-DSS scope scores high (positive adjustment — risk is amplified by remediation failure).

Each adjustment axis swings ±2.0 points, centered at 0.5. With three axes, the maximum total environmental swing is ±6.0 points, compared to ±4.0 in the original B4. The additional axis was calibrated to maintain similar score distributions by keeping the same per-axis `max_adjust` value.

### 4.2. Single-Vulnerability Mode (Weighted Dimensions)

When no `findings` array is present, ORES uses a multi-dimensional weighted scoring model designed for a different question: "How risky is this one specific vulnerability in this specific context?"

This mode decomposes risk into five dimensions, each computed from its contributing signals and combined via weighted sum:

| Dimension | Weight | What It Captures |
|-----------|--------|-----------------|
| Base Vulnerability | 30% | Intrinsic severity (CVSS, NIST) |
| Exploitability | 25% | Real-world exploit activity (EPSS, threat intel) |
| Environmental Context | 20% | Deployment risk (asset criticality, exposure, blast radius) |
| Remediation Gap | 15% | Mitigation posture (patch availability, compliance) |
| Lateral Risk | 10% | Spread potential (lateral movement, blast scope) |

The weights reflect the research finding that **severity and exploitability together account for over half of effective risk**, while environmental and remediation context provide critical differentiation between otherwise-similar vulnerabilities.

The output is an integer in [0, 100]. Factor contributions are distributed using the largest-remainder method to ensure they sum exactly to the total score without rounding drift.

### 4.3. Mode Selection

The engine automatically selects the scoring mode based on the input:

| Input Shape | Mode | Algorithm | Output Scale |
|-------------|------|-----------|-------------|
| `findings` present (≥1 entry) | Multi-finding | B4 | 0–100 (B4's 0–10 × 10) |
| `findings` absent | Single-vulnerability | Weighted dimensions | 0–100 |

Both modes share the same signal parsers, normalization pipeline, and explanation builder. The response format is identical — callers don't need to know which algorithm was used, though the `version` field indicates the model variant.

---

## 5. Signal Normalization: What Happens Before Scoring

Before any scoring algorithm runs, every signal goes through a normalization pipeline that converts heterogeneous inputs into a common [0, 1] scale. This pipeline is shared between both modes and is critical to ORES's ability to accept partial input gracefully.

### 5.1. Normalization Strategies

Different signal types require different normalization strategies:

| Strategy | Signals | Method |
|----------|---------|--------|
| Linear scaling | `cvss` | `base_score / 10.0` |
| Pass-through | `epss` | Already in [0, 1] |
| Enum mapping | `nist`, `asset.criticality`, `asset.data_classification`, `compliance.regulatory_impact` | Lookup table to fixed values |
| Boolean | `threat_intel`, `asset.network_exposure`, `blast_radius.lateral_movement_possible`, `patch` fields | `true → 1.0, false → 0.0` |
| Logarithmic | `blast_radius.affected_systems` | `log₁₀(n) / log₁₀(1000)`, capped at 1.0 |
| Time-based | `patch.patch_age_days` | `min(days / 90, 1.0)`, only when patch is available |

### 5.2. Default Values

When a signal is absent, the scoring model uses neutral defaults — values chosen so that the missing dimension has minimal effect on the final score. Defaults are set at or near the midpoint (0.5 for continuous values, 0.0 for binary amplifiers like active exploitation).

The key design principle: **missing data should not penalize or reward.** A missing blast radius signal should not inflate the score (as if the blast radius were maximum) or deflate it (as if it were zero). It should be neutral.

---

## 6. Confidence: Quantifying Input Quality

Every ORES response includes a confidence value that tells the caller how much of the scoring model was driven by real data versus neutral defaults.

Confidence is a weighted average of signal coverage across scoring dimensions. For each dimension, we compute `(signals provided for this dimension) / (total possible signals for this dimension)`, then weight by the dimension's importance:

```
confidence = Σ(coverage_fraction × dimension_weight)
```

A confidence of 1.0 means every dimension was fully covered by real signals. A confidence of 0.15 means only one signal was provided (e.g., just CVSS, covering half of the base vulnerability dimension).

**Confidence is metadata, not a penalty.** It does not modify the score. The score already accounts for missing data through defaults. Confidence tells the consumer whether to trust the score for automated workflows or route it to a human reviewer.

---

## 7. Determinism Guarantee

Both scoring modes are fully deterministic: identical inputs always produce identical outputs, regardless of platform, deployment mode (CLI, daemon, WASM), or execution timing.

This is guaranteed by:

1. **Sorted processing order.** Signal names and findings are sorted before processing. Go's map iteration order is non-deterministic; ORES eliminates this by sorting.
2. **Pure computation.** No clock reads, random state, network calls, or external data fetches. The engine is a pure function of its inputs.
3. **Stable integer rounding.** The largest-remainder method produces deterministic integer factor contributions for any given set of dimension scores.
4. **Versioned model.** Every result includes the model version. A given version always scores a given input identically, even across ORES releases.

This makes ORES suitable for audit logs, SLA enforcement, compliance workflows, diff-based alerting, and any context where score reproducibility is required.

---

## 8. What We Train in the Lab

The formulas above are the *output* of the research process. Here is what happens before they reach production — the work users don't see.

### 8.1. Synthetic Data Generation

We generate thousands of synthetic identities with controlled distributions of findings, blast radius, and vulnerability values. The distributions are modeled on real-world security posture data:

- **Finding severity** follows a right-skewed distribution (most findings are medium, critical findings are rare).
- **Finding count** follows a log-normal distribution (most identities have 1-5 findings, a few have 50+).
- **Blast radius and vulnerability** are drawn from beta distributions calibrated to real CMDB and network topology data.

### 8.2. Parameter Space Exploration

For each approach, we sweep the parameter space systematically:

- Decay rates from 0.1 to 0.9
- Scale factors from 0.05 to 0.30
- Maximum adjustments from 0.5 to 4.0
- Various offset values

Each configuration is evaluated against the full synthetic dataset and scored on:

1. **Rank stability** — Do small input changes produce small rank changes? (Lipschitz continuity)
2. **Score separation** — Are there enough distinct score values to support 5-tier triage (critical/high/medium/low/info)?
3. **Monotonicity** — Does adding a high-severity finding always increase the score? Does improving blast radius always decrease it?
4. **Expert alignment** — Do the rankings match the priority ordering that experienced security analysts would assign?

### 8.3. Expert Validation

Simulated rankings are reviewed by security practitioners who evaluate whether the scoring matches their triage intuition. Key validation questions:

- "Would you fix this identity before that one?"
- "Does this score feel right given what you see?"
- "Where does the model surprise you?"

Surprises are investigated. Sometimes the model is wrong and parameters are adjusted. Sometimes the expert's intuition was biased by incomplete information — and the model's fuller picture was actually correct. Both outcomes are documented.

### 8.4. Sensitivity Analysis

We measure how much the score changes when each input changes by a fixed amount. This reveals which inputs the model is most sensitive to and whether that sensitivity matches security priorities:

- A 1-point increase in the most severe finding should have more effect than a 1-point increase in the 5th finding.
- Flipping `actively_exploited` from false to true should have more effect than changing `data_classification` from `internal` to `confidential`.
- Environmental factors should modulate the score, not dominate it.

### 8.5. Version Control

Every parameter change is versioned. The model version string (e.g., `0.2.0`) is a semantic version:

- **Major** — Breaking change to the scoring algorithm or output scale.
- **Minor** — New capabilities (e.g., new scoring mode, new adjustment axis) that don't change existing scores.
- **Patch** — Parameter tuning that may change scores for existing inputs.

Historical model versions are documented so that score changes can be attributed to specific model updates rather than input changes.

---

## 9. Comparison with Existing Frameworks

| Property | CVSS | EPSS | CISA KEV | ORES |
|----------|------|------|----------|------|
| Input scope | Single vulnerability | Single vulnerability | Single vulnerability | Single vulnerability OR identity with multiple findings |
| Environmental context | Optional (CVSS-E) | No | No | Yes (asset, blast radius, compliance, patch) |
| Exploit intelligence | No | Yes (probabilistic) | Yes (binary) | Yes (both probabilistic and binary) |
| Remediation posture | No | No | No | Yes (patch availability, staleness, controls) |
| Multi-finding aggregation | No | No | No | Yes (B4 mode) |
| Explainability | Vector string | Probability + percentile | Yes/No | Factor-by-factor decomposition with reasoning |
| Deterministic | Yes | Yes (for a given model date) | Yes | Yes |
| Open source | Standard (not software) | Model (not software) | Data feed | Full engine + model |

ORES is not a replacement for these frameworks — it *consumes* them. CVSS and NIST feed the base vulnerability dimension. EPSS feeds exploitability. KEV status maps to `threat_intel.actively_exploited`. ORES adds the environmental and remediation context that none of them capture individually, and produces a single composite score.

---

## 10. Limitations and Future Work

### Current Limitations

1. **Weights are research-informed, not ML-trained.** The dimension weights and sub-weights were selected through simulation and expert validation, not through supervised learning on labeled incident data. As labeled datasets become available, we plan to validate and refine the weights using gradient-based optimization.

2. **No temporal dynamics.** ORES scores a point-in-time snapshot. It does not model how risk changes over time (e.g., a vulnerability that has been unpatched for 90 days is riskier than one unpatched for 1 day — this is partially captured by `patch_staleness`, but the broader trajectory is not modeled).

3. **CVSS vector parsing.** The `vector` field in the CVSS signal is accepted but not parsed. A future version will extract sub-scores (Attack Vector, Attack Complexity, etc.) to enrich the base vulnerability dimension beyond the composite base score.

4. **Fixed adjustment axes.** The three environmental adjustment axes in B4 mode have fixed sub-weights. Future versions may allow per-organization calibration while preserving cross-organization comparability of the base score.

### Planned Research

- **Supervised weight optimization** using labeled incident response data (which vulnerabilities were actually exploited, which caused breaches).
- **Additional signal types**: CISA advisories, cloud posture signals, software bill of materials (SBOM) data, runtime reachability analysis.
- **Temporal scoring**: Model risk as a function of time, not just current state.
- **Cross-organization benchmarking**: Anonymized score distributions to help organizations understand where they stand relative to industry baselines.

---

## References

1. FIRST. *Common Vulnerability Scoring System v3.1: Specification Document.* https://www.first.org/cvss/v3.1/specification-document
2. FIRST. *Exploit Prediction Scoring System (EPSS).* https://www.first.org/epss/
3. CISA. *Known Exploited Vulnerabilities Catalog.* https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. Rig Security. *Risk Score Simulation.* Internal research, `rigsecurity/ml-playground` PR #4.
5. Gallagher et al. *The Largest Remainder Method.* Applied to proportional seat allocation and adapted here for integer score decomposition.
