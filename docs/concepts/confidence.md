# Confidence

Every `EvaluationResult` includes a `confidence` value in `[0.0, 1.0]`. Confidence tells you how much of the scoring model was backed by actual signals you provided, as opposed to neutral defaults.

---

## What Confidence Means

ORES can always produce a score, even when only a single signal is provided. Missing signals fall back to neutral defaults — values chosen to represent "no information" for that dimension. The `confidence` value quantifies how reliable that score is.

A confidence of `1.0` means every scoring dimension was covered by at least one signal you provided. A confidence of `0.0` would mean no signals were recognized. In practice, providing a CVSS score alone yields a confidence around `0.30` because only the `base_vulnerability` dimension is covered.

Think of confidence as an answer to: **"How much of the 100-point model was driven by real data versus assumptions?"**

---

## How Confidence Is Calculated

Confidence is a weighted average across the five scoring dimensions. For each dimension, ORES checks whether you provided any of the recognized signal types for that dimension:

| Dimension | Weight | Signal Types |
|-----------|--------|-------------|
| `base_vulnerability` | 30% | `cvss`, `nist` |
| `exploitability` | 25% | `epss`, `threat_intel` |
| `environmental_context` | 20% | `asset`, `blast_radius` |
| `remediation_gap` | 15% | `patch`, `compliance` |
| `lateral_risk` | 10% | `blast_radius` |

For each dimension, the coverage fraction is `(sources covered) / (total sources)`. Coverage for each dimension is then multiplied by that dimension's weight, and the results are summed.

**Examples:**

- You provide only `cvss`: `base_vulnerability` is fully covered → `1.0 × 0.30 = 0.30` confidence.
- You provide `cvss` + `epss` + `threat_intel`: `base_vulnerability` fully covered, `exploitability` fully covered → `(0.30 × 1.0) + (0.25 × 1.0) = 0.55` confidence.
- You provide all signal types: all dimensions fully covered → `1.0` confidence.

---

## Confidence Ranges

| Range | Interpretation |
|-------|----------------|
| `0.00 – 0.30` | Very low. Only one or two dimensions are covered. Scores should be treated as rough directional signals, not authoritative risk assessments. |
| `0.30 – 0.55` | Low to moderate. The foundational vulnerability and exploitability dimensions are likely covered, but environmental context is missing. Scores are useful for triage but should be supplemented with asset data. |
| `0.55 – 0.75` | Moderate to good. Most dimensions have at least one signal. Scores are reasonably reliable for prioritization. |
| `0.75 – 1.00` | High to complete. All or nearly all dimensions are covered by real signals. Scores are reliable for automated decision-making, SLA enforcement, and audit trails. |

---

## How to Improve Confidence

Add signals for the uncovered dimensions. The most impactful additions (sorted by weight contribution):

1. **Add `cvss` or `nist`** if not already present — covers `base_vulnerability` (+30%)
2. **Add `epss` and/or `threat_intel`** — covers `exploitability` (+25%)
3. **Add `asset`** — covers `environmental_context` (+10% to +20%)
4. **Add `blast_radius`** — covers `environmental_context` and `lateral_risk` (+10% to +30%)
5. **Add `patch`** — covers `remediation_gap` (+7.5% to +15%)
6. **Add `compliance`** — covers `remediation_gap` (+7.5% to +15%)

The explanation in every result includes `derived_from` lists for each factor. Any factor showing `"derived_from": ["defaults"]` indicates an uncovered dimension — adding the corresponding signal type will improve both coverage and score accuracy.

---

## Confidence in the API Response

Confidence is returned in the `explanation` field of every result:

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationResult",
  "score": 62,
  "label": "medium",
  "version": "0.1.0-preview",
  "explanation": {
    "signals_provided": 2,
    "signals_used": 2,
    "signals_unknown": 0,
    "unknown_signals": [],
    "warnings": [],
    "confidence": 0.55,
    "factors": [ ... ]
  }
}
```

The `signals_provided`, `signals_used`, and `signals_unknown` fields give you an additional view into input quality:

- `signals_provided` — Total number of signal keys in the request
- `signals_used` — Signals that were recognized and successfully normalized
- `signals_unknown` — Signals that were not recognized (typos, unsupported types); these are also listed in `unknown_signals`

A request where `signals_used < signals_provided` means some signals were either unknown or invalid. Check the `warnings` array for details.

---

## Confidence Is Not a Score Quality Penalty

Confidence is a metadata field, not a penalty applied to the score. The score itself already reflects defaults for uncovered dimensions. Confidence is there to tell you — and your downstream systems — how much of the score is based on real data.

For automated workflows, you might choose to:

- Route scores below a confidence threshold to a human reviewer
- Suppress automated ticket creation until confidence reaches a minimum level
- Store confidence alongside scores in your vulnerability tracking system to enable "re-score when more data arrives" workflows
