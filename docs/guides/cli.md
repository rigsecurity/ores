# :material-console: CLI Reference

The `ores` CLI is the fastest way to score vulnerabilities from your terminal. It reads risk signals from a file or stdin and writes results to stdout — perfect for scripting, CI pipelines, and ad-hoc analysis.

---

## Commands

### `ores evaluate`

Evaluate a set of risk signals and produce a composite score.

```
ores evaluate [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--file` | `-f` | stdin | Input file (JSON or YAML). When omitted, reads from stdin. |
| `--output` | `-o` | `json` | Output format: `json`, `yaml`, or `table`. |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Evaluation succeeded |
| `1` | Input error (invalid file, malformed JSON/YAML, no valid signals) or internal error |

#### Input Format

Both JSON and YAML are accepted. The input must be a valid `EvaluationRequest` envelope:

=== "JSON"

    ```json
    {
      "apiVersion": "ores.dev/v1",
      "kind": "EvaluationRequest",
      "signals": {
        "cvss": { "base_score": 9.8 },
        "epss": { "probability": 0.91, "percentile": 0.98 },
        "threat_intel": { "actively_exploited": true },
        "asset": { "criticality": "high", "network_exposure": true }
      }
    }
    ```

=== "YAML"

    ```yaml
    apiVersion: ores.dev/v1
    kind: EvaluationRequest
    signals:
      cvss:
        base_score: 9.8
      epss:
        probability: 0.91
        percentile: 0.98
      threat_intel:
        actively_exploited: true
      asset:
        criticality: high
        network_exposure: true
    ```

#### Output Formats

=== ":material-code-json: JSON (default)"

    Structured JSON output. Ideal for piping into `jq` or downstream tools.

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

=== ":material-file-code: YAML"

    YAML output. Useful when results feed into YAML-native pipelines such as Kubernetes operators or GitOps workflows.

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
        - factor: environmental_context
          contribution: 17
          derived_from: [asset]
          reasoning: "Environmental risk based on asset criticality and exposure (high impact: 74%)"
        - factor: remediation_gap
          contribution: 13
          derived_from: [defaults]
          reasoning: "Remediation posture based on patch availability and compliance (moderate impact: 50%)"
        - factor: lateral_risk
          contribution: 9
          derived_from: [defaults]
          reasoning: "Lateral movement potential based on blast radius (moderate impact: 30%)"
    ```

=== ":material-table: Table"

    Human-readable tabular output. Best for terminal use and quick inspection.

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

!!! tip "Quick field lookup"
    Pipe through `grep` to find fields for a specific signal:

    ```bash
    ores signals | grep cvss
    ```

---

### `ores version`

Print the CLI version and model version.

```
ores version
```

```
ores version 0.1.0-preview (model: 0.1.0-preview)
```

---

## :material-book-open-variant: Common Recipes

### Score a single CVE with only CVSS

```bash
echo '{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "cvss": { "base_score": 7.5 }
  }
}' | ores evaluate -o table
```

### Extract just the score with `jq`

```bash
ores evaluate -f signals.json | jq .score
```

### Extract a summary object

```bash
ores evaluate -f signals.json | jq '{
  score: .score,
  label: .label,
  confidence: .explanation.confidence
}'
```

### List all factors and their contributions

```bash
ores evaluate -f signals.json \
  | jq -r '.explanation.factors[] | "\(.factor)\t+\(.contribution)"'
```

### Check if any warnings were raised

```bash
ores evaluate -f signals.json \
  | jq -e '.explanation.warnings | length > 0' \
  && echo "Warnings present" \
  || echo "Clean evaluation"
```

---

## :material-pipe: Piping from Vulnerability Scanners

Many scanners (Grype, Trivy, etc.) can output structured JSON. Transform their output into an ORES `EvaluationRequest` and pipe it directly.

### Grype

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

### Trivy

```bash
trivy image --format json nginx:1.24 \
  | jq '
    .Results[0].Vulnerabilities[0] |
    {
      apiVersion: "ores.dev/v1",
      kind: "EvaluationRequest",
      signals: {
        cvss: {
          base_score: .CVSS.nvd.V3Score
        }
      }
    }
  ' \
  | ores evaluate -o table
```

!!! info "Batch scoring"
    To score every vulnerability in a scan, iterate with `jq` array indexing or use a `for` loop over the matches array.

---

## :material-robot: CI / CD Integration

### Fail the pipeline on critical scores

```bash
SCORE=$(ores evaluate -f signals.json | jq .score)
if [ "$SCORE" -ge 90 ]; then
  echo "::error::CRITICAL risk score: $SCORE — blocking pipeline"
  exit 1
fi
echo "Risk score: $SCORE — within threshold"
```

### GitHub Actions step

```yaml
- name: Score vulnerability
  run: |
    SCORE=$(ores evaluate -f signals.json | jq .score)
    LABEL=$(ores evaluate -f signals.json | jq -r .label)
    echo "score=$SCORE" >> "$GITHUB_OUTPUT"
    echo "label=$LABEL" >> "$GITHUB_OUTPUT"
    if [ "$SCORE" -ge 90 ]; then
      echo "::error::Risk score $SCORE ($LABEL) exceeds threshold"
      exit 1
    fi
  id: ores
```

!!! warning "Cache the evaluation"
    The example above calls `ores evaluate` twice. In a real pipeline, capture the full JSON output once and extract fields from it:

    ```bash
    RESULT=$(ores evaluate -f signals.json)
    SCORE=$(echo "$RESULT" | jq .score)
    LABEL=$(echo "$RESULT" | jq -r .label)
    ```

### Process a directory of signal files

```bash
for f in signals/*.yaml; do
  SCORE=$(ores evaluate -f "$f" | jq .score)
  LABEL=$(ores evaluate -f "$f" | jq -r .label)
  printf "%-40s  score=%s  label=%s\n" "$f" "$SCORE" "$LABEL"
done
```

---

## Error Handling

When the input is malformed or no valid signals are found, `ores evaluate` exits with code `1` and prints an error to stderr:

```
Error: evaluation failed: no valid signals: all 2 signals were invalid or unknown
```

!!! note "Partial failures are not errors"
    When a signal is recognized but contains invalid field values (e.g., `base_score: 15`), the signal is skipped with a warning. The evaluation still succeeds if at least one valid signal remains. Check `explanation.warnings` in the output for details.

```bash
# Detect warnings programmatically
ores evaluate -f signals.json \
  | jq -r '.explanation.warnings[]' \
  | while read -r w; do echo "WARNING: $w"; done
```
