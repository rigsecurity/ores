# Signals

<div class="ores-hero" style="margin-bottom: 2rem; padding: 2rem 1.5rem 1.5rem;" markdown>

**Signals are the raw inputs to ORES.** Each signal is a single, typed piece of risk information — a CVSS score, an EPSS probability, an asset classification, or a threat intel flag. The engine normalizes every signal to a common `[0, 1]` scale and feeds the results into five [scoring dimensions](scoring.md).

You can provide **as few or as many** signals as you have. Missing signals fall back to neutral defaults; the [confidence](confidence.md) value in every result tells you how much of the model was covered by real data.

</div>

---

## Signal Envelope

All signals are submitted inside an `EvaluationRequest`:

```json
{
  "apiVersion": "ores.dev/v1",
  "kind": "EvaluationRequest",
  "signals": {
    "<signal_name>": { ... },
    "<signal_name>": { ... }
  }
}
```

The `signals` map keys are signal type names (listed below). Each value is the signal-specific payload described in this catalog.

---

## At a Glance

ORES ships with **eight built-in signal types** across four scoring dimensions:

<div class="ores-signal-grid" markdown>

<div class="ores-signal-card" markdown>

#### :material-shield-bug-outline: `cvss`

CVSS base score and vector string

Feeds **Base Vulnerability**

</div>

<div class="ores-signal-card" markdown>

#### :material-alert-decagram-outline: `nist`

NIST severity classification

Feeds **Base Vulnerability**

</div>

<div class="ores-signal-card" markdown>

#### :material-chart-timeline-variant-shimmer: `epss`

EPSS exploit probability & percentile

Feeds **Exploitability**

</div>

<div class="ores-signal-card" markdown>

#### :material-skull-crossbones-outline: `threat_intel`

Active exploitation & ransomware flags

Feeds **Exploitability**

</div>

<div class="ores-signal-card" markdown>

#### :material-server-security: `asset`

Asset criticality, exposure, data class

Feeds **Environmental Context**

</div>

<div class="ores-signal-card" markdown>

#### :material-radius-outline: `blast_radius`

Affected systems & lateral movement

Feeds **Environmental Context** + **Lateral Risk**

</div>

<div class="ores-signal-card" markdown>

#### :material-wrench-clock: `patch`

Patch availability, age, controls

Feeds **Remediation Gap**

</div>

<div class="ores-signal-card" markdown>

#### :material-scale-balance: `compliance`

Compliance frameworks & regulatory impact

Feeds **Remediation Gap**

</div>

</div>

!!! tip "Don't have all 8 signals? That's perfectly fine."
    ORES is designed to work with **partial data**. Even a single `cvss` signal will produce a valid score. Each additional signal you provide improves accuracy and [confidence](confidence.md). Start with what you have and enrich over time.

---

## Signal Reference

### :material-shield-bug-outline: `cvss` {: #cvss }

The CVSS signal accepts a base score or vector string from **any CVSS version** (v2, v3.x, v4).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `base_score` | `number` | at least one of `base_score` or `vector` | CVSS base score in `[0, 10]` |
| `vector` | `string` | at least one of `base_score` or `vector` | Full CVSS vector string (e.g., `CVSS:3.1/AV:N/...`) |

When both fields are provided, `base_score` is used for scoring. The `vector` field is accepted for reference but is not parsed by the current engine version.

??? info "Normalization Formula"
    ```
    severity = base_score / 10.0
    ```

    A CVSS 9.8 normalizes to **0.98**. A CVSS 4.0 normalizes to **0.40**.

=== "YAML"

    ```yaml
    signals:
      cvss:
        base_score: 9.8
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "cvss": {
          "base_score": 9.8,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      }
    }
    ```

---

### :material-alert-decagram-outline: `nist` {: #nist }

The NIST signal provides the qualitative severity classification used in the National Vulnerability Database (NVD).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | `string` | yes | One of: `info`, `low`, `medium`, `high`, `critical` |
| `cwe` | `string` | no | CWE identifier (e.g., `CWE-79`). Accepted for reference; not used in scoring. |

??? info "Normalization Formula"
    Discrete mapping from severity label to normalized value:

    | Value | Normalized |
    |-------|-----------|
    | `info` | 0.1 |
    | `low` | 0.3 |
    | `medium` | 0.5 |
    | `high` | 0.7 |
    | `critical` | 1.0 |

=== "YAML"

    ```yaml
    signals:
      nist:
        severity: critical
        cwe: "CWE-89"
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "nist": {
          "severity": "critical",
          "cwe": "CWE-89"
        }
      }
    }
    ```

---

### :material-chart-timeline-variant-shimmer: `epss` {: #epss }

The EPSS signal provides exploit prediction data from the [Exploit Prediction Scoring System](https://www.first.org/epss/).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `probability` | `number` | at least one of `probability` or `percentile` | Probability of exploitation within 30 days. Range: `[0, 1]` |
| `percentile` | `number` | at least one of `probability` or `percentile` | Percentile rank among all scored CVEs. Range: `[0, 1]` |

??? info "Normalization Formula"
    Both fields are **already on a `[0, 1]` scale** and are used directly — no transformation needed.

=== "YAML"

    ```yaml
    signals:
      epss:
        probability: 0.91
        percentile: 0.98
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "epss": {
          "probability": 0.91,
          "percentile": 0.98
        }
      }
    }
    ```

!!! tip "Where to get EPSS data"
    You can look up EPSS data for any CVE from the [FIRST EPSS API](https://api.first.org/data/v1/epss?cve=CVE-2021-44228).

---

### :material-skull-crossbones-outline: `threat_intel` {: #threat_intel }

The `threat_intel` signal captures **confirmed threat activity** from intelligence sources such as CISA KEV, vendor advisories, or in-house threat feeds.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `actively_exploited` | `bool` | at least one of the two fields | Confirmed active exploitation in the wild |
| `ransomware_associated` | `bool` | at least one of the two fields | Associated with known ransomware campaigns |

??? info "Normalization Formula"
    Boolean fields map directly:

    - `true` &rarr; **1.0**
    - `false` &rarr; **0.0**

=== "YAML"

    ```yaml
    signals:
      threat_intel:
        actively_exploited: true
        ransomware_associated: false
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "threat_intel": {
          "actively_exploited": true,
          "ransomware_associated": false
        }
      }
    }
    ```

!!! note
    `actively_exploited: true` is equivalent to appearing on the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.

---

### :material-server-security: `asset` {: #asset }

The `asset` signal describes the characteristics of the **system exposed** to the vulnerability — its business importance, network position, and data sensitivity.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `criticality` | `string` | at least one of the three fields | Business criticality: `low`, `medium`, `high`, `crown_jewel` |
| `network_exposure` | `bool` | at least one of the three fields | Directly reachable from an untrusted network? |
| `data_classification` | `string` | at least one of the three fields | Most sensitive data: `public`, `internal`, `confidential`, `pii`, `restricted` |

??? info "Normalization Formula"
    **Criticality:**

    | Value | Normalized |
    |-------|-----------|
    | `low` | 0.2 |
    | `medium` | 0.5 |
    | `high` | 0.7 |
    | `crown_jewel` | 1.0 |

    **Data Classification:**

    | Value | Normalized |
    |-------|-----------|
    | `public` | 0.1 |
    | `internal` | 0.3 |
    | `confidential` | 0.6 |
    | `pii` | 0.8 |
    | `restricted` | 1.0 |

    **Network Exposure:**

    - `true` &rarr; **1.0**
    - `false` &rarr; **0.0**

=== "YAML"

    ```yaml
    signals:
      asset:
        criticality: crown_jewel
        network_exposure: true
        data_classification: pii
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "asset": {
          "criticality": "crown_jewel",
          "network_exposure": true,
          "data_classification": "pii"
        }
      }
    }
    ```

---

### :material-radius-outline: `blast_radius` {: #blast_radius }

The `blast_radius` signal estimates the potential **scope of a successful exploit** — how many systems could be affected and whether lateral movement is possible.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `affected_systems` | `number` | at least one of the two fields | Number of systems potentially impacted. Must be `>= 0`. |
| `lateral_movement_possible` | `bool` | at least one of the two fields | Could a successful exploit enable lateral movement? |

??? info "Normalization Formula"
    **Blast scope** uses a ==log~10~ scale== capped at 1.0:

    ```
    blast_scope = min(log10(affected_systems) / log10(1000), 1.0)
    ```

    | Affected Systems | Normalized |
    |-----------------|-----------|
    | 1 | ~0.00 |
    | 10 | 0.33 |
    | 100 | 0.67 |
    | 1,000+ | 1.00 |

    **Lateral Movement:**

    - `true` &rarr; **1.0**
    - `false` &rarr; **0.0**

=== "YAML"

    ```yaml
    signals:
      blast_radius:
        affected_systems: 250
        lateral_movement_possible: true
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "blast_radius": {
          "affected_systems": 250,
          "lateral_movement_possible": true
        }
      }
    }
    ```

---

### :material-wrench-clock: `patch` {: #patch }

The `patch` signal describes the **remediation posture** — whether a fix exists, how long it has been available, and whether compensating controls are in place.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `patch_available` | `bool` | at least one of the three fields | Vendor-supplied patch available? |
| `patch_age_days` | `number` | at least one of the three fields | Days since the patch was released. Must be `>= 0`. |
| `compensating_control` | `bool` | at least one of the three fields | Compensating control in place (WAF rule, segmentation, etc.)? |

??? info "Normalization Formula"
    - **`remediation_available`**: `true` &rarr; 1.0, `false` &rarr; 0.0
    - **`patch_staleness`**: Only computed when `patch_available` is `true`:

        ```
        patch_staleness = min(patch_age_days / 90.0, 1.0)
        ```

        A patch available for **90+ days** without deployment is considered ==fully stale== (1.0).

    - **`has_compensating_control`**: `true` &rarr; 1.0, `false` &rarr; 0.0

=== "YAML"

    ```yaml
    signals:
      patch:
        patch_available: true
        patch_age_days: 60
        compensating_control: false
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "patch": {
          "patch_available": true,
          "patch_age_days": 60,
          "compensating_control": false
        }
      }
    }
    ```

!!! warning "Patch staleness matters"
    A vulnerability with a patch that has been sitting undeployed for 90 days is treated as a **maximum remediation gap** — often a bigger risk indicator than vulnerabilities with no patch at all, because it reflects organizational inaction.

---

### :material-scale-balance: `compliance` {: #compliance }

The `compliance` signal describes the **regulatory and compliance context** for the affected system.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `frameworks_affected` | `[]string` | at least one of the two fields | List of compliance frameworks (e.g., `["PCI-DSS", "SOC2", "HIPAA"]`) |
| `regulatory_impact` | `string` | at least one of the two fields | Regulatory impact severity: `low`, `medium`, `high`, `critical` |

??? info "Normalization Formula"
    **Compliance scope:**

    ```
    compliance_scope = min(len(frameworks_affected) / 5.0, 1.0)
    ```

    Five or more frameworks yields a scope of **1.0**.

    **Regulatory impact:**

    | Value | Normalized |
    |-------|-----------|
    | `low` | 0.2 |
    | `medium` | 0.5 |
    | `high` | 0.7 |
    | `critical` | 1.0 |

=== "YAML"

    ```yaml
    signals:
      compliance:
        frameworks_affected:
          - PCI-DSS
          - SOC2
          - HIPAA
        regulatory_impact: high
    ```

=== "JSON"

    ```json
    {
      "signals": {
        "compliance": {
          "frameworks_affected": ["PCI-DSS", "SOC2", "HIPAA"],
          "regulatory_impact": "high"
        }
      }
    }
    ```

---

## Complete Example

Here is a full `EvaluationRequest` with all eight signals populated:

```yaml
apiVersion: ores.dev/v1
kind: EvaluationRequest
signals:
  cvss:
    base_score: 9.8
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  nist:
    severity: critical
    cwe: "CWE-89"
  epss:
    probability: 0.91
    percentile: 0.98
  threat_intel:
    actively_exploited: true
    ransomware_associated: true
  asset:
    criticality: crown_jewel
    network_exposure: true
    data_classification: restricted
  blast_radius:
    affected_systems: 500
    lateral_movement_possible: true
  patch:
    patch_available: true
    patch_age_days: 45
    compensating_control: false
  compliance:
    frameworks_affected:
      - PCI-DSS
      - SOC2
      - HIPAA
    regulatory_impact: critical
```

This request would produce **confidence: 1.0** (all dimensions fully covered) and a score in the upper **critical** range.

---

## Listing Signals at Runtime

You can inspect the full signal catalog at any time using the CLI:

```bash
ores signals
```

```
NAME          DESCRIPTION                                                               FIELDS
----          -----------                                                               ------
asset         Asset criticality, network exposure, and data classification context      criticality, network_exposure, data_classification
blast_radius  Blast radius: number of affected systems and lateral movement potential    affected_systems, lateral_movement_possible
compliance    Compliance frameworks affected and regulatory impact severity              frameworks_affected, regulatory_impact
cvss          Common Vulnerability Scoring System score and vector string                base_score, vector
epss          Exploit Prediction Scoring System probability and percentile               probability, percentile
nist          NIST severity classification and optional CWE identifier                   severity, cwe
patch         Patch availability, age, and compensating control status                   patch_available, patch_age_days, compensating_control
threat_intel  Threat intelligence: active exploitation and ransomware association        actively_exploited, ransomware_associated
```
