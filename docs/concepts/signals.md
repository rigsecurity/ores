# Signals

A **signal** is a single, typed piece of risk information provided to the ORES engine. Signals are the raw inputs to the scoring pipeline. The engine normalizes each signal to a common `[0, 1]` scale and feeds the results into the scoring model.

You can provide as few or as many signals as you have available. Missing signals fall back to neutral defaults; the `confidence` field in every result tells you how much of the model was covered by actual data. See [Confidence](confidence.md) for details.

---

## Signal Envelope

All signals are submitted inside an `EvaluationRequest` envelope:

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

## Signal Catalog

ORES ships with eight built-in signal types:

| Name | Description | Scoring Dimension |
|------|-------------|-------------------|
| `cvss` | CVSS base score and vector string | `base_vulnerability` |
| `nist` | NIST severity classification | `base_vulnerability` |
| `epss` | EPSS exploit probability and percentile | `exploitability` |
| `threat_intel` | Active exploitation and ransomware association | `exploitability` |
| `asset` | Asset criticality, network exposure, data classification | `environmental_context` |
| `blast_radius` | Affected systems count and lateral movement potential | `environmental_context`, `lateral_risk` |
| `patch` | Patch availability, age, and compensating controls | `remediation_gap` |
| `compliance` | Compliance frameworks affected and regulatory impact | `remediation_gap` |

---

## `cvss`

The CVSS signal accepts a CVSS base score or vector string from any version (CVSSv2, CVSSv3.x, CVSSv4).

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `base_score` | `number` | at least one of `base_score` or `vector` | CVSS base score in `[0, 10]` |
| `vector` | `string` | at least one of `base_score` or `vector` | Full CVSS vector string (e.g., `CVSS:3.1/AV:N/...`) |

When both fields are provided, `base_score` is used for scoring. The `vector` field is accepted for reference but is not parsed by the current engine version.

**Normalization:** `severity = base_score / 10.0`

**Example:**

```yaml
signals:
  cvss:
    base_score: 9.8
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

---

## `nist`

The NIST signal provides the qualitative severity classification used in the NVD.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | `string` | yes | One of: `info`, `low`, `medium`, `high`, `critical` |
| `cwe` | `string` | no | CWE identifier (e.g., `CWE-79`). Accepted for reference; not used in scoring. |

**Normalization:**

| Value | Normalized |
|-------|-----------|
| `info` | 0.1 |
| `low` | 0.3 |
| `medium` | 0.5 |
| `high` | 0.7 |
| `critical` | 1.0 |

**Example:**

```yaml
signals:
  nist:
    severity: critical
    cwe: "CWE-89"
```

---

## `epss`

The EPSS signal provides exploit prediction data from the [Exploit Prediction Scoring System](https://www.first.org/epss/).

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `probability` | `number` | at least one of `probability` or `percentile` | Probability that the vulnerability will be exploited within 30 days. Range: `[0, 1]` |
| `percentile` | `number` | at least one of `probability` or `percentile` | Percentile rank among all scored CVEs. Range: `[0, 1]` |

Both fields are already on a `[0, 1]` scale and are used directly.

**Example:**

```yaml
signals:
  epss:
    probability: 0.91
    percentile: 0.98
```

!!! tip
    You can obtain EPSS data for any CVE from the [FIRST EPSS API](https://api.first.org/data/v1/epss?cve=CVE-2021-44228).

---

## `threat_intel`

The `threat_intel` signal captures confirmed threat activity from intelligence sources such as CISA KEV, vendor advisories, or in-house threat feeds.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `actively_exploited` | `bool` | at least one of the two fields | Whether this vulnerability is confirmed as actively exploited in the wild |
| `ransomware_associated` | `bool` | at least one of the two fields | Whether this vulnerability is associated with known ransomware campaigns |

**Normalization:** Boolean fields map to `1.0` (true) or `0.0` (false).

**Example:**

```yaml
signals:
  threat_intel:
    actively_exploited: true
    ransomware_associated: false
```

!!! note
    `actively_exploited: true` is equivalent to appearing on the CISA Known Exploited Vulnerabilities (KEV) catalog.

---

## `asset`

The `asset` signal describes the characteristics of the system that is exposed to the vulnerability.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `criticality` | `string` | at least one of the three fields | Business criticality of the asset. One of: `low`, `medium`, `high`, `crown_jewel` |
| `network_exposure` | `bool` | at least one of the three fields | Whether the asset is directly reachable from an untrusted network |
| `data_classification` | `string` | at least one of the three fields | Most sensitive data classification stored or processed. One of: `public`, `internal`, `confidential`, `pii`, `restricted` |

**Normalization:**

Criticality values:

| Value | Normalized |
|-------|-----------|
| `low` | 0.2 |
| `medium` | 0.5 |
| `high` | 0.7 |
| `crown_jewel` | 1.0 |

Data classification values:

| Value | Normalized |
|-------|-----------|
| `public` | 0.1 |
| `internal` | 0.3 |
| `confidential` | 0.6 |
| `pii` | 0.8 |
| `restricted` | 1.0 |

Network exposure: `true` → `1.0`, `false` → `0.0`

**Example:**

```yaml
signals:
  asset:
    criticality: crown_jewel
    network_exposure: true
    data_classification: pii
```

---

## `blast_radius`

The `blast_radius` signal estimates the potential scope of a successful exploit — how many systems could be affected and whether lateral movement is possible.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `affected_systems` | `number` | at least one of the two fields | Number of systems potentially impacted. Must be `>= 0`. |
| `lateral_movement_possible` | `bool` | at least one of the two fields | Whether a successful exploit could enable lateral movement to adjacent systems |

**Normalization:**

- `blast_scope` uses a log₁₀ scale capped at 1.0: `log10(affected_systems) / log10(1000)`. This means 1 system → ~0.0, 10 systems → 0.33, 100 systems → 0.67, 1000+ systems → 1.0.
- `lateral_movement`: `true` → `1.0`, `false` → `0.0`

**Example:**

```yaml
signals:
  blast_radius:
    affected_systems: 250
    lateral_movement_possible: true
```

---

## `patch`

The `patch` signal describes the remediation posture for the vulnerability — whether a fix exists, how long it has been available, and whether any compensating controls are in place.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `patch_available` | `bool` | at least one of the three fields | Whether a vendor-supplied patch is available |
| `patch_age_days` | `number` | at least one of the three fields | Number of days since the patch was released. Must be `>= 0`. |
| `compensating_control` | `bool` | at least one of the three fields | Whether a compensating control (e.g., WAF rule, network segmentation) is in place |

**Normalization:**

- `remediation_available`: `true` → `1.0`, `false` → `0.0`
- `patch_staleness`: Only computed when `patch_available` is `true`. `min(patch_age_days / 90.0, 1.0)`. A patch that has been available for 90+ days is fully stale.
- `has_compensating_control`: `true` → `1.0`, `false` → `0.0`

**Example:**

```yaml
signals:
  patch:
    patch_available: true
    patch_age_days: 60
    compensating_control: false
```

---

## `compliance`

The `compliance` signal describes the regulatory and compliance context for the affected system.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `frameworks_affected` | `[]string` | at least one of the two fields | List of compliance frameworks that apply to this system (e.g., `["PCI-DSS", "SOC2", "HIPAA"]`) |
| `regulatory_impact` | `string` | at least one of the two fields | Severity of the regulatory impact. One of: `low`, `medium`, `high`, `critical` |

**Normalization:**

- `compliance_scope = min(len(frameworks_affected) / 5.0, 1.0)`. Five or more frameworks yields a scope of 1.0.
- Regulatory impact values:

| Value | Normalized |
|-------|-----------|
| `low` | 0.2 |
| `medium` | 0.5 |
| `high` | 0.7 |
| `critical` | 1.0 |

**Example:**

```yaml
signals:
  compliance:
    frameworks_affected:
      - PCI-DSS
      - SOC2
      - HIPAA
    regulatory_impact: high
```

---

## Listing Signals at Runtime

You can see the signal catalog at any time using the CLI or API:

```bash
ores signals
```

```
NAME          DESCRIPTION                                               FIELDS
----          -----------                                               ------
asset         Asset criticality, network exposure, and data classification context  criticality, network_exposure, data_classification
blast_radius  Blast radius: number of affected systems and lateral movement potential  affected_systems, lateral_movement_possible
compliance    Compliance frameworks affected and regulatory impact severity  frameworks_affected, regulatory_impact
cvss          Common Vulnerability Scoring System score and vector string  base_score, vector
epss          Exploit Prediction Scoring System probability and percentile  probability, percentile
nist          NIST severity classification and optional CWE identifier  severity, cwe
patch         Patch availability, age, and compensating control status  patch_available, patch_age_days, compensating_control
threat_intel  Threat intelligence: active exploitation and ransomware association  actively_exploited, ransomware_associated
```
