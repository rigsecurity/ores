# :material-puzzle-plus-outline: Proposing a New Signal Type

Signal types are the primary extension point in ORES. If your organization uses a risk data source not covered by the built-in signals, you can add a new signal type by implementing the `Signal` interface and registering it with the engine.

This page walks through the full process: proposing, implementing, testing, and submitting a new signal type.

---

## :material-checkbox-marked-circle-outline: When to Propose a New Signal

Before investing time in implementation, verify that your signal is a good fit.

!!! question "Ask yourself these three questions"

    - [x] **Is this data source distinct?** If the data could be represented by combining existing signals, use them instead.
    - [x] **Is it generalizable?** Signal types should be useful to multiple organizations. Highly organization-specific data (e.g., internal ticket IDs) is better handled in a custom engine build.
    - [x] **Can you normalize it to `[0, 1]`?** Every signal must produce normalized factor values in the `[0, 1]` range. If your data cannot be meaningfully normalized, it may not fit the model.

If you answered **no** to any of these, reconsider whether a new signal type is the right approach.

!!! tip "Not sure? Open an issue first"
    [Open a signal request issue](https://github.com/rigsecurity/ores/issues/new?template=signal_request.yml) to get feedback before you start coding.

---

## :material-code-braces: The Signal Interface

Every signal type must implement the `signals.Signal` interface defined in `pkg/signals/signal.go`:

```go
// Signal defines the interface for a recognized signal type.
type Signal interface {
    // Name returns the signal type identifier (e.g., "cvss", "epss").
    // Must be lowercase, underscore-separated, unique across all registered signals.
    Name() string // (1)!

    // Description returns a single-sentence human-readable description.
    Description() string // (2)!

    // Fields returns the list of accepted input field names.
    // Used for documentation and the `ores signals` / ListSignals output.
    Fields() []string // (3)!

    // Validate checks that raw is a valid input for this signal.
    // Returns a descriptive error if invalid, nil if valid.
    // Must not modify raw.
    Validate(raw any) error // (4)!

    // Normalize converts raw to a NormalizedSignal (map[string]float64).
    // All factor values must be in [0.0, 1.0].
    // Must call Validate internally and return its error if validation fails.
    Normalize(raw any) (NormalizedSignal, error) // (5)!
}
```

1. Lowercase `snake_case`. Must be unique across all registered signals.
2. One sentence. Shows up in `ores signals` and `ListSignals` output.
3. Documents the accepted JSON keys for this signal.
4. Pure validation — must not mutate `raw`.
5. Always calls `Validate` first. Returns normalized factors in `[0.0, 1.0]`.

---

## :material-list-status: Implementation Guide

### Step 1: Choose signal and factor names

!!! abstract "Naming conventions"

    **Signal names** use lowercase `snake_case`:

    :material-check: `vendor_severity`, `sla_breach`, `exploit_db`

    :material-close: `VendorSeverity`, `SLA-Breach`, `exploitDB`

    **Factor names** (keys in the `NormalizedSignal` map) must:

    - Use lowercase `snake_case`
    - Describe **what the factor represents**, not where it came from
    - Not collide with existing factor names

??? note "Existing factor names (for collision checking)"
    `severity`, `nist_severity`, `exploit_probability`, `exploit_percentile`, `active_exploitation`, `ransomware_risk`, `asset_criticality`, `network_exposure`, `data_sensitivity`, `blast_scope`, `lateral_movement`, `remediation_available`, `patch_staleness`, `has_compensating_control`, `regulatory_severity`, `compliance_scope`

    Check `pkg/signals/parsers/` and `pkg/model/model.go` for the latest list.

---

### Step 2: Create the parser file

Create `pkg/signals/parsers/<name>.go`. Here is an annotated template:

```go
package parsers

import (
    "errors"
    "fmt"

    "github.com/rigsecurity/ores/pkg/signals"
)

// MySignal parses <description of what this signal represents>.
type MySignal struct{}

func (m *MySignal) Name() string { return "my_signal" }

func (m *MySignal) Description() string {
    return "Short description of what this signal provides"
}

func (m *MySignal) Fields() []string {
    return []string{"field_one", "field_two"}
}

func (m *MySignal) Validate(raw any) error {
    mRaw, ok := raw.(map[string]any)
    if !ok {
        return errors.New("my_signal: input must be a map")
    }

    hasAny := false

    if val, ok := mRaw["field_one"]; ok {
        hasAny = true
        f, ok := toFloat64(val)
        if !ok {
            return fmt.Errorf("my_signal: field_one must be a number, got %T", val)
        }
        if f < 0 || f > 1 {
            return fmt.Errorf("my_signal: field_one must be in [0, 1], got %v", f)
        }
    }

    if val, ok := mRaw["field_two"]; ok {
        hasAny = true
        if _, ok := toBool(val); !ok {
            return fmt.Errorf("my_signal: field_two must be a bool, got %T", val)
        }
    }

    if !hasAny {
        return errors.New("my_signal: at least one of field_one or field_two is required")
    }

    return nil
}

func (m *MySignal) Normalize(raw any) (signals.NormalizedSignal, error) {
    if err := m.Validate(raw); err != nil {
        return nil, err
    }

    mRaw := raw.(map[string]any)
    ns := make(signals.NormalizedSignal)

    if val, ok := mRaw["field_one"]; ok {
        f, _ := toFloat64(val)
        ns["my_factor_name"] = f // already in [0, 1]
    }

    if val, ok := mRaw["field_two"]; ok {
        b, _ := toBool(val)
        if b {
            ns["my_other_factor"] = 1.0
        } else {
            ns["my_other_factor"] = 0.0
        }
    }

    return ns, nil
}
```

!!! info "Helper functions"
    The helpers `toFloat64`, `toBool`, `toString`, and `toStringSlice` are defined in `pkg/signals/parsers/helpers.go` and available to all parsers in the package.

---

### Step 3: Register the signal

Add your signal to `pkg/signals/parsers/register.go`:

```go
func RegisterAll(r *signals.Registry) {
    r.Register(&CVSS{})
    r.Register(&EPSS{})
    r.Register(&NIST{})
    r.Register(&Asset{})
    r.Register(&ThreatIntel{})
    r.Register(&BlastRadius{})
    r.Register(&Patch{})
    r.Register(&Compliance{})
    r.Register(&MySignal{}) // <-- add this line
}
```

---

### Step 4: Update the scoring model (if needed)

If your signal introduces **new factor keys**, they need to be wired into the scoring model:

| File | What to update |
|:-----|:---------------|
| `pkg/model/model.go` | Dimension scoring functions |
| `pkg/model/coverage.go` | Confidence calculation |

!!! warning "New dimensions require discussion"
    If your signal represents a genuinely **new dimension of risk** (rather than contributing to an existing one), discuss this in your issue before implementing. New dimensions require a model version bump and review from maintainers.

---

## :material-scale-balance: Normalization Rules

All factor values produced by `Normalize` must satisfy:

1. **Range `[0, 1]`** — Values below 0 or above 1 will be clamped by the model, but your normalizer should not produce out-of-range values.
2. **Monotonic direction** — Higher values must represent higher risk. Never invert a scale inside a normalizer.
3. **Meaningful scale** — Avoid binary 0/1 for continuous inputs. Use a logarithmic or linear mapping that reflects the actual risk gradient.
4. **No floating point surprises** — Avoid division by zero. Test edge cases (0, maximum value, boundary values).

??? example "Good normalization examples"

    | Input | Range | Normalization | Rationale |
    |:------|:------|:--------------|:----------|
    | CVSS base score | 0 - 10 | `score / 10.0` | Linear, simple, meaningful |
    | EPSS probability | 0 - 1 | Pass-through | Already normalized |
    | System count | 0 - inf | `log10(max(systems, 1)) / log10(1000)` | Logarithmic cap at 1000 systems |
    | Patch age (days) | 0 - inf | `min(days / 90.0, 1.0)` | Linear, capped at 90 days fully stale |

---

## :material-test-tube: Testing Requirements

Every signal parser must have a test file `pkg/signals/parsers/<name>_test.go` using table-driven tests.

### Required coverage

- [x] **`Validate` — valid inputs**: At least one test per valid input combination
- [x] **`Validate` — invalid inputs**: At least one test per error path (wrong type, out of range, missing required fields)
- [x] **`Normalize` — correct factor values**: Verify the output map contains expected keys and values
- [x] **`Normalize` — edge cases**: Zero values, maximum values, single-field inputs
- [x] **`Name`, `Description`, `Fields`**: Verify these return non-empty values

### Example test structure

```go
package parsers_test

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/rigsecurity/ores/pkg/signals/parsers"
)

func TestMySignal_Validate(t *testing.T) {
    t.Parallel()

    s := &parsers.MySignal{}

    tests := []struct {
        name    string
        input   any
        wantErr bool
    }{
        {
            name:    "valid field_one",
            input:   map[string]any{"field_one": 0.5},
            wantErr: false,
        },
        {
            name:    "invalid: not a map",
            input:   "string",
            wantErr: true,
        },
        {
            name:    "invalid: field_one out of range",
            input:   map[string]any{"field_one": 1.5},
            wantErr: true,
        },
        {
            name:    "invalid: no fields",
            input:   map[string]any{},
            wantErr: true,
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            err := s.Validate(tc.input)
            if tc.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

func TestMySignal_Normalize(t *testing.T) {
    t.Parallel()

    s := &parsers.MySignal{}

    t.Run("field_one produces correct factor", func(t *testing.T) {
        t.Parallel()
        ns, err := s.Normalize(map[string]any{"field_one": 0.6})
        require.NoError(t, err)
        assert.InDelta(t, 0.6, ns["my_factor_name"], 0.001)
    })
}
```

Run before submitting:

```bash
task test && task lint
```

---

## :material-clipboard-check: Pull Request Checklist

Before opening a PR for a new signal type, verify every item:

- [ ] `pkg/signals/parsers/<name>.go` implements all five `Signal` methods
- [ ] `pkg/signals/parsers/<name>_test.go` provides table-driven tests with 100% line coverage
- [ ] Signal is registered in `pkg/signals/parsers/register.go`
- [ ] Factor keys either reuse existing names or are added to `pkg/model/model.go` and `pkg/model/coverage.go`
- [ ] `task test` passes with no race conditions
- [ ] `task lint` passes with no new findings
- [ ] Signal is documented with name, description, fields, normalization rules, and an example YAML in `docs/concepts/signals.md`
- [ ] PR description explains: what data source this signal represents, why it belongs in the model, and what dimension(s) it covers
