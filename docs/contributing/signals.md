# Proposing a New Signal Type

Signal types are the primary extension point in ORES. If your organization uses a risk data source that is not covered by the built-in signals, you can add a new signal type by implementing the `Signal` interface and registering it with the engine.

This page walks through the full process: proposing, implementing, testing, and submitting a new signal type.

---

## When to Propose a New Signal

Before implementing a new signal type, ask:

1. **Is this data source distinct?** If the data could be represented by combining existing signals, use them instead.
2. **Is it generalizable?** Signal types should be useful to multiple organizations. Highly organization-specific data (e.g., internal ticket IDs) is better handled in a custom engine build.
3. **Can you normalize it to `[0, 1]`?** Every signal must produce normalized factor values in the `[0, 1]` range. If your data cannot be meaningfully normalized, it may not fit the model.

If you're unsure, [open a signal request issue](https://github.com/rigsecurity/ores/issues/new?template=signal_request.yml) before investing time in implementation.

---

## The Signal Interface

Every signal type must implement the `signals.Signal` interface:

```go
// Signal defines the interface for a recognized signal type.
type Signal interface {
    // Name returns the signal type identifier (e.g., "cvss", "epss").
    // Must be lowercase, underscore-separated, unique across all registered signals.
    Name() string

    // Description returns a single-sentence human-readable description.
    Description() string

    // Fields returns the list of accepted input field names.
    // Used for documentation and the `ores signals` / ListSignals output.
    Fields() []string

    // Validate checks that raw is a valid input for this signal.
    // Returns a descriptive error if invalid, nil if valid.
    // Must not modify raw.
    Validate(raw any) error

    // Normalize converts raw to a NormalizedSignal (map[string]float64).
    // All factor values must be in [0.0, 1.0].
    // Must call Validate internally and return its error if validation fails.
    Normalize(raw any) (NormalizedSignal, error)
}
```

---

## Implementation Guide

### Step 1: Choose a signal name and factor names

Signal names use lowercase snake_case (e.g., `vendor_severity`, `sla_breach`, `exploit_db`).

Factor names are the keys in the `NormalizedSignal` map. They must:
- Use lowercase snake_case
- Be descriptive of what the factor represents, not where it came from
- Not collide with existing factor names (check `pkg/signals/parsers/` and `pkg/model/model.go`)

Existing factor names: `severity`, `nist_severity`, `exploit_probability`, `exploit_percentile`, `active_exploitation`, `ransomware_risk`, `asset_criticality`, `network_exposure`, `data_sensitivity`, `blast_scope`, `lateral_movement`, `remediation_available`, `patch_staleness`, `has_compensating_control`, `regulatory_severity`, `compliance_scope`.

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

// Name returns the signal type identifier.
func (m *MySignal) Name() string { return "my_signal" }

// Description returns a human-readable description of this signal.
func (m *MySignal) Description() string {
    return "Short description of what this signal provides"
}

// Fields returns the list of recognized input field names.
func (m *MySignal) Fields() []string {
    return []string{"field_one", "field_two"}
}

// Validate checks that raw is a map containing valid field values.
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

// Normalize converts raw MySignal input to normalized factor values.
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

The helper functions `toFloat64`, `toBool`, `toString`, and `toStringSlice` are defined in `pkg/signals/parsers/helpers.go` and are available to all parsers in the package.

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
    r.Register(&MySignal{}) // add this line
}
```

### Step 4: Update the scoring model (if needed)

If your signal introduces new factor keys, they need to be wired into the scoring model in `pkg/model/model.go` (dimension scoring functions) and `pkg/model/coverage.go` (confidence calculation).

If your signal contributes to an existing dimension, add its factor keys to the appropriate `dimDefinition.score` function. If it represents a genuinely new dimension of risk, discuss this in your issue before implementing - new dimensions require a model version bump.

---

## Normalization Rules

All factor values produced by `Normalize` must satisfy:

1. **Range `[0, 1]`**: Values below 0 or above 1 will be clamped by the model, but your normalizer should not produce out-of-range values.
2. **Monotonic direction**: Higher values must represent higher risk. Never invert a scale inside a normalizer.
3. **Meaningful scale**: Avoid binary 0/1 for continuous inputs. Use a logarithmic or linear mapping that reflects the actual risk gradient.
4. **No floating point surprises**: Avoid division by zero. Test edge cases (0, maximum value, boundary values).

**Good normalization examples:**

- CVSS base score (0–10): `score / 10.0` - linear, simple, meaningful
- EPSS probability (0–1): pass-through - already normalized
- System count (0–∞): `log10(max(systems, 1)) / log10(1000)` - logarithmic cap at 1000 systems
- Patch age in days (0–∞): `min(days / 90.0, 1.0)` - linear, capped at 90 days fully stale

---

## Testing Requirements

Every signal parser must have a test file `pkg/signals/parsers/<name>_test.go` using table-driven tests.

Required test coverage:

1. **`Validate` - valid inputs**: At least one test per valid input combination
2. **`Validate` - invalid inputs**: At least one test per error path (wrong type, out of range, missing required fields)
3. **`Normalize` - correct factor values**: Verify the output map contains the expected keys and values
4. **`Normalize` - edge cases**: Zero values, maximum values, single-field inputs
5. **`Name`, `Description`, `Fields`**: Verify these return non-empty values

Example test structure:

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

Run tests before submitting:

```bash
task test
task lint
```

---

## Pull Request Checklist

Before opening a PR for a new signal type:

- [ ] `pkg/signals/parsers/<name>.go` implements all five `Signal` methods
- [ ] `pkg/signals/parsers/<name>_test.go` provides table-driven tests with 100% line coverage
- [ ] Signal is registered in `pkg/signals/parsers/register.go`
- [ ] Factor keys are either reusing existing names or added to `pkg/model/model.go` and `pkg/model/coverage.go`
- [ ] `task test` passes with no race conditions
- [ ] `task lint` passes with no new findings
- [ ] Signal is documented with name, description, fields, normalization rules, and an example YAML in `docs/concepts/signals.md`
- [ ] PR description explains: what data source this signal represents, why it belongs in the model, and what dimension(s) it covers
