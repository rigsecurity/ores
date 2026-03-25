package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// complianceImpactScores maps regulatory impact labels to normalized values.
var complianceImpactScores = map[string]float64{
	"low":      0.2,
	"medium":   0.5,
	"high":     0.7,
	"critical": 1.0,
}

// Compliance parses compliance and regulatory impact signals.
type Compliance struct{}

// Name returns the signal type identifier.
func (c *Compliance) Name() string { return "compliance" }

// Description returns a human-readable description of this signal.
func (c *Compliance) Description() string {
	return "Compliance frameworks affected and regulatory impact severity"
}

// Fields returns the list of recognized input field names.
func (c *Compliance) Fields() []string {
	return []string{"frameworks_affected", "regulatory_impact"}
}

// Validate checks that raw is a map with at least one valid field present.
func (c *Compliance) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("compliance: input must be a map")
	}

	hasAny := false

	if fwVal, ok := m["frameworks_affected"]; ok {
		hasAny = true

		if _, ok := toStringSlice(fwVal); !ok {
			return fmt.Errorf("compliance: frameworks_affected must be a []string, got %T", fwVal)
		}
	}

	if riVal, ok := m["regulatory_impact"]; ok {
		hasAny = true

		ri, ok := toString(riVal)
		if !ok {
			return fmt.Errorf("compliance: regulatory_impact must be a string, got %T", riVal)
		}

		if _, valid := complianceImpactScores[ri]; !valid {
			return fmt.Errorf("compliance: regulatory_impact %q is not valid; must be one of low, medium, high, critical", ri)
		}
	}

	if !hasAny {
		return errors.New("compliance: at least one of frameworks_affected or regulatory_impact is required")
	}

	return nil
}

// Normalize converts raw Compliance input to normalized factor values.
// compliance_scope = min(len(frameworks) / 5.0, 1.0).
func (c *Compliance) Normalize(raw any) (signals.NormalizedSignal, error) {
	if err := c.Validate(raw); err != nil {
		return nil, err
	}

	m := raw.(map[string]any)
	ns := make(signals.NormalizedSignal)

	if fwVal, ok := m["frameworks_affected"]; ok {
		frameworks, _ := toStringSlice(fwVal)
		scope := float64(len(frameworks)) / 5.0

		if scope > 1.0 {
			scope = 1.0
		}

		ns["compliance_scope"] = scope
	}

	if riVal, ok := m["regulatory_impact"]; ok {
		ri, _ := toString(riVal)
		ns["regulatory_severity"] = complianceImpactScores[ri]
	}

	return ns, nil
}
