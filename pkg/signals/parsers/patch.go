package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// Patch parses patch availability and remediation signals.
type Patch struct{}

// Name returns the signal type identifier.
func (p *Patch) Name() string { return "patch" }

// Description returns a human-readable description of this signal.
func (p *Patch) Description() string {
	return "Patch availability, age, and compensating control status"
}

// Fields returns the list of recognized input field names.
func (p *Patch) Fields() []string {
	return []string{"patch_available", "patch_age_days", "compensating_control"}
}

// Validate checks that raw is a map with at least one valid field, and that
// patch_age_days, if present, is non-negative.
func (p *Patch) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("patch: input must be a map")
	}

	hasAny := false

	if paVal, ok := m["patch_available"]; ok {
		hasAny = true

		if _, ok := toBool(paVal); !ok {
			return fmt.Errorf("patch: patch_available must be a bool, got %T", paVal)
		}
	}

	if padVal, ok := m["patch_age_days"]; ok {
		hasAny = true

		days, ok := toFloat64(padVal)
		if !ok {
			return fmt.Errorf("patch: patch_age_days must be a number, got %T", padVal)
		}

		if days < 0 {
			return fmt.Errorf("patch: patch_age_days must be >= 0, got %v", days)
		}
	}

	if ccVal, ok := m["compensating_control"]; ok {
		hasAny = true

		if _, ok := toBool(ccVal); !ok {
			return fmt.Errorf("patch: compensating_control must be a bool, got %T", ccVal)
		}
	}

	if !hasAny {
		return errors.New("patch: at least one of patch_available, patch_age_days, or compensating_control is required")
	}

	return nil
}

// Normalize converts raw Patch input to normalized factor values.
// patch_staleness is only emitted when patch_available is true.
func (p *Patch) Normalize(raw any) (signals.NormalizedSignal, error) {
	if err := p.Validate(raw); err != nil {
		return nil, err
	}

	m := raw.(map[string]any)
	ns := make(signals.NormalizedSignal)

	patchAvailable := false

	if paVal, ok := m["patch_available"]; ok {
		available, _ := toBool(paVal)
		patchAvailable = available

		if available {
			ns["remediation_available"] = 1.0
		} else {
			ns["remediation_available"] = 0.0
		}
	}

	if padVal, ok := m["patch_age_days"]; ok {
		days, _ := toFloat64(padVal)

		var staleness float64

		if patchAvailable {
			staleness = days / 90.0
			if staleness > 1.0 {
				staleness = 1.0
			}
		}

		ns["patch_staleness"] = staleness
	}

	if ccVal, ok := m["compensating_control"]; ok {
		cc, _ := toBool(ccVal)

		if cc {
			ns["has_compensating_control"] = 1.0
		} else {
			ns["has_compensating_control"] = 0.0
		}
	}

	return ns, nil
}
