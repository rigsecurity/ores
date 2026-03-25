package parsers

import (
	"errors"
	"fmt"
	"math"

	"github.com/rigsecurity/ores/pkg/signals"
)

// BlastRadius parses blast radius signals describing attack scope potential.
type BlastRadius struct{}

// Name returns the signal type identifier.
func (b *BlastRadius) Name() string { return "blast_radius" }

// Description returns a human-readable description of this signal.
func (b *BlastRadius) Description() string {
	return "Blast radius: number of affected systems and lateral movement potential"
}

// Fields returns the list of recognized input field names.
func (b *BlastRadius) Fields() []string {
	return []string{"affected_systems", "lateral_movement_possible"}
}

// Validate checks that raw is a map with at least one valid field, and that
// affected_systems, if present, is a non-negative integer.
func (b *BlastRadius) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("blast_radius: input must be a map")
	}

	hasAny := false

	if sysVal, ok := m["affected_systems"]; ok {
		hasAny = true

		sys, ok := toFloat64(sysVal)
		if !ok {
			return fmt.Errorf("blast_radius: affected_systems must be a number, got %T", sysVal)
		}

		if sys < 0 {
			return fmt.Errorf("blast_radius: affected_systems must be >= 0, got %v", sys)
		}
	}

	if latVal, ok := m["lateral_movement_possible"]; ok {
		hasAny = true

		if _, ok := toBool(latVal); !ok {
			return fmt.Errorf("blast_radius: lateral_movement_possible must be a bool, got %T", latVal)
		}
	}

	if !hasAny {
		return errors.New("blast_radius: at least one of affected_systems or lateral_movement_possible is required")
	}

	return nil
}

// Normalize converts raw BlastRadius input to normalized factor values.
// blast_scope uses a log10 scale capped at 1.0 (1000 systems = 1.0).
func (b *BlastRadius) Normalize(raw any) (signals.NormalizedSignal, error) {
	if err := b.Validate(raw); err != nil {
		return nil, err
	}

	m := raw.(map[string]any)
	ns := make(signals.NormalizedSignal)

	if sysVal, ok := m["affected_systems"]; ok {
		sys, _ := toFloat64(sysVal)

		var scope float64

		if sys >= 2 {
			scope = math.Log10(sys) / math.Log10(1000)
			if scope > 1.0 {
				scope = 1.0
			}
		}

		ns["blast_scope"] = scope
	}

	if latVal, ok := m["lateral_movement_possible"]; ok {
		lateral, _ := toBool(latVal)

		if lateral {
			ns["lateral_movement"] = 1.0
		} else {
			ns["lateral_movement"] = 0.0
		}
	}

	return ns, nil
}
