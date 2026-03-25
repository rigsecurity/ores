package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// ThreatIntel parses threat intelligence signals.
type ThreatIntel struct{}

// Name returns the signal type identifier.
func (t *ThreatIntel) Name() string { return "threat_intel" }

// Description returns a human-readable description of this signal.
func (t *ThreatIntel) Description() string {
	return "Threat intelligence: active exploitation and ransomware association"
}

// Fields returns the list of recognized input field names.
func (t *ThreatIntel) Fields() []string {
	return []string{"actively_exploited", "ransomware_associated"}
}

// Validate checks that raw is a map with at least one valid bool field.
func (t *ThreatIntel) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("threat_intel: input must be a map")
	}

	hasAny := false

	if aeVal, ok := m["actively_exploited"]; ok {
		hasAny = true

		if _, ok := toBool(aeVal); !ok {
			return fmt.Errorf("threat_intel: actively_exploited must be a bool, got %T", aeVal)
		}
	}

	if raVal, ok := m["ransomware_associated"]; ok {
		hasAny = true

		if _, ok := toBool(raVal); !ok {
			return fmt.Errorf("threat_intel: ransomware_associated must be a bool, got %T", raVal)
		}
	}

	if !hasAny {
		return errors.New("threat_intel: at least one of actively_exploited or ransomware_associated is required")
	}

	return nil
}

// Normalize converts raw ThreatIntel input to normalized factor values.
func (t *ThreatIntel) Normalize(raw any) (signals.NormalizedSignal, error) {
	if err := t.Validate(raw); err != nil {
		return nil, err
	}

	m := raw.(map[string]any)
	ns := make(signals.NormalizedSignal)

	if aeVal, ok := m["actively_exploited"]; ok {
		ae, _ := toBool(aeVal)

		if ae {
			ns["active_exploitation"] = 1.0
		} else {
			ns["active_exploitation"] = 0.0
		}
	}

	if raVal, ok := m["ransomware_associated"]; ok {
		ra, _ := toBool(raVal)

		if ra {
			ns["ransomware_risk"] = 1.0
		} else {
			ns["ransomware_risk"] = 0.0
		}
	}

	return ns, nil
}
