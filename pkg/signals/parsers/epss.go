package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// EPSS parses Exploit Prediction Scoring System signals.
type EPSS struct{}

// Name returns the signal type identifier.
func (e *EPSS) Name() string { return "epss" }

// Description returns a human-readable description of this signal.
func (e *EPSS) Description() string {
	return "Exploit Prediction Scoring System probability and percentile"
}

// Fields returns the list of recognized input field names.
func (e *EPSS) Fields() []string { return []string{"probability", "percentile"} }

// Validate checks that raw is a map containing at least one of probability or
// percentile, and that any present values are floats in [0, 1].
func (e *EPSS) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("epss: input must be a map")
	}

	probVal, hasProb := m["probability"]
	pctVal, hasPct := m["percentile"]

	if !hasProb && !hasPct {
		return errors.New("epss: at least one of probability or percentile is required")
	}

	if hasProb {
		prob, ok := toFloat64(probVal)
		if !ok {
			return fmt.Errorf("epss: probability must be a number, got %T", probVal)
		}

		if prob < 0 || prob > 1 {
			return fmt.Errorf("epss: probability must be in [0, 1], got %v", prob)
		}
	}

	if hasPct {
		pct, ok := toFloat64(pctVal)
		if !ok {
			return fmt.Errorf("epss: percentile must be a number, got %T", pctVal)
		}

		if pct < 0 || pct > 1 {
			return fmt.Errorf("epss: percentile must be in [0, 1], got %v", pct)
		}
	}

	return nil
}

// Normalize converts raw EPSS input to normalized factor values.
// Produces exploit_probability and/or exploit_percentile as-is (already 0-1).
func (e *EPSS) Normalize(raw any) (signals.NormalizedSignal, error) {
	m, err := toMap(raw)
	if err != nil {
		return nil, err
	}
	if err := e.Validate(raw); err != nil {
		return nil, err
	}
	ns := make(signals.NormalizedSignal)

	if probVal, ok := m["probability"]; ok {
		prob, _ := toFloat64(probVal)
		ns["exploit_probability"] = prob
	}

	if pctVal, ok := m["percentile"]; ok {
		pct, _ := toFloat64(pctVal)
		ns["exploit_percentile"] = pct
	}

	return ns, nil
}
