package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// CVSS parses Common Vulnerability Scoring System signals.
type CVSS struct{}

// Name returns the signal type identifier.
func (c *CVSS) Name() string { return "cvss" }

// Description returns a human-readable description of this signal.
func (c *CVSS) Description() string {
	return "Common Vulnerability Scoring System score and vector string"
}

// Fields returns the list of recognized input field names.
func (c *CVSS) Fields() []string { return []string{"base_score", "vector"} }

// Validate checks that raw is a map containing at least base_score or vector,
// and that base_score, if present, is a number in [0, 10].
func (c *CVSS) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("cvss: input must be a map")
	}

	scoreVal, hasScore := m["base_score"]
	_, hasVector := m["vector"]

	if !hasScore && !hasVector {
		return errors.New("cvss: at least one of base_score or vector is required")
	}

	if hasScore {
		score, ok := toFloat64(scoreVal)
		if !ok {
			return fmt.Errorf("cvss: base_score must be a number, got %T", scoreVal)
		}

		if score < 0 || score > 10 {
			return fmt.Errorf("cvss: base_score must be in [0, 10], got %v", score)
		}
	}

	return nil
}

// Normalize converts raw CVSS input to normalized factor values.
// Produces severity = base_score / 10.0 when base_score is present.
func (c *CVSS) Normalize(raw any) (signals.NormalizedSignal, error) {
	m, err := toMap(raw)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(raw); err != nil {
		return nil, err
	}
	ns := make(signals.NormalizedSignal)

	if scoreVal, ok := m["base_score"]; ok {
		score, _ := toFloat64(scoreVal)
		ns["severity"] = score / 10.0
	}

	return ns, nil
}
