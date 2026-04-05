package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// nistSeverityScores maps NIST severity labels to normalized values.
var nistSeverityScores = map[string]float64{
	"info":     0.1,
	"low":      0.3,
	"medium":   0.5,
	"high":     0.7,
	"critical": 1.0,
}

// NIST parses NIST severity classification signals.
type NIST struct{}

// Name returns the signal type identifier.
func (n *NIST) Name() string { return "nist" }

// Description returns a human-readable description of this signal.
func (n *NIST) Description() string {
	return "NIST severity classification and optional CWE identifier"
}

// Fields returns the list of recognized input field names.
func (n *NIST) Fields() []string { return []string{"severity", "cwe"} }

// Validate checks that raw is a map with a valid severity enum value.
func (n *NIST) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("nist: input must be a map")
	}

	sevVal, hasSev := m["severity"]
	if !hasSev {
		return errors.New("nist: severity is required")
	}

	sev, ok := toString(sevVal)
	if !ok {
		return fmt.Errorf("nist: severity must be a string, got %T", sevVal)
	}

	if _, valid := nistSeverityScores[sev]; !valid {
		return fmt.Errorf("nist: severity %q is not valid; must be one of info, low, medium, high, critical", sev)
	}

	return nil
}

// Normalize converts raw NIST input to normalized factor values.
// Produces nist_severity mapped from the severity enum.
func (n *NIST) Normalize(raw any) (signals.NormalizedSignal, error) {
	m, err := toMap(raw)
	if err != nil {
		return nil, err
	}
	if err := n.Validate(raw); err != nil {
		return nil, err
	}
	ns := make(signals.NormalizedSignal)

	sev, _ := toString(m["severity"])
	ns["nist_severity"] = nistSeverityScores[sev]

	return ns, nil
}
