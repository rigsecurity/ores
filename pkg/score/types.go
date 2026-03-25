// Package score defines the core types for the ORES risk scoring engine,
// including request/response envelopes, score labels, and the additive factor
// decomposition used to explain how a score was calculated.
package score

import (
	"errors"
	"fmt"
)

// API envelope constants shared by all ORES resources.
const (
	APIVersion            = "ores.dev/v1"
	KindEvaluationRequest = "EvaluationRequest"
	KindEvaluationResult  = "EvaluationResult"
)

// Label is the human-readable severity label for a score.
type Label string

// Severity labels map score ranges to named tiers.
const (
	LabelCritical Label = "critical"
	LabelHigh     Label = "high"
	LabelMedium   Label = "medium"
	LabelLow      Label = "low"
	LabelInfo     Label = "info"
)

// LabelForScore returns the severity label for a score in [0, 100].
func LabelForScore(s int) Label {
	switch {
	case s >= 90:
		return LabelCritical
	case s >= 70:
		return LabelHigh
	case s >= 40:
		return LabelMedium
	case s >= 10:
		return LabelLow
	default:
		return LabelInfo
	}
}

// EvaluationRequest is the input to the ORES engine.
type EvaluationRequest struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Signals    map[string]any `json:"signals"`
}

// Validate checks that the request has required envelope fields and at least one signal.
func (r *EvaluationRequest) Validate() error {
	if r.APIVersion == "" {
		return errors.New("apiVersion is required")
	}
	if r.APIVersion != APIVersion {
		return fmt.Errorf("unsupported apiVersion %q, expected %q", r.APIVersion, APIVersion)
	}
	if r.Kind != KindEvaluationRequest {
		return fmt.Errorf("unexpected kind %q, expected %q", r.Kind, KindEvaluationRequest)
	}
	if len(r.Signals) == 0 {
		return errors.New("at least one signal is required")
	}
	return nil
}

// EvaluationResult is the output of the ORES engine.
type EvaluationResult struct {
	APIVersion  string      `json:"apiVersion"  yaml:"apiVersion"`
	Kind        string      `json:"kind"        yaml:"kind"`
	Score       int         `json:"score"       yaml:"score"`
	Label       Label       `json:"label"       yaml:"label"`
	Version     string      `json:"version"     yaml:"version"`
	Explanation Explanation `json:"explanation"  yaml:"explanation"`
}

// Explanation breaks down how the score was calculated.
type Explanation struct {
	SignalsProvided int      `json:"signals_provided" yaml:"signals_provided"`
	SignalsUsed     int      `json:"signals_used"     yaml:"signals_used"`
	SignalsUnknown  int      `json:"signals_unknown"  yaml:"signals_unknown"`
	UnknownSignals  []string `json:"unknown_signals"  yaml:"unknown_signals"`
	Warnings        []string `json:"warnings"         yaml:"warnings"`
	Confidence      float64  `json:"confidence"       yaml:"confidence"`
	Factors         []Factor `json:"factors"          yaml:"factors"`
}

// Factor is one component of the additive score decomposition.
type Factor struct {
	Name         string   `json:"name"         yaml:"name"`
	Contribution int      `json:"contribution" yaml:"contribution"`
	DerivedFrom  []string `json:"derived_from" yaml:"derived_from"`
	Reasoning    string   `json:"reasoning"    yaml:"reasoning"`
}

// SignalDescriptor describes a recognized signal type.
type SignalDescriptor struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Fields      []string `json:"fields"`
}
