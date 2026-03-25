// Package explain constructs human-readable explanations from model output,
// mapping dimension contributions to the signals that produced them.
package explain

import (
	"fmt"

	"github.com/rigsecurity/ores/pkg/model"
	"github.com/rigsecurity/ores/pkg/score"
)

// dimensionSignals is derived from model.DefaultDimensions to ensure a single source
// of truth for the dimension-to-signal mapping used in both confidence calculation
// and explanation generation.
var dimensionSignals = buildDimensionSignals()

func buildDimensionSignals() map[string][]string {
	m := make(map[string][]string)

	for _, dim := range model.DefaultDimensions() {
		m[dim.Name] = dim.Sources
	}

	return m
}

var dimensionReasoningTemplates = map[string]string{
	"base_vulnerability":    "Base severity score from vulnerability data",
	"exploitability":        "Likelihood of exploitation based on threat landscape",
	"environmental_context": "Environmental risk based on asset criticality and exposure",
	"remediation_gap":       "Remediation posture based on patch availability and compliance",
	"lateral_risk":          "Lateral movement potential based on blast radius",
}

// Build constructs an Explanation from model output and signal metadata.
// totalProvided is the total number of signals in the original request (used + invalid + unknown).
func Build(
	contributions []model.FactorContribution,
	provided map[string]bool,
	unknownSignals []string,
	warnings []string,
	confidence float64,
	totalProvided int,
) score.Explanation {
	factors := make([]score.Factor, 0, len(contributions))

	for _, c := range contributions {
		derivedFrom := derivedSignals(c.Name, provided)
		reasoning := generateReasoning(c.Name, c.RawScore)
		factors = append(factors, score.Factor{
			Name:         c.Name,
			Contribution: c.Contribution,
			DerivedFrom:  derivedFrom,
			Reasoning:    reasoning,
		})
	}

	signalsUsed := len(provided)

	if unknownSignals == nil {
		unknownSignals = []string{}
	}

	if warnings == nil {
		warnings = []string{}
	}

	return score.Explanation{
		SignalsProvided: totalProvided,
		SignalsUsed:     signalsUsed,
		SignalsUnknown:  len(unknownSignals),
		UnknownSignals:  unknownSignals,
		Warnings:        warnings,
		Confidence:      confidence,
		Factors:         factors,
	}
}

var b4FactorSignals = map[string][]string{
	"base_finding":         {},
	"additional_findings":  {},
	"environmental_adjust": {"asset"},
	"blast_radius_adjust":  {"blast_radius"},
	"remediation_adjust":   {"patch", "compliance"},
}

var b4ReasoningTemplates = map[string]string{
	"base_finding":         "Anchored on most critical finding",
	"additional_findings":  "Additional findings contribute decaying bonus",
	"environmental_adjust": "Environmental context adjustment based on asset criticality and exposure",
	"blast_radius_adjust":  "Blast radius adjustment based on affected systems and lateral movement",
	"remediation_adjust":   "Remediation posture adjustment based on patch availability and compliance",
}

// BuildB4 constructs an Explanation for B4 mode results.
func BuildB4(
	contributions []model.FactorContribution,
	provided map[string]bool,
	unknownSignals []string,
	warnings []string,
	confidence float64,
	findingsCount int,
) score.Explanation {
	factors := make([]score.Factor, 0, len(contributions))

	for _, c := range contributions {
		derivedFrom := derivedB4Signals(c.Name, provided)
		reasoning := generateB4Reasoning(c.Name, c.RawScore)
		factors = append(factors, score.Factor{
			Name:         c.Name,
			Contribution: c.Contribution,
			DerivedFrom:  derivedFrom,
			Reasoning:    reasoning,
		})
	}

	if unknownSignals == nil {
		unknownSignals = []string{}
	}
	if warnings == nil {
		warnings = []string{}
	}

	return score.Explanation{
		SignalsProvided: len(provided),
		SignalsUsed:     len(provided),
		SignalsUnknown:  len(unknownSignals),
		FindingsCount:   findingsCount,
		UnknownSignals:  unknownSignals,
		Warnings:        warnings,
		Confidence:      confidence,
		Factors:         factors,
	}
}

func derivedB4Signals(factorName string, provided map[string]bool) []string {
	if factorName == "base_finding" || factorName == "additional_findings" {
		return []string{"findings"}
	}

	candidates := b4FactorSignals[factorName]
	var result []string
	for _, s := range candidates {
		if provided[s] {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return []string{"defaults"}
	}
	return result
}

func generateB4Reasoning(factorName string, rawScore float64) string {
	template := b4ReasoningTemplates[factorName]
	if template == "" {
		template = "Contributing factor"
	}

	if factorName == "base_finding" {
		return fmt.Sprintf("%s (severity: %.1f)", template, rawScore)
	}

	level := "neutral"
	if rawScore >= 0.7 {
		level = "increases score"
	} else if rawScore <= 0.3 {
		level = "decreases score"
	}

	return fmt.Sprintf("%s (%s)", template, level)
}

func derivedSignals(dimName string, provided map[string]bool) []string {
	candidates := dimensionSignals[dimName]

	var result []string

	for _, s := range candidates {
		if provided[s] {
			result = append(result, s)
		}
	}

	if len(result) == 0 {
		return []string{"defaults"}
	}

	return result
}

func generateReasoning(dimName string, rawScore float64) string {
	template := dimensionReasoningTemplates[dimName]
	if template == "" {
		template = "Contributing factor"
	}

	level := "moderate"
	if rawScore >= 0.7 {
		level = "high"
	} else if rawScore <= 0.3 {
		level = "low"
	}

	return fmt.Sprintf("%s (%s impact: %.0f%%)", template, level, rawScore*100)
}
