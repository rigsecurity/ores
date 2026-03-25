// Package explain constructs human-readable explanations from model output,
// mapping dimension contributions to the signals that produced them.
package explain

import (
	"fmt"

	"github.com/rigsecurity/ores/pkg/model"
	"github.com/rigsecurity/ores/pkg/score"
)

// dimensionSignals maps dimension names to the signal types that feed them.
var dimensionSignals = map[string][]string{
	"base_vulnerability":    {"cvss", "nist"},
	"exploitability":        {"epss", "threat_intel"},
	"environmental_context": {"asset", "blast_radius"},
	"remediation_gap":       {"patch", "compliance"},
	"lateral_risk":          {"blast_radius"},
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
