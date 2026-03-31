package model

import (
	"maps"
	"math"

	"github.com/rigsecurity/ores/pkg/signals"
)

// ScoreResult holds the aggregated score and its per-dimension decomposition.
type ScoreResult struct {
	Score   int
	Factors []FactorContribution
}

// FactorContribution records one dimension's contribution to the overall score.
type FactorContribution struct {
	Name         string
	RawScore     float64
	Weight       float64
	Contribution int
}

// Model is the fixed-weight B4-variant scoring engine.
type Model struct{}

// New returns a new Model instance.
func New() *Model {
	return &Model{}
}

// Version returns the model version string.
func (m *Model) Version() string {
	return ModelVersion
}

// dimDefinition holds everything needed to compute one dimension's score.
type dimDefinition struct {
	name   string
	weight float64
	score  func(factors map[string]float64) float64
}

// get returns the factor value for key, falling back to defaultVal if absent.
func get(factors map[string]float64, key string, defaultVal float64) float64 {
	if v, ok := factors[key]; ok {
		return v
	}

	return defaultVal
}

// dimDefs is the ordered list of scoring dimensions.
var dimDefs = []dimDefinition{
	{
		name:   "base_vulnerability",
		weight: 0.30,
		score: func(f map[string]float64) float64 {
			severity := get(f, "severity", 0.5)
			nistSeverity := get(f, "nist_severity", 0.5)

			return severity*0.7 + nistSeverity*0.3
		},
	},
	{
		name:   "exploitability",
		weight: 0.25,
		score: func(f map[string]float64) float64 {
			prob := get(f, "exploit_probability", 0.3)
			pct := get(f, "exploit_percentile", 0.3)
			active := get(f, "active_exploitation", 0.0)
			ransom := get(f, "ransomware_risk", 0.0)

			return prob*0.5 + pct*0.1 + active*0.3 + ransom*0.1
		},
	},
	{
		name:   "environmental_context",
		weight: 0.20,
		score: func(f map[string]float64) float64 {
			criticality := get(f, "asset_criticality", 0.5)
			exposure := get(f, "network_exposure", 0.5)
			scope := get(f, "blast_scope", 0.5)
			sensitivity := get(f, "data_sensitivity", 0.5)

			return criticality*0.4 + exposure*0.3 + scope*0.2 + sensitivity*0.1
		},
	},
	{
		name:   "remediation_gap",
		weight: 0.15,
		score: func(f map[string]float64) float64 {
			avail := get(f, "remediation_available", 0.5)
			staleness := get(f, "patch_staleness", 0.5)
			compensating := get(f, "has_compensating_control", 0.0)
			regSeverity := get(f, "regulatory_severity", 0.3)
			compScope := get(f, "compliance_scope", 0.3)

			gap := avail * staleness * (1 - compensating*0.5)

			return gap*0.5 + regSeverity*0.3 + compScope*0.2
		},
	},
	{
		name:   "lateral_risk",
		weight: 0.10,
		score: func(f map[string]float64) float64 {
			lateral := get(f, "lateral_movement", 0.0)
			scope := get(f, "blast_scope", 0.3)

			return lateral*0.6 + scope*0.4
		},
	},
}

// ScoreWeighted computes the risk score for the given normalized signals.
// It merges all signals into a single factor map, computes per-dimension scores,
// aggregates with weighted sum * 100, rounds to integer (half-up), and uses the
// largest-remainder method to distribute integer contributions that sum exactly to the score.
func (m *Model) ScoreWeighted(normalized []signals.NormalizedSignal) (*ScoreResult, error) {
	// Merge all normalized signals into one factor map (last write wins for duplicates).
	factors := make(map[string]float64)

	for _, sig := range normalized {
		maps.Copy(factors, sig)
	}

	// Compute the raw (float) weighted sum.
	type dimResult struct {
		name         string
		raw          float64
		weight       float64
		floatContrib float64 // raw contribution before rounding (raw * weight * 100)
	}

	dims := make([]dimResult, len(dimDefs))

	var floatTotal float64

	for i, def := range dimDefs {
		raw := def.score(factors)
		// Clamp dimension score to [0, 1].
		if raw < 0 {
			raw = 0
		} else if raw > 1 {
			raw = 1
		}

		contrib := raw * def.weight * 100
		dims[i] = dimResult{
			name:         def.name,
			raw:          raw,
			weight:       def.weight,
			floatContrib: contrib,
		}
		floatTotal += contrib
	}

	// Round total with half-up rounding and clamp to [0, 100].
	score := int(math.Floor(floatTotal + 0.5))

	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	// Distribute integer contributions using the largest-remainder method.
	floats := make([]float64, len(dims))
	for i, d := range dims {
		floats[i] = d.floatContrib
	}
	contributions := distributeContributions(floats, score)

	// Build result.
	result := &ScoreResult{
		Score:   score,
		Factors: make([]FactorContribution, len(dims)),
	}

	for i, d := range dims {
		result.Factors[i] = FactorContribution{
			Name:         d.name,
			RawScore:     d.raw,
			Weight:       d.weight,
			Contribution: contributions[i],
		}
	}

	return result, nil
}

// Score routes to the appropriate scoring algorithm based on whether findings are present.
func (m *Model) Score(findings []float64, normalized []signals.NormalizedSignal) (*ScoreResult, error) {
	if len(findings) > 0 {
		factors := make(map[string]float64)
		for _, sig := range normalized {
			maps.Copy(factors, sig)
		}
		return m.ScoreB4(findings, factors)
	}
	return m.ScoreWeighted(normalized)
}
