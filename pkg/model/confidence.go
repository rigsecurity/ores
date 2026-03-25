package model

import "github.com/rigsecurity/ores/pkg/signals"

// dimensionCoverage describes which factor keys indicate signal coverage for a scoring dimension.
// Each inner slice is one "signal source" — if any factor key from that source is present,
// the source is counted as covered.
type dimensionCoverage struct {
	name    string
	weight  float64
	sources [][]string // each element is a set of factor keys that together constitute one signal source
}

// dimensions lists every scoring dimension and the factor keys that cover each signal source.
var dimensions = []dimensionCoverage{
	{
		name:   "base_vulnerability",
		weight: 0.30,
		sources: [][]string{
			{"severity"},      // cvss
			{"nist_severity"}, // nist
		},
	},
	{
		name:   "exploitability",
		weight: 0.25,
		sources: [][]string{
			{"exploit_probability", "exploit_percentile"}, // epss
			{"active_exploitation", "ransomware_risk"},    // threat_intel
		},
	},
	{
		name:   "environmental_context",
		weight: 0.20,
		sources: [][]string{
			{"asset_criticality", "network_exposure", "data_sensitivity"}, // asset
			{"blast_scope", "lateral_movement"},                           // blast_radius
		},
	},
	{
		name:   "remediation_gap",
		weight: 0.15,
		sources: [][]string{
			{"remediation_available", "patch_staleness", "has_compensating_control"}, // patch
			{"regulatory_severity", "compliance_scope"},                              // compliance
		},
	},
	{
		name:   "lateral_risk",
		weight: 0.10,
		sources: [][]string{
			{"blast_scope", "lateral_movement"}, // blast_radius
		},
	},
}

// Confidence returns a value in [0.0, 1.0] representing how well the provided
// signals cover the five scoring dimensions. It is a weighted average of
// (sources covered / total sources) per dimension.
func Confidence(normalized []signals.NormalizedSignal) float64 {
	// Merge all factor keys from all signals.
	present := make(map[string]bool)

	for _, sig := range normalized {
		for k := range sig {
			present[k] = true
		}
	}

	var total float64

	for _, dim := range dimensions {
		covered := 0

		for _, sourceKeys := range dim.sources {
			for _, key := range sourceKeys {
				if present[key] {
					covered++

					break
				}
			}
		}

		coverage := float64(covered) / float64(len(dim.sources))
		total += coverage * dim.weight
	}

	// Clamp to [0.0, 1.0] for safety.
	if total > 1.0 {
		return 1.0
	}

	return total
}
