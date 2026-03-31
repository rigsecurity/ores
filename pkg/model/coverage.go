package model

import "math"

// DimensionDef describes a scoring dimension's coverage by named signal types.
// Each source is a signal name (e.g., "cvss", "epss") that contributes to the dimension.
type DimensionDef struct {
	Name    string
	Weight  float64
	Sources []string // signal names (not factor keys) that cover this dimension
}

// DefaultDimensions returns the dimension definitions used for signal-name-based
// confidence calculation. The signal names correspond to registered parser names.
func DefaultDimensions() []DimensionDef {
	return []DimensionDef{
		{Name: "base_vulnerability", Weight: 0.30, Sources: []string{"cvss", "nist"}},
		{Name: "exploitability", Weight: 0.25, Sources: []string{"epss", "threat_intel"}},
		{Name: "environmental_context", Weight: 0.20, Sources: []string{"asset", "blast_radius"}},
		{Name: "remediation_gap", Weight: 0.15, Sources: []string{"patch", "compliance"}},
		{Name: "lateral_risk", Weight: 0.10, Sources: []string{"blast_radius"}},
	}
}

// CalculateConfidence returns a value in [0.0, 1.0] representing how well the
// provided signal names cover the given scoring dimensions. It is a weighted
// average of (sources covered / total sources) per dimension.
// The result is rounded to 4 decimal places to avoid IEEE 754 representation artifacts.
func CalculateConfidence(dims []DimensionDef, provided map[string]bool) float64 {
	var total float64

	for _, dim := range dims {
		covered := 0

		for _, src := range dim.Sources {
			if provided[src] {
				covered++
			}
		}

		if len(dim.Sources) == 0 {
			continue
		}

		coverage := float64(covered) / float64(len(dim.Sources))
		total += coverage * dim.Weight
	}

	if total > 1.0 {
		return 1.0
	}

	// Round to 4 decimal places to avoid IEEE 754 artifacts like 0.7000000000000001.
	return math.Round(total*10000) / 10000
}

// B4Axis describes one B4 adjustment axis and the signals that feed it.
type B4Axis struct {
	Name    string
	Signals []string
}

// B4Axes returns the three adjustment axes for B4 mode.
// This is the single source of truth for which signals are used in B4 context adjustment.
func B4Axes() []B4Axis {
	return []B4Axis{
		{Name: "environmental_adjust", Signals: []string{"asset"}},
		{Name: "blast_radius_adjust", Signals: []string{"blast_radius"}},
		{Name: "remediation_adjust", Signals: []string{"patch", "compliance"}},
	}
}

// B4ContextSignals returns the set of signal names used in B4 context adjustment.
func B4ContextSignals() map[string]bool {
	m := make(map[string]bool)
	for _, axis := range B4Axes() {
		for _, sig := range axis.Signals {
			m[sig] = true
		}
	}
	return m
}

// CalculateB4Confidence returns a value in [0.0, 1.0] representing how many of
// the three B4 adjustment axes have at least one signal provided.
func CalculateB4Confidence(provided map[string]bool) float64 {
	axes := B4Axes()
	covered := 0

	for _, axis := range axes {
		for _, sig := range axis.Signals {
			if provided[sig] {
				covered++
				break
			}
		}
	}

	if len(axes) == 0 {
		return 0
	}

	total := float64(covered) / float64(len(axes))
	return math.Round(total*10000) / 10000
}
