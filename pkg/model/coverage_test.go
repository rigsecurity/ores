package model_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultDimensions(t *testing.T) {
	dims := model.DefaultDimensions()
	require.Len(t, dims, 5)

	expectedNames := []string{
		"base_vulnerability",
		"exploitability",
		"environmental_context",
		"remediation_gap",
		"lateral_risk",
	}

	var totalWeight float64

	for i, dim := range dims {
		assert.Equal(t, expectedNames[i], dim.Name, "dimension %d name mismatch", i)
		assert.Greater(t, dim.Weight, 0.0, "dimension %s weight must be positive", dim.Name)
		assert.NotEmpty(t, dim.Sources, "dimension %s must have at least one source", dim.Name)
		totalWeight += dim.Weight
	}

	assert.InDelta(t, 1.0, totalWeight, 0.0001, "dimension weights must sum to 1.0")
}

func TestDefaultDimensionsSources(t *testing.T) {
	dims := model.DefaultDimensions()

	expectedSources := map[string][]string{
		"base_vulnerability":    {"cvss", "nist"},
		"exploitability":        {"epss", "threat_intel"},
		"environmental_context": {"asset", "blast_radius"},
		"remediation_gap":       {"patch", "compliance"},
		"lateral_risk":          {"blast_radius"},
	}

	for _, dim := range dims {
		expected, ok := expectedSources[dim.Name]
		require.True(t, ok, "unexpected dimension: %s", dim.Name)
		assert.Equal(t, expected, dim.Sources, "sources mismatch for dimension %s", dim.Name)
	}
}

func TestCalculateConfidenceFullCoverage(t *testing.T) {
	dims := model.DefaultDimensions()
	provided := map[string]bool{
		"cvss":         true,
		"nist":         true,
		"epss":         true,
		"threat_intel": true,
		"asset":        true,
		"blast_radius": true,
		"patch":        true,
		"compliance":   true,
	}

	confidence := model.CalculateConfidence(dims, provided)
	assert.InDelta(t, 1.0, confidence, 0.0001, "full coverage should yield confidence 1.0")
}

func TestCalculateConfidenceNoCoverage(t *testing.T) {
	dims := model.DefaultDimensions()
	provided := map[string]bool{}

	confidence := model.CalculateConfidence(dims, provided)
	assert.InDelta(t, 0.0, confidence, 0.0001, "no coverage should yield confidence 0.0")
}

func TestCalculateConfidencePartialCoverage(t *testing.T) {
	dims := model.DefaultDimensions()

	tests := []struct {
		name      string
		provided  map[string]bool
		wantAbove float64
		wantBelow float64
	}{
		{
			name:      "only cvss",
			provided:  map[string]bool{"cvss": true},
			wantAbove: 0.0,
			wantBelow: 1.0,
		},
		{
			name:      "cvss and epss",
			provided:  map[string]bool{"cvss": true, "epss": true},
			wantAbove: 0.0,
			wantBelow: 1.0,
		},
		{
			name:      "one source per dimension",
			provided:  map[string]bool{"cvss": true, "epss": true, "asset": true, "patch": true, "blast_radius": true},
			wantAbove: 0.4,
			wantBelow: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence := model.CalculateConfidence(dims, tt.provided)
			assert.Greater(t, confidence, tt.wantAbove, "confidence should be above %.2f", tt.wantAbove)
			assert.Less(t, confidence, tt.wantBelow, "confidence should be below %.2f", tt.wantBelow)
		})
	}
}

func TestCalculateConfidenceEmptyDimensions(t *testing.T) {
	provided := map[string]bool{"cvss": true}
	confidence := model.CalculateConfidence(nil, provided)
	assert.InDelta(t, 0.0, confidence, 0.0001, "no dimensions should yield confidence 0.0")
}

func TestCalculateConfidenceEmptySources(t *testing.T) {
	dims := []model.DimensionDef{
		{Name: "empty_dim", Weight: 0.5, Sources: []string{}},
		{Name: "normal_dim", Weight: 0.5, Sources: []string{"cvss"}},
	}
	provided := map[string]bool{"cvss": true}

	confidence := model.CalculateConfidence(dims, provided)
	// Only normal_dim contributes: 1.0 * 0.5 = 0.5
	assert.InDelta(t, 0.5, confidence, 0.0001)
}

func TestCalculateConfidenceNilProvided(t *testing.T) {
	dims := model.DefaultDimensions()
	confidence := model.CalculateConfidence(dims, nil)
	assert.InDelta(t, 0.0, confidence, 0.0001, "nil provided should yield confidence 0.0")
}

func TestCalculateConfidenceIrrelevantSignals(t *testing.T) {
	dims := model.DefaultDimensions()
	// Signals that don't map to any dimension source should not increase confidence.
	provided := map[string]bool{
		"unknown_signal": true,
		"another_one":    true,
	}

	confidence := model.CalculateConfidence(dims, provided)
	assert.InDelta(t, 0.0, confidence, 0.0001, "unrecognized signals should not affect confidence")
}

func TestCalculateConfidenceHalfCoveragePerDimension(t *testing.T) {
	dims := model.DefaultDimensions()
	// Provide exactly one source per two-source dimension.
	// Note: blast_radius is a source for both environmental_context and lateral_risk.
	provided := map[string]bool{
		"cvss":         true, // 1/2 of base_vulnerability
		"epss":         true, // 1/2 of exploitability
		"asset":        true, // 1/2 of environmental_context (blast_radius also covers it)
		"patch":        true, // 1/2 of remediation_gap
		"blast_radius": true, // 1/2 of environmental_context + 1/1 of lateral_risk
	}

	confidence := model.CalculateConfidence(dims, provided)
	// base_vulnerability: 1/2 * 0.30 = 0.15
	// exploitability: 1/2 * 0.25 = 0.125
	// environmental_context: 2/2 * 0.20 = 0.20 (both asset and blast_radius provided)
	// remediation_gap: 1/2 * 0.15 = 0.075
	// lateral_risk: 1/1 * 0.10 = 0.10
	// Total: 0.65
	assert.InDelta(t, 0.65, confidence, 0.0001)
}
