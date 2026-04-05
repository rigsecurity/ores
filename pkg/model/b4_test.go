package model_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestB4ParametersMatchResearch verifies the exact parameter values from the research spec.
func TestB4ParametersMatchResearch(t *testing.T) {
	p := model.B4Params()
	assert.InDelta(t, 0.5, p.DecayRate, 0.0001, "decay_rate")
	assert.InDelta(t, 0.15, p.ScaleFactor, 0.0001, "scale_factor")
	assert.InDelta(t, 2.0, p.MaxAdd, 0.0001, "max_add")
	assert.InDelta(t, 2.0, p.MaxAdjust, 0.0001, "max_adjust")
	assert.InDelta(t, -0.5, p.BaseOffset, 0.0001, "base_offset")
}

// TestB4EmptyFindings ensures nil and empty slices return an error.
func TestB4EmptyFindings(t *testing.T) {
	m := model.New()

	_, err := m.ScoreB4(nil, nil)
	require.Error(t, err, "nil findings must return error")

	_, err = m.ScoreB4([]float64{}, nil)
	require.Error(t, err, "empty findings must return error")
}

// TestB4SingleFinding: [10] → score 95  (base=9.5, all adjusts neutral → raw=9.5 → 95).
func TestB4SingleFinding(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{10}, nil)
	require.NoError(t, err)
	assert.Equal(t, 95, result.Score)
}

// TestB4SingleLowFinding: [2] → score 15.
func TestB4SingleLowFinding(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{2}, nil)
	require.NoError(t, err)
	assert.Equal(t, 15, result.Score)
}

// TestB4TwoFindings: [10, 9] → bonus pushes past 10 → capped at max_finding → 100.
func TestB4TwoFindings(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{10, 9}, nil)
	require.NoError(t, err)
	assert.Equal(t, 100, result.Score)
}

// TestB4BonusCapsAtMaxAdd: many findings → bonus cannot exceed max_add=2.0 →
// base=8.5+2.0=10.5 but capped at max_finding=9.0 → score=90.
func TestB4BonusCapsAtMaxAdd(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{9, 8, 8, 7, 6, 5}, nil)
	require.NoError(t, err)
	assert.LessOrEqual(t, result.Score, 90, "bonus cap must keep score ≤ 90 for max_finding=9")
}

// TestB4CapAtMaxFinding: raw exceeds max_finding → clipped to 8.0 → score=80.
func TestB4CapAtMaxFinding(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{8, 8, 8, 8}, nil)
	require.NoError(t, err)
	assert.LessOrEqual(t, result.Score, 80, "score must not exceed max_finding×10")
	assert.Greater(t, result.Score, 70, "score should still be above 70")
}

// TestB4ClampAtZero: [1] with all-zero factors → negative adjusts drive raw<0 → clamp to 0.
func TestB4ClampAtZero(t *testing.T) {
	m := model.New()
	allZero := map[string]float64{
		"asset_criticality":     0,
		"network_exposure":      0,
		"data_sensitivity":      0,
		"blast_scope":           0,
		"lateral_movement":      0,
		"remediation_available": 0,
		"patch_staleness":       0,
		"regulatory_severity":   0,
		"compliance_scope":      0,
	}
	result, err := m.ScoreB4([]float64{1}, allZero)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, result.Score, 0, "score must be non-negative")
}

// TestB4EnvironmentalAdjustHigh verifies that all-high environmental factors
// increase the score compared to neutral defaults.
func TestB4EnvironmentalAdjustHigh(t *testing.T) {
	m := model.New()
	base, err := m.ScoreB4([]float64{5}, nil)
	require.NoError(t, err)

	high, err := m.ScoreB4([]float64{5}, map[string]float64{
		"asset_criticality": 1,
		"network_exposure":  1,
		"data_sensitivity":  1,
	})
	require.NoError(t, err)

	assert.Greater(t, high.Score, base.Score,
		"high environmental factors must increase score above neutral baseline")
}

// TestB4EnvironmentalAdjustLow verifies that all-zero environmental factors
// decrease the score compared to neutral defaults.
func TestB4EnvironmentalAdjustLow(t *testing.T) {
	m := model.New()
	base, err := m.ScoreB4([]float64{5}, nil)
	require.NoError(t, err)

	low, err := m.ScoreB4([]float64{5}, map[string]float64{
		"asset_criticality": 0,
		"network_exposure":  0,
		"data_sensitivity":  0,
	})
	require.NoError(t, err)

	assert.Less(t, low.Score, base.Score,
		"zero environmental factors must decrease score below neutral baseline")
}

// TestB4BlastRadiusAdjust verifies that blast radius direction is correct.
func TestB4BlastRadiusAdjust(t *testing.T) {
	m := model.New()

	high, err := m.ScoreB4([]float64{5}, map[string]float64{
		"blast_scope":      1,
		"lateral_movement": 1,
	})
	require.NoError(t, err)

	low, err := m.ScoreB4([]float64{5}, map[string]float64{
		"blast_scope":      0,
		"lateral_movement": 0,
	})
	require.NoError(t, err)

	assert.Greater(t, high.Score, low.Score,
		"high blast radius must score higher than low blast radius")
}

// TestB4RemediationAdjust verifies that high remediation burden increases score.
func TestB4RemediationAdjust(t *testing.T) {
	m := model.New()

	high, err := m.ScoreB4([]float64{5}, map[string]float64{
		"remediation_available": 1,
		"patch_staleness":       1,
		"regulatory_severity":   1,
		"compliance_scope":      1,
	})
	require.NoError(t, err)

	low, err := m.ScoreB4([]float64{5}, map[string]float64{
		"remediation_available": 0,
		"patch_staleness":       0,
		"regulatory_severity":   0,
		"compliance_scope":      0,
	})
	require.NoError(t, err)

	assert.Greater(t, high.Score, low.Score,
		"high remediation burden must score higher than no burden")
}

// TestB4Determinism ensures 100 consecutive calls return identical results.
func TestB4Determinism(t *testing.T) {
	m := model.New()
	factors := map[string]float64{
		"asset_criticality": 0.7,
		"network_exposure":  0.6,
		"blast_scope":       0.5,
	}

	first, err := m.ScoreB4([]float64{8, 6, 4}, factors)
	require.NoError(t, err)

	for i := range 100 {
		result, err2 := m.ScoreB4([]float64{8, 6, 4}, factors)
		require.NoError(t, err2, "iteration %d", i)
		assert.Equal(t, first.Score, result.Score, "score must be identical on iteration %d", i)
		assert.Equal(t, first.Factors, result.Factors, "factors must be identical on iteration %d", i)
	}
}

// TestB4FactorsSumToScore verifies the largest-remainder distribution invariant:
// the sum of integer contributions must always equal the total score.
func TestB4FactorsSumToScore(t *testing.T) {
	m := model.New()

	cases := []struct {
		name     string
		findings []float64
		factors  map[string]float64
	}{
		{"single high", []float64{10}, nil},
		{"single low", []float64{2}, nil},
		{"two findings", []float64{10, 9}, nil},
		{"capped bonus", []float64{9, 8, 8, 7, 6, 5}, nil},
		{"capped at max finding", []float64{8, 8, 8, 8}, nil},
		{"high env", []float64{5}, map[string]float64{"asset_criticality": 1, "network_exposure": 1, "data_sensitivity": 1}},
		{"low env", []float64{5}, map[string]float64{"asset_criticality": 0, "network_exposure": 0, "data_sensitivity": 0}},
		{"mixed", []float64{7, 5, 3}, map[string]float64{"asset_criticality": 0.8, "blast_scope": 0.6, "patch_staleness": 0.4}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := m.ScoreB4(tc.findings, tc.factors)
			require.NoError(t, err)

			total := 0
			for _, f := range result.Factors {
				total += f.Contribution
			}

			assert.Equal(t, result.Score, total,
				"factor contributions must sum exactly to score")
		})
	}
}

// TestB4UnsortedFindings verifies that input order does not affect the result.
func TestB4UnsortedFindings(t *testing.T) {
	m := model.New()

	sorted, err := m.ScoreB4([]float64{9, 7, 5, 3}, nil)
	require.NoError(t, err)

	unsorted, err := m.ScoreB4([]float64{3, 9, 5, 7}, nil)
	require.NoError(t, err)

	assert.Equal(t, sorted.Score, unsorted.Score,
		"score must be the same regardless of findings input order")
	assert.Equal(t, sorted.Factors, unsorted.Factors,
		"factors must be the same regardless of findings input order")
}

// TestB4FactorNames verifies the exact factor names returned by ScoreB4.
func TestB4FactorNames(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{7}, nil)
	require.NoError(t, err)

	expected := []string{
		"base_finding",
		"additional_findings",
		"environmental_adjust",
		"blast_radius_adjust",
		"remediation_adjust",
	}

	require.Len(t, result.Factors, len(expected))

	for i, f := range result.Factors {
		assert.Equal(t, expected[i], f.Name, "factor name at index %d", i)
	}
}

// TestB4FactorWeightsAreZero verifies that all B4 factor weights are 0
// (weights are not applicable in B4 mode).
func TestB4FactorWeightsAreZero(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{7}, nil)
	require.NoError(t, err)

	for _, f := range result.Factors {
		assert.InDelta(t, 0.0, f.Weight, 0.0001, "weight must be 0 for B4 factor %s", f.Name)
	}
}

// TestB4ZeroFinding: [0] → base = -0.5, neutral adjusts = 0, raw = -0.5 → clamp to 0 → score=0.
func TestB4ZeroFinding(t *testing.T) {
	m := model.New()
	result, err := m.ScoreB4([]float64{0}, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Score, "a finding of 0 should produce score 0")
}

// TestB4FindingsSliceNotMutated verifies that ScoreB4 does not modify the caller's slice.
func TestB4FindingsSliceNotMutated(t *testing.T) {
	m := model.New()
	findings := []float64{3, 9, 5, 7}
	original := make([]float64, len(findings))
	copy(original, findings)

	_, err := m.ScoreB4(findings, nil)
	require.NoError(t, err)
	assert.Equal(t, original, findings, "ScoreB4 must not mutate the caller's findings slice")
}

// TestB4ExactRegressionPins pins exact score outputs for specific inputs to catch
// regressions from formula changes. These values are derived from the current algorithm.
func TestB4ExactRegressionPins(t *testing.T) {
	m := model.New()

	tests := []struct {
		name      string
		findings  []float64
		factors   map[string]float64
		wantScore int
	}{
		{"single_max", []float64{10}, nil, 95},
		{"single_low", []float64{2}, nil, 15},
		{"single_zero", []float64{0}, nil, 0},
		{"two_max", []float64{10, 9}, nil, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.ScoreB4(tt.findings, tt.factors)
			require.NoError(t, err)
			assert.Equal(t, tt.wantScore, result.Score, "exact score pin for %s", tt.name)
		})
	}
}

// TestB4AxisIsolation verifies each axis independently by holding the other two neutral.
func TestB4AxisIsolation(t *testing.T) {
	m := model.New()
	base, err := m.ScoreB4([]float64{5}, nil)
	require.NoError(t, err)

	t.Run("environmental only", func(t *testing.T) {
		high, err := m.ScoreB4([]float64{5}, map[string]float64{
			"asset_criticality": 1.0, "network_exposure": 1.0, "data_sensitivity": 1.0,
		})
		require.NoError(t, err)
		low, err := m.ScoreB4([]float64{5}, map[string]float64{
			"asset_criticality": 0.0, "network_exposure": 0.0, "data_sensitivity": 0.0,
		})
		require.NoError(t, err)
		assert.Greater(t, high.Score, base.Score, "high env > neutral")
		assert.Less(t, low.Score, base.Score, "low env < neutral")
	})

	t.Run("blast_radius only", func(t *testing.T) {
		high, err := m.ScoreB4([]float64{5}, map[string]float64{
			"blast_scope": 1.0, "lateral_movement": 1.0,
		})
		require.NoError(t, err)
		low, err := m.ScoreB4([]float64{5}, map[string]float64{
			"blast_scope": 0.0, "lateral_movement": 0.0,
		})
		require.NoError(t, err)
		assert.Greater(t, high.Score, base.Score, "high blast > neutral")
		assert.Less(t, low.Score, base.Score, "low blast < neutral")
	})

	t.Run("remediation only", func(t *testing.T) {
		high, err := m.ScoreB4([]float64{5}, map[string]float64{
			"remediation_available": 1.0, "patch_staleness": 1.0,
			"regulatory_severity": 1.0, "compliance_scope": 1.0,
		})
		require.NoError(t, err)
		low, err := m.ScoreB4([]float64{5}, map[string]float64{
			"remediation_available": 0.0, "patch_staleness": 0.0,
			"regulatory_severity": 0.0, "compliance_scope": 0.0,
		})
		require.NoError(t, err)
		assert.Greater(t, high.Score, base.Score, "high remediation > neutral")
		assert.Less(t, low.Score, base.Score, "low remediation < neutral")
	})
}
