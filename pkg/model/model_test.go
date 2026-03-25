package model_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/model"
	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewModel(t *testing.T) {
	m := model.New()
	require.NotNil(t, m)
}

func TestModelVersion(t *testing.T) {
	m := model.New()
	assert.Equal(t, "0.2.0", m.Version())
}

func TestModelDeterminism(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 0.8, "nist_severity": 0.7},
		{"exploit_probability": 0.6, "active_exploitation": 1.0},
		{"asset_criticality": 0.7, "network_exposure": 1.0},
	}

	result1, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)

	result2, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)

	assert.Equal(t, result1.Score, result2.Score)
	assert.Equal(t, result1.Factors, result2.Factors)
}

func TestModelHighSeverity(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 1.0},
		{"active_exploitation": 1.0},
		{"asset_criticality": 1.0},
	}

	result, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)
	// Three strong signals covering base_vulnerability, exploitability, and environmental_context
	// should score meaningfully higher than low-severity baselines (~26).
	assert.GreaterOrEqual(t, result.Score, 50, "high severity inputs should score >= 50")
}

func TestModelLowSeverity(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 0.1},
	}

	result, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)
	assert.LessOrEqual(t, result.Score, 40, "low severity only should score <= 40")
}

func TestModelFactorSum(t *testing.T) {
	m := model.New()

	testCases := [][]signals.NormalizedSignal{
		{{"severity": 0.8}},
		{{"severity": 1.0}, {"active_exploitation": 1.0}, {"asset_criticality": 1.0}},
		{{"severity": 0.1}},
		{
			{"severity": 0.5, "nist_severity": 0.5},
			{"exploit_probability": 0.5, "exploit_percentile": 0.5, "active_exploitation": 0.0, "ransomware_risk": 0.0},
			{"asset_criticality": 0.5, "network_exposure": 0.5, "blast_scope": 0.5, "data_sensitivity": 0.5},
			{"remediation_available": 1.0, "patch_staleness": 0.5, "has_compensating_control": 0.0, "regulatory_severity": 0.3, "compliance_scope": 0.2},
			{"lateral_movement": 0.0, "blast_scope": 0.3},
		},
	}

	for _, sigs := range testCases {
		result, err := m.ScoreWeighted(sigs)
		require.NoError(t, err)

		total := 0
		for _, f := range result.Factors {
			total += f.Contribution
		}

		assert.Equal(t, result.Score, total,
			"factor contributions must sum exactly to the score")
	}
}

func TestModelScoreRange(t *testing.T) {
	m := model.New()

	testCases := [][]signals.NormalizedSignal{
		{},
		{{"severity": 0.0}},
		{{"severity": 1.0}},
		{{"severity": 1.0}, {"active_exploitation": 1.0}, {"asset_criticality": 1.0}, {"lateral_movement": 1.0}},
	}

	for _, sigs := range testCases {
		result, err := m.ScoreWeighted(sigs)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, result.Score, 0)
		assert.LessOrEqual(t, result.Score, 100)
	}
}

func TestModelFactorNames(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 0.5},
	}

	result, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)

	expectedNames := []string{
		"base_vulnerability",
		"exploitability",
		"environmental_context",
		"remediation_gap",
		"lateral_risk",
	}

	require.Len(t, result.Factors, len(expectedNames))

	for i, f := range result.Factors {
		assert.Equal(t, expectedNames[i], f.Name)
	}
}

func TestModelFactorWeights(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 0.5},
	}

	result, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)

	expectedWeights := map[string]float64{
		"base_vulnerability":    0.30,
		"exploitability":        0.25,
		"environmental_context": 0.20,
		"remediation_gap":       0.15,
		"lateral_risk":          0.10,
	}

	for _, f := range result.Factors {
		expected, ok := expectedWeights[f.Name]
		require.True(t, ok, "unexpected factor name: %s", f.Name)
		assert.InDelta(t, expected, f.Weight, 0.0001)
	}
}

func TestModelWeightsSumToOne(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 0.5},
	}

	result, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)

	var totalWeight float64

	for _, f := range result.Factors {
		totalWeight += f.Weight
	}

	assert.InDelta(t, 1.0, totalWeight, 0.0001,
		"dimension weights must sum to 1.0 to produce correct scores")
}

func TestModelEmptySignals(t *testing.T) {
	m := model.New()

	result, err := m.ScoreWeighted(nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)

	// With all defaults, factor sum must still equal score
	total := 0
	for _, f := range result.Factors {
		total += f.Contribution
	}

	assert.Equal(t, result.Score, total)
}

func TestModelRawScoreInRange(t *testing.T) {
	m := model.New()
	sigs := []signals.NormalizedSignal{
		{"severity": 0.7, "nist_severity": 0.5},
		{"exploit_probability": 0.4, "active_exploitation": 1.0},
	}

	result, err := m.ScoreWeighted(sigs)
	require.NoError(t, err)

	for _, f := range result.Factors {
		assert.GreaterOrEqual(t, f.RawScore, 0.0, "raw score must be >= 0 for factor %s", f.Name)
		assert.LessOrEqual(t, f.RawScore, 1.0, "raw score must be <= 1 for factor %s", f.Name)
	}
}
