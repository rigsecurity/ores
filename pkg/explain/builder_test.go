package explain_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/explain"
	"github.com/rigsecurity/ores/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNormal(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "base_vulnerability", RawScore: 0.8, Weight: 0.30, Contribution: 24},
		{Name: "exploitability", RawScore: 0.5, Weight: 0.25, Contribution: 12},
	}
	provided := map[string]bool{
		"cvss": true,
		"epss": true,
		"nist": true,
	}

	explanation := explain.Build(contributions, provided, nil, nil, 0.65, 3)

	require.Len(t, explanation.Factors, 2)
	assert.Equal(t, 3, explanation.SignalsProvided)
	assert.Equal(t, 3, explanation.SignalsUsed)
	assert.Equal(t, 0, explanation.SignalsUnknown)
	assert.InDelta(t, 0.65, explanation.Confidence, 0.0001)

	f0 := explanation.Factors[0]
	assert.Equal(t, "base_vulnerability", f0.Name)
	assert.Equal(t, 24, f0.Contribution)
	assert.NotEmpty(t, f0.Reasoning)
	assert.Contains(t, f0.Reasoning, "high") // rawScore 0.8 >= 0.7

	f1 := explanation.Factors[1]
	assert.Equal(t, "exploitability", f1.Name)
	assert.Equal(t, 12, f1.Contribution)
	assert.NotEmpty(t, f1.Reasoning)
	assert.Contains(t, f1.Reasoning, "moderate") // rawScore 0.5 is moderate
}

func TestBuildWithUnknownSignals(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "base_vulnerability", RawScore: 0.5, Weight: 0.30, Contribution: 15},
	}
	provided := map[string]bool{
		"cvss": true,
	}
	unknownSignals := []string{"foo_signal", "bar_signal"}

	explanation := explain.Build(contributions, provided, unknownSignals, nil, 0.15, 3)

	assert.Equal(t, 3, explanation.SignalsProvided)
	assert.Equal(t, 1, explanation.SignalsUsed)
	assert.Equal(t, 2, explanation.SignalsUnknown)
	assert.Equal(t, []string{"foo_signal", "bar_signal"}, explanation.UnknownSignals)
	assert.Empty(t, explanation.Warnings)
}

func TestBuildWithWarnings(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "base_vulnerability", RawScore: 0.6, Weight: 0.30, Contribution: 18},
	}
	provided := map[string]bool{
		"cvss": true,
	}
	warnings := []string{"epss: probability must be in [0, 1], got 1.5"}

	explanation := explain.Build(contributions, provided, nil, warnings, 0.15, 2)

	assert.Equal(t, 2, explanation.SignalsProvided)
	assert.Equal(t, 1, explanation.SignalsUsed)
	require.Len(t, explanation.Warnings, 1)
	assert.Contains(t, explanation.Warnings[0], "epss")
}

func TestBuildDerivedFromMatchesProvided(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "base_vulnerability", RawScore: 0.7, Weight: 0.30, Contribution: 21},
	}
	// Only cvss provided, not nist.
	provided := map[string]bool{
		"cvss": true,
	}

	explanation := explain.Build(contributions, provided, nil, nil, 0.15, 1)

	require.Len(t, explanation.Factors, 1)
	assert.Equal(t, []string{"cvss"}, explanation.Factors[0].DerivedFrom)
}

func TestBuildDerivedFromDefaultsWhenNoneProvided(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "lateral_risk", RawScore: 0.2, Weight: 0.10, Contribution: 2},
	}
	// blast_radius not in provided, so derived should fall back to defaults.
	provided := map[string]bool{
		"cvss": true,
	}

	explanation := explain.Build(contributions, provided, nil, nil, 0.15, 1)

	require.Len(t, explanation.Factors, 1)
	assert.Equal(t, []string{"defaults"}, explanation.Factors[0].DerivedFrom)
}

func TestBuildNilSlicesInitialized(t *testing.T) {
	contributions := []model.FactorContribution{}
	provided := map[string]bool{}

	explanation := explain.Build(contributions, provided, nil, nil, 0.0, 0)

	assert.NotNil(t, explanation.UnknownSignals)
	assert.NotNil(t, explanation.Warnings)
}

func TestBuildReasoningLevels(t *testing.T) {
	tests := []struct {
		rawScore  float64
		wantLevel string
	}{
		{0.9, "high"},
		{0.7, "high"},
		{0.5, "moderate"},
		{0.3, "low"},
		{0.1, "low"},
	}

	for _, tt := range tests {
		contributions := []model.FactorContribution{
			{Name: "base_vulnerability", RawScore: tt.rawScore, Weight: 0.30, Contribution: 10},
		}

		explanation := explain.Build(contributions, map[string]bool{}, nil, nil, 0.0, 0)

		require.Len(t, explanation.Factors, 1)
		assert.Contains(t, explanation.Factors[0].Reasoning, tt.wantLevel,
			"rawScore %.1f should produce level %q", tt.rawScore, tt.wantLevel)
	}
}

func TestBuildB4Normal(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "base_finding", RawScore: 9.8, Weight: 0, Contribution: 93},
		{Name: "additional_findings", RawScore: 0.5, Weight: 0, Contribution: 10},
		{Name: "environmental_adjust", RawScore: 0.7, Weight: 0, Contribution: 5},
		{Name: "blast_radius_adjust", RawScore: 0.6, Weight: 0, Contribution: 3},
		{Name: "remediation_adjust", RawScore: 0.3, Weight: 0, Contribution: -2},
	}
	provided := map[string]bool{"asset": true, "blast_radius": true, "patch": true}

	explanation := explain.BuildB4(contributions, provided, nil, nil, 1.0, 3)

	require.Len(t, explanation.Factors, 5)
	assert.Equal(t, 3, explanation.FindingsCount)
	assert.InDelta(t, 1.0, explanation.Confidence, 0.0001)
	assert.Equal(t, []string{"findings"}, explanation.Factors[0].DerivedFrom)
	assert.Contains(t, explanation.Factors[0].Reasoning, "critical finding")
	assert.Contains(t, explanation.Factors[2].DerivedFrom, "asset")
}

func TestBuildB4NoSignals(t *testing.T) {
	contributions := []model.FactorContribution{
		{Name: "base_finding", RawScore: 5.0, Weight: 0, Contribution: 45},
		{Name: "additional_findings", RawScore: 0.0, Weight: 0, Contribution: 0},
		{Name: "environmental_adjust", RawScore: 0.5, Weight: 0, Contribution: 0},
		{Name: "blast_radius_adjust", RawScore: 0.5, Weight: 0, Contribution: 0},
		{Name: "remediation_adjust", RawScore: 0.5, Weight: 0, Contribution: 0},
	}

	explanation := explain.BuildB4(contributions, map[string]bool{}, nil, nil, 0.0, 1)

	assert.Equal(t, 1, explanation.FindingsCount)
	assert.InDelta(t, 0.0, explanation.Confidence, 0.0001)
	assert.NotNil(t, explanation.UnknownSignals)
	assert.NotNil(t, explanation.Warnings)
}

func TestBuildB4NilSlicesInitialized(t *testing.T) {
	contributions := []model.FactorContribution{}
	explanation := explain.BuildB4(contributions, map[string]bool{}, nil, nil, 0.0, 0)
	assert.NotNil(t, explanation.UnknownSignals)
	assert.NotNil(t, explanation.Warnings)
}
