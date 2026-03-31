package engine_test

import (
	"context"
	"testing"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/model"
	"github.com/rigsecurity/ores/pkg/score"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validRequest(signals map[string]any) *score.EvaluationRequest {
	return &score.EvaluationRequest{
		APIVersion: score.APIVersion,
		Kind:       score.KindEvaluationRequest,
		Signals:    signals,
	}
}

func b4Request(findings []float64, signals map[string]any) *score.EvaluationRequest {
	return &score.EvaluationRequest{
		APIVersion: score.APIVersion,
		Kind:       score.KindEvaluationRequest,
		Findings:   findings,
		Signals:    signals,
	}
}

func TestEngineEvaluate(t *testing.T) {
	e := engine.New()
	req := validRequest(map[string]any{
		"cvss": map[string]any{"base_score": 7.5},
		"epss": map[string]any{"probability": 0.6, "percentile": 0.8},
	})

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, score.APIVersion, result.APIVersion)
	assert.Equal(t, score.KindEvaluationResult, result.Kind)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
	assert.NotEmpty(t, string(result.Label))
	assert.Equal(t, model.ModelVersion, result.Version)
	assert.Equal(t, "weighted", result.Mode)
	assert.Greater(t, result.Explanation.Confidence, 0.0)

	// Factor contributions must sum to the total score.
	total := 0
	for _, f := range result.Explanation.Factors {
		total += f.Contribution
	}

	assert.Equal(t, result.Score, total)
}

func TestEngineEvaluateInvalidRequest(t *testing.T) {
	e := engine.New()

	t.Run("missing api version", func(t *testing.T) {
		req := &score.EvaluationRequest{
			Kind:    score.KindEvaluationRequest,
			Signals: map[string]any{"cvss": map[string]any{"base_score": 5.0}},
		}
		_, err := e.Evaluate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid request")
	})

	t.Run("no signals", func(t *testing.T) {
		req := &score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Signals:    map[string]any{},
		}
		_, err := e.Evaluate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid request")
	})
}

func TestEngineEvaluateWithUnknownSignals(t *testing.T) {
	e := engine.New()
	req := validRequest(map[string]any{
		"cvss":          map[string]any{"base_score": 6.0},
		"unknown_thing": map[string]any{"value": 42},
	})

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 2, result.Explanation.SignalsProvided)
	assert.Equal(t, 1, result.Explanation.SignalsUsed)
	assert.Equal(t, 1, result.Explanation.SignalsUnknown)
	assert.Equal(t, []string{"unknown_thing"}, result.Explanation.UnknownSignals)
}

func TestEngineEvaluateWithInvalidSignalValues(t *testing.T) {
	e := engine.New()
	req := validRequest(map[string]any{
		"cvss": map[string]any{"base_score": 15.0}, // out of range
		"epss": map[string]any{"probability": 0.4},
	})

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.Explanation.SignalsUsed)
	require.Len(t, result.Explanation.Warnings, 1)
	assert.Contains(t, result.Explanation.Warnings[0], "cvss")
}

func TestEngineEvaluateAllSignalsInvalid(t *testing.T) {
	e := engine.New()
	req := validRequest(map[string]any{
		"cvss": map[string]any{"base_score": 99.0},  // invalid
		"epss": map[string]any{"probability": -1.0}, // invalid
	})

	_, err := e.Evaluate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid signals")
}

func TestEngineSignals(t *testing.T) {
	e := engine.New()
	descs := e.Signals()

	assert.Len(t, descs, 8)

	// Verify sorted order.
	for i := 1; i < len(descs); i++ {
		assert.Less(t, descs[i-1].Name, descs[i].Name, "signal descriptors should be sorted by name")
	}

	// Spot-check names and fields are non-empty.
	for _, d := range descs {
		assert.NotEmpty(t, d.Name)
		assert.NotEmpty(t, d.Description)
		assert.NotEmpty(t, d.Fields)
	}
}

func TestEngineVersion(t *testing.T) {
	e := engine.New()
	assert.Equal(t, model.ModelVersion, e.Version())
}

func TestEngineEvaluateB4Mode(t *testing.T) {
	e := engine.New()
	req := b4Request(
		[]float64{8.5, 6.0, 4.2},
		map[string]any{
			"asset":        map[string]any{"criticality": "high", "network_exposure": true},
			"blast_radius": map[string]any{"affected_systems": 50, "lateral_movement_possible": true},
		},
	)

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "b4", result.Mode)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
	assert.Positive(t, result.Explanation.FindingsCount)
}

func TestEngineEvaluateWeightedMode(t *testing.T) {
	e := engine.New()
	req := validRequest(map[string]any{
		"cvss": map[string]any{"base_score": 7.5},
		"epss": map[string]any{"probability": 0.6, "percentile": 0.8},
	})

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "weighted", result.Mode)
}

func TestEngineEvaluateB4FindingsOnly(t *testing.T) {
	e := engine.New()
	req := b4Request([]float64{7.0, 5.0}, nil)

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "b4", result.Mode)
	assert.InDelta(t, 0.0, result.Explanation.Confidence, 0.0001)
}

func TestEngineEvaluateB4EmptyFindingsFallsThrough(t *testing.T) {
	e := engine.New()
	req := b4Request(
		[]float64{},
		map[string]any{
			"cvss": map[string]any{"base_score": 7.5},
		},
	)

	result, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "weighted", result.Mode)
}

func TestEngineEvaluateB4IgnoresSeveritySignals(t *testing.T) {
	e := engine.New()

	// B4 request with a CVSS signal — should be ignored, score driven by findings only.
	reqB4 := b4Request(
		[]float64{5.0},
		map[string]any{
			"cvss": map[string]any{"base_score": 10.0}, // severity signal, must be ignored
		},
	)
	resultB4, err := e.Evaluate(context.Background(), reqB4)
	require.NoError(t, err)
	require.NotNil(t, resultB4)

	assert.Equal(t, "b4", resultB4.Mode)

	// Findings-only B4 with the same finding — score must be identical.
	reqFindingsOnly := b4Request([]float64{5.0}, nil)
	resultFindingsOnly, err := e.Evaluate(context.Background(), reqFindingsOnly)
	require.NoError(t, err)

	assert.Equal(t, resultFindingsOnly.Score, resultB4.Score,
		"CVSS signal should be ignored in B4 mode; score should match findings-only result")
}

func TestEngineEvaluateB4FindingsValidation(t *testing.T) {
	e := engine.New()
	req := b4Request([]float64{5.0, 11.0}, nil) // 11.0 is out of [0, 10]

	_, err := e.Evaluate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid request")
}

func TestEngineDeterminism(t *testing.T) {
	e := engine.New()
	req := validRequest(map[string]any{
		"cvss": map[string]any{"base_score": 7.5},
		"epss": map[string]any{"probability": 0.6, "percentile": 0.8},
		"nist": map[string]any{"severity": "high"},
	})

	result1, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)

	result2, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, result1.Score, result2.Score)
	assert.Equal(t, result1.Explanation.Factors, result2.Explanation.Factors)
}
