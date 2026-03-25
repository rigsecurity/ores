package engine_test

import (
	"context"
	"testing"

	"github.com/rigsecurity/ores/pkg/engine"
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
	assert.Equal(t, "0.1.0-preview", result.Version)
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
	assert.Equal(t, "0.1.0-preview", e.Version())
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
