package score_test

import (
	"encoding/json"
	"testing"

	"github.com/rigsecurity/ores/pkg/score"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelForScore(t *testing.T) {
	tests := []struct {
		name     string
		score    int
		expected score.Label
	}{
		{"critical high", 100, score.LabelCritical},
		{"critical low", 90, score.LabelCritical},
		{"high high", 89, score.LabelHigh},
		{"high low", 70, score.LabelHigh},
		{"medium high", 69, score.LabelMedium},
		{"medium low", 40, score.LabelMedium},
		{"low high", 39, score.LabelLow},
		{"low low", 10, score.LabelLow},
		{"info high", 9, score.LabelInfo},
		{"info low", 0, score.LabelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, score.LabelForScore(tt.score))
		})
	}
}

func TestEvaluationResultJSON(t *testing.T) {
	result := score.EvaluationResult{
		APIVersion: score.APIVersion,
		Kind:       score.KindEvaluationResult,
		Score:      94,
		Label:      score.LabelCritical,
		Version:    "0.2.0",
		Explanation: score.Explanation{
			SignalsProvided: 2,
			SignalsUsed:     2,
			SignalsUnknown:  0,
			UnknownSignals:  []string{},
			Warnings:        []string{},
			Confidence:      0.45,
			Factors: []score.Factor{
				{
					Name:         "base_vulnerability",
					Contribution: 60,
					DerivedFrom:  []string{"cvss"},
					Reasoning:    "High base severity",
				},
				{
					Name:         "exploitability",
					Contribution: 34,
					DerivedFrom:  []string{"epss"},
					Reasoning:    "High exploit probability",
				},
			},
		},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded score.EvaluationResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result, decoded)
}

func TestEvaluationRequestValidation(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Signals:    map[string]any{"cvss": map[string]any{"base_score": 8.1}},
		}
		assert.NoError(t, req.Validate())
	})

	t.Run("missing api version", func(t *testing.T) {
		req := score.EvaluationRequest{
			Kind:    score.KindEvaluationRequest,
			Signals: map[string]any{"cvss": map[string]any{"base_score": 8.1}},
		}
		assert.Error(t, req.Validate())
	})

	t.Run("wrong api version", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: "ores.dev/v999",
			Kind:       score.KindEvaluationRequest,
			Signals:    map[string]any{"cvss": map[string]any{"base_score": 8.1}},
		}
		assert.Error(t, req.Validate())
	})

	t.Run("empty signals", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Signals:    map[string]any{},
		}
		assert.Error(t, req.Validate())
	})

	t.Run("wrong kind", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       "WrongKind",
			Signals:    map[string]any{"cvss": map[string]any{"base_score": 5.0}},
		}
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected kind")
	})

	t.Run("nil signals", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Signals:    nil,
		}
		assert.Error(t, req.Validate())
	})
}

func TestEvaluationRequestValidationWithFindings(t *testing.T) {
	t.Run("valid findings with signals", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Findings:   []float64{7.5, 9.0, 3.2},
			Signals:    map[string]any{"cvss": map[string]any{"base_score": 8.1}},
		}
		assert.NoError(t, req.Validate())
	})

	t.Run("valid findings without signals", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Findings:   []float64{5.0, 8.5},
		}
		assert.NoError(t, req.Validate())
	})

	t.Run("finding out of range high", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Findings:   []float64{5.0, 10.1},
		}
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "finding[1]")
	})

	t.Run("finding out of range negative", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Findings:   []float64{-0.1, 5.0},
		}
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "finding[0]")
	})

	t.Run("empty findings falls through to require signals", func(t *testing.T) {
		req := score.EvaluationRequest{
			APIVersion: score.APIVersion,
			Kind:       score.KindEvaluationRequest,
			Findings:   []float64{},
		}
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one signal is required")
	})
}

func TestEvaluationResultHasMode(t *testing.T) {
	result := score.EvaluationResult{
		APIVersion: score.APIVersion,
		Kind:       score.KindEvaluationResult,
		Score:      75,
		Label:      score.LabelHigh,
		Mode:       "findings",
		Version:    "0.2.0",
		Explanation: score.Explanation{
			FindingsCount:  3,
			Confidence:     0.8,
			UnknownSignals: []string{},
			Warnings:       []string{},
			Factors:        []score.Factor{},
		},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded score.EvaluationResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "findings", decoded.Mode)
	assert.Equal(t, 3, decoded.Explanation.FindingsCount)
}
