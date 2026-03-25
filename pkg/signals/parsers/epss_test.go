package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.EPSS{}

func TestEPSSImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.EPSS{}
	assert.Equal(t, "epss", s.Name())
	assert.NotEmpty(t, s.Description())
}

func TestEPSSValidate(t *testing.T) {
	e := &parsers.EPSS{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid probability only",
			input:   map[string]any{"probability": 0.5},
			wantErr: false,
		},
		{
			name:    "valid percentile only",
			input:   map[string]any{"percentile": 0.8},
			wantErr: false,
		},
		{
			name:    "valid both fields",
			input:   map[string]any{"probability": 0.1, "percentile": 0.9},
			wantErr: false,
		},
		{
			name:    "valid probability zero",
			input:   map[string]any{"probability": 0.0},
			wantErr: false,
		},
		{
			name:    "valid probability one",
			input:   map[string]any{"probability": 1.0},
			wantErr: false,
		},
		{
			name:    "missing both fields",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "probability below range",
			input:   map[string]any{"probability": -0.01},
			wantErr: true,
		},
		{
			name:    "probability above range",
			input:   map[string]any{"probability": 1.01},
			wantErr: true,
		},
		{
			name:    "percentile below range",
			input:   map[string]any{"percentile": -0.01},
			wantErr: true,
		},
		{
			name:    "percentile above range",
			input:   map[string]any{"percentile": 1.01},
			wantErr: true,
		},
		{
			name:    "probability wrong type",
			input:   map[string]any{"probability": "high"},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   42,
			wantErr: true,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEPSSNormalize(t *testing.T) {
	e := &parsers.EPSS{}

	tests := []struct {
		name  string
		input any
		check func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "probability 0.5",
			input: map[string]any{"probability": 0.5},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.5, ns["exploit_probability"], 0.0001)
			},
		},
		{
			name:  "percentile 0.9",
			input: map[string]any{"percentile": 0.9},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.9, ns["exploit_percentile"], 0.0001)
			},
		},
		{
			name:  "both fields",
			input: map[string]any{"probability": 0.3, "percentile": 0.7},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.3, ns["exploit_probability"], 0.0001)
				assert.InDelta(t, 0.7, ns["exploit_percentile"], 0.0001)
			},
		},
		{
			name:  "probability zero",
			input: map[string]any{"probability": 0.0},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["exploit_probability"], 0.0001)
			},
		},
		{
			name:  "probability one",
			input: map[string]any{"probability": 1.0},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["exploit_probability"], 0.0001)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := e.Normalize(tt.input)
			require.NoError(t, err)
			tt.check(t, ns)
		})
	}
}

func TestEPSSNormalizeInvalidInput(t *testing.T) {
	e := &parsers.EPSS{}

	_, err := e.Normalize("invalid")
	require.Error(t, err)

	_, err = e.Normalize(map[string]any{"probability": 5.0})
	require.Error(t, err)
}

func TestEPSSFields(t *testing.T) {
	e := &parsers.EPSS{}
	fields := e.Fields()
	assert.Contains(t, fields, "probability")
	assert.Contains(t, fields, "percentile")
}
