package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.CVSS{}

func TestCVSSImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.CVSS{}
	assert.Equal(t, "cvss", s.Name())
}

func TestCVSSValidate(t *testing.T) {
	c := &parsers.CVSS{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid base_score",
			input:   map[string]any{"base_score": 7.5},
			wantErr: false,
		},
		{
			name:    "valid base_score zero",
			input:   map[string]any{"base_score": 0.0},
			wantErr: false,
		},
		{
			name:    "valid base_score ten",
			input:   map[string]any{"base_score": 10.0},
			wantErr: false,
		},
		{
			name:    "valid vector only",
			input:   map[string]any{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
			wantErr: false,
		},
		{
			name:    "valid base_score and vector",
			input:   map[string]any{"base_score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
			wantErr: false,
		},
		{
			name:    "missing both fields",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "base_score below range",
			input:   map[string]any{"base_score": -0.1},
			wantErr: true,
		},
		{
			name:    "base_score above range",
			input:   map[string]any{"base_score": 10.1},
			wantErr: true,
		},
		{
			name:    "base_score wrong type",
			input:   map[string]any{"base_score": "high"},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   "invalid",
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
			err := c.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCVSSNormalize(t *testing.T) {
	c := &parsers.CVSS{}

	tests := []struct {
		name     string
		input    any
		wantKeys []string
		check    func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "base_score 7.5",
			input: map[string]any{"base_score": 7.5},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.75, ns["severity"], 0.0001)
			},
		},
		{
			name:  "base_score 0.0",
			input: map[string]any{"base_score": 0.0},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["severity"], 0.0001)
			},
		},
		{
			name:  "base_score 10.0",
			input: map[string]any{"base_score": 10.0},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["severity"], 0.0001)
			},
		},
		{
			name:  "vector only (no severity factor)",
			input: map[string]any{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				_, hasSeverity := ns["severity"]
				assert.False(t, hasSeverity)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := c.Normalize(tt.input)
			require.NoError(t, err)
			tt.check(t, ns)
		})
	}
}

func TestCVSSFields(t *testing.T) {
	c := &parsers.CVSS{}
	fields := c.Fields()
	assert.Contains(t, fields, "base_score")
	assert.Contains(t, fields, "vector")
}
