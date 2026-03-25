package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.NIST{}

func TestNISTImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.NIST{}
	assert.Equal(t, "nist", s.Name())
	assert.NotEmpty(t, s.Description())
}

func TestNISTValidate(t *testing.T) {
	n := &parsers.NIST{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid info",
			input:   map[string]any{"severity": "info"},
			wantErr: false,
		},
		{
			name:    "valid low",
			input:   map[string]any{"severity": "low"},
			wantErr: false,
		},
		{
			name:    "valid medium",
			input:   map[string]any{"severity": "medium"},
			wantErr: false,
		},
		{
			name:    "valid high",
			input:   map[string]any{"severity": "high"},
			wantErr: false,
		},
		{
			name:    "valid critical",
			input:   map[string]any{"severity": "critical"},
			wantErr: false,
		},
		{
			name:    "valid severity with cwe",
			input:   map[string]any{"severity": "high", "cwe": "CWE-79"},
			wantErr: false,
		},
		{
			name:    "invalid severity value",
			input:   map[string]any{"severity": "extreme"},
			wantErr: true,
		},
		{
			name:    "missing severity",
			input:   map[string]any{"cwe": "CWE-79"},
			wantErr: true,
		},
		{
			name:    "empty map",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "severity wrong type",
			input:   map[string]any{"severity": 5},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   "critical",
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
			err := n.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNISTNormalize(t *testing.T) {
	n := &parsers.NIST{}

	tests := []struct {
		name         string
		input        any
		wantSeverity float64
	}{
		{name: "info", input: map[string]any{"severity": "info"}, wantSeverity: 0.1},
		{name: "low", input: map[string]any{"severity": "low"}, wantSeverity: 0.3},
		{name: "medium", input: map[string]any{"severity": "medium"}, wantSeverity: 0.5},
		{name: "high", input: map[string]any{"severity": "high"}, wantSeverity: 0.7},
		{name: "critical", input: map[string]any{"severity": "critical"}, wantSeverity: 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := n.Normalize(tt.input)
			require.NoError(t, err)
			assert.InDelta(t, tt.wantSeverity, ns["nist_severity"], 0.0001)
		})
	}
}

func TestNISTNormalizeInvalidInput(t *testing.T) {
	n := &parsers.NIST{}

	_, err := n.Normalize("invalid")
	require.Error(t, err)

	_, err = n.Normalize(map[string]any{"severity": "extreme"})
	require.Error(t, err)
}

func TestNISTFields(t *testing.T) {
	n := &parsers.NIST{}
	fields := n.Fields()
	assert.Contains(t, fields, "severity")
	assert.Contains(t, fields, "cwe")
}
