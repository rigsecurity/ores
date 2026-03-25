package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.ThreatIntel{}

func TestThreatIntelImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.ThreatIntel{}
	assert.Equal(t, "threat_intel", s.Name())
}

func TestThreatIntelValidate(t *testing.T) {
	ti := &parsers.ThreatIntel{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid actively_exploited only",
			input:   map[string]any{"actively_exploited": true},
			wantErr: false,
		},
		{
			name:    "valid ransomware_associated only",
			input:   map[string]any{"ransomware_associated": false},
			wantErr: false,
		},
		{
			name:    "valid both fields",
			input:   map[string]any{"actively_exploited": true, "ransomware_associated": true},
			wantErr: false,
		},
		{
			name:    "empty map",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "actively_exploited wrong type",
			input:   map[string]any{"actively_exploited": "yes"},
			wantErr: true,
		},
		{
			name:    "ransomware_associated wrong type",
			input:   map[string]any{"ransomware_associated": 1},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   true,
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
			err := ti.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestThreatIntelNormalize(t *testing.T) {
	ti := &parsers.ThreatIntel{}

	tests := []struct {
		name  string
		input any
		check func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "actively_exploited true",
			input: map[string]any{"actively_exploited": true},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["active_exploitation"], 0.0001)
			},
		},
		{
			name:  "actively_exploited false",
			input: map[string]any{"actively_exploited": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["active_exploitation"], 0.0001)
			},
		},
		{
			name:  "ransomware_associated true",
			input: map[string]any{"ransomware_associated": true},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["ransomware_risk"], 0.0001)
			},
		},
		{
			name:  "ransomware_associated false",
			input: map[string]any{"ransomware_associated": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["ransomware_risk"], 0.0001)
			},
		},
		{
			name:  "both fields",
			input: map[string]any{"actively_exploited": true, "ransomware_associated": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["active_exploitation"], 0.0001)
				assert.InDelta(t, 0.0, ns["ransomware_risk"], 0.0001)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := ti.Normalize(tt.input)
			require.NoError(t, err)
			tt.check(t, ns)
		})
	}
}

func TestThreatIntelFields(t *testing.T) {
	ti := &parsers.ThreatIntel{}
	fields := ti.Fields()
	assert.Contains(t, fields, "actively_exploited")
	assert.Contains(t, fields, "ransomware_associated")
}
