package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.Asset{}

func TestAssetImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.Asset{}
	assert.Equal(t, "asset", s.Name())
}

func TestAssetValidate(t *testing.T) {
	a := &parsers.Asset{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid criticality only",
			input:   map[string]any{"criticality": "low"},
			wantErr: false,
		},
		{
			name:    "valid criticality medium",
			input:   map[string]any{"criticality": "medium"},
			wantErr: false,
		},
		{
			name:    "valid criticality high",
			input:   map[string]any{"criticality": "high"},
			wantErr: false,
		},
		{
			name:    "valid criticality crown_jewel",
			input:   map[string]any{"criticality": "crown_jewel"},
			wantErr: false,
		},
		{
			name:    "valid network_exposure only",
			input:   map[string]any{"network_exposure": true},
			wantErr: false,
		},
		{
			name:    "valid data_classification only",
			input:   map[string]any{"data_classification": "public"},
			wantErr: false,
		},
		{
			name:    "valid all fields",
			input:   map[string]any{"criticality": "high", "network_exposure": true, "data_classification": "pii"},
			wantErr: false,
		},
		{
			name:    "invalid criticality value",
			input:   map[string]any{"criticality": "extreme"},
			wantErr: true,
		},
		{
			name:    "invalid data_classification value",
			input:   map[string]any{"data_classification": "top_secret"},
			wantErr: true,
		},
		{
			name:    "criticality wrong type",
			input:   map[string]any{"criticality": 3},
			wantErr: true,
		},
		{
			name:    "network_exposure wrong type",
			input:   map[string]any{"network_exposure": "yes"},
			wantErr: true,
		},
		{
			name:    "empty map",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   "high",
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
			err := a.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAssetNormalize(t *testing.T) {
	a := &parsers.Asset{}

	tests := []struct {
		name  string
		input any
		check func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "criticality low",
			input: map[string]any{"criticality": "low"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.2, ns["asset_criticality"], 0.0001)
			},
		},
		{
			name:  "criticality medium",
			input: map[string]any{"criticality": "medium"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.5, ns["asset_criticality"], 0.0001)
			},
		},
		{
			name:  "criticality high",
			input: map[string]any{"criticality": "high"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.7, ns["asset_criticality"], 0.0001)
			},
		},
		{
			name:  "criticality crown_jewel",
			input: map[string]any{"criticality": "crown_jewel"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["asset_criticality"], 0.0001)
			},
		},
		{
			name:  "network_exposure true",
			input: map[string]any{"network_exposure": true},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["network_exposure"], 0.0001)
			},
		},
		{
			name:  "network_exposure false",
			input: map[string]any{"network_exposure": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["network_exposure"], 0.0001)
			},
		},
		{
			name:  "data_classification public",
			input: map[string]any{"data_classification": "public"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.1, ns["data_sensitivity"], 0.0001)
			},
		},
		{
			name:  "data_classification internal",
			input: map[string]any{"data_classification": "internal"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.3, ns["data_sensitivity"], 0.0001)
			},
		},
		{
			name:  "data_classification confidential",
			input: map[string]any{"data_classification": "confidential"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.6, ns["data_sensitivity"], 0.0001)
			},
		},
		{
			name:  "data_classification pii",
			input: map[string]any{"data_classification": "pii"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.8, ns["data_sensitivity"], 0.0001)
			},
		},
		{
			name:  "data_classification restricted",
			input: map[string]any{"data_classification": "restricted"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["data_sensitivity"], 0.0001)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := a.Normalize(tt.input)
			require.NoError(t, err)
			tt.check(t, ns)
		})
	}
}

func TestAssetFields(t *testing.T) {
	a := &parsers.Asset{}
	fields := a.Fields()
	assert.Contains(t, fields, "criticality")
	assert.Contains(t, fields, "network_exposure")
	assert.Contains(t, fields, "data_classification")
}
