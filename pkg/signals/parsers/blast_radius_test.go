package parsers_test

import (
	"math"
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.BlastRadius{}

func TestBlastRadiusImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.BlastRadius{}
	assert.Equal(t, "blast_radius", s.Name())
	assert.NotEmpty(t, s.Description())
}

func TestBlastRadiusValidate(t *testing.T) {
	br := &parsers.BlastRadius{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid affected_systems only",
			input:   map[string]any{"affected_systems": 10},
			wantErr: false,
		},
		{
			name:    "valid affected_systems zero",
			input:   map[string]any{"affected_systems": 0},
			wantErr: false,
		},
		{
			name:    "valid lateral_movement_possible only",
			input:   map[string]any{"lateral_movement_possible": true},
			wantErr: false,
		},
		{
			name:    "valid both fields",
			input:   map[string]any{"affected_systems": 50, "lateral_movement_possible": false},
			wantErr: false,
		},
		{
			name:    "affected_systems negative",
			input:   map[string]any{"affected_systems": -1},
			wantErr: true,
		},
		{
			name:    "affected_systems wrong type",
			input:   map[string]any{"affected_systems": "many"},
			wantErr: true,
		},
		{
			name:    "lateral_movement_possible wrong type",
			input:   map[string]any{"lateral_movement_possible": "yes"},
			wantErr: true,
		},
		{
			name:    "empty map",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   100,
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
			err := br.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBlastRadiusNormalize(t *testing.T) {
	br := &parsers.BlastRadius{}

	tests := []struct {
		name  string
		input any
		check func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "affected_systems 0",
			input: map[string]any{"affected_systems": 0},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["blast_scope"], 0.0001)
			},
		},
		{
			name:  "affected_systems 1",
			input: map[string]any{"affected_systems": 1},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["blast_scope"], 0.0001)
			},
		},
		{
			name:  "affected_systems 10",
			input: map[string]any{"affected_systems": 10},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				// log10(10)/log10(1000) = 1/3
				expected := math.Log10(10) / math.Log10(1000)
				assert.InDelta(t, expected, ns["blast_scope"], 0.0001)
			},
		},
		{
			name:  "affected_systems 1000 (max)",
			input: map[string]any{"affected_systems": 1000},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["blast_scope"], 0.0001)
			},
		},
		{
			name:  "affected_systems 9999 (capped at 1.0)",
			input: map[string]any{"affected_systems": 9999},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["blast_scope"], 0.0001)
			},
		},
		{
			name:  "lateral_movement_possible true",
			input: map[string]any{"lateral_movement_possible": true},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["lateral_movement"], 0.0001)
			},
		},
		{
			name:  "lateral_movement_possible false",
			input: map[string]any{"lateral_movement_possible": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["lateral_movement"], 0.0001)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := br.Normalize(tt.input)
			require.NoError(t, err)
			tt.check(t, ns)
		})
	}
}

func TestBlastRadiusNormalizeInvalidInput(t *testing.T) {
	br := &parsers.BlastRadius{}

	_, err := br.Normalize("invalid")
	require.Error(t, err)

	_, err = br.Normalize(map[string]any{})
	require.Error(t, err)
}

func TestBlastRadiusFields(t *testing.T) {
	br := &parsers.BlastRadius{}
	fields := br.Fields()
	assert.Contains(t, fields, "affected_systems")
	assert.Contains(t, fields, "lateral_movement_possible")
}
