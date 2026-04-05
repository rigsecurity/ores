package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.Patch{}

func TestPatchImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.Patch{}
	assert.Equal(t, "patch", s.Name())
	assert.NotEmpty(t, s.Description())
}

func TestPatchValidate(t *testing.T) {
	p := &parsers.Patch{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid patch_available only",
			input:   map[string]any{"patch_available": true},
			wantErr: false,
		},
		{
			name:    "valid patch_age_days only",
			input:   map[string]any{"patch_age_days": 30},
			wantErr: false,
		},
		{
			name:    "valid compensating_control only",
			input:   map[string]any{"compensating_control": false},
			wantErr: false,
		},
		{
			name:    "valid all fields",
			input:   map[string]any{"patch_available": true, "patch_age_days": 45, "compensating_control": false},
			wantErr: false,
		},
		{
			name:    "valid patch_age_days zero",
			input:   map[string]any{"patch_age_days": 0},
			wantErr: false,
		},
		{
			name:    "patch_age_days negative",
			input:   map[string]any{"patch_age_days": -1},
			wantErr: true,
		},
		{
			name:    "patch_available wrong type",
			input:   map[string]any{"patch_available": "yes"},
			wantErr: true,
		},
		{
			name:    "patch_age_days wrong type",
			input:   map[string]any{"patch_age_days": "30"},
			wantErr: true,
		},
		{
			name:    "compensating_control wrong type",
			input:   map[string]any{"compensating_control": 0},
			wantErr: true,
		},
		{
			name:    "empty map",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   "patch",
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
			err := p.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPatchNormalize(t *testing.T) {
	p := &parsers.Patch{}

	tests := []struct {
		name  string
		input any
		check func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "patch_available true",
			input: map[string]any{"patch_available": true},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["remediation_available"], 0.0001)
			},
		},
		{
			name:  "patch_available false",
			input: map[string]any{"patch_available": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["remediation_available"], 0.0001)
			},
		},
		{
			name:  "patch_age_days 0 with patch_available true",
			input: map[string]any{"patch_available": true, "patch_age_days": 0},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["patch_staleness"], 0.0001)
			},
		},
		{
			name:  "patch_age_days 45 with patch_available true",
			input: map[string]any{"patch_available": true, "patch_age_days": 45},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				// 45/90 = 0.5
				assert.InDelta(t, 0.5, ns["patch_staleness"], 0.0001)
			},
		},
		{
			name:  "patch_age_days 90 with patch_available true (max)",
			input: map[string]any{"patch_available": true, "patch_age_days": 90},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["patch_staleness"], 0.0001)
			},
		},
		{
			name:  "patch_age_days 180 with patch_available true (capped at 1.0)",
			input: map[string]any{"patch_available": true, "patch_age_days": 180},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["patch_staleness"], 0.0001)
			},
		},
		{
			name:  "patch_age_days with patch_available false (staleness 0.0)",
			input: map[string]any{"patch_available": false, "patch_age_days": 90},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["patch_staleness"], 0.0001)
			},
		},
		{
			name:  "patch_age_days only (no patch_available, staleness 0.0)",
			input: map[string]any{"patch_age_days": 90},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["patch_staleness"], 0.0001)
			},
		},
		{
			name:  "compensating_control true",
			input: map[string]any{"compensating_control": true},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["has_compensating_control"], 0.0001)
			},
		},
		{
			name:  "compensating_control false",
			input: map[string]any{"compensating_control": false},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.0, ns["has_compensating_control"], 0.0001)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := p.Normalize(tt.input)
			require.NoError(t, err)
			tt.check(t, ns)
		})
	}
}

func TestPatchNormalizeInvalidInput(t *testing.T) {
	p := &parsers.Patch{}

	_, err := p.Normalize("invalid")
	require.Error(t, err)

	_, err = p.Normalize(map[string]any{})
	require.Error(t, err)
}

func TestPatchFields(t *testing.T) {
	p := &parsers.Patch{}
	fields := p.Fields()
	assert.Contains(t, fields, "patch_available")
	assert.Contains(t, fields, "patch_age_days")
	assert.Contains(t, fields, "compensating_control")
}

func TestPatchAvailableWithoutAgeDays(t *testing.T) {
	p := &parsers.Patch{}
	ns, err := p.Normalize(map[string]any{"patch_available": true})
	require.NoError(t, err)
	assert.InDelta(t, 1.0, ns["remediation_available"], 0.001)
	_, hasStaleness := ns["patch_staleness"]
	assert.False(t, hasStaleness, "patch_staleness should not be emitted when patch_age_days is absent")
}
