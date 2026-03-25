package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ signals.Signal = &parsers.Compliance{}

func TestComplianceImplementsSignal(t *testing.T) {
	var s signals.Signal = &parsers.Compliance{}
	assert.Equal(t, "compliance", s.Name())
	assert.NotEmpty(t, s.Description())
}

func TestComplianceValidate(t *testing.T) {
	c := &parsers.Compliance{}

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "valid frameworks_affected only",
			input:   map[string]any{"frameworks_affected": []any{"PCI-DSS", "HIPAA"}},
			wantErr: false,
		},
		{
			name:    "valid regulatory_impact only",
			input:   map[string]any{"regulatory_impact": "high"},
			wantErr: false,
		},
		{
			name:    "valid both fields",
			input:   map[string]any{"frameworks_affected": []any{"SOC2"}, "regulatory_impact": "critical"},
			wantErr: false,
		},
		{
			name:    "valid regulatory_impact low",
			input:   map[string]any{"regulatory_impact": "low"},
			wantErr: false,
		},
		{
			name:    "valid regulatory_impact medium",
			input:   map[string]any{"regulatory_impact": "medium"},
			wantErr: false,
		},
		{
			name:    "empty map",
			input:   map[string]any{},
			wantErr: true,
		},
		{
			name:    "invalid regulatory_impact value",
			input:   map[string]any{"regulatory_impact": "extreme"},
			wantErr: true,
		},
		{
			name:    "frameworks_affected wrong type",
			input:   map[string]any{"frameworks_affected": "PCI-DSS"},
			wantErr: true,
		},
		{
			name:    "frameworks_affected non-string elements",
			input:   map[string]any{"frameworks_affected": []any{1, 2}},
			wantErr: true,
		},
		{
			name:    "regulatory_impact wrong type",
			input:   map[string]any{"regulatory_impact": 3},
			wantErr: true,
		},
		{
			name:    "not a map",
			input:   "compliance",
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

func TestComplianceNormalize(t *testing.T) {
	c := &parsers.Compliance{}

	tests := []struct {
		name  string
		input any
		check func(t *testing.T, ns signals.NormalizedSignal)
	}{
		{
			name:  "1 framework",
			input: map[string]any{"frameworks_affected": []any{"PCI-DSS"}},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				// 1/5 = 0.2
				assert.InDelta(t, 0.2, ns["compliance_scope"], 0.0001)
			},
		},
		{
			name:  "5 frameworks (max)",
			input: map[string]any{"frameworks_affected": []any{"PCI-DSS", "HIPAA", "SOC2", "ISO27001", "GDPR"}},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["compliance_scope"], 0.0001)
			},
		},
		{
			name:  "10 frameworks (capped at 1.0)",
			input: map[string]any{"frameworks_affected": []any{"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10"}},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["compliance_scope"], 0.0001)
			},
		},
		{
			name:  "regulatory_impact low",
			input: map[string]any{"regulatory_impact": "low"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.2, ns["regulatory_severity"], 0.0001)
			},
		},
		{
			name:  "regulatory_impact medium",
			input: map[string]any{"regulatory_impact": "medium"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.5, ns["regulatory_severity"], 0.0001)
			},
		},
		{
			name:  "regulatory_impact high",
			input: map[string]any{"regulatory_impact": "high"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 0.7, ns["regulatory_severity"], 0.0001)
			},
		},
		{
			name:  "regulatory_impact critical",
			input: map[string]any{"regulatory_impact": "critical"},
			check: func(t *testing.T, ns signals.NormalizedSignal) {
				t.Helper()
				assert.InDelta(t, 1.0, ns["regulatory_severity"], 0.0001)
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

func TestComplianceNormalizeInvalidInput(t *testing.T) {
	c := &parsers.Compliance{}

	_, err := c.Normalize("invalid")
	require.Error(t, err)

	_, err = c.Normalize(map[string]any{})
	require.Error(t, err)
}

func TestComplianceNormalizeEmptyFrameworks(t *testing.T) {
	c := &parsers.Compliance{}

	ns, err := c.Normalize(map[string]any{"frameworks_affected": []any{}})
	require.NoError(t, err)
	assert.InDelta(t, 0.0, ns["compliance_scope"], 0.0001)
}

func TestComplianceFields(t *testing.T) {
	c := &parsers.Compliance{}
	fields := c.Fields()
	assert.Contains(t, fields, "frameworks_affected")
	assert.Contains(t, fields, "regulatory_impact")
}
