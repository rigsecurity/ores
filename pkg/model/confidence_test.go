package model_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/model"
	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/stretchr/testify/assert"
)

func TestConfidence(t *testing.T) {
	tests := []struct {
		name     string
		signals  []signals.NormalizedSignal
		wantLow  float64
		wantHigh float64
	}{
		{
			name: "full coverage all 8 signals",
			signals: []signals.NormalizedSignal{
				// cvss -> severity
				{"severity": 0.8},
				// nist -> nist_severity
				{"nist_severity": 0.7},
				// epss -> exploit_probability, exploit_percentile
				{"exploit_probability": 0.5, "exploit_percentile": 0.6},
				// threat_intel -> active_exploitation, ransomware_risk
				{"active_exploitation": 1.0, "ransomware_risk": 0.0},
				// asset -> asset_criticality, network_exposure, data_sensitivity
				{"asset_criticality": 1.0, "network_exposure": 1.0},
				// blast_radius -> blast_scope, lateral_movement
				{"blast_scope": 0.5, "lateral_movement": 1.0},
				// patch -> remediation_available, patch_staleness, has_compensating_control
				{"remediation_available": 1.0, "patch_staleness": 0.5},
				// compliance -> regulatory_severity, compliance_scope
				{"regulatory_severity": 0.7, "compliance_scope": 0.4},
			},
			wantLow:  0.99,
			wantHigh: 1.01,
		},
		{
			name: "single signal cvss only",
			signals: []signals.NormalizedSignal{
				{"severity": 0.8},
			},
			// Only half of base_vulnerability (weight 0.30): 0.30 * 0.5 = 0.15
			wantLow:  0.14,
			wantHigh: 0.16,
		},
		{
			name:     "no signals",
			signals:  []signals.NormalizedSignal{},
			wantLow:  0.0,
			wantHigh: 0.0,
		},
		{
			name:     "nil signals slice",
			signals:  nil,
			wantLow:  0.0,
			wantHigh: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := model.Confidence(tt.signals)

			if tt.wantLow == 0.0 && tt.wantHigh == 0.0 {
				assert.InDelta(t, 0.0, got, 0.0001)
			} else {
				assert.GreaterOrEqual(t, got, tt.wantLow)
				assert.LessOrEqual(t, got, tt.wantHigh)
			}
		})
	}
}

func TestConfidenceRange(t *testing.T) {
	// Confidence must always be in [0.0, 1.0]
	tests := []signals.NormalizedSignal{
		{"severity": 0.5},
		{"unknown_factor": 0.9},
		{},
	}

	for _, sig := range tests {
		got := model.Confidence([]signals.NormalizedSignal{sig})
		assert.GreaterOrEqual(t, got, 0.0)
		assert.LessOrEqual(t, got, 1.0)
	}
}
