// Package main demonstrates embedding the ORES engine as a Go library.
// It submits all 8 signal types and prints the scored result as JSON.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/score"
)

func main() {
	e := engine.New()

	req := &score.EvaluationRequest{
		APIVersion: score.APIVersion,
		Kind:       score.KindEvaluationRequest,
		Signals: map[string]any{
			"cvss":         map[string]any{"base_score": 9.8},
			"epss":         map[string]any{"probability": 0.95, "percentile": 0.99},
			"threat_intel": map[string]any{"actively_exploited": true, "ransomware_associated": true},
			"asset":        map[string]any{"criticality": "crown_jewel", "network_exposure": true, "data_classification": "pii"},
			"blast_radius": map[string]any{"affected_systems": 142, "lateral_movement_possible": true},
			"nist":         map[string]any{"severity": "critical", "cwe": "CWE-79"},
			"compliance":   map[string]any{"frameworks_affected": []any{"pci_dss", "hipaa"}, "regulatory_impact": "high"},
			"patch":        map[string]any{"patch_available": true, "patch_age_days": 45, "compensating_control": false},
		},
	}

	result, err := e.Evaluate(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err = enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding result: %s\n", err)
		os.Exit(1)
	}
}
