package parsers

import (
	"errors"
	"fmt"

	"github.com/rigsecurity/ores/pkg/signals"
)

// assetCriticalityScores maps criticality labels to normalized values.
var assetCriticalityScores = map[string]float64{
	"low":         0.2,
	"medium":      0.5,
	"high":        0.7,
	"crown_jewel": 1.0,
}

// dataClassificationScores maps data classification labels to normalized values.
var dataClassificationScores = map[string]float64{
	"public":       0.1,
	"internal":     0.3,
	"confidential": 0.6,
	"pii":          0.8,
	"restricted":   1.0,
}

// Asset parses asset context signals including criticality, exposure, and data classification.
type Asset struct{}

// Name returns the signal type identifier.
func (a *Asset) Name() string { return "asset" }

// Description returns a human-readable description of this signal.
func (a *Asset) Description() string {
	return "Asset criticality, network exposure, and data classification context"
}

// Fields returns the list of recognized input field names.
func (a *Asset) Fields() []string {
	return []string{"criticality", "network_exposure", "data_classification"}
}

// Validate checks that raw is a map with at least one valid field present.
func (a *Asset) Validate(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("asset: input must be a map")
	}

	hasAny := false

	if critVal, ok := m["criticality"]; ok {
		hasAny = true

		crit, ok := toString(critVal)
		if !ok {
			return fmt.Errorf("asset: criticality must be a string, got %T", critVal)
		}

		if _, valid := assetCriticalityScores[crit]; !valid {
			return fmt.Errorf("asset: criticality %q is not valid; must be one of low, medium, high, crown_jewel", crit)
		}
	}

	if expVal, ok := m["network_exposure"]; ok {
		hasAny = true

		if _, ok := toBool(expVal); !ok {
			return fmt.Errorf("asset: network_exposure must be a bool, got %T", expVal)
		}
	}

	if dcVal, ok := m["data_classification"]; ok {
		hasAny = true

		dc, ok := toString(dcVal)
		if !ok {
			return fmt.Errorf("asset: data_classification must be a string, got %T", dcVal)
		}

		if _, valid := dataClassificationScores[dc]; !valid {
			return fmt.Errorf("asset: data_classification %q is not valid; must be one of public, internal, confidential, pii, restricted", dc)
		}
	}

	if !hasAny {
		return errors.New("asset: at least one of criticality, network_exposure, or data_classification is required")
	}

	return nil
}

// Normalize converts raw Asset input to normalized factor values.
func (a *Asset) Normalize(raw any) (signals.NormalizedSignal, error) {
	m, err := toMap(raw)
	if err != nil {
		return nil, err
	}
	if err := a.Validate(raw); err != nil {
		return nil, err
	}
	ns := make(signals.NormalizedSignal)

	if critVal, ok := m["criticality"]; ok {
		crit, _ := toString(critVal)
		ns["asset_criticality"] = assetCriticalityScores[crit]
	}

	if expVal, ok := m["network_exposure"]; ok {
		exposed, _ := toBool(expVal)

		if exposed {
			ns["network_exposure"] = 1.0
		} else {
			ns["network_exposure"] = 0.0
		}
	}

	if dcVal, ok := m["data_classification"]; ok {
		dc, _ := toString(dcVal)
		ns["data_sensitivity"] = dataClassificationScores[dc]
	}

	return ns, nil
}
