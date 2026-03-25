// Package engine wires together the signal registry, parsers, scoring model,
// and explanation builder into a single Evaluate call.
package engine

import (
	"context"
	"fmt"
	"sort"

	"github.com/rigsecurity/ores/pkg/explain"
	"github.com/rigsecurity/ores/pkg/model"
	"github.com/rigsecurity/ores/pkg/score"
	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
)

// contextSignals is the set of signal names used for B4 context adjustment.
// Severity signals (cvss, epss, nist, threat_intel) are intentionally excluded
// because B4 mode derives severity from the findings slice, not signal inputs.
var contextSignals = map[string]bool{
	"asset": true, "blast_radius": true, "compliance": true, "patch": true,
}

// Engine is the main evaluation pipeline.
type Engine struct {
	registry *signals.Registry
	model    *model.Model
}

// New creates an Engine with all built-in signal parsers registered.
func New() *Engine {
	reg := signals.NewRegistry()
	parsers.RegisterAll(reg)

	return &Engine{
		registry: reg,
		model:    model.New(),
	}
}

// Evaluate runs the full pipeline: validate request, parse and normalize signals,
// score, and build an explanation. Routes to B4 mode when findings are present,
// otherwise runs weighted single-vulnerability mode.
func (e *Engine) Evaluate(_ context.Context, req *score.EvaluationRequest) (*score.EvaluationResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if req.HasFindings() {
		return e.evaluateB4(req)
	}
	return e.evaluateWeighted(req)
}

// evaluateB4 handles requests with findings. Only context signals (asset,
// blast_radius, compliance, patch) are processed; severity signals are ignored.
// It is valid to supply findings with no context signals — the adjustment axes
// will use their neutral defaults (confidence → 0.0).
func (e *Engine) evaluateB4(req *score.EvaluationRequest) (*score.EvaluationResult, error) {
	var (
		normalized     []signals.NormalizedSignal
		provided       = make(map[string]bool)
		unknownSignals []string
		warnings       []string
	)

	// Sort signal names for deterministic processing.
	names := make([]string, 0, len(req.Signals))
	for name := range req.Signals {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		// Skip severity signals — B4 derives severity from findings.
		if !contextSignals[name] {
			continue
		}

		raw := req.Signals[name]

		sig, ok := e.registry.Get(name)
		if !ok {
			unknownSignals = append(unknownSignals, name)
			continue
		}

		if err := sig.Validate(raw); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %s", name, err.Error()))
			continue
		}

		norm, err := sig.Normalize(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: normalization failed: %s", name, err.Error()))
			continue
		}

		normalized = append(normalized, norm)
		provided[name] = true
	}

	// B4 does not require context signals — findings alone are valid.
	result, err := e.model.Score(req.Findings, normalized)
	if err != nil {
		return nil, fmt.Errorf("scoring failed: %w", err)
	}

	confidence := model.CalculateB4Confidence(provided)
	explanation := explain.BuildB4(result.Factors, provided, unknownSignals, warnings, confidence, len(req.Findings))

	return &score.EvaluationResult{
		APIVersion:  score.APIVersion,
		Kind:        score.KindEvaluationResult,
		Score:       result.Score,
		Label:       score.LabelForScore(result.Score),
		Mode:        "b4",
		Version:     e.model.Version(),
		Explanation: explanation,
	}, nil
}

// evaluateWeighted handles requests without findings using the weighted
// multi-dimension scoring model.
func (e *Engine) evaluateWeighted(req *score.EvaluationRequest) (*score.EvaluationResult, error) {
	var (
		normalized     []signals.NormalizedSignal
		provided       = make(map[string]bool)
		unknownSignals []string
		warnings       []string
	)

	// Sort signal names for deterministic processing.
	names := make([]string, 0, len(req.Signals))
	for name := range req.Signals {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		raw := req.Signals[name]

		sig, ok := e.registry.Get(name)
		if !ok {
			unknownSignals = append(unknownSignals, name)

			continue
		}

		if err := sig.Validate(raw); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %s", name, err.Error()))

			continue
		}

		norm, err := sig.Normalize(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: normalization failed: %s", name, err.Error()))

			continue
		}

		normalized = append(normalized, norm)
		provided[name] = true
	}

	if len(provided) == 0 {
		return nil, fmt.Errorf("no valid signals: all %d signals were invalid or unknown", len(req.Signals))
	}

	result, err := e.model.Score(nil, normalized)
	if err != nil {
		return nil, fmt.Errorf("scoring failed: %w", err)
	}

	confidence := model.CalculateConfidence(model.DefaultDimensions(), provided)
	explanation := explain.Build(result.Factors, provided, unknownSignals, warnings, confidence, len(req.Signals))

	return &score.EvaluationResult{
		APIVersion:  score.APIVersion,
		Kind:        score.KindEvaluationResult,
		Score:       result.Score,
		Label:       score.LabelForScore(result.Score),
		Mode:        "weighted",
		Version:     e.model.Version(),
		Explanation: explanation,
	}, nil
}

// Signals returns descriptors for all registered signal types, sorted by name.
func (e *Engine) Signals() []score.SignalDescriptor {
	all := e.registry.All()
	descs := make([]score.SignalDescriptor, len(all))

	for i, s := range all {
		descs[i] = score.SignalDescriptor{
			Name:        s.Name(),
			Description: s.Description(),
			Fields:      s.Fields(),
		}
	}

	sort.Slice(descs, func(i, j int) bool { return descs[i].Name < descs[j].Name })

	return descs
}

// Version returns the model version string.
func (e *Engine) Version() string {
	return e.model.Version()
}
