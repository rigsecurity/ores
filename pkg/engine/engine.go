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

// contextSignals is derived from model.B4ContextSignals — the single source of truth
// for which signal names are used in B4 context adjustment. Severity signals are
// intentionally excluded because B4 mode derives severity from the findings slice.
var contextSignals = model.B4ContextSignals()

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

// processedSignals holds the output of parsing and normalizing a request's signals.
type processedSignals struct {
	normalized     []signals.NormalizedSignal
	provided       map[string]bool
	unknownSignals []string
	warnings       []string
}

// processSignals parses, validates, and normalizes signals from a request.
// When accept is non-nil, only signal names for which accept returns true are
// processed; the rest are silently skipped. Signal names are sorted for
// deterministic output.
func (e *Engine) processSignals(req *score.EvaluationRequest, accept func(string) bool) processedSignals {
	ps := processedSignals{provided: make(map[string]bool)}

	// Sort signal names for deterministic processing.
	names := make([]string, 0, len(req.Signals))
	for name := range req.Signals {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if accept != nil && !accept(name) {
			continue
		}

		raw := req.Signals[name]

		sig, ok := e.registry.Get(name)
		if !ok {
			ps.unknownSignals = append(ps.unknownSignals, name)
			continue
		}

		if err := sig.Validate(raw); err != nil {
			ps.warnings = append(ps.warnings, fmt.Sprintf("%s: %s", name, err.Error()))
			continue
		}

		norm, err := sig.Normalize(raw)
		if err != nil {
			ps.warnings = append(ps.warnings, fmt.Sprintf("%s: normalization failed: %s", name, err.Error()))
			continue
		}

		ps.normalized = append(ps.normalized, norm)
		ps.provided[name] = true
	}

	return ps
}

// evaluateB4 handles requests with findings. Only context signals (asset,
// blast_radius, compliance, patch) are processed; severity signals are ignored.
// It is valid to supply findings with no context signals — the adjustment axes
// will use their neutral defaults (confidence → 0.0).
func (e *Engine) evaluateB4(req *score.EvaluationRequest) (*score.EvaluationResult, error) {
	ps := e.processSignals(req, func(name string) bool { return contextSignals[name] })

	result, err := e.model.Score(req.Findings, ps.normalized)
	if err != nil {
		return nil, fmt.Errorf("scoring failed: %w", err)
	}

	confidence := model.CalculateB4Confidence(ps.provided)
	explanation := explain.BuildB4(result.Factors, ps.provided, ps.unknownSignals, ps.warnings, confidence, len(req.Findings))

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
	ps := e.processSignals(req, nil)

	if len(ps.provided) == 0 {
		return nil, fmt.Errorf("no valid signals: all %d signals were invalid or unknown", len(req.Signals))
	}

	result, err := e.model.Score(nil, ps.normalized)
	if err != nil {
		return nil, fmt.Errorf("scoring failed: %w", err)
	}

	confidence := model.CalculateConfidence(model.DefaultDimensions(), ps.provided)
	explanation := explain.Build(result.Factors, ps.provided, ps.unknownSignals, ps.warnings, confidence, len(req.Signals))

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
