package main

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	oresv1 "github.com/rigsecurity/ores/gen/proto/ores/v1"
	"github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/score"
)

// OresHandler implements the OresServiceHandler interface backed by the ORES engine.
type OresHandler struct {
	engine *engine.Engine
}

// Verify interface satisfaction at compile time.
var _ oresv1connect.OresServiceHandler = (*OresHandler)(nil)

// Evaluate handles an evaluation request by converting the proto Struct to a signal map,
// calling the engine, and converting the result back to proto types.
func (h *OresHandler) Evaluate(
	ctx context.Context,
	req *connect.Request[oresv1.EvaluateRequest],
) (*connect.Response[oresv1.EvaluateResponse], error) {
	engineReq := &score.EvaluationRequest{
		APIVersion: req.Msg.ApiVersion,
		Kind:       req.Msg.Kind,
		Findings:   req.Msg.Findings,
		Signals:    structToSignals(req.Msg.Signals),
	}

	result, err := h.engine.Evaluate(ctx, engineReq)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&oresv1.EvaluateResponse{
		ApiVersion:  result.APIVersion,
		Kind:        result.Kind,
		Score:       safeInt32(result.Score), //nolint:gosec // score is always in [0,100]
		Label:       string(result.Label),
		Version:     result.Version,
		Mode:        result.Mode,
		Explanation: explanationToProto(result.Explanation),
	}), nil
}

// ListSignals returns descriptors for all registered signal types.
func (h *OresHandler) ListSignals(
	_ context.Context,
	_ *connect.Request[oresv1.ListSignalsRequest],
) (*connect.Response[oresv1.ListSignalsResponse], error) {
	descs := h.engine.Signals()
	protoDescs := make([]*oresv1.SignalDescriptor, len(descs))

	for i, d := range descs {
		protoDescs[i] = &oresv1.SignalDescriptor{
			Name:        d.Name,
			Description: d.Description,
			Fields:      d.Fields,
		}
	}

	return connect.NewResponse(&oresv1.ListSignalsResponse{
		Signals: protoDescs,
	}), nil
}

// GetVersion returns the model version string.
func (h *OresHandler) GetVersion(
	_ context.Context,
	_ *connect.Request[oresv1.GetVersionRequest],
) (*connect.Response[oresv1.GetVersionResponse], error) {
	return connect.NewResponse(&oresv1.GetVersionResponse{
		Version: h.engine.Version(),
	}), nil
}

// structToSignals converts a google.protobuf.Struct to map[string]any for the engine.
// A nil Struct maps to an empty (non-nil) map.
func structToSignals(s *structpb.Struct) map[string]any {
	if s == nil {
		return map[string]any{}
	}

	return s.AsMap()
}

// explanationToProto converts the engine Explanation type to its proto equivalent.
func explanationToProto(e score.Explanation) *oresv1.Explanation {
	factors := make([]*oresv1.Factor, len(e.Factors))
	for i, f := range e.Factors {
		factors[i] = &oresv1.Factor{
			Name:         f.Name,
			Contribution: safeInt32(f.Contribution), //nolint:gosec // contribution is bounded by score [0,100]
			DerivedFrom:  f.DerivedFrom,
			Reasoning:    f.Reasoning,
		}
	}

	return &oresv1.Explanation{
		SignalsProvided: safeInt32(e.SignalsProvided), //nolint:gosec // signal counts are small positive integers
		SignalsUsed:     safeInt32(e.SignalsUsed),     //nolint:gosec // signal counts are small positive integers
		SignalsUnknown:  safeInt32(e.SignalsUnknown),  //nolint:gosec // signal counts are small positive integers
		FindingsCount:   safeInt32(e.FindingsCount),  //nolint:gosec // findings count is a small positive integer
		UnknownSignals:  e.UnknownSignals,
		Warnings:        e.Warnings,
		Confidence:      e.Confidence,
		Factors:         factors,
	}
}

// safeInt32 converts an int to int32.
// All values passed here are bounded small integers (scores, counts) that fit in int32.
func safeInt32(n int) int32 {
	return int32(n) //nolint:gosec // callers ensure value is in int32 range
}
