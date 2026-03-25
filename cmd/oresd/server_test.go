package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	oresv1 "github.com/rigsecurity/ores/gen/proto/ores/v1"
	"github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
	"github.com/rigsecurity/ores/pkg/engine"
)

func newTestClient(t *testing.T) oresv1connect.OresServiceClient {
	t.Helper()

	e := engine.New()
	h := &OresHandler{engine: e}

	logger := slog.New(slog.DiscardHandler)
	mux := newMux(h, logger)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return oresv1connect.NewOresServiceClient(srv.Client(), srv.URL, connect.WithSendCompression("identity"))
}

func TestEvaluateHandler(t *testing.T) {
	client := newTestClient(t)

	signals, err := structpb.NewStruct(map[string]any{
		"cvss": map[string]any{"base_score": 7.5},
		"epss": map[string]any{"probability": 0.6, "percentile": 0.8},
	})
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Signals:    signals,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg)

	assert.GreaterOrEqual(t, resp.Msg.Score, int32(0))
	assert.LessOrEqual(t, resp.Msg.Score, int32(100))
	assert.NotEmpty(t, resp.Msg.Label)
	assert.Equal(t, "ores.dev/v1", resp.Msg.ApiVersion)
	assert.Equal(t, "EvaluationResult", resp.Msg.Kind)
}

func TestListSignalsHandler(t *testing.T) {
	client := newTestClient(t)

	resp, err := client.ListSignals(context.Background(), connect.NewRequest(&oresv1.ListSignalsRequest{}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg)

	assert.Len(t, resp.Msg.Signals, 8)

	for _, sig := range resp.Msg.Signals {
		assert.NotEmpty(t, sig.Name)
		assert.NotEmpty(t, sig.Description)
		assert.NotEmpty(t, sig.Fields)
	}
}

func TestGetVersionHandler(t *testing.T) {
	client := newTestClient(t)

	resp, err := client.GetVersion(context.Background(), connect.NewRequest(&oresv1.GetVersionRequest{}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg)

	assert.Equal(t, "0.2.0", resp.Msg.Version)
}

func TestEvaluateHandlerEmptySignals(t *testing.T) {
	client := newTestClient(t)

	// An empty signals struct should cause a validation error.
	signals, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)

	_, err = client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Signals:    signals,
	}))
	require.Error(t, err)

	var connectErr *connect.Error
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	e := engine.New()
	h := &OresHandler{engine: e}
	logger := slog.New(slog.DiscardHandler)
	mux := newMux(h, logger)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func TestEvaluateHandlerNilSignals(t *testing.T) {
	client := newTestClient(t)

	// A nil signals struct should cause a validation error.
	_, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Signals:    nil,
	}))
	require.Error(t, err)

	var connectErr *connect.Error
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
}

func TestEvaluateHandlerWrongKind(t *testing.T) {
	client := newTestClient(t)

	signals, err := structpb.NewStruct(map[string]any{
		"cvss": map[string]any{"base_score": 5.0},
	})
	require.NoError(t, err)

	_, err = client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "WrongKind",
		Signals:    signals,
	}))
	require.Error(t, err)

	var connectErr *connect.Error
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
}

func TestEvaluateHandlerExplanationFields(t *testing.T) {
	client := newTestClient(t)

	signals, err := structpb.NewStruct(map[string]any{
		"cvss":         map[string]any{"base_score": 9.0},
		"epss":         map[string]any{"probability": 0.9, "percentile": 0.95},
		"threat_intel": map[string]any{"actively_exploited": true},
	})
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Signals:    signals,
	}))
	require.NoError(t, err)

	expl := resp.Msg.Explanation
	require.NotNil(t, expl)
	assert.Equal(t, int32(3), expl.SignalsProvided)
	assert.Equal(t, int32(3), expl.SignalsUsed)
	assert.Equal(t, int32(0), expl.SignalsUnknown)
	assert.NotEmpty(t, expl.Factors)
	assert.Greater(t, expl.Confidence, 0.0)

	// Every factor must have a name and reasoning.
	for _, f := range expl.Factors {
		assert.NotEmpty(t, f.Name)
		assert.NotEmpty(t, f.Reasoning)
		assert.NotEmpty(t, f.DerivedFrom)
	}
}

func TestAuditMiddlewareNonEvaluatePath(t *testing.T) {
	srv := newTestServer(t)

	// Non-evaluate paths should pass through without error.
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHealthEndpoint(t *testing.T) {
	srv := newTestServer(t)

	resp, err := srv.Client().Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestReadinessEndpoint(t *testing.T) {
	srv := newTestServer(t)

	resp, err := srv.Client().Get(srv.URL + "/readyz")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestEvaluateHandlerB4Mode(t *testing.T) {
	client := newTestClient(t)

	signals, err := structpb.NewStruct(map[string]any{
		"asset": map[string]any{"criticality": "crown_jewel", "network_exposure": true},
	})
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Findings:   []float64{9.8, 7.5},
		Signals:    signals,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg)

	assert.Equal(t, "b4", resp.Msg.Mode)
	assert.GreaterOrEqual(t, resp.Msg.Score, int32(0))
	assert.LessOrEqual(t, resp.Msg.Score, int32(100))
	assert.Positive(t, resp.Msg.Explanation.FindingsCount)
}

func TestEvaluateHandlerB4FindingsOnly(t *testing.T) {
	client := newTestClient(t)

	resp, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Findings:   []float64{5.0},
	}))
	require.NoError(t, err)
	assert.Equal(t, "b4", resp.Msg.Mode)
	assert.InDelta(t, 0.0, resp.Msg.Explanation.Confidence, 0.0001)
}

func TestEvaluateHandlerWeightedModeHasMode(t *testing.T) {
	client := newTestClient(t)

	signals, err := structpb.NewStruct(map[string]any{
		"cvss": map[string]any{"base_score": 7.5},
	})
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Signals:    signals,
	}))
	require.NoError(t, err)
	assert.Equal(t, "weighted", resp.Msg.Mode)
}
