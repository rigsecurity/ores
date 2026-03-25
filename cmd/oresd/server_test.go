package main

import (
	"context"
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

	mux := newMux(h)
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

	assert.Equal(t, "0.1.0-preview", resp.Msg.Version)
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
	mux := newMux(h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
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
