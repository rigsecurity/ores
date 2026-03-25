package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rigsecurity/ores/pkg/score"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunEvaluateFromFile(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"cvss": map[string]any{"base_score": 8.1},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.Equal(t, score.APIVersion, result.APIVersion)
	assert.Equal(t, score.KindEvaluationResult, result.Kind)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
	assert.NotEmpty(t, string(result.Label))
	assert.NotEmpty(t, result.Version)
	assert.Greater(t, result.Explanation.Confidence, 0.0)
}

func TestRunEvaluateYAMLOutput(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"epss": map[string]any{"probability": 0.5, "percentile": 0.7},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(path, "yaml", &buf)
	require.NoError(t, err)

	// The yaml library lowercases field names when no yaml struct tags are present.
	assert.Contains(t, buf.String(), "apiversion:")
	assert.Contains(t, buf.String(), score.APIVersion)
}

func TestRunEvaluateTableOutput(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"cvss": map[string]any{"base_score": 6.5},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(path, "table", &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Score:")
	assert.Contains(t, out, "Label:")
	assert.Contains(t, out, "FACTOR")
}

func TestRunEvaluateInvalidFormat(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"cvss": map[string]any{"base_score": 5.0},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(path, "toml", &buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output format")
}

func TestRunEvaluateMissingFile(t *testing.T) {
	var buf bytes.Buffer
	err := runEvaluate("/no/such/file.json", "json", &buf)
	require.Error(t, err)
}

func TestRunEvaluateInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json or yaml}"), 0o600))

	var buf bytes.Buffer
	err := runEvaluate(path, "json", &buf)
	require.Error(t, err)
}

func TestRunEvaluateYAMLInput(t *testing.T) {
	yamlInput := `apiVersion: ores.dev/v1
kind: EvaluationRequest
signals:
  cvss:
    base_score: 7.0
`

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlInput), 0o600))

	var buf bytes.Buffer
	err := runEvaluate(path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.Equal(t, score.APIVersion, result.APIVersion)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
}
