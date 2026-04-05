package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/score"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEngine returns a shared engine for tests.
func testEngine() *engine.Engine { return engine.New() }

func TestRootCommand(t *testing.T) {
	cmd := newRootCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "ores", cmd.Use)
	assert.Len(t, cmd.Commands(), 3, "root command should have 3 subcommands")
}

func TestEvaluateCommand(t *testing.T) {
	cmd := newEvaluateCmd(testEngine())
	require.NotNil(t, cmd)
	assert.Equal(t, "evaluate", cmd.Use)

	// Verify flags are registered.
	fileFlag := cmd.Flags().Lookup("file")
	require.NotNil(t, fileFlag)
	assert.Equal(t, "f", fileFlag.Shorthand)

	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)
	assert.Equal(t, "json", outputFlag.DefValue)
}

func TestEvaluateCommandWithFile(t *testing.T) {
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

	cmd := newEvaluateCmd(testEngine())
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"-f", path})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), score.APIVersion)
}

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
	err = runEvaluate(testEngine(), path, "json", &buf)
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
	err = runEvaluate(testEngine(), path, "yaml", &buf)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "apiVersion:")
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
	err = runEvaluate(testEngine(), path, "table", &buf)
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
	err = runEvaluate(testEngine(), path, "toml", &buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output format")
}

func TestRunEvaluateMissingFile(t *testing.T) {
	var buf bytes.Buffer
	err := runEvaluate(testEngine(), "/no/such/file.json", "json", &buf)
	require.Error(t, err)
}

func TestRunEvaluateInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json or yaml}"), 0o600))

	var buf bytes.Buffer
	err := runEvaluate(testEngine(), path, "json", &buf)
	require.Error(t, err)
}

func TestRunEvaluateWithUnknownSignals(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"cvss":         map[string]any{"base_score": 7.5},
			"unknown_data": map[string]any{"value": 42},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(testEngine(), path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.Equal(t, 1, result.Explanation.SignalsUnknown)
	assert.Contains(t, result.Explanation.UnknownSignals, "unknown_data")
}

func TestRunEvaluateWithWarnings(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"cvss": map[string]any{"base_score": 5.0},
			"epss": map[string]any{"probability": 99.0}, // out of range
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(testEngine(), path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.NotEmpty(t, result.Explanation.Warnings)
}

func TestRunEvaluateTableWithWarningsAndUnknown(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"signals": map[string]any{
			"cvss":  map[string]any{"base_score": 5.0},
			"epss":  map[string]any{"probability": 99.0}, // out of range → warning
			"bogus": map[string]any{"x": 1},              // unknown signal
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(testEngine(), path, "table", &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Unknown signals:")
	assert.Contains(t, out, "Warnings:")
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
	err := runEvaluate(testEngine(), path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.Equal(t, score.APIVersion, result.APIVersion)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
}

func TestRunEvaluateB4FromFile(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"findings":   []any{9.8, 7.5, 4.2},
		"signals": map[string]any{
			"asset": map[string]any{"criticality": "high"},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(testEngine(), path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.Equal(t, "b4", result.Mode)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
}

func TestRunEvaluateB4TableOutput(t *testing.T) {
	input := map[string]any{
		"apiVersion": score.APIVersion,
		"kind":       score.KindEvaluationRequest,
		"findings":   []any{9.8, 7.5},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	var buf bytes.Buffer
	err = runEvaluate(testEngine(), path, "table", &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Score:")
	assert.Contains(t, out, "Mode:")
	assert.Contains(t, out, "b4")
	assert.Contains(t, out, "Findings:")
}

func TestRunEvaluateYAMLB4Input(t *testing.T) {
	yamlInput := `apiVersion: ores.dev/v1
kind: EvaluationRequest
findings:
  - 9.8
  - 7.5
  - 4.2
signals:
  asset:
    criticality: high
`

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlInput), 0o600))

	var buf bytes.Buffer
	err := runEvaluate(testEngine(), path, "json", &buf)
	require.NoError(t, err)

	var result score.EvaluationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Equal(t, "b4", result.Mode)
	assert.GreaterOrEqual(t, result.Score, 0)
	assert.LessOrEqual(t, result.Score, 100)
}

func TestRunEvaluateBinaryInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.dat")
	require.NoError(t, os.WriteFile(path, []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}, 0o600))

	var buf bytes.Buffer
	err := runEvaluate(testEngine(), path, "json", &buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing request")
}
