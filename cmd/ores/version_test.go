package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunVersion(t *testing.T) {
	e := engine.New()

	var buf bytes.Buffer
	err := runVersion(e, "text", &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ores model version")
	assert.Contains(t, out, model.ModelVersion)
}

func TestRunVersionJSON(t *testing.T) {
	e := engine.New()

	var buf bytes.Buffer
	err := runVersion(e, "json", &buf)
	require.NoError(t, err)

	var result versionOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Equal(t, model.ModelVersion, result.Version)
}

func TestRunVersionYAML(t *testing.T) {
	e := engine.New()

	var buf bytes.Buffer
	err := runVersion(e, "yaml", &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "version:")
	assert.Contains(t, out, model.ModelVersion)
}

func TestVersionCommand(t *testing.T) {
	e := engine.New()

	cmd := newVersionCmd(e)
	require.NotNil(t, cmd)
	assert.Equal(t, "version", cmd.Use)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), model.ModelVersion)
}
