package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunVersion(t *testing.T) {
	var buf bytes.Buffer
	err := runVersion(&buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ores model version")
	assert.Contains(t, out, "0.2.0")
}

func TestVersionCommand(t *testing.T) {
	cmd := newVersionCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "version", cmd.Use)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "0.2.0")
}
