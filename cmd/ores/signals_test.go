package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalsCommand(t *testing.T) {
	cmd := newSignalsCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "signals", cmd.Use)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "cvss")
}

func TestRunSignals(t *testing.T) {
	var buf bytes.Buffer
	err := runSignals(&buf)
	require.NoError(t, err)

	out := buf.String()

	// Verify header.
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "DESCRIPTION")
	assert.Contains(t, out, "FIELDS")

	// Verify all 8 signal types are listed.
	expectedSignals := []string{
		"asset",
		"blast_radius",
		"compliance",
		"cvss",
		"epss",
		"nist",
		"patch",
		"threat_intel",
	}

	for _, name := range expectedSignals {
		assert.Contains(t, out, name, "signal %q should be listed", name)
	}
}
