package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalsCommand(t *testing.T) {
	e := engine.New()

	cmd := newSignalsCmd(e)
	require.NotNil(t, cmd)
	assert.Equal(t, "signals", cmd.Use)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "cvss")
}

func TestRunSignals(t *testing.T) {
	e := engine.New()

	var buf bytes.Buffer
	err := runSignals(e, &buf)
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

	// Verify exactly 8 signals (count data rows, not header/separator).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	dataLines := 0
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "NAME") && !strings.HasPrefix(line, "----") {
			dataLines++
		}
	}
	assert.Equal(t, len(expectedSignals), dataLines, "should list exactly %d signals", len(expectedSignals))
}
