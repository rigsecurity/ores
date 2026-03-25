package parsers_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/rigsecurity/ores/pkg/signals/parsers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAll(t *testing.T) {
	reg := signals.NewRegistry()
	parsers.RegisterAll(reg)

	expectedSignals := []string{
		"cvss",
		"epss",
		"nist",
		"asset",
		"blast_radius",
		"threat_intel",
		"compliance",
		"patch",
	}

	all := reg.All()
	assert.Len(t, all, len(expectedSignals))

	for _, name := range expectedSignals {
		sig, ok := reg.Get(name)
		require.True(t, ok, "signal %q should be registered", name)
		assert.Equal(t, name, sig.Name())
		assert.NotEmpty(t, sig.Description(), "signal %q should have a description", name)
		assert.NotEmpty(t, sig.Fields(), "signal %q should have fields", name)
	}
}
