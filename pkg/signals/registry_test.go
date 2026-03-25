package signals_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubSignal struct{}

func (s *stubSignal) Name() string         { return "stub" }
func (s *stubSignal) Description() string  { return "A stub signal" }
func (s *stubSignal) Fields() []string     { return []string{"value"} }
func (s *stubSignal) Validate(_ any) error { return nil }
func (s *stubSignal) Normalize(_ any) (signals.NormalizedSignal, error) {
	return signals.NormalizedSignal{"stub_factor": 0.5}, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := signals.NewRegistry()
	reg.Register(&stubSignal{})

	sig, ok := reg.Get("stub")
	require.True(t, ok)
	assert.Equal(t, "stub", sig.Name())
}

func TestRegistryGetMissing(t *testing.T) {
	reg := signals.NewRegistry()
	_, ok := reg.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryAll(t *testing.T) {
	reg := signals.NewRegistry()
	reg.Register(&stubSignal{})
	all := reg.All()
	assert.Len(t, all, 1)
	assert.Equal(t, "stub", all[0].Name())
}

func TestRegistryValidateKnownSignal(t *testing.T) {
	reg := signals.NewRegistry()
	reg.Register(&stubSignal{})

	err := reg.Validate("stub", map[string]any{"value": 1})
	assert.NoError(t, err)
}

func TestRegistryValidateUnknownSignal(t *testing.T) {
	reg := signals.NewRegistry()
	err := reg.Validate("unknown", map[string]any{})
	assert.ErrorIs(t, err, signals.ErrUnknownSignal)
}
