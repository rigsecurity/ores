package signals_test

import (
	"testing"

	"github.com/rigsecurity/ores/pkg/signals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSignal struct{}

func (s *fakeSignal) Name() string         { return "fake" }
func (s *fakeSignal) Description() string  { return "A fake signal for testing" }
func (s *fakeSignal) Fields() []string     { return []string{"value"} }
func (s *fakeSignal) Validate(_ any) error { return nil }
func (s *fakeSignal) Normalize(_ any) (signals.NormalizedSignal, error) {
	return signals.NormalizedSignal{"fake_factor": 0.5}, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := signals.NewRegistry()
	reg.Register(&fakeSignal{})

	sig, ok := reg.Get("fake")
	require.True(t, ok)
	assert.Equal(t, "fake", sig.Name())
}

func TestRegistryGetMissing(t *testing.T) {
	reg := signals.NewRegistry()
	_, ok := reg.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryAll(t *testing.T) {
	reg := signals.NewRegistry()
	reg.Register(&fakeSignal{})
	all := reg.All()
	assert.Len(t, all, 1)
	assert.Equal(t, "fake", all[0].Name())
}

func TestRegistryValidateKnownSignal(t *testing.T) {
	reg := signals.NewRegistry()
	reg.Register(&fakeSignal{})

	err := reg.Validate("fake", map[string]any{"value": 1})
	assert.NoError(t, err)
}

func TestRegistryValidateUnknownSignal(t *testing.T) {
	reg := signals.NewRegistry()
	err := reg.Validate("unknown", map[string]any{})
	assert.ErrorIs(t, err, signals.ErrUnknownSignal)
}
