package signals

import (
	"errors"
	"fmt"
)

// ErrUnknownSignal is returned when an operation references a signal type that
// has not been registered.
var ErrUnknownSignal = errors.New("unknown signal type")

// Registry holds all registered Signal implementations and provides lookup,
// enumeration, and validation helpers.
type Registry struct {
	signals map[string]Signal
}

// NewRegistry returns an empty, ready-to-use Registry.
func NewRegistry() *Registry {
	return &Registry{signals: make(map[string]Signal)}
}

// Register adds s to the registry, keyed by s.Name().
func (r *Registry) Register(s Signal) {
	r.signals[s.Name()] = s
}

// Get returns the Signal registered under name and whether it was found.
func (r *Registry) Get(name string) (Signal, bool) {
	s, ok := r.signals[name]
	return s, ok
}

// All returns every registered Signal in unspecified order.
func (r *Registry) All() []Signal {
	result := make([]Signal, 0, len(r.signals))
	for _, s := range r.signals {
		result = append(result, s)
	}

	return result
}

// Validate looks up name in the registry and delegates to its Validate method.
// Returns ErrUnknownSignal (wrapped) if name is not registered.
func (r *Registry) Validate(name string, raw any) error {
	s, ok := r.signals[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownSignal, name)
	}

	return s.Validate(raw)
}
