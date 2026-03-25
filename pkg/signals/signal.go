// Package signals defines the Signal interface, NormalizedSignal type, and
// Registry for managing all recognized signal types in the ORES engine.
package signals

// Signal defines the interface for a recognized signal type.
type Signal interface {
	Name() string
	Description() string
	Fields() []string
	Validate(raw any) error
	Normalize(raw any) (NormalizedSignal, error)
}
