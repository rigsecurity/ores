package parsers

import "github.com/rigsecurity/ores/pkg/signals"

// RegisterAll registers all built-in signal parsers with the provided registry.
func RegisterAll(reg *signals.Registry) {
	reg.Register(&CVSS{})
	reg.Register(&EPSS{})
	reg.Register(&NIST{})
	reg.Register(&Asset{})
	reg.Register(&BlastRadius{})
	reg.Register(&ThreatIntel{})
	reg.Register(&Compliance{})
	reg.Register(&Patch{})
}
