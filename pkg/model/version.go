// Package model implements the ORES dual-mode scoring engine:
// weighted dimensions for single-vulnerability scoring and B4 for multi-finding identity scoring.
// Both modes are deterministic: identical inputs always produce identical outputs.
package model

// ModelVersion is the current version of the ORES scoring model.
// Tests should reference this constant rather than hardcoding the version string.
const ModelVersion = "0.2.0"
