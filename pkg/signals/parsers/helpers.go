// Package parsers implements all built-in signal parsers for the ORES engine.
// Each parser validates raw input maps and normalizes field values to
// named float64 factors in the [0.0, 1.0] range.
package parsers

import "errors"

// errNotAMap is returned when Normalize is called with a non-map value.
var errNotAMap = errors.New("input must be a map")

// toMap performs a guarded type assertion to map[string]any.
// This is used by Normalize methods to avoid a panic if called without Validate.
func toMap(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errNotAMap
	}
	return m, nil
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func toBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func toString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func toStringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}

	result := make([]string, 0, len(arr))

	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}

		result = append(result, s)
	}

	return result, true
}
