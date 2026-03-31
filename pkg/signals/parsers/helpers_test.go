package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   float64
		wantOK bool
	}{
		{name: "float64", input: float64(3.14), want: 3.14, wantOK: true},
		{name: "float32", input: float32(2.5), want: 2.5, wantOK: true},
		{name: "int", input: int(42), want: 42.0, wantOK: true},
		{name: "int64", input: int64(100), want: 100.0, wantOK: true},
		{name: "int32", input: int32(7), want: 7.0, wantOK: true},
		{name: "zero float64", input: float64(0), want: 0.0, wantOK: true},
		{name: "negative float64", input: float64(-1.5), want: -1.5, wantOK: true},
		{name: "string", input: "not a number", want: 0, wantOK: false},
		{name: "bool", input: true, want: 0, wantOK: false},
		{name: "nil", input: nil, want: 0, wantOK: false},
		{name: "slice", input: []int{1, 2}, want: 0, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toFloat64(tt.input)
			assert.Equal(t, tt.wantOK, ok)

			if ok {
				assert.InDelta(t, tt.want, got, 0.001)
			}
		})
	}
}

func TestToBool(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   bool
		wantOK bool
	}{
		{name: "true", input: true, want: true, wantOK: true},
		{name: "false", input: false, want: false, wantOK: true},
		{name: "string", input: "true", want: false, wantOK: false},
		{name: "int", input: 1, want: false, wantOK: false},
		{name: "nil", input: nil, want: false, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toBool(tt.input)
			assert.Equal(t, tt.wantOK, ok)

			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestToString(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   string
		wantOK bool
	}{
		{name: "valid string", input: "hello", want: "hello", wantOK: true},
		{name: "empty string", input: "", want: "", wantOK: true},
		{name: "int", input: 42, want: "", wantOK: false},
		{name: "bool", input: true, want: "", wantOK: false},
		{name: "nil", input: nil, want: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toString(tt.input)
			assert.Equal(t, tt.wantOK, ok)

			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   []string
		wantOK bool
	}{
		{
			name:   "valid string slice",
			input:  []any{"a", "b", "c"},
			want:   []string{"a", "b", "c"},
			wantOK: true,
		},
		{
			name:   "empty slice",
			input:  []any{},
			want:   []string{},
			wantOK: true,
		},
		{
			name:   "mixed types",
			input:  []any{"a", 1},
			want:   nil,
			wantOK: false,
		},
		{
			name:   "not a slice",
			input:  "not a slice",
			want:   nil,
			wantOK: false,
		},
		{
			name:   "nil",
			input:  nil,
			want:   nil,
			wantOK: false,
		},
		{
			name:   "int slice",
			input:  []any{1, 2, 3},
			want:   nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toStringSlice(tt.input)
			assert.Equal(t, tt.wantOK, ok)

			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestToMap(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{name: "valid map", input: map[string]any{"key": "val"}, wantErr: false},
		{name: "empty map", input: map[string]any{}, wantErr: false},
		{name: "string", input: "not a map", wantErr: true},
		{name: "int", input: 42, wantErr: true},
		{name: "nil", input: nil, wantErr: true},
		{name: "slice", input: []string{"a"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toMap(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}
