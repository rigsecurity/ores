//go:build wasip1

// Package main is the WASM entry point for the ORES engine.
// It reads an EvaluationRequest JSON from stdin and writes an
// EvaluationResult JSON to stdout, following the wasip1 command model.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/score"
)

func main() {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		writeError(fmt.Sprintf("failed to read stdin: %s", err))
		os.Exit(1)
	}

	if len(input) == 0 {
		writeError("no input provided on stdin")
		os.Exit(1)
	}

	var req score.EvaluationRequest
	if err := json.Unmarshal(input, &req); err != nil {
		writeError(fmt.Sprintf("invalid JSON: %s", err))
		os.Exit(1)
	}

	eng := engine.New()

	result, err := eng.Evaluate(context.Background(), &req)
	if err != nil {
		writeError(err.Error())
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err := enc.Encode(result); err != nil {
		writeError(fmt.Sprintf("failed to write output: %s", err))
		os.Exit(1)
	}
}

func writeError(msg string) {
	errResp := map[string]string{"error": msg}
	output, _ := json.Marshal(errResp)
	os.Stderr.Write(output)   //nolint:errcheck
	os.Stderr.Write([]byte("\n")) //nolint:errcheck
}
