package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/rigsecurity/ores/pkg/score"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

func newEvaluateCmd() *cobra.Command {
	var (
		filePath     string
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate risk signals and produce a score",
		Long: `Evaluate a set of risk signals and return an ORES score.

Input is read from a file (-f) or from stdin when no file is given.
Both JSON and YAML input formats are supported.

Examples:
  ores evaluate -f signals.yaml
  cat signals.json | ores evaluate
  ores evaluate -f signals.json -o table`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvaluate(filePath, outputFormat, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Input file (JSON or YAML); defaults to stdin")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format: json, yaml, or table")

	return cmd
}

// runEvaluate reads input from filePath (or stdin when filePath is empty),
// calls the engine, and writes the result to w. It is a named function so
// evaluate_test.go can invoke it directly.
func runEvaluate(filePath, outputFormat string, w io.Writer) error {
	data, err := readInput(filePath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	req, err := parseRequest(data)
	if err != nil {
		return fmt.Errorf("parsing request: %w", err)
	}

	e := engine.New()

	result, err := e.Evaluate(context.Background(), req)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	return writeResult(result, outputFormat, w)
}

const maxInputSize = 10 << 20 // 10 MB

func readInput(filePath string) ([]byte, error) {
	if filePath == "" {
		return io.ReadAll(io.LimitReader(os.Stdin, maxInputSize))
	}

	f, err := os.Open(filePath) //nolint:gosec // path is user-supplied CLI input
	if err != nil {
		return nil, err //nolint:wrapcheck // wrapped at call site
	}
	defer f.Close() //nolint:errcheck // best-effort close on read-only file

	return io.ReadAll(io.LimitReader(f, maxInputSize))
}

// parseRequest accepts both JSON and YAML. We try JSON first; if it fails we
// attempt YAML. For YAML we round-trip through a generic map → JSON so that
// JSON struct tags (e.g. `json:"apiVersion"`) are honoured, because the yaml
// library matches on lowercased field names rather than json tag values.
func parseRequest(data []byte) (*score.EvaluationRequest, error) {
	var req score.EvaluationRequest

	if err := json.Unmarshal(data, &req); err == nil {
		return &req, nil
	}

	// Fallback: YAML → generic map → JSON → struct so json tags are respected.
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("input is not valid JSON or YAML: %w", err)
	}

	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encoding YAML as JSON: %w", err)
	}

	if err = json.Unmarshal(jsonBytes, &req); err != nil {
		return nil, fmt.Errorf("decoding request from YAML input: %w", err)
	}

	return &req, nil
}

func writeResult(result *score.EvaluationResult, format string, w io.Writer) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(result, w)
	case "yaml":
		return writeYAML(result, w)
	case "table":
		return writeTable(result, w)
	default:
		return fmt.Errorf("unknown output format %q; expected json, yaml, or table", format)
	}
}

func writeJSON(result *score.EvaluationResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	return nil
}

func writeYAML(result *score.EvaluationResult, w io.Writer) error {
	if err := yaml.NewEncoder(w).Encode(result); err != nil {
		return fmt.Errorf("encoding YAML: %w", err)
	}

	return nil
}

// tabWriter wraps tabwriter.Writer and accumulates the first write error so
// callers don't need to check every fmt.Fprintf return value individually.
type tabWriter struct {
	tw  *tabwriter.Writer
	err error
}

func newTabWriter(w io.Writer) *tabWriter {
	return &tabWriter{tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)}
}

func (t *tabWriter) printf(format string, args ...any) {
	if t.err != nil {
		return
	}

	_, t.err = fmt.Fprintf(t.tw, format, args...)
}

func (t *tabWriter) println(args ...any) {
	if t.err != nil {
		return
	}

	_, t.err = fmt.Fprintln(t.tw, args...)
}

func (t *tabWriter) flush() error {
	if t.err != nil {
		return t.err
	}

	return t.tw.Flush()
}

func writeTable(result *score.EvaluationResult, w io.Writer) error {
	tw := newTabWriter(w)

	tw.printf("Score:\t%d\n", result.Score)
	tw.printf("Label:\t%s\n", result.Label)
	tw.printf("Version:\t%s\n", result.Version)
	tw.printf("Confidence:\t%.2f\n", result.Explanation.Confidence)
	tw.printf("Signals used:\t%d / %d\n", result.Explanation.SignalsUsed, result.Explanation.SignalsProvided)

	if len(result.Explanation.UnknownSignals) > 0 {
		tw.printf("Unknown signals:\t%s\n", strings.Join(result.Explanation.UnknownSignals, ", "))
	}

	if len(result.Explanation.Warnings) > 0 {
		tw.printf("Warnings:\t%s\n", strings.Join(result.Explanation.Warnings, "; "))
	}

	tw.println("\nFACTOR\tCONTRIBUTION\tREASONING")
	tw.println("------\t------------\t---------")

	for _, f := range result.Explanation.Factors {
		tw.printf("%s\t%d\t%s\n", f.Name, f.Contribution, f.Reasoning)
	}

	return tw.flush()
}
