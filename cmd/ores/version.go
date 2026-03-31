package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

func newVersionCmd(e *engine.Engine) *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the ORES scoring model version",
		Long:  "Print the version of the ORES scoring model.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVersion(e, outputFormat, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format: text, json, or yaml")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"text", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

type versionOutput struct {
	Version string `json:"version" yaml:"version"`
}

func runVersion(e *engine.Engine, outputFormat string, w io.Writer) error {
	v := e.Version()

	switch strings.ToLower(outputFormat) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(versionOutput{Version: v}); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	case "yaml":
		enc := yaml.NewEncoder(w)
		if err := enc.Encode(versionOutput{Version: v}); err != nil {
			return fmt.Errorf("encoding YAML: %w", err)
		}
		return enc.Close()
	default:
		if _, err := fmt.Fprintf(w, "ores model version %s\n", v); err != nil {
			return fmt.Errorf("writing version: %w", err)
		}
		return nil
	}
}
