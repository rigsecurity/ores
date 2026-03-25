package main

import (
	"fmt"
	"io"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the ORES scoring model version",
		Long:  "Print the version of the ORES scoring model.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVersion(cmd.OutOrStdout())
		},
	}
}

func runVersion(w io.Writer) error {
	e := engine.New()
	v := e.Version()

	if _, err := fmt.Fprintf(w, "ores version %s (model: %s)\n", v, v); err != nil {
		return fmt.Errorf("writing version: %w", err)
	}

	return nil
}
