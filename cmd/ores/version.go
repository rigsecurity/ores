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

	if _, err := fmt.Fprintln(w, e.Version()); err != nil {
		return fmt.Errorf("writing version: %w", err)
	}

	return nil
}
