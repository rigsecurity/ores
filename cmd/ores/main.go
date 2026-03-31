// Package main is the entry point for the ORES command-line interface.
package main

import (
	"fmt"
	"os"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	e := engine.New()

	cmd := &cobra.Command{
		Use:   "ores",
		Short: "ORES — Open Risk Evaluation & Scoring",
		Long:  "ORES — Open Risk Evaluation & Scoring\n\nEvaluate risk signals and produce a deterministic score.",
	}

	cmd.AddCommand(
		newEvaluateCmd(e),
		newSignalsCmd(e),
		newVersionCmd(e),
	)

	return cmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
