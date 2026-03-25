package main

import (
	"io"
	"strings"

	"github.com/rigsecurity/ores/pkg/engine"
	"github.com/spf13/cobra"
)

func newSignalsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "signals",
		Short: "List all recognized signal types",
		Long:  "List all signal types recognized by the ORES engine, including their fields.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSignals(cmd.OutOrStdout())
		},
	}
}

func runSignals(w io.Writer) error {
	e := engine.New()
	descs := e.Signals()

	tw := newTabWriter(w)
	tw.println("NAME\tDESCRIPTION\tFIELDS")
	tw.println("----\t-----------\t------")

	for _, d := range descs {
		tw.printf("%s\t%s\t%s\n", d.Name, d.Description, strings.Join(d.Fields, ", "))
	}

	return tw.flush()
}
