package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

func main() {
	var cmd = &cobra.Command{
		Use:   "seal",
		Short: "A tool for signing using the rsa algorithm",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(`seal`, Version, runtime.GOOS, runtime.GOARCH, Commit)
			fmt.Println(`Build at`, Date)
			fmt.Println(`Run 'seal --help' for usage.`)
			return nil
		},
	}
	cmd.AddCommand(
		ca(),
		sign(),
		read(),
	)
	e := cmd.Execute()
	if e != nil {
		os.Exit(1)
	}
}
