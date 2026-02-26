package main

import (
	"os"

	"github.com/asset-probe/cmd/probe/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
